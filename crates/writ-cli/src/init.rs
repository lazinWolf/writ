//! `writ init`: put a project under writ in one command.
//!
//! - Writes a starter `writ.yaml` (observe mode) unless one exists.
//! - Adds writ's hook to `.claude/settings.json`, so every Claude Code tool
//!   call in the project is decided by writ.
//! - Wraps the stdio MCP servers in `.cursor/mcp.json` with `writ wrap`.
//!   Claude Code's own MCP servers need no wrapping: the hook sees their calls.
//!
//! Every file it changes is copied to `<file>.writ-backup` first.
//! `writ init --undo` removes writ's hook and unwraps the servers, leaving
//! `writ.yaml` and the flight log in place.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::claude_code;

const STARTER: &str = include_str!("starter.yaml");

pub struct Options {
    pub dir: Option<PathBuf>,
    pub undo: bool,
    pub enforce: bool,
    pub force: bool,
}

pub fn run(options: Options) -> Result<ExitCode> {
    let dir = match &options.dir {
        Some(d) => d.clone(),
        None => std::env::current_dir()?,
    };
    let dir = dir
        .canonicalize()
        .with_context(|| format!("cannot open {}", dir.display()))?;
    let writ = claude_code::current_exe();
    if options.undo {
        undo(&dir)?;
        return Ok(ExitCode::SUCCESS);
    }

    let policy = dir.join("writ.yaml");
    if policy.exists() && !options.force {
        println!("kept      {} (already exists; --force replaces it)", policy.display());
    } else {
        let text = starter(&dir, options.enforce);
        // The template must always be a valid policy.
        writ_policy::Policy::from_yaml_str(&text).context("the starter policy doesn't parse (a writ bug)")?;
        if policy.exists() {
            backup(&policy)?;
        }
        std::fs::write(&policy, text)?;
        let mode = if options.enforce { "enforce" } else { "observe" };
        println!("wrote     {} ({mode} mode)", policy.display());
    }

    let settings = dir.join(".claude/settings.json");
    let mut doc = read_json(&settings)?;
    if add_hooks(&mut doc, &writ)? {
        if settings.exists() {
            backup(&settings)?;
        }
        std::fs::create_dir_all(settings.parent().expect("has a parent"))?;
        write_json(&settings, &doc)?;
        println!("hooked    {} (PreToolUse, PostToolUse)", settings.display());
    } else {
        println!("kept      {} (writ's hook is already there)", settings.display());
    }

    let cursor = dir.join(".cursor/mcp.json");
    if cursor.exists() {
        let mut doc = read_json(&cursor)?;
        let (wrapped, skipped) = wrap_servers(&mut doc, &writ, &policy);
        if !wrapped.is_empty() {
            backup(&cursor)?;
            write_json(&cursor, &doc)?;
            println!("wrapped   {}: {}", cursor.display(), wrapped.join(", "));
        }
        if !skipped.is_empty() {
            println!(
                "skipped   {}: {} (remote servers; writ's HTTP gateway is planned)",
                cursor.display(),
                skipped.join(", ")
            );
        }
    }

    println!();
    println!("Next: use Claude Code in this project as usual, then run `writ report`.");
    if !options.enforce {
        println!("Nothing is blocked until you set `mode: enforce` in writ.yaml.");
    }
    Ok(ExitCode::SUCCESS)
}

fn starter(dir: &Path, enforce: bool) -> String {
    let name: String = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = if name.is_empty() { "project".to_string() } else { name };
    let text = STARTER.replace("{namespace}", &name);
    if enforce {
        text.replace("\nmode: observe\n", "\nmode: enforce\n")
    } else {
        text
    }
}

fn is_writ_hook(entry: &Value) -> bool {
    entry["hooks"].as_array().is_some_and(|hooks| {
        hooks
            .iter()
            .any(|h| h["command"].as_str().is_some_and(|c| c.contains(" hook claude-code")))
    })
}

/// Adds writ's PreToolUse and PostToolUse hooks. False if already present.
fn add_hooks(settings: &mut Value, writ: &Path) -> Result<bool> {
    let Value::Object(root) = settings else {
        bail!("settings.json is not a JSON object");
    };
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let Value::Object(hooks) = hooks else {
        bail!("settings.json `hooks` is not an object");
    };
    let ours = claude_code::settings_hooks(writ);
    let mut changed = false;
    for event in ["PreToolUse", "PostToolUse"] {
        let list = hooks.entry(event).or_insert_with(|| json!([]));
        let Value::Array(list) = list else {
            bail!("settings.json `hooks.{event}` is not a list");
        };
        if !list.iter().any(is_writ_hook) {
            list.extend(ours[event].as_array().expect("an array").iter().cloned());
            changed = true;
        }
    }
    Ok(changed)
}

fn remove_hooks(settings: &mut Value) -> bool {
    let mut changed = false;
    if let Some(Value::Object(hooks)) = settings.get_mut("hooks") {
        for list in hooks.values_mut() {
            if let Value::Array(list) = list {
                let before = list.len();
                list.retain(|e| !is_writ_hook(e));
                changed |= list.len() != before;
            }
        }
        hooks.retain(|_, v| v.as_array().is_none_or(|l| !l.is_empty()));
    }
    changed
}

/// Rewrites stdio servers (`command` + `args`) to run under `writ wrap`.
/// Returns the names wrapped and the names skipped (remote servers).
fn wrap_servers(doc: &mut Value, writ: &Path, policy: &Path) -> (Vec<String>, Vec<String>) {
    let (mut wrapped, mut skipped) = (Vec::new(), Vec::new());
    let Some(Value::Object(servers)) = doc.get_mut("mcpServers") else {
        return (wrapped, skipped);
    };
    for (name, server) in servers.iter_mut() {
        let Some(command) = server.get("command").and_then(Value::as_str).map(str::to_string) else {
            skipped.push(name.clone());
            continue;
        };
        if is_wrapped(server) {
            continue;
        }
        let mut args = vec![
            json!("wrap"),
            json!("--name"),
            json!(server_name(name)),
            json!("--policy"),
            json!(policy.display().to_string()),
            json!("--"),
            json!(command),
        ];
        args.extend(
            server
                .get("args")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        server["command"] = json!(writ.display().to_string());
        server["args"] = Value::Array(args);
        wrapped.push(name.clone());
    }
    (wrapped, skipped)
}

fn is_wrapped(server: &Value) -> bool {
    server["args"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        == Some("wrap")
        && server["args"].as_array().is_some_and(|a| a.iter().any(|v| v == "--"))
}

fn unwrap_servers(doc: &mut Value) -> Vec<String> {
    let mut restored = Vec::new();
    let Some(Value::Object(servers)) = doc.get_mut("mcpServers") else {
        return restored;
    };
    for (name, server) in servers.iter_mut() {
        if !is_wrapped(server) {
            continue;
        }
        let args = server["args"].as_array().cloned().unwrap_or_default();
        let split = args.iter().position(|v| v == "--").expect("checked");
        let Some((command, rest)) = args[split + 1..].split_first() else {
            continue;
        };
        server["command"] = command.clone();
        server["args"] = Value::Array(rest.to_vec());
        restored.push(name.clone());
    }
    restored
}

/// A config key as a `writ wrap --name`: characters outside `[A-Za-z0-9_.-]` become `-`.
fn server_name(key: &str) -> String {
    let name: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if name.is_empty() { "server".into() } else { name }
}

fn undo(dir: &Path) -> Result<()> {
    let settings = dir.join(".claude/settings.json");
    if settings.exists() {
        let mut doc = read_json(&settings)?;
        if remove_hooks(&mut doc) {
            write_json(&settings, &doc)?;
            println!("unhooked  {}", settings.display());
        }
    }
    let cursor = dir.join(".cursor/mcp.json");
    if cursor.exists() {
        let mut doc = read_json(&cursor)?;
        let restored = unwrap_servers(&mut doc);
        if !restored.is_empty() {
            write_json(&cursor, &doc)?;
            println!("unwrapped {}: {}", cursor.display(), restored.join(", "));
        }
    }
    println!("kept      {} and the flight log", dir.join("writ.yaml").display());
    Ok(())
}

fn read_json(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let text = std::fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    serde_json::from_str(&text).with_context(|| format!("{} is not valid JSON; not touching it", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
}

/// Copies `path` to `<path>.writ-backup`, keeping the first backup ever made.
fn backup(path: &Path) -> Result<()> {
    let mut name = path.as_os_str().to_owned();
    name.push(".writ-backup");
    let target = PathBuf::from(name);
    if !target.exists() {
        std::fs::copy(path, &target).with_context(|| format!("cannot back up {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_starter_policy_parses_in_both_modes() {
        for enforce in [false, true] {
            let text = starter(Path::new("/x/my proj"), enforce);
            let policy = writ_policy::Policy::from_yaml_str(&text).unwrap();
            assert_eq!(policy.namespace, "my-proj");
            assert_eq!(policy.mode == writ_policy::Mode::Observe, !enforce);
        }
    }

    #[test]
    fn hooks_merge_idempotently_and_undo() {
        let mut doc = json!({ "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "mine" }] }] }, "model": "x" });
        assert!(add_hooks(&mut doc, Path::new("/bin/writ")).unwrap());
        assert!(!add_hooks(&mut doc, Path::new("/bin/writ")).unwrap());
        assert_eq!(doc["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);
        assert!(remove_hooks(&mut doc));
        assert_eq!(doc["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "mine");
        assert!(doc["hooks"].get("PostToolUse").is_none());
        assert_eq!(doc["model"], "x");
    }

    #[test]
    fn servers_wrap_and_unwrap() {
        let original = json!({ "mcpServers": {
            "github": { "command": "npx", "args": ["-y", "@x/github"], "env": { "T": "1" } },
            "remote": { "url": "https://example.com/mcp" },
        }});
        let mut doc = original.clone();
        let (wrapped, skipped) = wrap_servers(&mut doc, Path::new("/bin/writ"), Path::new("/p/writ.yaml"));
        assert_eq!(
            (wrapped, skipped),
            (vec!["github".to_string()], vec!["remote".to_string()])
        );
        assert_eq!(doc["mcpServers"]["github"]["command"], "/bin/writ");
        assert_eq!(
            doc["mcpServers"]["github"]["args"],
            json!([
                "wrap",
                "--name",
                "github",
                "--policy",
                "/p/writ.yaml",
                "--",
                "npx",
                "-y",
                "@x/github"
            ])
        );
        // Wrapping twice changes nothing.
        let again = doc.clone();
        wrap_servers(&mut doc, Path::new("/bin/writ"), Path::new("/p/writ.yaml"));
        assert_eq!(doc, again);
        assert_eq!(unwrap_servers(&mut doc), vec!["github".to_string()]);
        assert_eq!(doc, original);
    }
}
