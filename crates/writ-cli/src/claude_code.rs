//! `writ hook claude-code`: Claude Code's PreToolUse and PostToolUse hooks.
//!
//! Claude Code runs the hook once per tool call, with the call as JSON on
//! stdin. Every tool goes through it (Bash, file edits, web fetches, MCP
//! tools), so this covers what an MCP proxy can't see. Each call becomes an
//! **action**: a source, a tool name and arguments that writ's policies
//! match (see [`action`]). writd decides it, keeping one task per Claude
//! Code session so taint and limits carry across calls.
//!
//! writ only ever narrows what Claude Code would do. An allowed call gets no
//! answer at all, so Claude Code's own permission rules still apply.
//! `require_sudo` becomes `ask` (Claude Code prompts its user) and `deny`
//! becomes `deny`. If writ can't decide (no policy, writd unreachable), the
//! call is denied with the reason.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use writ_daemon::Client;
use writ_daemon::protocol::ScopedRequest;
use writ_policy::Outcome;

/// What Claude Code sends a hook on stdin (the fields writ reads).
#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub session_id: String,
    #[serde(default)]
    pub cwd: Option<String>,
    pub hook_event_name: String,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(default)]
    pub tool_use_id: Option<String>,
}

/// A Claude Code tool call, as writ's policies see it.
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    /// `shell`, `fs`, `web`, `agent`, `claude`, or `mcp:<server>`.
    pub source: String,
    /// `shell.exec`, `fs.read`, `fs.write`, `fs.search`, `web.fetch`,
    /// `web.search`, `agent.spawn`, `<server>.<tool>` for MCP tools, and
    /// `claude.<Tool>` for the rest.
    pub tool: String,
    pub args: Value,
}

/// Maps a Claude Code tool call to an action. Paths are made absolute
/// (against `cwd`) and normalized, so `args.path within writ.workspace` and
/// `args.path matches "*/.mcp.json"` mean what they say.
pub fn action(tool_name: &str, input: &Value, cwd: Option<&str>) -> Action {
    let s = |key: &str| input.get(key).and_then(Value::as_str);
    let path = |key: &str| s(key).map(|p| absolute(p, cwd));
    let mut args = Map::new();
    let mut put = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            args.insert(key.to_string(), value);
        }
    };
    let (source, tool) = match tool_name {
        "Bash" => {
            let command = s("command").unwrap_or_default();
            put("command", Some(json!(command)));
            put("argv", Some(json!(shell_words(command))));
            put("description", s("description").map(|d| json!(d)));
            put("background", input.get("run_in_background").cloned());
            ("shell", "shell.exec".to_string())
        }
        "Read" => {
            put("path", path("file_path").map(Value::from));
            ("fs", "fs.read".to_string())
        }
        "Write" | "Edit" | "MultiEdit" => {
            put("path", path("file_path").map(Value::from));
            put("kind", Some(json!(tool_name.to_lowercase())));
            ("fs", "fs.write".to_string())
        }
        "NotebookEdit" => {
            put("path", path("notebook_path").map(Value::from));
            put("kind", Some(json!("notebook")));
            ("fs", "fs.write".to_string())
        }
        "Glob" | "Grep" | "LS" => {
            put(
                "path",
                path("path").or_else(|| cwd.map(str::to_string)).map(Value::from),
            );
            put("pattern", s("pattern").map(|p| json!(p)));
            ("fs", "fs.search".to_string())
        }
        "WebFetch" => {
            let url = s("url").unwrap_or_default();
            put("url", Some(json!(url)));
            put("host", host(url).map(Value::from));
            ("web", "web.fetch".to_string())
        }
        "WebSearch" => {
            put("query", s("query").map(|q| json!(q)));
            ("web", "web.search".to_string())
        }
        "Task" | "Agent" => {
            put("subagent_type", s("subagent_type").map(|t| json!(t)));
            put("description", s("description").map(|d| json!(d)));
            ("agent", "agent.spawn".to_string())
        }
        name => match mcp_tool(name) {
            Some((server, tool)) => {
                return Action {
                    source: format!("mcp:{server}"),
                    tool: format!("{server}.{tool}"),
                    args: input.clone(),
                };
            }
            None => {
                return Action {
                    source: "claude".into(),
                    tool: format!("claude.{name}"),
                    args: input.clone(),
                };
            }
        },
    };
    Action {
        source: source.to_string(),
        tool,
        args: Value::Object(args),
    }
}

/// `mcp__<server>__<tool>` → `(server, tool)`.
fn mcp_tool(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    (!server.is_empty() && !tool.is_empty()).then_some((server, tool))
}

/// Lexically normalized absolute path; relative paths resolve against `cwd`.
fn absolute(path: &str, cwd: Option<&str>) -> String {
    let joined = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{path}", cwd.unwrap_or(""))
    };
    let mut parts: Vec<&str> = Vec::new();
    for segment in joined.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

/// The host of an `http(s)://` URL, lowercased.
fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Splits a command line into words, honoring quotes and backslashes. Shell
/// operators (`&&`, `|`, `;`) stay words of their own when spaced, so
/// `args.argv` sees every command in a chain. Not a shell parser: policies
/// should also match on `args.command`.
fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = command.chars();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => word.extend(chars.next()),
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, '\\') => {
                word.extend(chars.next());
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            (None, c) => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// Runs one hook invocation: reads Claude Code's JSON on stdin and prints
/// the hook's answer on stdout. Always exits 0, so Claude Code reads the
/// answer (including denials when writ itself fails).
pub fn run(policy: Option<&Path>, principal: Option<&str>, log: Option<&Path>) -> Result<ExitCode> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    let input: HookInput = serde_json::from_str(&raw).context("hook input is not Claude Code's hook JSON")?;
    let pre = input.hook_event_name == "PreToolUse";
    match handle(&input, policy, principal, log) {
        Ok(Some(answer)) => println!("{answer}"),
        Ok(None) => {}
        // Fail closed, but only where a call can still be stopped.
        Err(e) if pre => println!("{}", answer("deny", &format!("writ could not decide this call: {e:#}"))),
        Err(e) => eprintln!("writ: {e:#}"),
    }
    Ok(ExitCode::SUCCESS)
}

fn handle(
    input: &HookInput,
    policy: Option<&Path>,
    principal: Option<&str>,
    log: Option<&Path>,
) -> Result<Option<String>> {
    let workspace = std::env::var("CLAUDE_PROJECT_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .or_else(|| input.cwd.clone());
    let policy_path = match policy {
        Some(p) => p.to_path_buf(),
        None => workspace
            .as_deref()
            .map(|w| Path::new(w).join("writ.yaml"))
            .context("no --policy given and no project directory to find writ.yaml in")?,
    };
    let files = crate::read_policy(&policy_path).with_context(|| {
        format!(
            "no usable policy at {} (run `writ init`, or remove writ's hook from .claude/settings.json)",
            policy_path.display()
        )
    })?;
    let action = action(&input.tool_name, &input.tool_input, input.cwd.as_deref());
    let request = ScopedRequest {
        scope: format!("claude-code:{}", input.session_id),
        policy: files.policy,
        entitlements: files.entitlements,
        workspace: workspace.map(|w| absolute(&w, None)),
        principal: principal.map(str::to_string),
        source: action.source,
        tool: action.tool,
        args: action.args,
        call_id: input.tool_use_id.clone().map_or(Value::Null, Value::from),
    };
    let socket = writ_daemon::default_socket_path();
    let mut client = Client::connect_or_start(&socket, log)?;
    match input.hook_event_name.as_str() {
        "PreToolUse" => {
            let decision = client.check(request)?;
            Ok(match decision.outcome {
                // Say nothing: Claude Code's own permissions still apply.
                Outcome::Allow => None,
                Outcome::RequireSudo => Some(answer("ask", &decision.reason)),
                Outcome::Deny => Some(answer("deny", &decision.reason)),
            })
        }
        "PostToolUse" => {
            client.executed(request)?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn answer(decision: &str, reason: &str) -> String {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": format!("writ: {reason}"),
        }
    })
    .to_string()
}

/// The hook entries `writ init` adds to `.claude/settings.json`.
pub fn settings_hooks(writ: &Path) -> Value {
    let command = format!("{} hook claude-code", shell_quote(&writ.display().to_string()));
    let entry = json!([{ "matcher": "*", "hooks": [{ "type": "command", "command": command }] }]);
    json!({ "PreToolUse": entry, "PostToolUse": entry })
}

fn shell_quote(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The path of the running `writ` binary, for hook commands.
pub fn current_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("writ"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_builtin_tools() {
        let a = action(
            "Bash",
            &json!({"command": "git push --force origin 'my branch'"}),
            Some("/w"),
        );
        assert_eq!((a.source.as_str(), a.tool.as_str()), ("shell", "shell.exec"));
        assert_eq!(a.args["argv"], json!(["git", "push", "--force", "origin", "my branch"]));

        let a = action(
            "Write",
            &json!({"file_path": "src/../.mcp.json", "content": "x"}),
            Some("/w"),
        );
        assert_eq!(a.tool, "fs.write");
        assert_eq!(a.args["path"], "/w/.mcp.json");
        assert!(a.args.get("content").is_none(), "file contents aren't logged");

        let a = action("WebFetch", &json!({"url": "https://User@Evil.example:8443/x?y"}), None);
        assert_eq!(
            (a.source.as_str(), a.args["host"].as_str()),
            ("web", Some("evil.example"))
        );

        let a = action("Grep", &json!({"pattern": "TODO"}), Some("/w"));
        assert_eq!(a.args["path"], "/w");
    }

    #[test]
    fn maps_mcp_and_other_tools() {
        let a = action("mcp__github__create_pull_request", &json!({"repo": "x"}), None);
        assert_eq!(
            (a.source.as_str(), a.tool.as_str()),
            ("mcp:github", "github.create_pull_request")
        );
        assert_eq!(a.args, json!({"repo": "x"}));
        let a = action("TodoWrite", &json!({}), None);
        assert_eq!((a.source.as_str(), a.tool.as_str()), ("claude", "claude.TodoWrite"));
    }

    #[test]
    fn splits_shell_words() {
        assert_eq!(shell_words(r#"a "b c" d\ e 'f"g'"#), ["a", "b c", "d e", "f\"g"]);
        assert_eq!(shell_words("x && rm -rf /"), ["x", "&&", "rm", "-rf", "/"]);
        assert_eq!(shell_words(r#"echo """#), ["echo", ""]);
    }
}
