mod claude_code;
mod init;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use writ_daemon::{Client, LEGACY_TASK_ENV, LoadedEntitlements, LoadedPolicy, SOCKET_ENV, TASK_ID_ENV, TOKEN_ENV};
use writ_policy::Policy;
use writ_proxy::{Backend, DaemonBackend, LocalBackend};
use writ_recorder::{Entry, Recorder};

#[derive(Parser)]
#[command(name = "writ", version, about = "Capability and policy layer for agent tool calls")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run an MCP server over stdio with every tools/call checked against a policy.
    ///
    /// Under `writ run` (WRIT_TOKEN set) the server joins that task through writd: the task's
    /// policy and limits apply, and --policy can only narrow them. Otherwise --policy is
    /// required and decisions are made in this process, or in writd with --daemon.
    /// The server never sees the token: it is removed from the server's environment.
    Wrap {
        /// Path to writ.yaml. Required unless WRIT_TOKEN is set.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// The server's name. Its session is `mcp:<name>`, which is what policies match in
        /// `data_flow.untrusted_sources` and `writ.session.name`. Derived from the command if omitted.
        #[arg(long)]
        name: Option<String>,
        /// Decide through writd (starting it if needed) so `writ ps` can see this session.
        #[arg(long)]
        daemon: bool,
        /// Flight recorder file [default: $WRIT_LOG or ~/.local/state/writ/flight.jsonl].
        /// With writd, only used if this command starts it.
        #[arg(long)]
        log: Option<PathBuf>,
        /// Don't wait for decisions to reach stable storage before forwarding calls (standalone only).
        #[arg(long)]
        no_fsync: bool,
        /// How long the server gets to exit after the client disconnects, before writ terminates it.
        #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
        shutdown_grace: Duration,
        /// The MCP server command and its arguments.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Run an agent as a writ task: every `writ wrap` it starts shares this policy and its limits.
    Run {
        /// Path to writ.yaml for the task.
        #[arg(long)]
        policy: PathBuf,
        /// The principal the task acts for, e.g. alice@example.com. Its entitlements come from
        /// the policy's entitlement source. Unverified: writ records it as asserted.
        #[arg(long)]
        principal: Option<String>,
        /// How long the task's token (WRIT_TOKEN) is valid. Sessions opened with it are
        /// denied once it expires.
        #[arg(long, default_value = "24h", value_parser = humantime::parse_duration)]
        ttl: Duration,
        /// Flight recorder file, used if this command starts writd.
        #[arg(long)]
        log: Option<PathBuf>,
        /// The agent command and its arguments.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Narrow this task's token for a sub-agent, without asking writd.
    ///
    /// Reads WRIT_TOKEN and appends a signed block: a narrowing policy, a label for the
    /// lineage, a shorter expiry. Servers the sub-agent wraps get the task's policy and
    /// every fork's, most restrictive outcome wins. A fork can only narrow; nothing in it
    /// can widen what the token grants. With a command, runs it with the forked token;
    /// without, prints the token.
    Fork {
        /// A policy the sub-agent is held to, on top of the task's. It can't declare an
        /// entitlement source (the task's applies).
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Names this branch in decisions and the log, e.g. `billing`.
        #[arg(long)]
        label: Option<String>,
        /// Expire the forked token sooner than its parent.
        #[arg(long, value_parser = humantime::parse_duration)]
        ttl: Option<Duration>,
        /// The sub-agent command and its arguments.
        #[arg(last = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Put a project under writ: a starter writ.yaml (observe mode), writ's Claude Code hook,
    /// and `writ wrap` around the stdio servers in .cursor/mcp.json.
    Init {
        /// The project directory [default: the current directory].
        dir: Option<PathBuf>,
        /// Start in enforce mode instead of observe mode.
        #[arg(long)]
        enforce: bool,
        /// Replace an existing writ.yaml (it's backed up first).
        #[arg(long)]
        force: bool,
        /// Remove writ's hook and unwrap servers. Keeps writ.yaml and the log.
        #[arg(long)]
        undo: bool,
    },
    /// Summarize what policies decided: per tool, what was or would have been refused, and
    /// privileged calls made after reading untrusted content.
    Report {
        /// Flight recorder file [default: $WRIT_LOG or ~/.local/state/writ/flight.jsonl].
        #[arg(long)]
        log: Option<PathBuf>,
        /// Only this task or session.
        #[arg(long)]
        task: Option<String>,
    },
    /// Decide an agent's tool calls from inside the agent's own hooks.
    Hook {
        #[command(subcommand)]
        target: HookTarget,
    },
    /// List live tasks.
    Ps,
    /// Decide calls waiting for approval (policies with an `approvals:` block, under writd).
    Sudo {
        #[command(subcommand)]
        action: SudoAction,
    },
    /// Validate a writ.yaml without running anything.
    Check { policy: PathBuf },
    /// Re-decide recorded calls under another policy and show what would change.
    ///
    /// Exits 1 if any call would be decided less restrictively (for example deny -> allow),
    /// so it can gate policy changes in CI; 0 otherwise.
    Replay {
        /// The candidate writ.yaml.
        #[arg(long)]
        policy: PathBuf,
        /// Flight recorder file [default: $WRIT_LOG or ~/.local/state/writ/flight.jsonl].
        #[arg(long)]
        log: Option<PathBuf>,
        /// Only replay calls from this task or session.
        #[arg(long)]
        task: Option<String>,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show or verify the flight recorder.
    Log {
        /// Flight recorder file [default: $WRIT_LOG or ~/.local/state/writ/flight.jsonl].
        #[arg(long)]
        log: Option<PathBuf>,
        /// Check the hash chain instead of printing entries.
        #[arg(long)]
        verify: bool,
        /// Only show entries from this session or task.
        #[arg(long)]
        session: Option<String>,
        /// Print raw JSON lines.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum HookTarget {
    /// Claude Code's PreToolUse/PostToolUse hook: reads the call on stdin and answers it.
    ///
    /// Every Claude Code tool goes through it: Bash (`shell.exec`), file reads and edits
    /// (`fs.read`, `fs.write`), web fetches (`web.fetch`, source `web`), sub-agents
    /// (`agent.spawn`) and MCP tools (`<server>.<tool>`, source `mcp:<server>`). Calls in one
    /// Claude Code session share a writ task in writd (started if needed). writ only narrows:
    /// an allowed call is left to Claude Code's own permissions, `require_sudo` makes Claude
    /// Code ask, and `deny` denies.
    ClaudeCode {
        /// Path to writ.yaml [default: $CLAUDE_PROJECT_DIR/writ.yaml].
        #[arg(long)]
        policy: Option<PathBuf>,
        /// The principal the session acts for (unverified).
        #[arg(long)]
        principal: Option<String>,
        /// Flight recorder file, used if this starts writd.
        #[arg(long)]
        log: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SudoAction {
    /// List calls waiting for approval, oldest first.
    List {
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show one waiting call in full: tool, arguments (redacted per policy), task facts, reason.
    Show { id: String },
    /// Let a waiting call run. It is re-checked first (task still live, limits not reached).
    Approve { id: String },
    /// Refuse a waiting call. The agent gets a policy denial.
    Deny { id: String },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            // stdout belongs to the MCP client during `wrap`, so errors go to stderr.
            eprintln!("writ: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Commands::Wrap {
            policy,
            name,
            daemon,
            log,
            no_fsync,
            shutdown_grace,
            command,
        } => {
            let name_derived = name.is_none();
            let name = match name {
                Some(name) => {
                    writ_policy::validate_session_name(&name).map_err(anyhow::Error::msg)?;
                    name
                }
                None => {
                    let name = derive_server_name(&command);
                    eprintln!(
                        "writ: no --name given; this server is `{}`. Pass --name if a policy refers to it.",
                        writ_policy::session_source(&name)
                    );
                    name
                }
            };
            let (backend, token) = wrap_backend(policy.as_deref(), daemon, log, !no_fsync)?;
            let config = writ_proxy::WrapConfig {
                backend,
                name,
                name_derived,
                command,
                shutdown_grace,
                forward_signals: true,
                token,
            };
            let code = writ_proxy::run(config, std::io::stdin(), std::io::stdout())?;
            Ok(exit_code(code))
        }
        Commands::Run {
            policy,
            principal,
            ttl,
            log,
            command,
        } => run_task(&policy, principal.as_deref(), ttl, log.as_deref(), &command),
        Commands::Fork {
            policy,
            label,
            ttl,
            command,
        } => fork(policy.as_deref(), label.as_deref(), ttl, &command),
        Commands::Ps => ps(),
        Commands::Init {
            dir,
            enforce,
            force,
            undo,
        } => init::run(init::Options {
            dir,
            undo,
            enforce,
            force,
        }),
        Commands::Report { log, task } => report(log, task.as_deref()),
        Commands::Hook {
            target: HookTarget::ClaudeCode { policy, principal, log },
        } => claude_code::run(policy.as_deref(), principal.as_deref(), log.as_deref()),
        Commands::Sudo { action } => sudo(action),
        Commands::Replay {
            policy,
            log,
            task,
            json,
        } => replay(&policy, log, task.as_deref(), json),
        Commands::Check { policy: path } => {
            let files = read_policy(&path)?;
            let parsed = Policy::from_yaml_str(&files.policy)?;
            println!(
                "{}: ok (namespace {}, enforcement {:?}, max_tool_calls {})",
                path.display(),
                parsed.namespace,
                parsed.enforcement,
                parsed
                    .limits
                    .max_tool_calls
                    .map_or("unlimited".to_string(), |n| n.to_string()),
            );
            if let Some(depth) = parsed.limits.max_depth {
                println!("  max_depth: {depth} (forks below the root)");
            }
            if !parsed.untrusted_sources.is_empty() {
                println!("  untrusted sources: {}", parsed.untrusted_sources.join(", "));
            }
            if let Some(spec) = &parsed.entitlements {
                println!(
                    "  entitlements: {} (tables used: {})",
                    spec.path,
                    match parsed.lookup_tables() {
                        t if t.is_empty() => "none".to_string(),
                        t => t.join(", "),
                    }
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Log {
            log,
            verify,
            session,
            json,
        } => {
            let path = log.unwrap_or_else(writ_recorder::default_log_path);
            if verify {
                let count = writ_recorder::verify(&path)?;
                println!("{}: {count} entries, hash chain intact", path.display());
                println!("note: the chain is not externally anchored; whoever can write this file can rewrite it");
                return Ok(ExitCode::SUCCESS);
            }
            let entries = writ_recorder::read_entries(&path)?;
            for entry in entries.iter().filter(|e| {
                session
                    .as_ref()
                    .is_none_or(|s| &e.session == s || e.data["task"].as_str() == Some(s))
            }) {
                if json {
                    println!("{}", serde_json::to_string(entry)?);
                } else {
                    println!("{}", format_entry(entry));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// A policy's text and, if it declares one, its entitlement source's text.
struct PolicyFiles {
    policy: String,
    entitlements: Option<String>,
}

/// Reads and validates a policy and its entitlement source. Each is read
/// once: the recorded hashes must describe exactly what is enforced.
fn read_policy(path: &Path) -> Result<PolicyFiles> {
    let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let loaded = LoadedPolicy::parse(&text).with_context(|| format!("{}", path.display()))?;
    let Some(spec) = &loaded.policy.entitlements else {
        return Ok(PolicyFiles {
            policy: text,
            entitlements: None,
        });
    };
    let source_path = path.parent().unwrap_or(Path::new(".")).join(&spec.path);
    let entitlements = std::fs::read_to_string(&source_path)
        .with_context(|| format!("cannot read the entitlement source {}", source_path.display()))?;
    let source = LoadedEntitlements::parse(&entitlements).with_context(|| format!("{}", source_path.display()))?;
    for table in loaded.policy.lookup_tables() {
        if !source.source.has_table(table) {
            bail!(
                "{}: a rule looks up table `{table}`, which {} doesn't have",
                path.display(),
                source_path.display()
            );
        }
    }
    Ok(PolicyFiles {
        policy: text,
        entitlements: Some(entitlements),
    })
}

/// The backend to decide through, and the token it joined a task with (if any).
fn wrap_backend(
    policy: Option<&Path>,
    daemon: bool,
    log: Option<PathBuf>,
    fsync: bool,
) -> Result<(Box<dyn Backend>, Option<String>)> {
    let non_empty = |key| std::env::var(key).ok().filter(|v| !v.is_empty());
    let token = non_empty(TOKEN_ENV);
    if token.is_none() && non_empty(LEGACY_TASK_ENV).is_some() {
        // Running outside the task would be silently looser than the caller expects.
        bail!(
            "{LEGACY_TASK_ENV} is set, but bare task ids no longer join a task: \
             run the agent under `writ run`, which sets {TOKEN_ENV}"
        );
    }
    let policy = policy.map(read_policy).transpose()?;
    let socket = writ_daemon::default_socket_path();

    if let Some(token) = token {
        // Fail closed: the task's limits can only be enforced by writd.
        let client = Client::connect(&socket)
            .with_context(|| format!("{TOKEN_ENV} is set but writd is unreachable; refusing to run the server"))?;
        // A narrowing policy reads the task's entitlement source; writd rejects one that declares its own.
        let (policy, entitlements) = match policy {
            Some(files) => (Some(files.policy), files.entitlements),
            None => (None, None),
        };
        let backend = DaemonBackend::new(client, Some(token.clone()), policy, entitlements);
        return Ok((Box::new(backend), Some(token)));
    }
    let Some(files) = policy else {
        bail!("--policy is required unless running under `writ run`");
    };
    if daemon {
        let client = Client::connect_or_start(&socket, log.as_deref())?;
        let backend = DaemonBackend::new(client, None, Some(files.policy), files.entitlements);
        return Ok((Box::new(backend), None));
    }
    let mut recorder = Recorder::open(log.unwrap_or_else(writ_recorder::default_log_path))?;
    recorder.set_fsync(fsync);
    let entitlements = files
        .entitlements
        .as_deref()
        .map(LoadedEntitlements::parse)
        .transpose()?;
    let backend = LocalBackend::new(recorder, LoadedPolicy::parse(&files.policy)?, entitlements);
    Ok((Box::new(backend), None))
}

fn fork(policy: Option<&Path>, label: Option<&str>, ttl: Option<Duration>, command: &[String]) -> Result<ExitCode> {
    let token = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|t| !t.is_empty())
        .with_context(|| {
            format!("{TOKEN_ENV} is not set: `writ fork` narrows a task's token, so run it under `writ run`")
        })?;
    let policy = policy
        .map(|path| -> Result<String> {
            let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
            let loaded = LoadedPolicy::parse(&text).with_context(|| format!("{}", path.display()))?;
            if loaded.policy.entitlements.is_some() {
                bail!(
                    "{}: a fork's policy can't declare an entitlement source; the task's applies",
                    path.display()
                );
            }
            Ok(text)
        })
        .transpose()?;
    if let Some(label) = label {
        writ_policy::validate_session_name(label).map_err(|e| anyhow::anyhow!("--label: {e}"))?;
    }
    let spec = writ_daemon::token::ForkSpec {
        label,
        policy: policy.as_deref(),
        ttl,
    };
    let forked = writ_daemon::token::fork(&token, &spec)?;
    let Some((program, args)) = command.split_first() else {
        println!("{forked}");
        return Ok(ExitCode::SUCCESS);
    };
    // Replace this process: the sub-agent gets our signals and our exit status.
    use std::os::unix::process::CommandExt;
    let err = Command::new(program).args(args).env(TOKEN_ENV, &forked).exec();
    Err(anyhow::Error::new(err).context(format!("failed to start `{program}`")))
}

fn run_task(
    policy: &Path,
    principal: Option<&str>,
    ttl: Duration,
    log: Option<&Path>,
    command: &[String],
) -> Result<ExitCode> {
    let files = read_policy(policy)?;
    let socket = writ_daemon::default_socket_path();
    // The connection stays open while the agent runs: if writ run dies, writd ends the task.
    let mut client = Client::connect_or_start(&socket, log)?;
    let meta = json!({
        "command": command,
        "user": std::env::var("USER").ok(),
        "cwd": std::env::current_dir().ok(),
    });
    let created = client.create_task(&files.policy, files.entitlements.as_deref(), principal, Some(ttl), meta)?;
    let task = created.task;

    let (program, args) = command.split_first().context("no command given")?;
    let mut child = Command::new(program)
        .args(args)
        .env(TOKEN_ENV, &created.token)
        .env(TASK_ID_ENV, &task)
        .env_remove(LEGACY_TASK_ENV)
        .env(SOCKET_ENV, &socket)
        .spawn()
        .with_context(|| format!("failed to start `{program}`"))?;

    // The agent shares our terminal and process group, so Ctrl-C reaches it directly;
    // swallow SIGINT here so writ run outlives it and can end the task. Forward the rest.
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ])?;
    let pid = child.id() as libc::pid_t;
    std::thread::spawn(move || {
        for signal in signals.forever() {
            if signal != signal_hook::consts::SIGINT {
                // SAFETY: kill(2) has no memory-safety preconditions.
                unsafe { libc::kill(pid, signal) };
            }
        }
    });

    let status = child.wait()?;
    if let Err(e) = client.end_task(&task) {
        eprintln!("writ: ending task {task}: {e:#}");
    }
    use std::os::unix::process::ExitStatusExt;
    Ok(exit_code(
        status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
    ))
}

fn ps() -> Result<ExitCode> {
    let socket = writ_daemon::default_socket_path();
    let Ok(mut client) = Client::connect(&socket) else {
        println!("writd is not running ({})", socket.display());
        return Ok(ExitCode::SUCCESS);
    };
    let tasks = client.ps()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    println!(
        "{:<28}  {:<10}  {:<20}  {:<18}  {:>8}  {:>11}  {:>6}  {:<7}  {:>8}  {:<24}  COMMAND",
        "TASK", "USER", "PRINCIPAL", "NAMESPACE", "SESSIONS", "CALLS", "DENIED", "TAINTED", "AGE", "SERVERS"
    );
    let any_principal = tasks.iter().any(|t| t.principal.is_some());
    for t in tasks {
        let calls = match t.max_tool_calls {
            Some(max) => format!("{}/{max}", t.counters.calls_allowed),
            None => t.counters.calls_allowed.to_string(),
        };
        let age = humantime::format_duration(Duration::from_secs(now.saturating_sub(t.started_ms) / 1000));
        let command = t.meta["command"]
            .as_array()
            .map(|c| c.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "))
            .unwrap_or_else(|| "(standalone wrap)".to_string());
        let servers = if t.servers.is_empty() {
            "-".to_string()
        } else {
            t.servers.join(",")
        };
        println!(
            "{:<28}  {:<10}  {:<20}  {:<18}  {:>8}  {:>11}  {:>6}  {:<7}  {:>8}  {:<24}  {}",
            t.task,
            t.meta["user"].as_str().unwrap_or("-"),
            // Asserted by whoever ran `writ run`; marked until roots are verified.
            t.principal.as_deref().map_or("-".to_string(), |p| format!("{p}?")),
            t.namespace,
            t.sessions,
            calls,
            t.counters.calls_denied,
            if t.tainted { "YES" } else { "no" },
            age.to_string(),
            servers,
            command
        );
    }
    if any_principal {
        println!("(? = principal asserted with `writ run --principal`, not verified)");
    }
    Ok(ExitCode::SUCCESS)
}

/// A best-effort name from the server command: the last argument that isn't a
/// flag, without its directory or extension. `npx -y @scope/server-postgres`
/// becomes `server-postgres`; `python3 -I tools/fake.py` becomes `fake`.
fn derive_server_name(command: &[String]) -> String {
    let arg = command
        .iter()
        .rev()
        .find(|a| !a.starts_with('-'))
        .map_or("server", String::as_str);
    let base = arg.rsplit('/').next().unwrap_or(arg);
    let stem = match base.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => base,
    };
    let name: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if name.is_empty() { "server".to_string() } else { name }
}

fn sudo(action: SudoAction) -> Result<ExitCode> {
    enum Kind {
        Approve,
        Other,
    }
    let action_kind = match action {
        SudoAction::Approve { .. } => Kind::Approve,
        _ => Kind::Other,
    };
    let socket = writ_daemon::default_socket_path();
    let connect = || {
        Client::connect(&socket)
            .with_context(|| format!("cannot reach writd at {}; approvals live in writd", socket.display()))
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let ago = |ms: u64| humantime::format_duration(Duration::from_secs(now.saturating_sub(ms) / 1000)).to_string();
    let left = |ms: u64| humantime::format_duration(Duration::from_secs(ms.saturating_sub(now) / 1000)).to_string();
    match action {
        SudoAction::List { json } => {
            // Like `writ ps`: no writd means nothing can be waiting.
            let Ok(mut client) = Client::connect(&socket) else {
                if json {
                    println!("[]");
                } else {
                    println!("writd is not running ({}): no calls are waiting", socket.display());
                }
                return Ok(ExitCode::SUCCESS);
            };
            let approvals = client.list_approvals()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&approvals)?);
                return Ok(ExitCode::SUCCESS);
            }
            if approvals.is_empty() {
                println!("no calls are waiting for approval");
                return Ok(ExitCode::SUCCESS);
            }
            println!(
                "{:<28}  {:>8}  {:>8}  {:<20}  {:<20}  {:<20}  REASON",
                "ID", "WAITING", "EXPIRES", "PRINCIPAL", "SERVER", "TOOL"
            );
            for a in approvals {
                println!(
                    "{:<28}  {:>8}  {:>8}  {:<20}  {:<20}  {:<20}  {}",
                    a.id,
                    ago(a.created_ms),
                    left(a.expires_ms),
                    a.principal.as_deref().map_or("-".to_string(), |p| format!("{p}?")),
                    a.server,
                    a.tool,
                    a.reason
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        SudoAction::Show { id } => {
            let approvals = connect()?.list_approvals()?;
            let a = approvals.iter().find(|a| a.id == id).with_context(|| {
                format!(
                    "no call is waiting for approval `{id}`: it may have been decided, timed out, \
                         or ended with its task (see `writ log`)"
                )
            })?;
            println!("approval   {}", a.id);
            println!("task       {}", a.task);
            match &a.principal {
                Some(p) => println!("for        {p} (unverified)"),
                None => println!("for        (no root principal)"),
            }
            println!("server     {}", a.server);
            println!("tool       {}", a.tool);
            match &a.arguments {
                Some(args) => println!(
                    "arguments  {}",
                    serde_json::to_string_pretty(args)?.replace('\n', "\n           ")
                ),
                None => println!("arguments  (not recorded by policy)"),
            }
            if a.tainted {
                println!("tainted    yes: read from {}", a.taint_sources.join(", "));
            } else {
                println!("tainted    no");
            }
            println!("why        {}", a.reason);
            println!("waiting    {} (expires in {})", ago(a.created_ms), left(a.expires_ms));
            Ok(ExitCode::SUCCESS)
        }
        SudoAction::Approve { id } | SudoAction::Deny { id } => {
            let approve = matches!(action_kind, Kind::Approve);
            if std::env::var_os(TOKEN_ENV).is_some() || std::env::var_os(TASK_ID_ENV).is_some() {
                // A guard, not a boundary: same-user processes can reach writd directly.
                bail!(
                    "refusing to decide approval `{id}` from inside a writ task ({TOKEN_ENV} is set): \
                     an agent must not approve its own calls. Run `writ sudo` from your own shell."
                );
            }
            // Who ran this command, as the OS knows them. Not authenticated beyond that:
            // anyone who can run commands as this user can approve.
            let approver = json!({ "user": local_user(), "via": "writ sudo", "authenticated": false });
            let decision = connect()?.resolve_approval(&id, approve, approver)?;
            match decision.outcome {
                writ_policy::Outcome::Allow => println!("approved {id}: the call runs now"),
                _ if approve => println!("{id} was approved but still refused: {}", decision.reason),
                _ => println!("denied {id}: the agent gets a policy denial"),
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `writ report`: what the policies decided, from the flight log.
fn report(log: Option<PathBuf>, only: Option<&str>) -> Result<ExitCode> {
    use std::collections::BTreeMap;
    let path = log.unwrap_or_else(writ_recorder::default_log_path);
    let entries = writ_recorder::read_entries(&path)?;
    let mine = |e: &&Entry| only.is_none_or(|t| e.session == t || e.data["task"].as_str() == Some(t));

    #[derive(Default)]
    struct Row {
        calls: u64,
        allowed: u64,
        human: u64,
        denied: u64,
        observed: u64,
    }
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    let mut tasks = std::collections::BTreeSet::new();
    let mut notable = Vec::new();
    let mut trifecta = 0;
    for e in entries.iter().filter(|e| e.kind == "tool_call").filter(mine) {
        let Ok(decision) = serde_json::from_value::<writ_policy::Decision>(e.data["decision"].clone()) else {
            continue;
        };
        let tool = e.data["tool"].as_str().unwrap_or("?").to_string();
        tasks.insert(e.data["task"].as_str().unwrap_or_default().to_string());
        let row = rows.entry(tool.clone()).or_default();
        row.calls += 1;
        match decision.decided() {
            writ_policy::Outcome::Allow => row.allowed += 1,
            writ_policy::Outcome::RequireSudo => row.human += 1,
            writ_policy::Outcome::Deny => row.denied += 1,
        }
        if decision.would.is_some() {
            row.observed += 1;
        }
        if decision.decided() != writ_policy::Outcome::Allow {
            if decision.reason.contains("is privileged and the task is tainted") {
                trifecta += 1;
            }
            notable.push((e.seq, tool, decision, e.data["arguments"].clone()));
        }
    }
    if rows.is_empty() {
        println!("no decisions in {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }
    let total: u64 = rows.values().map(|r| r.calls).sum();
    let observed: u64 = rows.values().map(|r| r.observed).sum();
    println!("{total} calls in {} task(s), from {}", tasks.len(), path.display());
    if observed > 0 {
        println!("{observed} would have been stopped, but weren't: their policy is in observe mode");
    }
    println!();
    println!(
        "{:<36} {:>6} {:>8} {:>11} {:>7} {:>9}",
        "TOOL", "CALLS", "ALLOWED", "NEEDS HUMAN", "DENIED", "OBSERVED"
    );
    for (tool, r) in &rows {
        println!(
            "{:<36} {:>6} {:>8} {:>11} {:>7} {:>9}",
            tool, r.calls, r.allowed, r.human, r.denied, r.observed
        );
    }

    let taints: Vec<&Entry> = entries.iter().filter(|e| e.kind == "taint").filter(mine).collect();
    if !taints.is_empty() {
        println!();
        println!("Untrusted content read:");
        for t in taints {
            println!(
                "  #{:<6} task {} read from {} ({})",
                t.seq,
                t.data["task"].as_str().unwrap_or("?"),
                t.data["source"].as_str().unwrap_or("?"),
                t.data["tool"].as_str().unwrap_or("?")
            );
        }
    }
    if trifecta > 0 {
        println!();
        println!("{trifecta} privileged call(s) came after untrusted content: the pattern prompt injections exploit.");
    }
    if !notable.is_empty() {
        println!();
        println!(
            "Calls the policy stopped or would have stopped (latest {}):",
            notable.len().min(20)
        );
        for (seq, tool, d, args) in notable.iter().rev().take(20).rev() {
            let what = ["command", "path", "url", "sql", "query"]
                .iter()
                .find_map(|k| args[k].as_str())
                .map(|v| format!(" {}", truncate(v, 60)))
                .unwrap_or_default();
            let tag = if d.would.is_some() { " (observe)" } else { "" };
            println!("  #{seq:<6} {}{tag}  {tool}{what}", d.decided().as_str().to_uppercase());
            println!("          {}", truncate(&d.reason, 140));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

fn replay(policy_path: &Path, log: Option<PathBuf>, task: Option<&str>, json: bool) -> Result<ExitCode> {
    let files = read_policy(policy_path)?;
    let policy = Policy::from_yaml_str(&files.policy)?;
    let entitlements = files
        .entitlements
        .as_deref()
        .map(LoadedEntitlements::parse)
        .transpose()?;
    let log = log.unwrap_or_else(writ_recorder::default_log_path);
    let entries = writ_recorder::read_entries(&log)?;
    let report = writ_daemon::replay::replay(
        &entries,
        &policy,
        entitlements.as_ref().map(|e| e.source.as_ref()),
        task,
    );
    let code = if report.loosened() > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(code);
    }

    println!(
        "replayed {} call{} from {} under {}: {} would change ({} looser, {} stricter)",
        report.replayed,
        if report.replayed == 1 { "" } else { "s" },
        log.display(),
        policy_path.display(),
        report.flips.len(),
        report.loosened(),
        report.tightened(),
    );
    if report.skipped > 0 {
        println!(
            "  {} skipped: arguments not recorded (record_arguments: false)",
            report.skipped
        );
    }
    if report.partial > 0 {
        println!(
            "  {} partial: arguments partly redacted, so a decision that reads them is a guess",
            report.partial
        );
    }
    let outcome = |o: writ_policy::Outcome| s_outcome(o).to_uppercase();
    for f in &report.flips {
        let args = f.arguments.to_string();
        let short: String = args.chars().take(80).collect();
        println!();
        println!(
            "{:>6}  {}  {} {}{}",
            f.seq,
            f.task,
            f.tool,
            short,
            if short.len() < args.len() { "…" } else { "" }
        );
        println!(
            "        {}{} -> {}  {}{}",
            outcome(f.before.outcome),
            f.settled.as_deref().map_or(String::new(), |s| format!(" (then {s})")),
            outcome(f.after.outcome),
            if f.loosens() { "LOOSER" } else { "stricter" },
            if f.partial { "  [partial]" } else { "" },
        );
        println!("        was: {}", f.before.reason);
        println!("        now: {}", f.after.reason);
    }
    if report.loosened() > 0 {
        println!();
        println!(
            "{} call(s) would be allowed more freely under {}",
            report.loosened(),
            policy_path.display()
        );
    }
    Ok(code)
}

fn s_outcome(outcome: writ_policy::Outcome) -> &'static str {
    match outcome {
        writ_policy::Outcome::Allow => "allow",
        writ_policy::Outcome::RequireSudo => "require_sudo",
        writ_policy::Outcome::Deny => "deny",
    }
}

/// `$USER`, else `$LOGNAME`, else the account name for this uid.
fn local_user() -> Option<String> {
    let env = |key| std::env::var(key).ok().filter(|v| !v.is_empty());
    env("USER").or_else(|| env("LOGNAME")).or_else(|| {
        // SAFETY: getpwuid returns a pointer to static storage or null; we copy the name out immediately.
        unsafe {
            let pw = libc::getpwuid(libc::getuid());
            (!pw.is_null()).then(|| std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
        }
    })
}

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn format_entry(entry: &Entry) -> String {
    let d = &entry.data;
    let s = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
    let command = |v: &Value| {
        v.as_array()
            .map(|c| c.iter().map(s).collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
    };
    let summary = match entry.kind.as_str() {
        "task_start" => format!(
            "{}{} (policy {} sha256:{:.12})",
            if d["implicit"] == json!(true) {
                "implicit task".to_string()
            } else {
                command(&d["meta"]["command"])
            },
            match d["root"]["principal"].as_str() {
                Some(p) => format!(" for {p} (unverified)"),
                None => String::new(),
            },
            s(&d["namespace"]),
            s(&d["policy_sha256"]),
        ),
        "session_start" => {
            let forks: Vec<&str> = d["writ"]["forks"]
                .as_array()
                .map(|f| {
                    f.iter()
                        .map(|f| f["label"].as_str().unwrap_or("(unlabelled)"))
                        .collect()
                })
                .unwrap_or_default();
            let lineage = if forks.is_empty() {
                String::new()
            } else {
                format!(", fork {}", forks.join(" > "))
            };
            format!(
                "{} {} (task {}{lineage})",
                s(&d["source"]),
                command(&d["info"]["command"]),
                s(&d["task"])
            )
        }
        "token_issued" => format!("token {} for task {}", s(&d["token"]), s(&d["task"])),
        "taint" => format!(
            "task {} tainted: {} read from {}",
            s(&d["task"]),
            s(&d["tool"]),
            s(&d["source"])
        ),
        "tool_call" => format!(
            "{}{} -> {}{} ({})",
            s(&d["tool"]),
            match &d["arguments"] {
                Value::Null => String::new(),
                args => {
                    let args = args.to_string();
                    let short: String = args.chars().take(80).collect();
                    format!(" {short}{}", if short.len() < args.len() { "…" } else { "" })
                }
            },
            s(&d["decision"]["outcome"]).to_uppercase(),
            match d["decision"]["approval"].as_str() {
                Some(id) => format!(" [waiting: {id}]"),
                None => String::new(),
            },
            s(&d["decision"]["reason"]),
        ),
        "approval" => format!(
            "{} {} {} -> {} ({})",
            s(&d["approval"]),
            s(&d["decision"]).to_uppercase(),
            s(&d["tool"]),
            s(&d["outcome"]["outcome"]).to_uppercase(),
            s(&d["outcome"]["reason"]),
        ),
        "tool_result" => format!(
            "{} {} in {}ms",
            s(&d["tool"]),
            if d["is_error"].as_bool() == Some(true) {
                "errored"
            } else {
                "ok"
            },
            d["duration_ms"],
        ),
        _ => d.to_string(),
    };
    format!(
        "{:>5}  {}  {}  {:<13}  {}",
        entry.seq, entry.ts, entry.session, entry.kind, summary
    )
}
