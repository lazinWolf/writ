use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use writ_daemon::{Client, LoadedPolicy, SOCKET_ENV, TASK_ENV};
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
    /// Under `writ run` (WRIT_TASK set) the server joins that task through writd: the task's
    /// policy and limits apply, and --policy can only narrow them. Otherwise --policy is
    /// required and decisions are made in this process, or in writd with --daemon.
    Wrap {
        /// Path to writ.yaml. Required unless WRIT_TASK is set.
        #[arg(long)]
        policy: Option<PathBuf>,
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
        /// Flight recorder file, used if this command starts writd.
        #[arg(long)]
        log: Option<PathBuf>,
        /// The agent command and its arguments.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// List live tasks.
    Ps,
    /// Validate a writ.yaml without running anything.
    Check { policy: PathBuf },
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
            daemon,
            log,
            no_fsync,
            shutdown_grace,
            command,
        } => {
            let backend = wrap_backend(policy.as_deref(), daemon, log, !no_fsync)?;
            let config = writ_proxy::WrapConfig {
                backend,
                command,
                shutdown_grace,
                forward_signals: true,
            };
            let code = writ_proxy::run(config, std::io::stdin(), std::io::stdout())?;
            Ok(exit_code(code))
        }
        Commands::Run { policy, log, command } => run_task(&policy, log.as_deref(), &command),
        Commands::Ps => ps(),
        Commands::Check { policy } => {
            let parsed = Policy::from_path(&policy)?;
            println!(
                "{}: ok (namespace {}, enforcement {:?}, max_tool_calls {})",
                policy.display(),
                parsed.namespace,
                parsed.enforcement,
                parsed
                    .limits
                    .max_tool_calls
                    .map_or("unlimited".to_string(), |n| n.to_string()),
            );
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

fn read_policy(path: &Path) -> Result<String> {
    // Read once: the recorded hash must describe exactly the policy being enforced.
    let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    LoadedPolicy::parse(&text).with_context(|| format!("{}", path.display()))?;
    Ok(text)
}

fn wrap_backend(policy: Option<&Path>, daemon: bool, log: Option<PathBuf>, fsync: bool) -> Result<Box<dyn Backend>> {
    let task = std::env::var(TASK_ENV).ok().filter(|t| !t.is_empty());
    let policy = policy.map(read_policy).transpose()?;
    let socket = writ_daemon::default_socket_path();

    if let Some(task) = task {
        // Fail closed: the task's limits can only be enforced by writd.
        let client = Client::connect(&socket)
            .with_context(|| format!("{TASK_ENV} is set but writd is unreachable; refusing to run the server"))?;
        return Ok(Box::new(DaemonBackend::new(client, Some(task), policy)));
    }
    let Some(policy) = policy else {
        bail!("--policy is required unless running under `writ run`");
    };
    if daemon {
        let client = Client::connect_or_start(&socket, log.as_deref())?;
        return Ok(Box::new(DaemonBackend::new(client, None, Some(policy))));
    }
    let mut recorder = Recorder::open(log.unwrap_or_else(writ_recorder::default_log_path))?;
    recorder.set_fsync(fsync);
    Ok(Box::new(LocalBackend::new(recorder, LoadedPolicy::parse(&policy)?)))
}

fn run_task(policy: &Path, log: Option<&Path>, command: &[String]) -> Result<ExitCode> {
    let policy = read_policy(policy)?;
    let socket = writ_daemon::default_socket_path();
    // The connection stays open while the agent runs: if writ run dies, writd ends the task.
    let mut client = Client::connect_or_start(&socket, log)?;
    let meta = json!({
        "command": command,
        "user": std::env::var("USER").ok(),
        "cwd": std::env::current_dir().ok(),
    });
    let task = client.create_task(&policy, meta)?;

    let (program, args) = command.split_first().context("no command given")?;
    let mut child = Command::new(program)
        .args(args)
        .env(TASK_ENV, &task)
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
        "{:<28}  {:<10}  {:<18}  {:>8}  {:>11}  {:>6}  {:>8}  COMMAND",
        "TASK", "USER", "NAMESPACE", "SESSIONS", "CALLS", "DENIED", "AGE"
    );
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
        println!(
            "{:<28}  {:<10}  {:<18}  {:>8}  {:>11}  {:>6}  {:>8}  {}",
            t.task,
            t.meta["user"].as_str().unwrap_or("-"),
            t.namespace,
            t.sessions,
            calls,
            t.counters.calls_denied,
            age.to_string(),
            command
        );
    }
    Ok(ExitCode::SUCCESS)
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
            "{} (policy {} sha256:{:.12})",
            if d["implicit"] == json!(true) {
                "implicit task".to_string()
            } else {
                command(&d["meta"]["command"])
            },
            s(&d["namespace"]),
            s(&d["policy_sha256"]),
        ),
        "session_start" => format!("{} (task {})", command(&d["info"]["command"]), s(&d["task"])),
        "tool_call" => format!(
            "{} -> {} ({})",
            s(&d["tool"]),
            s(&d["decision"]["outcome"]).to_uppercase(),
            s(&d["decision"]["reason"]),
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
