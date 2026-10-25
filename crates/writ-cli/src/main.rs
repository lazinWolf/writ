use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use writ_policy::Policy;
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
    Wrap {
        /// Path to writ.yaml.
        #[arg(long)]
        policy: PathBuf,
        /// Flight recorder file [default: $WRIT_LOG or ~/.local/state/writ/flight.jsonl].
        #[arg(long)]
        log: Option<PathBuf>,
        /// Wait for each decision to reach stable storage before forwarding the call.
        #[arg(long)]
        fsync: bool,
        /// How long the server gets to exit after the client disconnects, before writ terminates it.
        #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
        shutdown_grace: Duration,
        /// The MCP server command and its arguments.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
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
        /// Only show entries from this session.
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
            log,
            fsync,
            shutdown_grace,
            command,
        } => {
            // Read once: the recorded hash must describe exactly the policy being enforced.
            let source =
                std::fs::read_to_string(&policy).with_context(|| format!("cannot read {}", policy.display()))?;
            let parsed = Policy::from_yaml_str(&source)?;
            let mut recorder = Recorder::open(log.unwrap_or_else(writ_recorder::default_log_path))?;
            recorder.set_fsync(fsync);
            let config = writ_proxy::WrapConfig {
                policy: parsed,
                policy_sha256: writ_recorder::sha256_hex(source.as_bytes()),
                recorder,
                command,
                session: writ_proxy::new_session_id(),
                shutdown_grace,
                forward_signals: true,
            };
            let code = writ_proxy::run(config, std::io::stdin(), std::io::stdout())?;
            Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
        }
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
            for entry in entries
                .iter()
                .filter(|e| session.as_ref().is_none_or(|s| &e.session == s))
            {
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

fn format_entry(entry: &Entry) -> String {
    let d = &entry.data;
    let s = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
    let summary = match entry.kind.as_str() {
        "session_start" => format!(
            "{} (policy {} sha256:{:.12})",
            d["command"]
                .as_array()
                .map(|c| c.iter().map(s).collect::<Vec<_>>().join(" "))
                .unwrap_or_default(),
            s(&d["namespace"]),
            s(&d["policy_sha256"]),
        ),
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
