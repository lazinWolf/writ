use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// writd: the local writ daemon. Owns tasks, decisions, and the flight recorder.
///
/// Usually started on demand by `writ run` or `writ wrap --daemon`.
#[derive(Parser)]
#[command(name = "writd", version)]
struct Args {
    /// Socket path [default: $WRIT_SOCKET or $XDG_RUNTIME_DIR/writ/writd.sock].
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Flight recorder file [default: $WRIT_LOG or ~/.local/state/writ/flight.jsonl].
    #[arg(long)]
    log: Option<PathBuf>,
    /// Don't wait for decisions to reach stable storage before answering.
    #[arg(long)]
    no_fsync: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let socket = args.socket.unwrap_or_else(writ_daemon::default_socket_path);
    let log = args.log.unwrap_or_else(writ_recorder::default_log_path);
    match writ_daemon::server::run(&socket, &log, !args.no_fsync) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("writd: {e:#}");
            ExitCode::from(2)
        }
    }
}
