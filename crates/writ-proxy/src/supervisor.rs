//! Server lifetime: decides when the wrapped server has finished and, if it
//! will not finish on its own, terminates it.
//!
//! The server runs in its own process group so that writ can signal launcher
//! chains (`npx` -> `node`) as a unit; signalling only the direct child would
//! orphan grandchildren that still hold the stdout pipe open.
//!
//! The session is over once the server has exited *and* its stdout has
//! closed. Escalation, each step only if the previous one did not end it:
//! - client closed stdin, or server closed stdout: wait `grace`, then SIGTERM
//! - server exited but stdout is still open (a grandchild holds it): wait
//!   `DRAIN`, then SIGTERM
//! - writ itself got SIGTERM/SIGINT/SIGHUP: SIGTERM immediately
//! - after any SIGTERM: wait `KILL_AFTER`, then SIGKILL
//! - after SIGKILL: wait `ABANDON_AFTER`, then stop waiting

use std::process::ExitStatus;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const DRAIN: Duration = Duration::from_secs(2);
const KILL_AFTER: Duration = Duration::from_secs(2);
const ABANDON_AFTER: Duration = Duration::from_secs(1);

pub enum Event {
    ClientClosed,
    StdoutClosed,
    ServerExited(ExitStatus),
    Signal(i32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    Term,
    Kill,
    Abandon,
}

/// How the session ended, for the flight recorder and writ's exit code.
pub struct Outcome {
    pub status: Option<ExitStatus>,
    /// `exited`, `terminated` (writ sent SIGTERM), `killed` (SIGKILL), or
    /// `abandoned` (the server's stdout never closed).
    pub termination: &'static str,
    /// A signal writ itself received, which it forwarded to the server.
    pub writ_signal: Option<i32>,
}

pub fn supervise(events: Receiver<Event>, pgid: u32, grace: Duration) -> Outcome {
    let mut status = None;
    let mut stdout_closed = false;
    let mut deadline: Option<(Instant, Step)> = None;
    let mut termination = "exited";
    let mut writ_signal = None;

    /// Sets a deadline unless an earlier one is already pending.
    fn arm(deadline: &mut Option<(Instant, Step)>, after: Duration, step: Step) {
        let at = Instant::now() + after;
        if deadline.is_none_or(|(current, _)| at < current) {
            *deadline = Some((at, step));
        }
    }

    while status.is_none() || !stdout_closed {
        let event = match deadline {
            Some((at, _)) => events.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => events.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Event::ClientClosed) => {
                if status.is_none() {
                    arm(&mut deadline, grace, Step::Term);
                }
            }
            Ok(Event::StdoutClosed) => {
                stdout_closed = true;
                if status.is_none() {
                    arm(&mut deadline, grace, Step::Term);
                }
            }
            Ok(Event::ServerExited(s)) => {
                status = Some(s);
                if !stdout_closed {
                    arm(&mut deadline, DRAIN, Step::Term);
                }
            }
            Ok(Event::Signal(sig)) => {
                writ_signal = Some(sig);
                termination = "terminated";
                signal_group(pgid, libc::SIGTERM);
                deadline = Some((Instant::now() + KILL_AFTER, Step::Kill));
            }
            Err(RecvTimeoutError::Timeout) => {
                let (_, step) = deadline.take().expect("timeouts only happen with a deadline");
                match step {
                    Step::Term => {
                        eprintln!("writ: MCP server did not finish; sending SIGTERM to its process group");
                        termination = "terminated";
                        signal_group(pgid, libc::SIGTERM);
                        deadline = Some((Instant::now() + KILL_AFTER, Step::Kill));
                    }
                    Step::Kill => {
                        eprintln!("writ: MCP server ignored SIGTERM; sending SIGKILL to its process group");
                        termination = "killed";
                        signal_group(pgid, libc::SIGKILL);
                        deadline = Some((Instant::now() + ABANDON_AFTER, Step::Abandon));
                    }
                    Step::Abandon => {
                        eprintln!("writ: MCP server's stdout is still open after SIGKILL; giving up on it");
                        termination = "abandoned";
                        break;
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    Outcome {
        status,
        termination,
        writ_signal,
    }
}

fn signal_group(pgid: u32, signal: i32) {
    let Ok(pgid) = i32::try_from(pgid) else { return };
    // SAFETY: kill(2) has no memory-safety preconditions. A negative pid
    // addresses the process group the server was spawned into.
    unsafe {
        libc::kill(-pgid, signal);
    }
}
