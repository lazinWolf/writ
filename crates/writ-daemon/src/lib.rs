//! writd: the local daemon that owns tasks, decisions, and the flight
//! recorder, plus the client used by `writ wrap`, `writ run`, and `writ ps`.
//!
//! In cooperative mode the task id travels between processes as the
//! `WRIT_TASK` environment variable. It is an unsigned identifier: any
//! process running as the same user can claim any task. Signed, attenuating
//! writs replace it in the next phase (plan-v2.md §4.1).

pub mod client;
pub mod engine;
pub mod protocol;
pub mod server;

use std::path::PathBuf;

pub use client::Client;
pub use engine::{
    ApprovalSummary, Authority, Engine, EngineError, LoadedEntitlements, LoadedPolicy, Resolution, TaskSummary,
};

/// Environment variable carrying the task a process belongs to.
pub const TASK_ENV: &str = "WRIT_TASK";
/// Environment variable overriding the writd socket path.
pub const SOCKET_ENV: &str = "WRIT_SOCKET";

/// `$WRIT_SOCKET`, else `$XDG_RUNTIME_DIR/writ/writd.sock`, else
/// `/tmp/writ-<uid>/writd.sock`.
pub fn default_socket_path() -> PathBuf {
    let non_empty = |key| std::env::var_os(key).filter(|v| !v.is_empty());
    if let Some(path) = non_empty(SOCKET_ENV) {
        return PathBuf::from(path);
    }
    if let Some(runtime) = non_empty("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("writ/writd.sock");
    }
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/writ-{uid}/writd.sock"))
}
