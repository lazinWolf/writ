//! writd: the local daemon that owns tasks, decisions, and the flight
//! recorder, plus the client used by `writ wrap`, `writ run`, and `writ ps`.
//!
//! In cooperative mode a task's authority travels between processes as a
//! signed token in the `WRIT_TOKEN` environment variable (see [`token`]).
//! Task ids only name tasks: writd refuses to join one by id.

pub mod client;
pub mod engine;
pub mod protocol;
pub mod replay;
pub mod server;
pub mod token;

use std::path::PathBuf;

pub use client::{Client, NewTask};
pub use engine::{
    ApprovalSummary, Authority, Engine, EngineError, LoadedEntitlements, LoadedPolicy, Resolution, TaskSummary,
};
pub use token::TOKEN_ENV;

/// Environment variable naming the task a process belongs to, for
/// display and scripts. It carries no authority: `WRIT_TOKEN` does.
pub const TASK_ID_ENV: &str = "WRIT_TASK_ID";
/// The unsigned task id earlier builds used for authority. `writ wrap`
/// refuses it rather than silently running outside the task.
pub const LEGACY_TASK_ENV: &str = "WRIT_TASK";
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
