//! writd's local protocol: newline-delimited JSON over a Unix socket, one
//! request and one response at a time per connection.
//!
//! A connection holds at most one session. When the connection drops, writd
//! closes that session and ends any task the connection created, so a
//! crashed `writ run` revokes its task's authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Create a root task from policy text. Returns `{"task": id}`.
    CreateTask {
        policy: String,
        /// The text of the policy's entitlement source, if it declares one.
        /// Read by the caller, which knows where the policy file lives.
        #[serde(default)]
        entitlements: Option<String>,
        /// The root principal (unverified).
        #[serde(default)]
        principal: Option<String>,
        meta: Value,
    },
    EndTask {
        task: String,
    },
    /// Open this connection's session. Returns `{"session": id}`.
    OpenSession {
        task: Option<String>,
        policy: Option<String>,
        /// The wrapped server's name; the session is `mcp:<name>`.
        name: String,
        /// Without a task: the text of `policy`'s entitlement source, if any.
        #[serde(default)]
        entitlements: Option<String>,
        info: Value,
    },
    /// Returns a `writ_policy::Decision`.
    Decide {
        call_id: Value,
        tool: String,
        args: Value,
    },
    /// One-way: writd sends no response. Used for events after the fact
    /// (tool results, protocol errors) so they stay off the call's critical path.
    Record {
        kind: String,
        data: Value,
    },
    /// Returns `{"hidden": [names]}`.
    HiddenTools {
        names: Vec<String>,
    },
    CloseSession {
        data: Value,
    },
    /// Returns `{"tasks": [TaskSummary]}`.
    Ps,
    /// Returns `{"approvals": [ApprovalSummary]}`: pending approvals, oldest first.
    ListApprovals,
    /// Approves or denies a pending approval. `approver` describes who
    /// (user, host); writd adds the peer's pid and uid. Returns the final
    /// `writ_policy::Decision`.
    ResolveApproval {
        id: String,
        approve: bool,
        approver: Value,
    },
    /// Blocks until the approval is settled or times out, then returns the
    /// final `writ_policy::Decision`. Send it on a connection of its own:
    /// nothing else on that connection is answered meanwhile.
    WaitApproval {
        id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        #[serde(default)]
        body: Value,
    },
    Error {
        message: String,
    },
}
