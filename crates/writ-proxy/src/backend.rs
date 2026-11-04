//! Where decisions are made and recorded: in this process (standalone
//! `writ wrap`) or in writd (a task shared with other sessions). Both run the
//! same `writ_daemon::Engine`.

use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use writ_daemon::{Client, Engine, LoadedEntitlements, LoadedPolicy};
use writ_policy::Decision;
use writ_recorder::Recorder;

pub trait Backend: Send {
    /// Opens the session for the server `name`; `info` (command, server pid)
    /// is recorded.
    fn open(&mut self, name: &str, info: Value) -> Result<String>;
    /// Decides and records one call. `Err` means the call must be denied.
    fn decide(&mut self, call_id: &Value, tool: &str, args: &Value) -> Result<Decision>;
    fn record(&mut self, kind: &str, data: Value) -> Result<()>;
    fn hidden_tools(&mut self, names: &[String]) -> Result<Vec<String>>;
    fn close(&mut self, data: Value) -> Result<()>;
}

/// Standalone: an implicit task with this session's policy, recorded locally.
pub struct LocalBackend {
    engine: Engine,
    policy: Option<LoadedPolicy>,
    entitlements: Option<LoadedEntitlements>,
    session: Option<String>,
}

impl LocalBackend {
    pub fn new(recorder: Recorder, policy: LoadedPolicy, entitlements: Option<LoadedEntitlements>) -> Self {
        LocalBackend {
            engine: Engine::new(recorder),
            policy: Some(policy),
            entitlements,
            session: None,
        }
    }

    fn session(&self) -> Result<&str> {
        self.session.as_deref().ok_or_else(|| anyhow!("session is not open"))
    }
}

impl Backend for LocalBackend {
    fn open(&mut self, name: &str, info: Value) -> Result<String> {
        let session = self
            .engine
            .open_session(None, self.policy.take(), self.entitlements.take(), name, info)?;
        self.session = Some(session.clone());
        Ok(session)
    }

    fn decide(&mut self, call_id: &Value, tool: &str, args: &Value) -> Result<Decision> {
        let session = self.session()?.to_string();
        Ok(self.engine.decide(&session, call_id, tool, args)?)
    }

    fn record(&mut self, kind: &str, data: Value) -> Result<()> {
        let session = self.session()?.to_string();
        Ok(self.engine.record(&session, kind, data)?)
    }

    fn hidden_tools(&mut self, names: &[String]) -> Result<Vec<String>> {
        Ok(self.engine.hidden_tools(self.session()?, names)?)
    }

    fn close(&mut self, data: Value) -> Result<()> {
        let session = self.session.take().context("session is not open")?;
        Ok(self.engine.close_session(&session, data)?)
    }
}

/// writd: join `task` (optionally narrowed by `policy`), or, without a task,
/// an implicit task from `policy` that `writ ps` can see.
pub struct DaemonBackend {
    client: Client,
    task: Option<String>,
    policy: Option<String>,
    entitlements: Option<String>,
}

impl DaemonBackend {
    /// `entitlements` is the text of `policy`'s entitlement source, if it declares one.
    pub fn new(client: Client, task: Option<String>, policy: Option<String>, entitlements: Option<String>) -> Self {
        DaemonBackend {
            client,
            task,
            policy,
            entitlements,
        }
    }
}

impl Backend for DaemonBackend {
    fn open(&mut self, name: &str, info: Value) -> Result<String> {
        self.client.open_session(
            self.task.as_deref(),
            self.policy.as_deref(),
            self.entitlements.as_deref(),
            name,
            info,
        )
    }

    fn decide(&mut self, call_id: &Value, tool: &str, args: &Value) -> Result<Decision> {
        self.client.decide(call_id, tool, args)
    }

    fn record(&mut self, kind: &str, data: Value) -> Result<()> {
        self.client.record(kind, data)
    }

    fn hidden_tools(&mut self, names: &[String]) -> Result<Vec<String>> {
        self.client.hidden_tools(names)
    }

    fn close(&mut self, data: Value) -> Result<()> {
        self.client.close_session(data)
    }
}
