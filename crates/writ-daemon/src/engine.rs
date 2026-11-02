//! Tasks, sessions, and decisions.
//!
//! A **task** is the root of authority: it is created with a policy (by
//! `writ run`, or implicitly by a standalone `writ wrap`) and its limits are
//! shared by every session that joins it. A **session** is one wrapped MCP
//! server. A session may carry its own policy, which can only narrow the
//! task's: both policies are evaluated and the most restrictive outcome
//! wins, and both sets of limits apply. When a task ends, its sessions lose
//! all authority.
//!
//! Every decision is recorded before it is returned, and allowed decisions
//! reach stable storage first if the recorder syncs. If recording fails, the
//! caller must deny the call.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use writ_policy::{Decision, Outcome, Policy};
use writ_recorder::{Recorder, RecorderError};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Recorder(#[from] RecorderError),
    #[error("unknown task `{0}`")]
    UnknownTask(String),
    #[error("unknown session `{0}`")]
    UnknownSession(String),
    #[error("{0}")]
    Invalid(String),
}

/// A policy together with the hash of the exact text it was parsed from.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub policy: Policy,
    pub sha256: String,
}

impl LoadedPolicy {
    pub fn parse(text: &str) -> Result<Self, EngineError> {
        let policy = Policy::from_yaml_str(text).map_err(|e| EngineError::Invalid(e.to_string()))?;
        Ok(LoadedPolicy {
            policy,
            sha256: writ_recorder::sha256_hex(text.as_bytes()),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Counters {
    pub calls_allowed: u64,
    pub calls_denied: u64,
}

struct Task {
    policy: LoadedPolicy,
    meta: Value,
    started_ms: u64,
    counters: Counters,
    sessions: BTreeSet<String>,
    /// Created for a single standalone session; ends with it.
    implicit: bool,
    ended: bool,
}

struct Session {
    task: String,
    policy: Option<LoadedPolicy>,
    counters: Counters,
}

/// One row of `writ ps`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskSummary {
    pub task: String,
    pub namespace: String,
    pub meta: Value,
    pub started_ms: u64,
    pub sessions: usize,
    pub max_tool_calls: Option<u64>,
    pub counters: Counters,
}

pub struct Engine {
    recorder: Recorder,
    tasks: BTreeMap<String, Task>,
    sessions: BTreeMap<String, Session>,
}

impl Engine {
    pub fn new(recorder: Recorder) -> Self {
        Engine {
            recorder,
            tasks: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }

    /// Creates a root task. `meta` describes who and what started it (command,
    /// user) and is recorded as given.
    pub fn create_task(&mut self, policy: LoadedPolicy, meta: Value) -> Result<String, EngineError> {
        self.create_task_inner(policy, meta, false)
    }

    fn create_task_inner(&mut self, policy: LoadedPolicy, meta: Value, implicit: bool) -> Result<String, EngineError> {
        let id = new_id("tsk");
        let data = json!({
            "task": id,
            "namespace": policy.policy.namespace,
            "policy_sha256": policy.sha256,
            "implicit": implicit,
            "meta": meta,
        });
        self.recorder.append_durable(&id, "task_start", data)?;
        self.tasks.insert(
            id.clone(),
            Task {
                policy,
                meta,
                started_ms: now_ms(),
                counters: Counters::default(),
                sessions: BTreeSet::new(),
                implicit,
                ended: false,
            },
        );
        Ok(id)
    }

    /// Ends a task. Its remaining sessions stay open but every later decision
    /// in them is a denial.
    pub fn end_task(&mut self, task_id: &str, reason: &str) -> Result<(), EngineError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| EngineError::UnknownTask(task_id.to_string()))?;
        if task.ended {
            return Ok(());
        }
        task.ended = true;
        let data =
            json!({ "task": task_id, "reason": reason, "counters": task.counters, "open_sessions": task.sessions });
        let empty = task.sessions.is_empty();
        if empty {
            self.tasks.remove(task_id);
        }
        self.recorder.append_durable(task_id, "task_end", data)?;
        Ok(())
    }

    /// Opens a session. With a task it joins that task, optionally narrowed by
    /// `own_policy`; without one, `own_policy` is required and becomes an
    /// implicit task of its own. `info` (command, server pid) is recorded.
    pub fn open_session(
        &mut self,
        task: Option<&str>,
        own_policy: Option<LoadedPolicy>,
        info: Value,
    ) -> Result<String, EngineError> {
        let (task_id, session_policy) = match task {
            Some(id) => {
                let task = self
                    .tasks
                    .get(id)
                    .ok_or_else(|| EngineError::UnknownTask(id.to_string()))?;
                if task.ended {
                    return Err(EngineError::Invalid(format!("task `{id}` has ended")));
                }
                (id.to_string(), own_policy)
            }
            None => {
                let policy = own_policy
                    .ok_or_else(|| EngineError::Invalid("a session without a task needs its own policy".into()))?;
                (self.create_task_inner(policy, json!({}), true)?, None)
            }
        };

        let id = new_id("ses");
        let data = json!({
            "task": task_id,
            "narrowing_policy_sha256": session_policy.as_ref().map(|p| &p.sha256),
            "info": info,
        });
        self.recorder.append_durable(&id, "session_start", data)?;
        self.tasks
            .get_mut(&task_id)
            .expect("task exists")
            .sessions
            .insert(id.clone());
        self.sessions.insert(
            id.clone(),
            Session {
                task: task_id,
                policy: session_policy,
                counters: Counters::default(),
            },
        );
        Ok(id)
    }

    /// Decides one tool call and records the decision before returning it.
    /// An `Err` means the decision could not be recorded: deny the call.
    pub fn decide(
        &mut self,
        session_id: &str,
        call_id: &Value,
        tool: &str,
        args: &Value,
    ) -> Result<Decision, EngineError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EngineError::UnknownSession(session_id.to_string()))?;
        let task = self
            .tasks
            .get(&session.task)
            .expect("sessions always reference a live task");

        let mut decision = if task.ended {
            Decision {
                outcome: Outcome::Deny,
                rule: None,
                reason: format!("task `{}` has ended; its authority is revoked", session.task),
            }
        } else {
            let from_task = task.policy.policy.evaluate(tool, args);
            match &session.policy {
                // Ties keep the task's decision: the narrowing policy only matters when stricter.
                Some(own) => {
                    let from_session = own.policy.evaluate(tool, args);
                    if from_session.outcome > from_task.outcome {
                        Decision {
                            reason: format!("{} (session policy)", from_session.reason),
                            ..from_session
                        }
                    } else {
                        from_task
                    }
                }
                None => from_task,
            }
        };
        if decision.outcome == Outcome::Allow {
            let limits = [
                (
                    task.policy.policy.limits.max_tool_calls,
                    task.counters.calls_allowed,
                    "task",
                ),
                (
                    session.policy.as_ref().and_then(|p| p.policy.limits.max_tool_calls),
                    session.counters.calls_allowed,
                    "session",
                ),
            ];
            if let Some((max, _, scope)) = limits.iter().find(|(max, used, _)| max.is_some_and(|m| *used >= m)) {
                decision.outcome = Outcome::Deny;
                decision.reason = format!("{scope} max_tool_calls limit reached ({})", max.unwrap());
            }
        }

        let mut data = json!({ "id": call_id, "task": session.task, "tool": tool, "decision": decision });
        // The narrowing policy's redaction applies on top of the task's; either can omit everything.
        let logged = task
            .policy
            .policy
            .arguments_for_log(tool, args)
            .and_then(|logged| match &session.policy {
                Some(own) => own.policy.arguments_for_log(tool, &logged),
                None => Some(logged),
            });
        match logged {
            Some(arguments) => data["arguments"] = arguments,
            None => data["arguments_omitted"] = json!(true),
        }
        // Only an allowed decision gates an action, so only it waits for stable storage.
        // A denial is persisted by the next sync, and a flood of denied calls (the shape
        // of an injection attempt) cannot force a sync per call.
        let allowed = decision.outcome == Outcome::Allow;
        if allowed {
            self.recorder.append_durable(session_id, "tool_call", data)?;
        } else {
            self.recorder.append(session_id, "tool_call", data)?;
        }
        let task_id = session.task.clone();
        for counters in [
            &mut self.sessions.get_mut(session_id).unwrap().counters,
            &mut self.tasks.get_mut(&task_id).unwrap().counters,
        ] {
            if allowed {
                counters.calls_allowed += 1;
            } else {
                counters.calls_denied += 1;
            }
        }
        Ok(decision)
    }

    /// Records a non-gating event (tool results, protocol errors, ...).
    pub fn record(&mut self, session_id: &str, kind: &str, mut data: Value) -> Result<(), EngineError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EngineError::UnknownSession(session_id.to_string()))?;
        if let Value::Object(map) = &mut data {
            map.insert("task".into(), json!(session.task));
        }
        self.recorder.append(session_id, kind, data)?;
        Ok(())
    }

    /// Tools to hide from `tools/list`: denied whatever their arguments by the
    /// task's policy or the session's own.
    pub fn hidden_tools(&self, session_id: &str, names: &[String]) -> Result<Vec<String>, EngineError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EngineError::UnknownSession(session_id.to_string()))?;
        let task = &self.tasks[&session.task];
        Ok(names
            .iter()
            .filter(|name| {
                task.ended
                    || task.policy.policy.always_denies(name)
                    || session.policy.as_ref().is_some_and(|p| p.policy.always_denies(name))
            })
            .cloned()
            .collect())
    }

    /// Closes a session, recording `data` merged with its counters. An
    /// implicit task ends with its only session; an ended task is dropped
    /// once its last session closes.
    pub fn close_session(&mut self, session_id: &str, mut data: Value) -> Result<(), EngineError> {
        let session = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| EngineError::UnknownSession(session_id.to_string()))?;
        if let Value::Object(map) = &mut data {
            map.insert("task".into(), json!(session.task));
            map.insert("counters".into(), json!(session.counters));
        }
        let result = self.recorder.append(session_id, "session_end", data);

        let task = self.tasks.get_mut(&session.task).expect("task exists");
        task.sessions.remove(session_id);
        if task.implicit && !task.ended {
            self.end_task(&session.task, "session closed")?;
        } else if task.ended && task.sessions.is_empty() {
            self.tasks.remove(&session.task);
        }
        result?;
        Ok(())
    }

    /// Records a daemon-level event (start, stop) outside any session.
    pub fn note(&mut self, kind: &str, data: Value) {
        if let Err(e) = self.recorder.append("writd", kind, data) {
            eprintln!("writd: {e}");
        }
    }

    /// Live tasks, oldest first.
    pub fn tasks(&self) -> Vec<TaskSummary> {
        let mut tasks: Vec<TaskSummary> = self
            .tasks
            .iter()
            .filter(|(_, t)| !t.ended)
            .map(|(id, t)| TaskSummary {
                task: id.clone(),
                namespace: t.policy.policy.namespace.clone(),
                meta: t.meta.clone(),
                started_ms: t.started_ms,
                sessions: t.sessions.len(),
                max_tool_calls: t.policy.policy.limits.max_tool_calls,
                counters: t.counters.clone(),
            })
            .collect();
        tasks.sort_by_key(|t| t.started_ms);
        tasks
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Unique enough to tell tasks and sessions apart within one log.
fn new_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{nanos:x}{:x}{n:x}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TASK_POLICY: &str = r#"
version: 1
namespace: task
limits:
  max_tool_calls: 3
capabilities:
  - tool: "db.*"
    redact: ["args.password"]
  - tool: "stripe.refund"
    conditions: ["args.amount <= 100"]
  - tool: "*"
    action: deny
"#;

    /// Narrower than the task: no refunds above 10, no db.drop.
    const SESSION_POLICY: &str = r#"
version: 1
namespace: session
capabilities:
  - tool: "db.*"
    redact: ["args.sql"]
  - tool: "db.drop"
    action: deny
  - tool: "stripe.refund"
    conditions: ["args.amount <= 10"]
  - tool: "shell.exec"
"#;

    fn engine() -> (Engine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let recorder = Recorder::open(dir.path().join("flight.jsonl")).unwrap();
        (Engine::new(recorder), dir)
    }

    fn policy(text: &str) -> LoadedPolicy {
        LoadedPolicy::parse(text).unwrap()
    }

    fn decide(engine: &mut Engine, session: &str, tool: &str, args: Value) -> Outcome {
        engine.decide(session, &json!(1), tool, &args).unwrap().outcome
    }

    #[test]
    fn session_policy_only_narrows() {
        let (mut e, _dir) = engine();
        let task = e.create_task(policy(TASK_POLICY), json!({})).unwrap();
        let s = e
            .open_session(Some(&task), Some(policy(SESSION_POLICY)), json!({}))
            .unwrap();

        assert_eq!(
            decide(&mut e, &s, "stripe.refund", json!({"amount": 50})),
            Outcome::Deny
        );
        assert_eq!(decide(&mut e, &s, "db.drop", json!({})), Outcome::Deny);
        // The session policy allows shell.exec, but the task does not: no widening.
        assert_eq!(decide(&mut e, &s, "shell.exec", json!({})), Outcome::Deny);
        assert_eq!(
            decide(&mut e, &s, "stripe.refund", json!({"amount": 5})),
            Outcome::Allow
        );
        assert_eq!(
            e.hidden_tools(&s, &["db.drop".into(), "db.query".into(), "shell.exec".into()])
                .unwrap(),
            ["db.drop", "shell.exec"]
        );
    }

    #[test]
    fn task_limits_are_shared_across_sessions() {
        let (mut e, _dir) = engine();
        let task = e.create_task(policy(TASK_POLICY), json!({})).unwrap();
        let a = e.open_session(Some(&task), None, json!({})).unwrap();
        let b = e.open_session(Some(&task), None, json!({})).unwrap();

        assert_eq!(decide(&mut e, &a, "db.query", json!({})), Outcome::Allow);
        assert_eq!(decide(&mut e, &b, "db.query", json!({})), Outcome::Allow);
        assert_eq!(decide(&mut e, &a, "db.query", json!({})), Outcome::Allow);
        let fourth = e.decide(&b, &json!(4), "db.query", &json!({})).unwrap();
        assert_eq!(fourth.outcome, Outcome::Deny);
        assert!(fourth.reason.contains("task max_tool_calls"), "{}", fourth.reason);

        let summary = &e.tasks()[0];
        assert_eq!(
            (
                summary.sessions,
                summary.counters.calls_allowed,
                summary.counters.calls_denied
            ),
            (2, 3, 1)
        );
    }

    #[test]
    fn ending_a_task_revokes_its_sessions() {
        let (mut e, _dir) = engine();
        let task = e.create_task(policy(TASK_POLICY), json!({})).unwrap();
        let s = e.open_session(Some(&task), None, json!({})).unwrap();
        e.end_task(&task, "test").unwrap();

        let d = e.decide(&s, &json!(1), "db.query", &json!({})).unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("revoked"));
        assert!(e.tasks().is_empty());
        assert!(e.open_session(Some(&task), None, json!({})).is_err());

        e.close_session(&s, json!({})).unwrap();
        assert!(matches!(
            e.open_session(Some(&task), None, json!({})),
            Err(EngineError::UnknownTask(_))
        ));
    }

    #[test]
    fn standalone_sessions_get_an_implicit_task() {
        let (mut e, _dir) = engine();
        assert!(e.open_session(None, None, json!({})).is_err());
        let s = e.open_session(None, Some(policy(TASK_POLICY)), json!({})).unwrap();
        assert_eq!(e.tasks().len(), 1);
        e.close_session(&s, json!({})).unwrap();
        assert!(e.tasks().is_empty(), "implicit task ends with its session");
    }

    #[test]
    fn redaction_from_both_policies_applies() {
        let (mut e, dir) = engine();
        let task = e.create_task(policy(TASK_POLICY), json!({})).unwrap();
        let s = e
            .open_session(Some(&task), Some(policy(SESSION_POLICY)), json!({}))
            .unwrap();
        decide(
            &mut e,
            &s,
            "db.query",
            json!({"sql": "select ssn", "password": "hunter2", "limit": 1}),
        );

        let log = std::fs::read_to_string(dir.path().join("flight.jsonl")).unwrap();
        assert!(!log.contains("hunter2") && !log.contains("select ssn"), "{log}");
        assert!(writ_recorder::verify(dir.path().join("flight.jsonl")).is_ok());
    }
}
