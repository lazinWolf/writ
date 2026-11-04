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
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use writ_policy::{
    Decision, DecisionContext, EntitlementSource, Facts, FileSource, Mode, Outcome, Policy, Root, SessionFacts,
};
use writ_recorder::{Recorder, RecorderError};

use crate::token::{self, Claims, Issuer, TokenError};

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
    #[error(transparent)]
    Token(#[from] TokenError),
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

/// An entitlement source together with the hash of the exact text it was
/// parsed from. Read once, when the task starts.
#[derive(Debug, Clone)]
pub struct LoadedEntitlements {
    pub source: Arc<dyn EntitlementSource>,
    pub sha256: String,
}

impl LoadedEntitlements {
    /// Parses a `source: file` entitlement file.
    pub fn parse(text: &str) -> Result<Self, EngineError> {
        let source = FileSource::from_yaml_str(text).map_err(|e| EngineError::Invalid(e.to_string()))?;
        Ok(LoadedEntitlements {
            source: Arc::new(source),
            sha256: writ_recorder::sha256_hex(text.as_bytes()),
        })
    }
}

/// Who a task acts for, and where its entitlements come from.
#[derive(Debug, Clone, Default)]
pub struct Authority {
    /// The root principal. Unverified: `writ run --principal` asserts it
    /// (plan-v2.md §4.1, root issuance, comes later).
    pub principal: Option<String>,
    /// Required exactly when the policy declares `entitlements:`.
    pub entitlements: Option<LoadedEntitlements>,
}

/// Checks that `entitlements` is what `policy` needs: present exactly when it
/// declares a source, and holding every table its lookups read.
fn check_entitlements(policy: &Policy, entitlements: Option<&LoadedEntitlements>) -> Result<(), EngineError> {
    match (&policy.entitlements, entitlements) {
        (Some(spec), None) => {
            return Err(EngineError::Invalid(format!(
                "the policy declares an entitlement source (`{}`) but none was loaded",
                spec.path
            )));
        }
        (None, Some(_)) => {
            return Err(EngineError::Invalid(
                "an entitlement source was given but the policy doesn't declare one".into(),
            ));
        }
        _ => {}
    }
    check_tables(policy, entitlements.map(|e| e.source.as_ref()))
}

fn check_tables(policy: &Policy, source: Option<&dyn EntitlementSource>) -> Result<(), EngineError> {
    for table in policy.lookup_tables() {
        if !source.is_some_and(|s| s.has_table(table)) {
            return Err(EngineError::Invalid(format!(
                "a rule looks up table `{table}`, which the entitlement source doesn't have"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Counters {
    pub calls_allowed: u64,
    pub calls_denied: u64,
}

struct Task {
    policy: LoadedPolicy,
    /// What conditions see as `writ.*`, minus per-session facts.
    facts: Facts,
    source: Option<Arc<dyn EntitlementSource>>,
    meta: Value,
    started_ms: u64,
    counters: Counters,
    sessions: BTreeSet<String>,
    /// Created for a single standalone session; ends with it.
    implicit: bool,
    ended: bool,
    /// The process that created the task (`writ run`), if known. It and its
    /// descendants (the agent) must not decide the task's approvals.
    creator_pid: Option<i32>,
    /// Allowed calls per fork, by fork id, across every session it reached.
    fork_calls: BTreeMap<String, u64>,
}

/// A policy that narrows a session: from a fork in its token, or its own
/// (`writ wrap --policy` under a task).
#[derive(Debug, Clone)]
struct Narrowing {
    policy: LoadedPolicy,
    /// The fork's id, if from one: its limits count calls from every session
    /// the fork reached, not just this one.
    fork: Option<String>,
    /// How decisions name it: "session policy", "fork `billing` policy".
    name: String,
}

/// What a verified token entitles a session to.
struct Grant {
    task: String,
    /// The forks' policies, oldest first.
    narrowing: Vec<Narrowing>,
    /// Every fork's id, oldest first, whether or not it carries a policy.
    forks: Vec<String>,
    /// Unix seconds.
    expires: Option<u64>,
    /// What the session record says about the token.
    lineage: Value,
}

/// A `require_sudo` call paused until a human decides, it times out, or its
/// task or session ends.
struct Approval {
    task: String,
    session: String,
    call_id: Value,
    tool: String,
    /// As recorded: redacted, or `None` if the policy omits arguments.
    arguments: Option<Value>,
    /// Why the call needs a human.
    reason: String,
    rule: Option<String>,
    created_ms: u64,
    expires_ms: u64,
    deadline: Instant,
    /// Set once decided; the waiting session collects it with
    /// [`Engine::take_resolution`].
    resolution: Option<Decision>,
}

/// One row of `writ sudo list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub id: String,
    pub task: String,
    pub session: String,
    pub principal: Option<String>,
    /// The session's source, `mcp:<name>`.
    pub server: String,
    pub tool: String,
    /// Redacted per policy; `null` when the policy omits arguments.
    pub arguments: Option<Value>,
    pub reason: String,
    pub rule: Option<String>,
    pub tainted: bool,
    pub taint_sources: Vec<String>,
    pub created_ms: u64,
    pub expires_ms: u64,
}

/// How a pending approval was settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Approve,
    Deny,
}

struct Session {
    task: String,
    /// `mcp:<name>`.
    source: String,
    /// Forks' policies, oldest first, then the session's own: each can only
    /// make a decision stricter.
    narrowing: Vec<Narrowing>,
    /// The token's fork ids, oldest first.
    forks: Vec<String>,
    /// When the token this session opened with expires, Unix seconds.
    expires: Option<u64>,
    counters: Counters,
    /// The `writ wrap` process serving this session, if known. It and its
    /// descendants (the MCP server) must not decide the task's approvals.
    pid: Option<i32>,
    /// The caller asks its own human for `require_sudo` (a Claude Code
    /// prompt), so writd doesn't pause the call.
    ask_natively: bool,
}

/// How long a scope (see [`Engine::decide_scoped`]) lives without a call.
pub const SCOPE_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

/// One action from a caller that keeps no connection: see
/// [`Engine::decide_scoped`].
#[derive(Debug, Clone)]
pub struct ScopedCall {
    /// Which calls share a task, e.g. `claude-code:<session id>`.
    pub scope: String,
    pub policy: LoadedPolicy,
    pub entitlements: Option<LoadedEntitlements>,
    /// `writ.workspace`, an absolute path.
    pub workspace: Option<String>,
    pub principal: Option<String>,
    /// Where the action goes: `shell`, `fs`, `web`, `mcp:<server>`, ...
    pub source: String,
    pub tool: String,
    pub args: Value,
    pub call_id: Value,
}

struct ScopeState {
    task: String,
    policy_sha256: String,
    /// Session per source.
    sessions: BTreeMap<String, String>,
    last_used: Instant,
}

/// A scoped call's source: 1-80 characters from `[A-Za-z0-9_.:-]`.
fn validate_source(source: &str) -> Result<(), EngineError> {
    let ok = !source.is_empty()
        && source.len() <= 80
        && source
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
    if ok {
        Ok(())
    } else {
        Err(EngineError::Invalid(format!("invalid source `{source}`")))
    }
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
    /// The root principal, if the task has one (unverified in this build).
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub tainted: bool,
    /// Untrusted sources the task has read from, in order.
    #[serde(default)]
    pub taint_sources: Vec<String>,
    /// The sources (`mcp:<name>`) of its open sessions.
    #[serde(default)]
    pub servers: Vec<String>,
}

pub struct Engine {
    recorder: Recorder,
    /// True in writd. A standalone `writ wrap` has nobody to ask, so its
    /// `require_sudo` calls are refused.
    approvals_enabled: bool,
    approvals: BTreeMap<String, Approval>,
    tasks: BTreeMap<String, Task>,
    sessions: BTreeMap<String, Session>,
    /// Signs task tokens. Its key lives only in this process.
    issuer: Issuer,
    /// Tasks of callers that keep no connection, by scope.
    scopes: BTreeMap<String, ScopeState>,
}

impl Engine {
    pub fn new(recorder: Recorder) -> Self {
        Engine {
            issuer: Issuer::default(),
            scopes: BTreeMap::new(),
            recorder,
            approvals_enabled: false,
            approvals: BTreeMap::new(),
            tasks: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }

    /// Lets `require_sudo` calls pause for a human when the task's policy has
    /// an `approvals:` block. Only writd does this: someone must be able to
    /// reach the engine to decide.
    pub fn enable_approvals(&mut self) {
        self.approvals_enabled = true;
    }

    /// Creates a root task acting for `authority`. `meta` describes who and
    /// what started it (command, user) and is recorded as given.
    pub fn create_task(
        &mut self,
        policy: LoadedPolicy,
        authority: Authority,
        meta: Value,
    ) -> Result<String, EngineError> {
        self.create_task_inner(policy, authority, meta, false)
    }

    fn create_task_inner(
        &mut self,
        policy: LoadedPolicy,
        authority: Authority,
        meta: Value,
        implicit: bool,
    ) -> Result<String, EngineError> {
        check_entitlements(&policy.policy, authority.entitlements.as_ref())?;
        let source = authority.entitlements.as_ref().map(|e| e.source.clone());
        // A principal the source doesn't know is entitled to nothing: its root
        // has no attributes, so every entitlement reading one fails closed.
        let root = authority.principal.map(|principal| Root {
            attributes: source
                .as_ref()
                .and_then(|s| s.root_attributes(&principal))
                .unwrap_or_default(),
            principal,
            verified: false,
        });
        let id = new_id("tsk");
        let data = json!({
            "task": id,
            "namespace": policy.policy.namespace,
            "policy_sha256": policy.sha256,
            "entitlements_sha256": authority.entitlements.as_ref().map(|e| &e.sha256),
            "root": root,
            "implicit": implicit,
            "meta": meta,
        });
        self.recorder.append_durable(&id, "task_start", data)?;
        self.tasks.insert(
            id.clone(),
            Task {
                policy,
                facts: Facts {
                    root,
                    ..Facts::default()
                },
                source,
                meta,
                started_ms: now_ms(),
                counters: Counters::default(),
                sessions: BTreeSet::new(),
                implicit,
                ended: false,
                creator_pid: None,
                fork_calls: BTreeMap::new(),
            },
        );
        Ok(id)
    }

    /// Mints the token that lets processes join `task`, valid for `ttl`.
    /// Only its fingerprint is recorded.
    pub fn task_token(&mut self, task_id: &str, ttl: Duration) -> Result<String, EngineError> {
        let task = self
            .tasks
            .get(task_id)
            .ok_or_else(|| EngineError::UnknownTask(task_id.to_string()))?;
        let claims = Claims {
            task: task_id.to_string(),
            namespace: task.policy.policy.namespace.clone(),
            policy_sha256: task.policy.sha256.clone(),
            principal: task.facts.root.as_ref().map(|r| r.principal.clone()),
            expires: token::now().saturating_add(ttl.as_secs()),
        };
        let token = self.issuer.mint(&claims)?;
        self.recorder.append(
            task_id,
            "token_issued",
            json!({ "task": task_id, "token": token::fingerprint(&token), "expires": claims.expires }),
        )?;
        Ok(token)
    }

    /// Checks a token and what it grants: signed by this writd, unexpired,
    /// for a live task whose namespace and policy it names, with fork
    /// policies that parse, bring no entitlement source, and stay within
    /// every `max_depth`.
    fn grant(&self, token: &str) -> Result<Grant, EngineError> {
        let verified = self.issuer.verify(token)?;
        let claims = &verified.claims;
        let task = self
            .tasks
            .get(&claims.task)
            .ok_or_else(|| EngineError::UnknownTask(claims.task.clone()))?;
        if task.ended {
            return Err(EngineError::Invalid(format!("task `{}` has ended", claims.task)));
        }
        if claims.namespace != task.policy.policy.namespace || claims.policy_sha256 != task.policy.sha256 {
            return Err(TokenError::Refused("it doesn't match its task's namespace and policy".into()).into());
        }
        let mut narrowing = Vec::new();
        for (depth, fork) in verified.forks.iter().enumerate() {
            for text in &fork.policies {
                let name = match &fork.label {
                    Some(label) => format!("fork `{label}` policy"),
                    None => format!("fork {} policy", depth + 1),
                };
                let policy = LoadedPolicy::parse(text).map_err(|e| EngineError::Invalid(format!("{name}: {e}")))?;
                if policy.policy.entitlements.is_some() {
                    return Err(EngineError::Invalid(format!(
                        "{name} declares an entitlement source; a fork reads the task's"
                    )));
                }
                if policy.policy.mode == Mode::Observe {
                    return Err(EngineError::Invalid(format!(
                        "{name} is in observe mode, which only a task's policy can be"
                    )));
                }
                check_tables(&policy.policy, task.source.as_deref())?;
                narrowing.push(Narrowing {
                    policy,
                    fork: Some(fork.id.clone()),
                    name,
                });
            }
        }
        let depth = verified.forks.len() as u64;
        if let Some(max) = std::iter::once(&task.policy)
            .chain(narrowing.iter().map(|n| &n.policy))
            .filter_map(|p| p.policy.limits.max_depth)
            .min()
            && depth > max
        {
            return Err(EngineError::Invalid(format!(
                "the token is forked {depth} deep; the policy allows max_depth {max}"
            )));
        }
        Ok(Grant {
            task: claims.task.clone(),
            narrowing,
            forks: verified.forks.iter().map(|f| f.id.clone()).collect(),
            expires: Some(verified.expires),
            lineage: json!({
                "token": verified.fingerprint,
                "depth": depth,
                "expires": verified.expires,
                "forks": verified.forks.iter().map(|f| json!({
                    "id": f.id,
                    "label": f.label,
                    "policy_sha256": f.policies.iter().map(|p| writ_recorder::sha256_hex(p.as_bytes())).collect::<Vec<_>>(),
                    "expires": f.expires,
                })).collect::<Vec<_>>(),
            }),
        })
    }

    /// Records the process that created `task`. It and its descendants (the
    /// agent) can't decide the task's approvals; see [`Engine::approval_processes`].
    pub fn set_task_process(&mut self, task: &str, pid: i32) {
        if let Some(task) = self.tasks.get_mut(task) {
            task.creator_pid = Some(pid);
        }
    }

    /// Records the process serving `session` (its `writ wrap`).
    pub fn set_session_process(&mut self, session: &str, pid: i32) {
        if let Some(session) = self.sessions.get_mut(session) {
            session.pid = Some(pid);
        }
    }

    /// The processes acting for an approval's task: whoever created the task
    /// and every wrapped server's proxy. A decision must not come from any of
    /// them or their descendants, or an agent (or a malicious MCP server)
    /// could approve its own calls.
    pub fn approval_processes(&self, id: &str) -> Vec<i32> {
        let Some(task) = self.approvals.get(id).and_then(|a| self.tasks.get(&a.task)) else {
            return Vec::new();
        };
        task.creator_pid
            .into_iter()
            .chain(task.sessions.iter().filter_map(|s| self.sessions.get(s)?.pid))
            .collect()
    }

    /// Denies every pending approval, recording `why`. writd calls this when
    /// it stops, so the log shows how each one ended.
    pub fn cancel_all_approvals(&mut self, why: &str) {
        self.cancel_approvals(why, |_| true);
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
        let owner = task_id.to_string();
        self.cancel_approvals("the task ended", |a| a.task == owner);
        let task = self.tasks.get_mut(task_id).expect("task exists");
        let data =
            json!({ "task": task_id, "reason": reason, "counters": task.counters, "open_sessions": task.sessions });
        let empty = task.sessions.is_empty();
        if empty {
            self.tasks.remove(task_id);
        }
        self.recorder.append_durable(task_id, "task_end", data)?;
        Ok(())
    }

    /// Opens a session for the server `name` (its source is `mcp:<name>`).
    /// With a task it joins that task, optionally narrowed by `own_policy`
    /// (which uses the task's entitlement source); without one, `own_policy`
    /// is required and becomes an implicit task of its own, with
    /// `own_entitlements` as its source. `info` (command, server pid) is
    /// recorded.
    pub fn open_session(
        &mut self,
        task: Option<&str>,
        own_policy: Option<LoadedPolicy>,
        own_entitlements: Option<LoadedEntitlements>,
        name: &str,
        info: Value,
    ) -> Result<String, EngineError> {
        // In-process callers are trusted with the task id; writd's peers present a token.
        let grant = task.map(|task| Grant {
            task: task.to_string(),
            narrowing: Vec::new(),
            forks: Vec::new(),
            expires: None,
            lineage: Value::Null,
        });
        writ_policy::validate_session_name(name).map_err(EngineError::Invalid)?;
        let source = writ_policy::session_source(name);
        self.open(grant, own_policy, own_entitlements, source, info)
    }

    /// Like [`Engine::open_session`] with a task, but the task comes from a
    /// token, which is verified first. Its forks' policies narrow the session.
    pub fn open_session_with_token(
        &mut self,
        token: &str,
        own_policy: Option<LoadedPolicy>,
        own_entitlements: Option<LoadedEntitlements>,
        name: &str,
        info: Value,
    ) -> Result<String, EngineError> {
        let grant = self.grant(token)?;
        writ_policy::validate_session_name(name).map_err(EngineError::Invalid)?;
        let source = writ_policy::session_source(name);
        self.open(Some(grant), own_policy, own_entitlements, source, info)
    }

    fn open(
        &mut self,
        grant: Option<Grant>,
        mut own_policy: Option<LoadedPolicy>,
        own_entitlements: Option<LoadedEntitlements>,
        source: String,
        info: Value,
    ) -> Result<String, EngineError> {
        let (task_id, mut narrowing, forks, expires, lineage) = match grant {
            Some(grant) => {
                let id = &grant.task;
                let task = self
                    .tasks
                    .get(id)
                    .ok_or_else(|| EngineError::UnknownTask(id.to_string()))?;
                if task.ended {
                    return Err(EngineError::Invalid(format!("task `{id}` has ended")));
                }
                if let Some(own) = &own_policy {
                    if own.policy.mode == Mode::Observe {
                        return Err(EngineError::Invalid(
                            "observe mode applies to a task's policy, not a narrowing one".into(),
                        ));
                    }
                    // Narrowing can't bring its own source: that could widen what the
                    // root is entitled to. It reads the task's.
                    if own.policy.entitlements.is_some() || own_entitlements.is_some() {
                        return Err(EngineError::Invalid(
                            "a narrowing policy can't declare an entitlement source; the task's applies".into(),
                        ));
                    }
                    check_tables(&own.policy, task.source.as_deref())?;
                }
                (grant.task, grant.narrowing, grant.forks, grant.expires, grant.lineage)
            }
            None => {
                let policy = own_policy
                    .take()
                    .ok_or_else(|| EngineError::Invalid("a session without a task needs its own policy".into()))?;
                let authority = Authority {
                    principal: None,
                    entitlements: own_entitlements,
                };
                let task = self.create_task_inner(policy, authority, json!({}), true)?;
                (task, Vec::new(), Vec::new(), None, Value::Null)
            }
        };
        if let Some(policy) = own_policy {
            narrowing.push(Narrowing {
                policy,
                fork: None,
                name: "session policy".into(),
            });
        }

        let id = new_id("ses");
        let own = narrowing.iter().find(|n| n.fork.is_none());
        let mut data = json!({
            "task": task_id,
            "source": source,
            "narrowing_policy_sha256": own.map(|n| &n.policy.sha256),
            "info": info,
        });
        if !lineage.is_null() {
            data["writ"] = lineage;
        }
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
                source,
                narrowing,
                forks,
                expires,
                counters: Counters::default(),
                pid: None,
                ask_natively: false,
            },
        );
        Ok(id)
    }

    /// Decides one action for a caller that keeps no connection open: a
    /// Claude Code hook runs as a fresh process for every tool call. Calls
    /// with the same `scope` (e.g. `claude-code:<session id>`) share one task,
    /// so taint and limits carry from call to call, with a session per
    /// source (`shell`, `web`, `mcp:github`, ...). If the policy text changes,
    /// the scope moves to a new task and keeps its taint: editing the policy
    /// doesn't launder an injection. Scopes idle for [`SCOPE_IDLE`] end.
    ///
    /// `require_sudo` is returned as is, never paused: the caller asks its
    /// own human (Claude Code's permission prompt).
    pub fn decide_scoped(&mut self, call: ScopedCall) -> Result<Decision, EngineError> {
        let session = self.scoped_session(&call)?;
        self.decide(&session, &call.call_id, &call.tool, &call.args)
    }

    /// Records that a scoped call ran (after Claude Code asked its user, say),
    /// and taints the task if its source is untrusted: its output is now in
    /// the agent's context.
    pub fn executed_scoped(&mut self, call: ScopedCall) -> Result<(), EngineError> {
        let session = self.scoped_session(&call)?;
        self.taint_if_untrusted(&session, &call.call_id, &call.tool)?;
        self.recorder.append(
            &session,
            "tool_executed",
            json!({ "id": call.call_id, "tool": call.tool, "task": self.sessions[&session].task }),
        )?;
        Ok(())
    }

    fn scoped_session(&mut self, call: &ScopedCall) -> Result<String, EngineError> {
        validate_source(&call.source)?;
        self.sweep_idle_scopes();
        let current = self
            .scopes
            .get(&call.scope)
            .filter(|s| s.policy_sha256 == call.policy.sha256 && self.tasks.get(&s.task).is_some_and(|t| !t.ended))
            .map(|s| s.task.clone());
        let task_id = match current {
            Some(task) => task,
            None => {
                let previous = self.scopes.remove(&call.scope);
                let mut carried = (false, Vec::new());
                if let Some(old) = &previous
                    && let Some(task) = self.tasks.get(&old.task)
                {
                    carried = (task.facts.tainted, task.facts.taint_sources.clone());
                }
                let meta = json!({
                    "scope": call.scope,
                    "workspace": call.workspace,
                    "replaces": previous.as_ref().map(|p| &p.task),
                    "carried_taint": carried.1,
                });
                let authority = Authority {
                    principal: call.principal.clone(),
                    entitlements: call.entitlements.clone(),
                };
                let task = self.create_task(call.policy.clone(), authority, meta)?;
                let facts = &mut self.tasks.get_mut(&task).expect("just created").facts;
                facts.workspace = call.workspace.clone();
                (facts.tainted, facts.taint_sources) = carried;
                if let Some(old) = previous {
                    for session in old.sessions.values() {
                        let _ = self.close_session(session, json!({ "termination": "policy changed" }));
                    }
                    let _ = self.end_task(&old.task, "policy changed");
                }
                self.scopes.insert(
                    call.scope.clone(),
                    ScopeState {
                        task: task.clone(),
                        policy_sha256: call.policy.sha256.clone(),
                        sessions: BTreeMap::new(),
                        last_used: Instant::now(),
                    },
                );
                task
            }
        };
        let scope = self.scopes.get_mut(&call.scope).expect("scope exists");
        scope.last_used = Instant::now();
        if let Some(session) = scope.sessions.get(&call.source) {
            return Ok(session.clone());
        }
        let grant = Grant {
            task: task_id,
            narrowing: Vec::new(),
            forks: Vec::new(),
            expires: None,
            lineage: Value::Null,
        };
        let session = self.open(
            Some(grant),
            None,
            None,
            call.source.clone(),
            json!({ "scope": call.scope }),
        )?;
        self.sessions.get_mut(&session).expect("just opened").ask_natively = true;
        self.scopes
            .get_mut(&call.scope)
            .expect("scope exists")
            .sessions
            .insert(call.source.clone(), session.clone());
        Ok(session)
    }

    fn sweep_idle_scopes(&mut self) {
        let idle: Vec<String> = self
            .scopes
            .iter()
            .filter(|(_, s)| s.last_used.elapsed() > SCOPE_IDLE)
            .map(|(k, _)| k.clone())
            .collect();
        for key in idle {
            let scope = self.scopes.remove(&key).expect("listed");
            for session in scope.sessions.values() {
                let _ = self.close_session(session, json!({ "termination": "idle" }));
            }
            let _ = self.end_task(&scope.task, "idle");
        }
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

        // Facts are computed here, by writd, never taken from the agent or the server.
        let facts = Facts {
            session: SessionFacts {
                name: Some(session.source.clone()),
            },
            ..task.facts.clone()
        };
        let ctx = DecisionContext::new(tool, args, &facts).with_source(task.source.as_deref());
        let expired = session.expires.is_some_and(|e| token::now() > e);
        let mut decision = if task.ended {
            Decision::new(
                Outcome::Deny,
                None,
                format!("task `{}` has ended; its authority is revoked", session.task),
            )
        } else if expired {
            Decision::new(
                Outcome::Deny,
                None,
                "the writ token this session opened with has expired".to_string(),
            )
        } else {
            // Ties keep the earlier decision: a narrowing policy only matters when stricter.
            let mut decision = task.policy.policy.evaluate(&ctx);
            for narrowing in &session.narrowing {
                let narrower = narrowing.policy.policy.evaluate(&ctx);
                if narrower.outcome > decision.outcome {
                    decision = Decision {
                        reason: format!("{} ({})", narrower.reason, narrowing.name),
                        ..narrower
                    };
                }
            }
            decision
        };
        if decision.outcome == Outcome::Allow
            && let Some(reason) = limit_reached(task, session)
        {
            decision.outcome = Outcome::Deny;
            decision.reason = reason;
        }
        // Observe mode records what the policy decided and lets the call through.
        // Revocation (an ended task, an expired token) isn't policy: it still denies.
        if task.policy.policy.mode == Mode::Observe && !task.ended && !expired && decision.outcome != Outcome::Allow {
            let would = decision.outcome;
            decision = Decision {
                outcome: Outcome::Allow,
                reason: format!(
                    "observe mode, not enforced: would {}: {}",
                    would.as_str(),
                    decision.reason
                ),
                would: Some(would),
                ..decision
            };
        }
        // Pause for a human instead of refusing, if this task can be asked.
        let timeout = approval_timeout(task, session).filter(|_| self.approvals_enabled && !session.ask_natively);
        if decision.outcome == Outcome::RequireSudo && timeout.is_some() {
            decision.approval = Some(new_id("apr"));
        }

        let mut data = json!({
            "id": call_id,
            "task": session.task,
            "tool": tool,
            "decision": decision,
            "facts": facts,
        });
        // Narrowing policies' redaction applies on top of the task's; any can omit everything.
        let logged = session
            .narrowing
            .iter()
            .fold(task.policy.policy.arguments_for_log(tool, args), |logged, n| {
                logged.and_then(|logged| n.policy.policy.arguments_for_log(tool, &logged))
            });
        match &logged {
            Some(arguments) => data["arguments"] = arguments.clone(),
            None => data["arguments_omitted"] = json!(true),
        }
        if let (Some(id), Some(timeout)) = (&decision.approval, timeout) {
            // Recorded durably: a pending approval is a decision someone will act on.
            self.recorder.append_durable(session_id, "tool_call", data)?;
            let now = now_ms();
            self.approvals.insert(
                id.clone(),
                Approval {
                    task: session.task.clone(),
                    session: session_id.to_string(),
                    call_id: call_id.clone(),
                    tool: tool.to_string(),
                    arguments: logged,
                    reason: decision.reason.clone(),
                    rule: decision.rule.clone(),
                    created_ms: now,
                    expires_ms: now + timeout.as_millis() as u64,
                    deadline: Instant::now() + timeout,
                    resolution: None,
                },
            );
            // Counted once it is decided.
            return Ok(decision);
        }
        // Only an allowed decision gates an action, so only it waits for stable storage.
        // A denial is persisted by the next sync, and a flood of denied calls (the shape
        // of an injection attempt) cannot force a sync per call.
        let allowed = decision.outcome == Outcome::Allow;
        if allowed {
            // Recorded first and durably: if this fails the call is denied, and a
            // taint without its call is the safe side to err on.
            self.taint_if_untrusted(session_id, call_id, tool)?;
            self.recorder.append_durable(session_id, "tool_call", data)?;
        } else {
            self.recorder.append(session_id, "tool_call", data)?;
        }
        self.count(session_id, allowed);
        Ok(decision)
    }

    /// An allowed call to an untrusted source taints its task before the call
    /// is forwarded: its result is about to enter the agent's context. Either
    /// policy may declare the source untrusted. Taint is never cleared.
    fn taint_if_untrusted(&mut self, session_id: &str, call_id: &Value, tool: &str) -> Result<(), EngineError> {
        let session = &self.sessions[session_id];
        let task = &self.tasks[&session.task];
        let source = &session.source;
        let taints = !task.facts.taint_sources.contains(source)
            && (task.policy.policy.is_untrusted(source)
                || session.narrowing.iter().any(|n| n.policy.policy.is_untrusted(source)));
        if !taints {
            return Ok(());
        }
        let (task_id, source) = (session.task.clone(), source.clone());
        self.recorder.append_durable(
            session_id,
            "taint",
            json!({ "task": task_id, "source": source, "id": call_id, "tool": tool }),
        )?;
        let facts = &mut self.tasks.get_mut(&task_id).expect("task exists").facts;
        facts.tainted = true;
        facts.taint_sources.push(source);
        Ok(())
    }

    fn count(&mut self, session_id: &str, allowed: bool) {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return;
        };
        let task_id = session.task.clone();
        let mut counters = vec![&mut session.counters];
        if let Some(task) = self.tasks.get_mut(&task_id) {
            if allowed {
                for fork in &session.forks {
                    *task.fork_calls.entry(fork.clone()).or_default() += 1;
                }
            }
            counters.push(&mut task.counters);
        }
        for c in counters {
            if allowed {
                c.calls_allowed += 1;
            } else {
                c.calls_denied += 1;
            }
        }
    }

    /// Pending approvals, oldest first.
    pub fn approvals(&self) -> Vec<ApprovalSummary> {
        let mut list: Vec<ApprovalSummary> = self
            .approvals
            .iter()
            .filter(|(_, a)| a.resolution.is_none())
            .map(|(id, a)| {
                let facts = self.tasks.get(&a.task).map(|t| &t.facts);
                ApprovalSummary {
                    id: id.clone(),
                    task: a.task.clone(),
                    session: a.session.clone(),
                    principal: facts.and_then(|f| f.root.as_ref()).map(|r| r.principal.clone()),
                    server: self
                        .sessions
                        .get(&a.session)
                        .map(|s| s.source.clone())
                        .unwrap_or_default(),
                    tool: a.tool.clone(),
                    arguments: a.arguments.clone(),
                    reason: a.reason.clone(),
                    rule: a.rule.clone(),
                    tainted: facts.is_some_and(|f| f.tainted),
                    taint_sources: facts.map(|f| f.taint_sources.clone()).unwrap_or_default(),
                    created_ms: a.created_ms,
                    expires_ms: a.expires_ms,
                }
            })
            .collect();
        list.sort_by_key(|a| a.created_ms);
        list
    }

    /// When a pending approval times out; `None` if it's unknown or decided.
    pub fn approval_deadline(&self, id: &str) -> Option<Instant> {
        self.approvals
            .get(id)
            .filter(|a| a.resolution.is_none())
            .map(|a| a.deadline)
    }

    /// Settles a pending approval. `approver` (who decided) is recorded as
    /// given. An approved call is re-checked first: its task may have ended,
    /// or its limits been reached, while it waited. Returns the final decision.
    pub fn resolve_approval(
        &mut self,
        id: &str,
        resolution: Resolution,
        approver: Value,
    ) -> Result<Decision, EngineError> {
        let approval = self
            .approvals
            .get(id)
            .ok_or_else(|| EngineError::Invalid(format!("unknown approval `{id}`")))?;
        if approval.resolution.is_some() {
            return Err(EngineError::Invalid(format!(
                "approval `{id}` has already been decided"
            )));
        }
        let who = match approver["user"].as_str() {
            Some(user) => format!("approver {user}"),
            None => "an approver".to_string(),
        };
        let decision = match resolution {
            Resolution::Deny => Decision::new(
                Outcome::Deny,
                approval.rule.clone(),
                format!("{who} denied this call; it needed approval because {}", approval.reason),
            ),
            Resolution::Approve => {
                let session = self.sessions.get(&approval.session);
                let task = self.tasks.get(&approval.task);
                let blocked = match (task, session) {
                    (Some(task), _) if task.ended => Some(format!("task `{}` ended while waiting", approval.task)),
                    (Some(task), Some(session)) => limit_reached(task, session),
                    _ => Some("its session ended while waiting".to_string()),
                };
                match blocked {
                    Some(why) => Decision::new(
                        Outcome::Deny,
                        approval.rule.clone(),
                        format!("approved by {who}, but {why}"),
                    ),
                    None => Decision::new(
                        Outcome::Allow,
                        approval.rule.clone(),
                        format!("approved by {who}; it needed approval because {}", approval.reason),
                    ),
                }
            }
        };
        let label = match resolution {
            Resolution::Approve => "approve",
            Resolution::Deny => "deny",
        };
        self.settle(id, label, approver, decision)
    }

    /// Denies a pending approval whose deadline has passed. A no-op if it's
    /// already decided or not yet due.
    pub fn expire_approval(&mut self, id: &str) -> Result<(), EngineError> {
        let Some(approval) = self.approvals.get(id) else {
            return Ok(());
        };
        if approval.resolution.is_some() || Instant::now() < approval.deadline {
            return Ok(());
        }
        let waited = Duration::from_millis(approval.expires_ms - approval.created_ms);
        let decision = Decision::new(
            Outcome::Deny,
            approval.rule.clone(),
            format!(
                "no approver decided within {}; the call was not executed",
                humantime::format_duration(waited)
            ),
        );
        self.settle(id, "timeout", Value::Null, decision).map(|_| ())
    }

    /// Records how an approval was settled and stores the final decision
    /// for the waiting session.
    fn settle(&mut self, id: &str, label: &str, approver: Value, decision: Decision) -> Result<Decision, EngineError> {
        let approval = &self.approvals[id];
        let (session_id, call_id, tool, task_id) = (
            approval.session.clone(),
            approval.call_id.clone(),
            approval.tool.clone(),
            approval.task.clone(),
        );
        let allowed = decision.outcome == Outcome::Allow;
        if allowed && self.sessions.contains_key(&session_id) {
            self.taint_if_untrusted(&session_id, &call_id, &tool)?;
        }
        let data = json!({
            "approval": id,
            "task": task_id,
            "id": call_id,
            "tool": tool,
            "decision": label,
            "approver": approver,
            "outcome": decision,
        });
        // Durable either way: an approval is a human's decision, and an approved call
        // is forwarded only after this returns.
        self.recorder.append_durable(&session_id, "approval", data)?;
        self.count(&session_id, allowed);
        self.approvals.get_mut(id).expect("approval exists").resolution = Some(decision.clone());
        Ok(decision)
    }

    /// The final decision of a settled approval, removing it. `None` while
    /// it's pending.
    pub fn take_resolution(&mut self, id: &str) -> Option<Decision> {
        self.approvals.get(id)?.resolution.as_ref()?;
        self.approvals.remove(id).and_then(|a| a.resolution)
    }

    /// Denies every pending approval matching `pending`, recording `why`.
    fn cancel_approvals(&mut self, why: &str, pending: impl Fn(&Approval) -> bool) {
        let ids: Vec<String> = self
            .approvals
            .iter()
            .filter(|(_, a)| a.resolution.is_none() && pending(a))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let rule = self.approvals[&id].rule.clone();
            let decision = Decision::new(Outcome::Deny, rule, format!("{why} while the call waited for approval"));
            if let Err(e) = self.settle(&id, "cancelled", Value::Null, decision) {
                eprintln!("writd: {e}");
            }
        }
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
                    || session.narrowing.iter().any(|n| n.policy.policy.always_denies(name))
            })
            .cloned()
            .collect())
    }

    /// Closes a session, recording `data` merged with its counters. An
    /// implicit task ends with its only session; an ended task is dropped
    /// once its last session closes.
    pub fn close_session(&mut self, session_id: &str, mut data: Value) -> Result<(), EngineError> {
        if !self.sessions.contains_key(session_id) {
            return Err(EngineError::UnknownSession(session_id.to_string()));
        }
        self.cancel_approvals("the session closed", |a| a.session == session_id);
        self.approvals.retain(|_, a| a.session != session_id);
        let session = self.sessions.remove(session_id).expect("session exists");
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
                principal: t.facts.root.as_ref().map(|r| r.principal.clone()),
                tainted: t.facts.tainted,
                taint_sources: t.facts.taint_sources.clone(),
                servers: t
                    .sessions
                    .iter()
                    .filter_map(|s| self.sessions.get(s).map(|s| s.source.clone()))
                    .collect(),
            })
            .collect();
        tasks.sort_by_key(|t| t.started_ms);
        tasks
    }
}

/// Why another allowed call would exceed a `max_tool_calls` limit, if it would.
fn limit_reached(task: &Task, session: &Session) -> Option<String> {
    let mut limits = vec![(
        task.policy.policy.limits.max_tool_calls,
        task.counters.calls_allowed,
        "task".to_string(),
    )];
    for n in &session.narrowing {
        let (used, scope) = match &n.fork {
            // A fork's limit is shared by every session opened with it.
            Some(fork) => (
                task.fork_calls.get(fork).copied().unwrap_or(0),
                n.name.trim_end_matches(" policy").to_string(),
            ),
            None => (session.counters.calls_allowed, "session".to_string()),
        };
        limits.push((n.policy.policy.limits.max_tool_calls, used, scope));
    }
    limits.iter().find_map(|(max, used, scope)| {
        max.filter(|m| used >= m)
            .map(|m| format!("{scope} max_tool_calls limit reached ({m})"))
    })
}

/// How long a `require_sudo` call may wait for a human, or `None` if the
/// task's policy has no `approvals:` block. A narrowing policy may shorten it.
fn approval_timeout(task: &Task, session: &Session) -> Option<Duration> {
    let base = task.policy.policy.approvals?.timeout;
    Some(
        session
            .narrowing
            .iter()
            .filter_map(|n| n.policy.policy.approvals)
            .map(|a| a.timeout)
            .fold(base, Duration::min),
    )
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
    fn tokens_join_live_tasks_and_expire() {
        let (mut e, _dir) = engine();
        let task = e
            .create_task(policy(TASK_POLICY), Authority::default(), json!({}))
            .unwrap();
        let token = e.task_token(&task, Duration::from_secs(1)).unwrap();
        let s = e.open_session_with_token(&token, None, None, "srv", json!({})).unwrap();
        assert_eq!(decide(&mut e, &s, "db.query", json!({})), Outcome::Allow);
        // Expiry has second precision: wait out the second it falls in.
        std::thread::sleep(Duration::from_millis(2100));
        let late = e.decide(&s, &json!(2), "db.query", &json!({})).unwrap();
        assert_eq!(late.outcome, Outcome::Deny);
        assert!(late.reason.contains("expired"), "{}", late.reason);
        assert!(
            e.open_session_with_token(&token, None, None, "srv2", json!({}))
                .is_err()
        );

        // A fresh token for an ended task joins nothing.
        let token = e.task_token(&task, Duration::from_secs(60)).unwrap();
        e.end_task(&task, "done").unwrap();
        let err = e
            .open_session_with_token(&token, None, None, "srv3", json!({}))
            .unwrap_err();
        assert!(err.to_string().contains("ended"), "{err}");
    }

    #[test]
    fn forks_are_held_to_max_depth() {
        let (mut e, _dir) = engine();
        let task = e
            .create_task(
                policy(&TASK_POLICY.replace("max_tool_calls: 3", "max_tool_calls: 3\n  max_depth: 1")),
                Authority::default(),
                json!({}),
            )
            .unwrap();
        let root = e.task_token(&task, Duration::from_secs(60)).unwrap();
        let narrow = format!("{SESSION_POLICY}limits:\n  max_depth: 0\n");
        let child = token::fork(
            &root,
            &token::ForkSpec {
                policy: Some(&narrow),
                ..Default::default()
            },
        )
        .unwrap();
        let grandchild = token::fork(&child, &token::ForkSpec::default()).unwrap();
        assert!(e.open_session_with_token(&root, None, None, "a", json!({})).is_ok());
        // The fork's own max_depth 0 is below its depth: it forbade being forked into.
        let err = e
            .open_session_with_token(&child, None, None, "b", json!({}))
            .unwrap_err();
        assert!(err.to_string().contains("max_depth 0"), "{err}");
        let err = e
            .open_session_with_token(&grandchild, None, None, "c", json!({}))
            .unwrap_err();
        assert!(err.to_string().contains("forked 2 deep"), "{err}");
    }

    #[test]
    fn session_policy_only_narrows() {
        let (mut e, _dir) = engine();
        let task = e
            .create_task(policy(TASK_POLICY), Authority::default(), json!({}))
            .unwrap();
        let s = e
            .open_session(Some(&task), Some(policy(SESSION_POLICY)), None, "srv", json!({}))
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
        let task = e
            .create_task(policy(TASK_POLICY), Authority::default(), json!({}))
            .unwrap();
        let a = e.open_session(Some(&task), None, None, "srv", json!({})).unwrap();
        let b = e.open_session(Some(&task), None, None, "srv", json!({})).unwrap();

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
        let task = e
            .create_task(policy(TASK_POLICY), Authority::default(), json!({}))
            .unwrap();
        let s = e.open_session(Some(&task), None, None, "srv", json!({})).unwrap();
        e.end_task(&task, "test").unwrap();

        let d = e.decide(&s, &json!(1), "db.query", &json!({})).unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("revoked"));
        assert!(e.tasks().is_empty());
        assert!(e.open_session(Some(&task), None, None, "srv", json!({})).is_err());

        e.close_session(&s, json!({})).unwrap();
        assert!(matches!(
            e.open_session(Some(&task), None, None, "srv", json!({})),
            Err(EngineError::UnknownTask(_))
        ));
    }

    #[test]
    fn standalone_sessions_get_an_implicit_task() {
        let (mut e, _dir) = engine();
        assert!(e.open_session(None, None, None, "srv", json!({})).is_err());
        let s = e
            .open_session(None, Some(policy(TASK_POLICY)), None, "srv", json!({}))
            .unwrap();
        assert_eq!(e.tasks().len(), 1);
        e.close_session(&s, json!({})).unwrap();
        assert!(e.tasks().is_empty(), "implicit task ends with its session");
    }

    const TAINT_POLICY: &str = r#"
version: 1
namespace: taint
data_flow:
  untrusted_sources: ["mcp:tickets"]
capabilities:
  - tool: "tickets.read"
  - tool: "tickets.locked"
    action: deny
  - tool: "stripe.refund"
    privileged: true
  - tool: "stripe.get_charge"
"#;

    #[test]
    fn reading_an_untrusted_source_taints_the_whole_task() {
        let (mut e, dir) = engine();
        let task = e
            .create_task(policy(TAINT_POLICY), Authority::default(), json!({}))
            .unwrap();
        let tickets = e.open_session(Some(&task), None, None, "tickets", json!({})).unwrap();
        let stripe = e.open_session(Some(&task), None, None, "stripe", json!({})).unwrap();

        assert_eq!(decide(&mut e, &stripe, "stripe.refund", json!({})), Outcome::Allow);
        // A denied call to the untrusted source doesn't taint: nothing was read.
        assert_eq!(decide(&mut e, &tickets, "tickets.locked", json!({})), Outcome::Deny);
        assert!(!e.tasks()[0].tainted);

        assert_eq!(decide(&mut e, &tickets, "tickets.read", json!({})), Outcome::Allow);
        assert_eq!(decide(&mut e, &tickets, "tickets.read", json!({})), Outcome::Allow);
        // The taint applies across sessions: the refund now needs a human.
        let d = e.decide(&stripe, &json!(9), "stripe.refund", &json!({})).unwrap();
        assert_eq!(d.outcome, Outcome::RequireSudo);
        assert!(d.reason.contains("mcp:tickets"), "{}", d.reason);
        assert_eq!(decide(&mut e, &stripe, "stripe.get_charge", json!({})), Outcome::Allow);

        let summary = &e.tasks()[0];
        assert!(summary.tainted);
        assert_eq!(summary.taint_sources, ["mcp:tickets"]);
        assert_eq!(summary.servers, ["mcp:tickets", "mcp:stripe"]);

        let log = writ_recorder::read_entries(dir.path().join("flight.jsonl")).unwrap();
        let taints: Vec<_> = log.iter().filter(|entry| entry.kind == "taint").collect();
        assert_eq!(taints.len(), 1, "tainted once");
        assert_eq!(taints[0].data["source"], "mcp:tickets");
        let refund = log
            .iter()
            .rfind(|entry| entry.kind == "tool_call" && entry.data["tool"] == "stripe.refund")
            .unwrap();
        assert_eq!(refund.data["facts"]["tainted"], json!(true));
        assert_eq!(refund.data["facts"]["session"]["name"], "mcp:stripe");
    }

    #[test]
    fn a_narrowing_policy_can_declare_more_untrusted_sources() {
        let (mut e, _dir) = engine();
        let task = e
            .create_task(policy(TAINT_POLICY), Authority::default(), json!({}))
            .unwrap();
        let narrow = "version: 1\nnamespace: n\ndata_flow:\n  untrusted_sources: [\"mcp:web\"]\ncapabilities:\n  - tool: \"*\"\n";
        let web = e
            .open_session(Some(&task), Some(policy(narrow)), None, "web", json!({}))
            .unwrap();
        // The task's policy has no rule for web.fetch, so it's denied: no taint.
        assert_eq!(decide(&mut e, &web, "web.fetch", json!({})), Outcome::Deny);
        assert!(!e.tasks()[0].tainted);
        assert_eq!(decide(&mut e, &web, "stripe.get_charge", json!({})), Outcome::Allow);
        assert_eq!(e.tasks()[0].taint_sources, ["mcp:web"]);
    }

    const REFUND_POLICY: &str = r#"
version: 1
namespace: refunds
entitlements:
  source: file
  path: entitlements.yaml
capabilities:
  - tool: "stripe.refund"
    lookup:
      charge: { table: charges, key: args.charge }
    entitlements: ["charge.customer in writ.root.entitled_customers"]
"#;

    const ENTITLEMENTS: &str = r#"
principals:
  alice: { entitled_customers: [cus_alice] }
tables:
  charges:
    ch_a: { customer: cus_alice }
    ch_b: { customer: cus_bob }
"#;

    fn alice() -> Authority {
        Authority {
            principal: Some("alice".into()),
            entitlements: Some(LoadedEntitlements::parse(ENTITLEMENTS).unwrap()),
        }
    }

    #[test]
    fn tasks_act_for_their_root_principal() {
        let (mut e, dir) = engine();
        let task = e.create_task(policy(REFUND_POLICY), alice(), json!({})).unwrap();
        let s = e.open_session(Some(&task), None, None, "stripe", json!({})).unwrap();
        assert_eq!(
            decide(&mut e, &s, "stripe.refund", json!({"charge": "ch_a"})),
            Outcome::Allow
        );
        let d = e
            .decide(&s, &json!(2), "stripe.refund", &json!({"charge": "ch_b"}))
            .unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("entitlement"), "{}", d.reason);
        assert_eq!(e.tasks()[0].principal.as_deref(), Some("alice"));

        // A principal the source doesn't know is entitled to nothing.
        let mallory = Authority {
            principal: Some("mallory".into()),
            ..alice()
        };
        let other = e.create_task(policy(REFUND_POLICY), mallory, json!({})).unwrap();
        let m = e.open_session(Some(&other), None, None, "stripe", json!({})).unwrap();
        assert_eq!(
            decide(&mut e, &m, "stripe.refund", json!({"charge": "ch_a"})),
            Outcome::Deny
        );

        let log = writ_recorder::read_entries(dir.path().join("flight.jsonl")).unwrap();
        let start = log.iter().find(|entry| entry.kind == "task_start").unwrap();
        assert_eq!(start.data["root"]["principal"], "alice");
        assert_eq!(start.data["root"]["verified"], json!(false));
        assert_eq!(start.data["root"]["entitled_customers"], json!(["cus_alice"]));
        assert_eq!(
            start.data["entitlements_sha256"],
            json!(writ_recorder::sha256_hex(ENTITLEMENTS.as_bytes()))
        );
    }

    #[test]
    fn entitlement_sources_must_match_the_policy() {
        let (mut e, _dir) = engine();
        // Declared but not loaded, and loaded but not declared.
        assert!(
            e.create_task(policy(REFUND_POLICY), Authority::default(), json!({}))
                .is_err()
        );
        assert!(e.create_task(policy(TASK_POLICY), alice(), json!({})).is_err());
        // A lookup of a table the source lacks fails when the task starts, not per call.
        let missing = REFUND_POLICY.replace("table: charges", "table: refunds");
        let err = e.create_task(policy(&missing), alice(), json!({})).unwrap_err();
        assert!(err.to_string().contains("`refunds`"), "{err}");

        // A narrowing policy can't bring its own source, but can use the task's.
        let task = e.create_task(policy(REFUND_POLICY), alice(), json!({})).unwrap();
        let own_source = e.open_session(Some(&task), Some(policy(REFUND_POLICY)), None, "s", json!({}));
        assert!(own_source.unwrap_err().to_string().contains("narrowing"));
        let narrow = "version: 1\nnamespace: n\ncapabilities:\n  - tool: \"stripe.refund\"\n    lookup:\n      charge: { table: charges, key: args.charge }\n    conditions: [\"charge.customer == \\\"cus_alice\\\"\"]\n";
        let s = e
            .open_session(Some(&task), Some(policy(narrow)), None, "s", json!({}))
            .unwrap();
        assert_eq!(
            decide(&mut e, &s, "stripe.refund", json!({"charge": "ch_a"})),
            Outcome::Allow
        );
    }

    const SUDO_POLICY: &str = r#"
version: 1
namespace: sudo
limits:
  max_tool_calls: 2
approvals:
  timeout: 50ms
capabilities:
  - tool: "stripe.refund"
    redact: ["args.card"]
    conditions: ["args.amount <= 100"]
    on_violation: require_sudo
  - tool: "db.query"
"#;

    fn sudo_engine() -> (Engine, tempfile::TempDir, String, String) {
        let (mut e, dir) = engine();
        e.enable_approvals();
        let task = e
            .create_task(policy(SUDO_POLICY), Authority::default(), json!({}))
            .unwrap();
        let s = e.open_session(Some(&task), None, None, "stripe", json!({})).unwrap();
        (e, dir, task, s)
    }

    fn pause(e: &mut Engine, s: &str, call: u64) -> String {
        let d = e
            .decide(
                s,
                &json!(call),
                "stripe.refund",
                &json!({"amount": 240, "card": "4242"}),
            )
            .unwrap();
        assert_eq!(d.outcome, Outcome::RequireSudo);
        d.approval.expect("paused for approval")
    }

    #[test]
    fn approvals_pause_then_settle() {
        let (mut e, dir, _task, s) = sudo_engine();
        let id = pause(&mut e, &s, 1);
        let pending = e.approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].server, "mcp:stripe");
        assert_eq!(pending[0].arguments.as_ref().unwrap()["card"], writ_policy::REDACTED);
        assert!(e.take_resolution(&id).is_none(), "still pending");
        assert_eq!(
            e.tasks()[0].counters,
            Counters::default(),
            "pending calls aren't counted"
        );

        let d = e
            .resolve_approval(&id, Resolution::Approve, json!({"user": "bob"}))
            .unwrap();
        assert_eq!(d.outcome, Outcome::Allow);
        assert!(d.reason.contains("approved by approver bob"), "{}", d.reason);
        assert!(e.approvals().is_empty());
        assert!(
            e.resolve_approval(&id, Resolution::Deny, json!({})).is_err(),
            "decided once"
        );
        assert_eq!(e.take_resolution(&id).unwrap().outcome, Outcome::Allow);
        assert!(e.take_resolution(&id).is_none(), "collected once");
        assert_eq!(e.tasks()[0].counters.calls_allowed, 1);

        let id = pause(&mut e, &s, 2);
        let d = e
            .resolve_approval(&id, Resolution::Deny, json!({"user": "bob"}))
            .unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("approver bob denied this call"), "{}", d.reason);
        assert!(!d.reason.contains("(an approver)"), "{}", d.reason);

        let log = writ_recorder::read_entries(dir.path().join("flight.jsonl")).unwrap();
        let settled: Vec<&str> = log
            .iter()
            .filter(|entry| entry.kind == "approval")
            .map(|entry| entry.data["decision"].as_str().unwrap())
            .collect();
        assert_eq!(settled, ["approve", "deny"]);
        assert!(
            !std::fs::read_to_string(dir.path().join("flight.jsonl"))
                .unwrap()
                .contains("4242")
        );
    }

    #[test]
    fn approved_calls_are_rechecked() {
        let (mut e, _dir, task, s) = sudo_engine();
        let a = pause(&mut e, &s, 1);
        let b = pause(&mut e, &s, 2);
        // Meanwhile two allowed calls reach max_tool_calls (2).
        assert_eq!(decide(&mut e, &s, "db.query", json!({})), Outcome::Allow);
        assert_eq!(decide(&mut e, &s, "db.query", json!({})), Outcome::Allow);
        let d = e.resolve_approval(&a, Resolution::Approve, json!({})).unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("max_tool_calls"), "{}", d.reason);

        e.end_task(&task, "test").unwrap();
        // Ending the task settled the other one: denied, nothing left pending.
        assert!(e.approvals().is_empty());
        let d = e.take_resolution(&b).unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("task ended"), "{}", d.reason);
    }

    #[test]
    fn approvals_time_out_and_close_with_their_session() {
        let (mut e, _dir, task, s) = sudo_engine();
        let id = pause(&mut e, &s, 1);
        e.expire_approval(&id).unwrap();
        assert!(e.take_resolution(&id).is_none(), "not yet due");
        std::thread::sleep(Duration::from_millis(60));
        e.expire_approval(&id).unwrap();
        let d = e.take_resolution(&id).unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("no approver decided within"), "{}", d.reason);

        let other = e.open_session(Some(&task), None, None, "stripe2", json!({})).unwrap();
        let id = pause(&mut e, &other, 2);
        e.close_session(&other, json!({})).unwrap();
        assert!(e.approval_deadline(&id).is_none() && e.take_resolution(&id).is_none());
        assert!(e.resolve_approval(&id, Resolution::Approve, json!({})).is_err());
    }

    #[test]
    fn without_writd_or_an_approvals_block_nothing_pauses() {
        // A standalone engine (no enable_approvals) has nobody to ask.
        let (mut e, _dir) = engine();
        let task = e
            .create_task(policy(SUDO_POLICY), Authority::default(), json!({}))
            .unwrap();
        let s = e.open_session(Some(&task), None, None, "stripe", json!({})).unwrap();
        let d = e
            .decide(&s, &json!(1), "stripe.refund", &json!({"amount": 240}))
            .unwrap();
        assert_eq!((d.outcome, d.approval), (Outcome::RequireSudo, None));

        // writd, but the policy has no approvals block: refused as before.
        let (mut e, _dir) = engine();
        e.enable_approvals();
        let no_block = SUDO_POLICY.replace("approvals:\n  timeout: 50ms\n", "");
        let task = e
            .create_task(policy(&no_block), Authority::default(), json!({}))
            .unwrap();
        let s = e.open_session(Some(&task), None, None, "stripe", json!({})).unwrap();
        let d = e
            .decide(&s, &json!(1), "stripe.refund", &json!({"amount": 240}))
            .unwrap();
        assert_eq!((d.outcome, d.approval), (Outcome::RequireSudo, None));
        assert_eq!(e.tasks()[0].counters.calls_denied, 1);
    }

    #[test]
    fn rejects_bad_server_names() {
        let (mut e, _dir) = engine();
        let task = e
            .create_task(policy(TASK_POLICY), Authority::default(), json!({}))
            .unwrap();
        assert!(e.open_session(Some(&task), None, None, "bad name", json!({})).is_err());
        assert!(e.open_session(Some(&task), None, None, "", json!({})).is_err());
    }

    #[test]
    fn decisions_record_the_facts_they_saw() {
        let (mut e, dir) = engine();
        let task = e
            .create_task(policy(TASK_POLICY), Authority::default(), json!({}))
            .unwrap();
        let s = e.open_session(Some(&task), None, None, "srv", json!({})).unwrap();
        decide(&mut e, &s, "db.query", json!({}));

        let log = writ_recorder::read_entries(dir.path().join("flight.jsonl")).unwrap();
        let call = log.iter().find(|entry| entry.kind == "tool_call").unwrap();
        assert_eq!(call.data["facts"]["tainted"], json!(false), "{}", call.data);
        assert_eq!(call.data["facts"]["taint_sources"], json!([]));
        assert!(call.data["facts"].get("root").is_none(), "no root principal yet");
    }

    #[test]
    fn redaction_from_both_policies_applies() {
        let (mut e, dir) = engine();
        let task = e
            .create_task(policy(TASK_POLICY), Authority::default(), json!({}))
            .unwrap();
        let s = e
            .open_session(Some(&task), Some(policy(SESSION_POLICY)), None, "srv", json!({}))
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
