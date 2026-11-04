//! What a decision can see besides the call itself.
//!
//! A policy decides a call from three things: the tool name, its arguments
//! (`args.*`), and **facts** about the task and session making it (`writ.*`).
//! Facts are computed by writd, never supplied by the agent or the server.
//!
//! [`Facts`] is a plain serializable struct on purpose: it is recorded with
//! every decision (so `writ log` and a later `writ replay` can see why a call
//! was decided the way it was), and it is the shape a future export to Cedar,
//! OPA, or AgentCore would carry (plan-v2.md D8).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::EntitlementSource;

/// The root of a task's authority: who the task acts for.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Root {
    /// The principal the task acts for, e.g. `alice@example.com`.
    pub principal: String,
    /// False until roots are minted from an identity proof (plan-v2.md §4.1).
    pub verified: bool,
    /// Entitlement attributes from the entitlement source (`writ.root.<name>`).
    #[serde(flatten)]
    pub attributes: Map<String, Value>,
}

/// Facts about the task and session a call belongs to, visible to
/// conditions as `writ.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Facts {
    /// `writ.root.*`. Absent when the task has no root principal, in which
    /// case every condition that reads it fails (fail closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<Root>,
    /// `writ.tainted`: the task has read from a declared untrusted source.
    #[serde(default)]
    pub tainted: bool,
    /// `writ.taint_sources`: which untrusted sources, in order first read.
    #[serde(default)]
    pub taint_sources: Vec<String>,
    /// `writ.session.*`: the wrapped server this call goes to.
    #[serde(default)]
    pub session: SessionFacts,
    /// `writ.workspace`: the directory the task works in (an absolute path),
    /// when the task has one: a Claude Code project, say. Absent otherwise,
    /// so `args.path within writ.workspace` fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionFacts {
    /// `writ.session.name`, e.g. `mcp:zendesk-tickets`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The source id of a wrapped MCP server named `name`: `mcp:<name>`. This is
/// what `writ.session.name` holds and what `data_flow.untrusted_sources`
/// lists.
pub fn session_source(name: &str) -> String {
    format!("mcp:{name}")
}

/// Checks a server name given to `writ wrap --name`: 1–64 characters from
/// `[A-Za-z0-9_.-]`.
pub fn validate_session_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid server name `{name}`: use 1-64 characters from A-Z, a-z, 0-9, `_`, `-`, `.`"
        ))
    }
}

/// The top-level `writ.*` fields a condition may read. Anything else is a
/// policy error at load time, so a typo can't silently fail every call.
pub(crate) const FACT_FIELDS: &[&str] = &["root", "tainted", "taint_sources", "session", "workspace"];

/// Everything one decision is made from.
#[derive(Debug, Clone, Copy)]
pub struct DecisionContext<'a> {
    pub tool: &'a str,
    pub args: &'a Value,
    pub facts: &'a Facts,
    /// Answers rules' `lookup:`s. Without one, every lookup finds nothing,
    /// so conditions that read a lookup fail closed.
    pub source: Option<&'a dyn EntitlementSource>,
}

impl<'a> DecisionContext<'a> {
    pub fn new(tool: &'a str, args: &'a Value, facts: &'a Facts) -> Self {
        DecisionContext {
            tool,
            args,
            facts,
            source: None,
        }
    }

    pub fn with_source(self, source: Option<&'a dyn EntitlementSource>) -> Self {
        DecisionContext { source, ..self }
    }
}

/// The values conditions resolve paths against: `args`, `writ`, and the
/// names a rule's `lookup:` bound.
#[derive(Clone)]
pub(crate) struct Scope<'a> {
    args: &'a Value,
    writ: Value,
    bindings: Map<String, Value>,
}

impl<'a> Scope<'a> {
    pub(crate) fn new(ctx: &DecisionContext<'a>) -> Self {
        Scope {
            args: ctx.args,
            writ: serde_json::to_value(ctx.facts).expect("facts serialize"),
            bindings: Map::new(),
        }
    }

    /// This scope plus `name` bound to `value`.
    pub(crate) fn bind(&mut self, name: &str, value: Value) {
        self.bindings.insert(name.to_string(), value);
    }

    /// Resolves a path whose first segment is `args`, `writ`, or a bound name.
    pub(crate) fn get(&self, path: &[String]) -> Option<&Value> {
        let (first, rest) = path.split_first()?;
        let mut current = match first.as_str() {
            "args" => self.args,
            "writ" => &self.writ,
            name => self.bindings.get(name)?,
        };
        for segment in rest {
            current = match current {
                Value::Object(map) => map.get(segment),
                Value::Array(items) => segment.parse::<usize>().ok().and_then(|i| items.get(i)),
                _ => None,
            }?;
        }
        Some(current)
    }
}
