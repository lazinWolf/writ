//! Parser and evaluator for `writ.yaml`.
//!
//! This build implements a subset of the spec in `plan-v2.md` §7.1: tool
//! rules with conditions over the call's arguments (`args.*`) and the task's
//! facts (`writ.*`, see [`Facts`]), entitlements checked against an
//! entitlement source (see [`entitlements`]), coarse taint, and the
//! `max_tool_calls` limit. Fields the
//! spec defines but this build does not enforce are rejected at load time, so
//! a policy never appears to grant a guarantee it does not have.
//!
//! Rule precedence follows D9: every matching rule is evaluated and the most
//! restrictive outcome wins. A rule whose pattern is exactly `*` applies only
//! to tools no other rule matches, and a tool no rule matches is denied.

mod condition;
mod context;
pub mod entitlements;
mod glob;
mod redact;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use condition::Condition;
use context::Scope;
pub use context::{DecisionContext, Facts, Root, SessionFacts, session_source, validate_session_name};
pub use entitlements::{EntitlementSource, FileSource};
pub use redact::MARKER as REDACTED;
use redact::RedactPath;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read policy {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("invalid writ.yaml: {0}")]
    Yaml(#[from] serde_norway::Error),
    #[error("invalid writ.yaml: {0}")]
    Invalid(String),
}

/// Spec fields that are part of writ.yaml but not enforced by this build.
const UNIMPLEMENTED_TOP_LEVEL: &[&str] = &[];
const UNIMPLEMENTED_DATA_FLOW: &[&str] = &["secrets", "pii_fields", "declassify"];
const UNIMPLEMENTED_ON_TAINT: &[&str] = &["other_mutations", "egress_to_untrusted_sinks"];
const UNIMPLEMENTED_LIMITS: &[&str] = &["max_depth", "max_parallel_agents", "max_budget_usd", "loop_breaker"];
const UNIMPLEMENTED_RULE: &[&str] = &[
    "idempotency",
    "preconditions",
    "classify",
    "deny_statements",
    "allow_functions",
    "pin_tenant_from_writ",
    "mutations",
    "sudo_approvers",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    #[default]
    Cooperative,
    Mediated,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Violation {
    #[default]
    Deny,
    RequireSudo,
}

/// Outcomes ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    RequireSudo,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: Outcome,
    /// Pattern of the rule that produced the outcome; `None` for deny-by-default.
    pub rule: Option<String>,
    pub reason: String,
    /// For `require_sudo` under writd with approvals on: the pending
    /// approval the call waits for (`writ sudo approve <id>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

impl Decision {
    pub fn new(outcome: Outcome, rule: Option<String>, reason: String) -> Self {
        Decision {
            outcome,
            rule,
            reason,
            approval: None,
        }
    }
}

/// The policy's `approvals:` block: `require_sudo` calls pause for a human
/// instead of being refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approvals {
    /// How long a paused call waits before it is denied.
    pub timeout: Duration,
}

/// The default `approvals.timeout`.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Default)]
pub struct Limits {
    pub max_tool_calls: Option<u64>,
}

#[derive(Debug, Clone)]
struct Lookup {
    name: String,
    table: String,
    key: Vec<String>,
}

#[derive(Debug, Clone)]
struct Rule {
    pattern: String,
    action: Action,
    /// Bound before any condition is checked, in name order.
    lookups: Vec<Lookup>,
    /// Bounds from the root principal's authority. When they all hold, the
    /// call is *covered*: taint doesn't add an approval requirement.
    entitlements: Vec<Condition>,
    on_entitlement_violation: Violation,
    conditions: Vec<Condition>,
    on_violation: Violation,
    redact: Vec<RedactPath>,
    record_arguments: bool,
    /// Guarded on tainted tasks (`data_flow.on_taint.privileged_mutations`).
    privileged: bool,
}

/// How a call's arguments may appear in the flight recorder, merged across
/// every rule that applies to the tool (most protective wins).
struct Recording<'a> {
    omit_all: bool,
    redact: Vec<&'a RedactPath>,
}

impl Recording<'_> {
    fn hides(&self, path: &[String]) -> bool {
        self.omit_all || self.redact.iter().any(|r| r.covers(path))
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub namespace: String,
    pub enforcement: Enforcement,
    pub limits: Limits,
    /// Sources whose content may be attacker-written (`mcp:<name>`). An
    /// allowed call to one taints its task.
    pub untrusted_sources: Vec<String>,
    /// What a privileged tool gets on a tainted task.
    on_taint_privileged: Outcome,
    /// Where `writ.root.*` and lookups come from, if anywhere.
    pub entitlements: Option<EntitlementsSpec>,
    /// Present when `require_sudo` calls should wait for a human.
    pub approvals: Option<Approvals>,
    rules: Vec<Rule>,
    fallback: Option<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    namespace: String,
    #[serde(default)]
    enforcement: Enforcement,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    data_flow: RawDataFlow,
    #[serde(default)]
    entitlements: Option<EntitlementsSpec>,
    #[serde(default)]
    approvals: Option<RawApprovals>,
    #[serde(default)]
    capabilities: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApprovals {
    /// A duration such as `15m` or `90s`.
    timeout: Option<String>,
}

/// The policy's `entitlements:` block.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementsSpec {
    pub source: SourceKind,
    /// For `source: file`: the file, relative to the policy file.
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    File,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLookup {
    table: String,
    key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawDataFlow {
    #[serde(default)]
    untrusted_sources: Vec<String>,
    #[serde(default)]
    on_taint: RawOnTaint,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawOnTaint {
    #[serde(default)]
    privileged_mutations: TaintAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TaintAction {
    #[default]
    RequireSudo,
    Deny,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_tool_calls: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    tool: String,
    #[serde(default)]
    action: Action,
    #[serde(default)]
    lookup: BTreeMap<String, RawLookup>,
    #[serde(default)]
    entitlements: Vec<String>,
    #[serde(default)]
    on_entitlement_violation: Option<Violation>,
    #[serde(default)]
    conditions: Vec<String>,
    #[serde(default)]
    on_violation: Violation,
    #[serde(default)]
    redact: Vec<String>,
    #[serde(default = "default_true")]
    record_arguments: bool,
    #[serde(default)]
    privileged: bool,
}

fn default_true() -> bool {
    true
}

impl Policy {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml_str(&text)
    }

    pub fn from_yaml_str(text: &str) -> Result<Self, PolicyError> {
        reject_unimplemented(&serde_norway::from_str(text)?)?;
        let raw: RawPolicy = serde_norway::from_str(text)?;

        if raw.version != 1 {
            return Err(invalid(format!("unsupported version {} (expected 1)", raw.version)));
        }
        if raw.enforcement != Enforcement::Cooperative {
            return Err(invalid(format!(
                "enforcement mode `{:?}` is not available in this build; use `cooperative`",
                raw.enforcement
            )));
        }

        for source in &raw.data_flow.untrusted_sources {
            let name = source.strip_prefix("mcp:").ok_or_else(|| {
                invalid(format!(
                    "untrusted source `{source}`: only MCP servers (`mcp:<name>`) are supported in this build"
                ))
            })?;
            validate_session_name(name).map_err(|e| invalid(format!("untrusted source `{source}`: {e}")))?;
        }

        let mut rules = Vec::new();
        let mut fallback = None;
        for raw_rule in raw.capabilities {
            let rule = Rule::from_raw(raw_rule)?;
            if rule.pattern == "*" {
                if fallback.replace(rule).is_some() {
                    return Err(invalid("more than one `tool: \"*\"` rule".to_string()));
                }
            } else {
                rules.push(rule);
            }
        }

        Ok(Policy {
            namespace: raw.namespace,
            enforcement: raw.enforcement,
            untrusted_sources: raw.data_flow.untrusted_sources,
            on_taint_privileged: match raw.data_flow.on_taint.privileged_mutations {
                TaintAction::RequireSudo => Outcome::RequireSudo,
                TaintAction::Deny => Outcome::Deny,
            },
            entitlements: raw.entitlements,
            approvals: raw
                .approvals
                .map(|a| -> Result<Approvals, PolicyError> {
                    let timeout = match a.timeout {
                        None => DEFAULT_APPROVAL_TIMEOUT,
                        Some(t) => humantime::parse_duration(&t)
                            .map_err(|e| invalid(format!("approvals.timeout `{t}`: {e}")))?,
                    };
                    if timeout.is_zero() {
                        return Err(invalid("approvals.timeout must be more than zero".to_string()));
                    }
                    Ok(Approvals { timeout })
                })
                .transpose()?,
            limits: Limits {
                max_tool_calls: raw.limits.max_tool_calls,
            },
            rules,
            fallback,
        })
    }

    /// Decides a single `tools/call`.
    pub fn evaluate(&self, ctx: &DecisionContext) -> Decision {
        let tool = ctx.tool;
        let candidates = self.candidates(tool);
        if candidates.is_empty() {
            return Decision::new(
                Outcome::Deny,
                None,
                format!("no rule matches tool `{tool}` (deny by default)"),
            );
        }

        let recording = Self::recording(&candidates);
        let scope = Scope::new(ctx);
        let decided: Vec<(Decision, bool)> = candidates
            .iter()
            .map(|rule| rule.decide(&scope, ctx.source, &recording))
            .collect();
        // Keep the first of the most restrictive, so the reported rule is the earliest one.
        let best = decided
            .iter()
            .map(|(d, _)| d)
            .fold(&decided[0].0, |best, d| if d.outcome > best.outcome { d } else { best })
            .clone();

        // A privileged tool on a tainted task: the task has read content that
        // may be attacker-written, so its arguments may be attacker-steered.
        // A rule whose entitlements all held covers the call: it is within the
        // root principal's own authority, so taint adds no approval.
        let uncovered = candidates
            .iter()
            .zip(&decided)
            .find(|(rule, (_, covered))| rule.privileged && !covered)
            .map(|(rule, _)| rule);
        match uncovered {
            Some(rule) if ctx.facts.tainted && self.on_taint_privileged > best.outcome => Decision::new(
                self.on_taint_privileged,
                Some(rule.pattern.clone()),
                format!(
                    "`{tool}` is privileged and the task is tainted (it read from {})",
                    ctx.facts.taint_sources.join(", ")
                ),
            ),
            _ => best,
        }
    }

    /// The tables this policy's lookups read, so a task can check its source
    /// has them before it starts.
    pub fn lookup_tables(&self) -> Vec<&str> {
        let mut tables: Vec<&str> = self
            .rules
            .iter()
            .chain(&self.fallback)
            .flat_map(|r| r.lookups.iter().map(|l| l.table.as_str()))
            .collect();
        tables.sort_unstable();
        tables.dedup();
        tables
    }

    /// True when content from `source` (`mcp:<name>`) may be attacker-written.
    pub fn is_untrusted(&self, source: &str) -> bool {
        self.untrusted_sources.iter().any(|s| s == source)
    }

    /// The arguments as they may be written to the flight recorder: `None`
    /// when any applicable rule sets `record_arguments: false`, otherwise a
    /// copy with every applicable `redact` path replaced by a marker.
    pub fn arguments_for_log(&self, tool: &str, args: &Value) -> Option<Value> {
        let recording = Self::recording(&self.candidates(tool));
        if recording.omit_all {
            return None;
        }
        let mut args = args.clone();
        for path in recording.redact {
            path.apply(&mut args);
        }
        Some(args)
    }

    fn recording<'a>(candidates: &[&'a Rule]) -> Recording<'a> {
        Recording {
            omit_all: candidates.iter().any(|r| !r.record_arguments),
            redact: candidates.iter().flat_map(|r| &r.redact).collect(),
        }
    }

    /// True when the tool is denied whatever its arguments are. Used to hide
    /// tools from `tools/list`; this is a usability aid, not the enforcement
    /// point (D6). Enforcement happens in [`Policy::evaluate`] on every call.
    pub fn always_denies(&self, tool: &str) -> bool {
        let candidates = self.candidates(tool);
        candidates.is_empty() || candidates.iter().any(|rule| rule.action == Action::Deny)
    }

    fn candidates(&self, tool: &str) -> Vec<&Rule> {
        let matching: Vec<&Rule> = self.rules.iter().filter(|r| glob::matches(&r.pattern, tool)).collect();
        if matching.is_empty() {
            self.fallback.iter().collect()
        } else {
            matching
        }
    }
}

impl Rule {
    fn from_raw(raw: RawRule) -> Result<Self, PolicyError> {
        if raw.tool.trim().is_empty() {
            return Err(invalid("a capability rule has an empty `tool` pattern".to_string()));
        }
        let tool = &raw.tool;
        if raw.action == Action::Deny
            && (!raw.conditions.is_empty() || !raw.entitlements.is_empty() || !raw.lookup.is_empty())
        {
            return Err(invalid(format!(
                "rule `{tool}`: conditions, entitlements, and lookups on a deny rule have no effect; remove them"
            )));
        }
        if raw.entitlements.is_empty() && raw.on_entitlement_violation.is_some() {
            return Err(invalid(format!(
                "rule `{tool}`: `on_entitlement_violation` without `entitlements` has no effect"
            )));
        }
        let mut lookups = Vec::new();
        for (name, l) in &raw.lookup {
            let valid_name = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && name.starts_with(|c: char| c.is_ascii_alphabetic());
            if !valid_name || name == "args" || name == "writ" {
                return Err(invalid(format!(
                    "rule `{tool}`: lookup name `{name}` must be a plain identifier other than `args` or `writ`"
                )));
            }
            let key = condition::parse_key_path(&l.key)
                .map_err(|e| invalid(format!("rule `{tool}`: lookup `{name}`: {e}")))?;
            lookups.push(Lookup {
                name: name.clone(),
                table: l.table.clone(),
                key,
            });
        }
        let bindings: Vec<String> = raw.lookup.keys().cloned().collect();
        let parse_all = |list: &[String], what: &str| -> Result<Vec<Condition>, PolicyError> {
            list.iter()
                .map(|c| {
                    Condition::parse_with(c, &bindings)
                        .map_err(|e| invalid(format!("rule `{tool}`: {what} `{c}`: {e}")))
                })
                .collect()
        };
        let entitlements = parse_all(&raw.entitlements, "entitlement")?;
        let conditions = parse_all(&raw.conditions, "condition")?;
        let redact = raw
            .redact
            .iter()
            .map(|r| RedactPath::parse(r).map_err(|e| invalid(format!("rule `{}`: {e}", raw.tool))))
            .collect::<Result<_, _>>()?;
        Ok(Rule {
            pattern: raw.tool,
            action: raw.action,
            lookups,
            entitlements,
            on_entitlement_violation: raw.on_entitlement_violation.unwrap_or_default(),
            conditions,
            on_violation: raw.on_violation,
            redact,
            record_arguments: raw.record_arguments,
            privileged: raw.privileged,
        })
    }

    /// Decides the call under this rule alone. The flag is true when the rule
    /// has entitlements and they all held (the call is *covered*).
    fn decide(&self, base: &Scope, source: Option<&dyn EntitlementSource>, recording: &Recording) -> (Decision, bool) {
        let rule = Some(self.pattern.clone());
        if self.action == Action::Deny {
            let reason = format!("denied by rule `{}`", self.pattern);
            return (Decision::new(Outcome::Deny, rule, reason), false);
        }

        // Bind lookups. A miss leaves the name unbound, so every condition
        // reading it fails closed; the miss is explained in the reason.
        let mut scope = base.clone();
        let mut misses = Vec::new();
        for lookup in &self.lookups {
            let key_path = lookup.key.join(".");
            let key_hidden = lookup.key[0] == "args" && recording.hides(&lookup.key[1..]);
            let key = base.get(&lookup.key).and_then(|k| match k {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });
            let found = match (&key, source) {
                (Some(key), Some(source)) => source.lookup(&lookup.table, key),
                _ => None,
            };
            match found {
                Some(value) => scope.bind(&lookup.name, value),
                None => misses.push(match (&key, source, key_hidden) {
                    (_, None, _) => format!("`{}`: no entitlement source", lookup.name),
                    (None, _, _) => format!("`{}`: {key_path} is missing or not a string", lookup.name),
                    (Some(_), _, true) => format!("`{}`: no `{}` entry for {key_path}", lookup.name, lookup.table),
                    (Some(key), _, false) => {
                        format!(
                            "`{}`: no `{}` entry for {key_path} = {key:?}",
                            lookup.name, lookup.table
                        )
                    }
                }),
            }
        }
        let explain = |condition: &Condition, reason: String| {
            // Decision reasons are recorded, so they must not echo a redacted value.
            let mut reason = if condition.arg_paths().any(|p| recording.hides(p)) {
                format!("`{condition}` failed (value redacted)")
            } else {
                reason
            };
            if !misses.is_empty() {
                reason.push_str(&format!(" (lookup {})", misses.join("; ")));
            }
            reason
        };
        let outcome_of = |violation: Violation| match violation {
            Violation::Deny => Outcome::Deny,
            Violation::RequireSudo => Outcome::RequireSudo,
        };

        for entitlement in &self.entitlements {
            if let Err(reason) = entitlement.check(&scope) {
                let reason = format!("outside the root's entitlement: {}", explain(entitlement, reason));
                let outcome = outcome_of(self.on_entitlement_violation);
                return (Decision::new(outcome, rule, reason), false);
            }
        }
        let covered = !self.entitlements.is_empty();
        for condition in &self.conditions {
            if let Err(reason) = condition.check(&scope) {
                let mut reason = explain(condition, reason);
                if covered {
                    // Tell whoever reviews it that the call is the root's own business.
                    reason.push_str(" (within the root's entitlement)");
                }
                let outcome = outcome_of(self.on_violation);
                return (Decision::new(outcome, rule, reason), covered);
            }
        }
        let reason = if covered {
            format!("allowed by rule `{}` (within the root's entitlement)", self.pattern)
        } else {
            format!("allowed by rule `{}`", self.pattern)
        };
        (Decision::new(Outcome::Allow, rule, reason), covered)
    }
}

fn invalid(message: String) -> PolicyError {
    PolicyError::Invalid(message)
}

fn reject_unimplemented(doc: &serde_norway::Value) -> Result<(), PolicyError> {
    let not_enforced = |field: &str| {
        invalid(format!(
            "`{field}` is part of the writ.yaml spec but is not enforced by this build; \
             remove it rather than rely on it"
        ))
    };
    let has = |value: &serde_norway::Value, key: &str| value.get(key).is_some();

    for key in UNIMPLEMENTED_TOP_LEVEL {
        if has(doc, key) {
            return Err(not_enforced(key));
        }
    }
    if let Some(data_flow) = doc.get("data_flow") {
        for key in UNIMPLEMENTED_DATA_FLOW {
            if has(data_flow, key) {
                return Err(not_enforced(&format!("data_flow.{key}")));
            }
        }
        if let Some(on_taint) = data_flow.get("on_taint") {
            for key in UNIMPLEMENTED_ON_TAINT {
                if has(on_taint, key) {
                    return Err(not_enforced(&format!("data_flow.on_taint.{key}")));
                }
            }
        }
    }
    if let Some(limits) = doc.get("limits") {
        for key in UNIMPLEMENTED_LIMITS {
            if has(limits, key) {
                return Err(not_enforced(&format!("limits.{key}")));
            }
        }
    }
    if let Some(serde_norway::Value::Sequence(rules)) = doc.get("capabilities") {
        for rule in rules {
            for key in UNIMPLEMENTED_RULE {
                if has(rule, key) {
                    return Err(not_enforced(&format!("capabilities[].{key}")));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    impl Policy {
        /// Evaluates with no task facts, as for a task with no root and no taint.
        fn eval(&self, tool: &str, args: &Value) -> Decision {
            self.evaluate(&DecisionContext::new(tool, args, &Facts::default()))
        }
    }

    const POLICY: &str = r#"
version: 1
namespace: test
limits:
  max_tool_calls: 3
capabilities:
  - tool: "postgres.*"
  - tool: "postgres.drop_table"
    action: deny
  - tool: "stripe.refund"
    conditions:
      - "args.amount <= 100.00"
    on_violation: require_sudo
  - tool: "*"
    action: deny
"#;

    fn policy() -> Policy {
        Policy::from_yaml_str(POLICY).unwrap()
    }

    #[test]
    fn allows_matching_rule() {
        let d = policy().eval("postgres.query", &json!({}));
        assert_eq!(d.outcome, Outcome::Allow);
        assert_eq!(d.rule.as_deref(), Some("postgres.*"));
    }

    #[test]
    fn most_restrictive_matching_rule_wins() {
        let d = policy().eval("postgres.drop_table", &json!({}));
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(d.rule.as_deref(), Some("postgres.drop_table"));
    }

    #[test]
    fn fallback_applies_only_when_nothing_else_matches() {
        assert_eq!(policy().eval("shell.exec", &json!({})).outcome, Outcome::Deny);
        assert_eq!(
            policy().eval("stripe.refund", &json!({"amount": 5})).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn condition_violation_requires_sudo() {
        let d = policy().eval("stripe.refund", &json!({"amount": 240}));
        assert_eq!(d.outcome, Outcome::RequireSudo);
        assert!(d.reason.contains("args.amount = 240"), "{}", d.reason);
    }

    #[test]
    fn deny_by_default_without_fallback() {
        let p = Policy::from_yaml_str("version: 1\nnamespace: t\ncapabilities:\n  - tool: a\n").unwrap();
        let d = p.eval("b", &json!({}));
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(d.rule, None);
        assert!(p.always_denies("b"));
        assert!(!p.always_denies("a"));
    }

    #[test]
    fn always_denies_ignores_conditional_rules() {
        let p = policy();
        assert!(p.always_denies("postgres.drop_table"));
        assert!(p.always_denies("shell.exec"));
        assert!(!p.always_denies("stripe.refund"));
    }

    #[test]
    fn rejects_unimplemented_fields() {
        let cases = [
            (
                "version: 1\nnamespace: t\ndata_flow:\n  declassify: []\n",
                "data_flow.declassify",
            ),
            (
                "version: 1\nnamespace: t\ndata_flow:\n  on_taint:\n    other_mutations: allow_within_limits\n",
                "data_flow.on_taint.other_mutations",
            ),
            (
                "version: 1\nnamespace: t\nlimits:\n  loop_breaker: strict\n",
                "limits.loop_breaker",
            ),
            (
                "version: 1\nnamespace: t\nlimits:\n  max_depth: 4\n",
                "limits.max_depth",
            ),
            (
                "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    preconditions: []\n",
                "preconditions",
            ),
        ];
        for (yaml, field) in cases {
            let err = Policy::from_yaml_str(yaml).unwrap_err().to_string();
            assert!(err.contains(field) && err.contains("not enforced"), "{err}");
        }
    }

    const REDACTING: &str = r#"
version: 1
namespace: t
capabilities:
  - tool: "stripe.*"
    redact: ["args.card"]
  - tool: "stripe.charge"
    conditions: ["args.card.number == \"4242\""]
  - tool: "vault.read"
    record_arguments: false
    conditions: ["args.path == \"ok\""]
  - tool: "*"
    redact: ["args.*.password"]
"#;

    #[test]
    fn redaction_merges_across_matching_rules() {
        let p = Policy::from_yaml_str(REDACTING).unwrap();
        let args = json!({"card": {"number": "1111"}, "amount": 5});
        assert_eq!(
            p.arguments_for_log("stripe.charge", &args),
            Some(json!({"card": REDACTED, "amount": 5}))
        );
        assert_eq!(p.arguments_for_log("vault.read", &json!({"path": "x"})), None);
        // The fallback applies only when no other rule matches.
        assert_eq!(
            p.arguments_for_log("db.login", &json!({"creds": {"password": "hunter2", "user": "a"}})),
            Some(json!({"creds": {"password": REDACTED, "user": "a"}}))
        );
        assert_eq!(
            p.arguments_for_log("stripe.list", &json!({"x": {"password": 1}})),
            Some(json!({"x": {"password": 1}}))
        );
    }

    #[test]
    fn decision_reasons_do_not_echo_redacted_values() {
        let p = Policy::from_yaml_str(REDACTING).unwrap();
        let d = p.eval("stripe.charge", &json!({"card": {"number": "1111"}}));
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(
            !d.reason.contains("1111") && d.reason.contains("redacted"),
            "{}",
            d.reason
        );

        let d = p.eval("vault.read", &json!({"path": "/secret/prod"}));
        assert!(!d.reason.contains("/secret/prod"), "{}", d.reason);
    }

    #[test]
    fn conditions_see_task_facts() {
        let p = Policy::from_yaml_str(
            r#"
version: 1
namespace: t
capabilities:
  - tool: "stripe.refund"
    conditions:
      - "writ.tainted == false"
      - "args.customer in writ.root.entitled_customers"
    on_violation: require_sudo
"#,
        )
        .unwrap();
        let args = json!({"customer": "cus_alice"});
        let mut facts = Facts {
            root: Some(Root {
                principal: "alice".into(),
                verified: false,
                attributes: [("entitled_customers".to_string(), json!(["cus_alice"]))]
                    .into_iter()
                    .collect(),
            }),
            ..Facts::default()
        };
        let decide = |facts: &Facts, args: &Value| p.evaluate(&DecisionContext::new("stripe.refund", args, facts));

        assert_eq!(decide(&facts, &args).outcome, Outcome::Allow);
        assert_eq!(
            decide(&facts, &json!({"customer": "cus_bob"})).outcome,
            Outcome::RequireSudo
        );
        facts.tainted = true;
        let d = decide(&facts, &args);
        assert_eq!(d.outcome, Outcome::RequireSudo);
        assert!(d.reason.contains("writ.tainted = true"), "{}", d.reason);
        // Without a root, conditions on it fail closed.
        assert_eq!(decide(&Facts::default(), &args).outcome, Outcome::RequireSudo);
    }

    #[test]
    fn redacted_values_stay_out_of_reasons_on_either_side() {
        let p = Policy::from_yaml_str(
            r#"
version: 1
namespace: t
capabilities:
  - tool: "x"
    redact: ["args.secret"]
    conditions: ["args.limit >= args.secret"]
"#,
        )
        .unwrap();
        let d = p.eval("x", &json!({"limit": 1, "secret": 4242}));
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(!d.reason.contains("4242"), "{}", d.reason);
    }

    const TAINT: &str = r#"
version: 1
namespace: t
data_flow:
  untrusted_sources: ["mcp:zendesk"]
capabilities:
  - tool: "zendesk.*"
  - tool: "stripe.refund"
    privileged: true
    conditions: ["args.amount <= 100"]
    on_violation: require_sudo
  - tool: "stripe.get_charge"
  - tool: "stripe.delete_customer"
    privileged: true
    action: deny
"#;

    #[test]
    fn taint_guards_privileged_tools_only() {
        let p = Policy::from_yaml_str(TAINT).unwrap();
        assert!(p.is_untrusted("mcp:zendesk") && !p.is_untrusted("mcp:stripe"));
        let tainted = Facts {
            tainted: true,
            taint_sources: vec!["mcp:zendesk".into()],
            ..Facts::default()
        };
        let decide = |facts: &Facts, tool: &str, args: Value| p.evaluate(&DecisionContext::new(tool, &args, facts));

        let clean = Facts::default();
        assert_eq!(
            decide(&clean, "stripe.refund", json!({"amount": 5})).outcome,
            Outcome::Allow
        );
        let d = decide(&tainted, "stripe.refund", json!({"amount": 5}));
        assert_eq!(d.outcome, Outcome::RequireSudo);
        assert!(
            d.reason.contains("tainted") && d.reason.contains("mcp:zendesk"),
            "{}",
            d.reason
        );
        // Non-privileged tools are unaffected.
        assert_eq!(decide(&tainted, "stripe.get_charge", json!({})).outcome, Outcome::Allow);
        // A stricter outcome stands, with its own reason.
        let d = decide(&tainted, "stripe.delete_customer", json!({}));
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("denied by rule"), "{}", d.reason);

        let strict = Policy::from_yaml_str(&TAINT.replace(
            "data_flow:\n",
            "data_flow:\n  on_taint:\n    privileged_mutations: deny\n",
        ))
        .unwrap();
        let d = strict.evaluate(&DecisionContext::new("stripe.refund", &json!({"amount": 5}), &tainted));
        assert_eq!(d.outcome, Outcome::Deny);
    }

    const REFUNDS: &str = r#"
version: 1
namespace: t
entitlements:
  source: file
  path: entitlements.yaml
capabilities:
  - tool: "stripe.refund"
    privileged: true
    lookup:
      charge: { table: charges, key: args.charge }
    entitlements:
      - "charge.customer in writ.root.entitled_customers"
      - "args.amount <= charge.amount"
    on_entitlement_violation: deny
    conditions:
      - "args.amount <= 100.00"
    on_violation: require_sudo
  - tool: "stripe.add_credit"
    privileged: true
"#;

    const SOURCE: &str = r#"
principals:
  alice:
    entitled_customers: [cus_alice]
tables:
  charges:
    ch_alice_small: { customer: cus_alice, amount: 40.00 }
    ch_alice_big: { customer: cus_alice, amount: 240.00 }
    ch_bob: { customer: cus_bob, amount: 5000.00 }
"#;

    fn alice(source: &FileSource, tainted: bool) -> Facts {
        Facts {
            root: Some(Root {
                principal: "alice".into(),
                verified: false,
                attributes: source.root_attributes("alice").unwrap(),
            }),
            tainted,
            taint_sources: if tainted { vec!["mcp:zendesk".into()] } else { vec![] },
            ..Facts::default()
        }
    }

    #[test]
    fn entitlements_bound_privileged_calls_by_the_root() {
        let p = Policy::from_yaml_str(REFUNDS).unwrap();
        assert_eq!(
            p.entitlements,
            Some(EntitlementsSpec {
                source: SourceKind::File,
                path: "entitlements.yaml".into()
            })
        );
        assert_eq!(p.lookup_tables(), ["charges"]);
        let source = FileSource::from_yaml_str(SOURCE).unwrap();
        let decide = |facts: &Facts, tool: &str, args: Value| {
            p.evaluate(&DecisionContext::new(tool, &args, facts).with_source(Some(&source)))
        };

        for tainted in [false, true] {
            let facts = alice(&source, tainted);
            // Somebody else's charge: denied, tainted or not, and no human is asked.
            let d = decide(&facts, "stripe.refund", json!({"charge": "ch_bob", "amount": 5000.0}));
            assert_eq!(d.outcome, Outcome::Deny, "{}", d.reason);
            assert!(d.reason.contains("outside the root's entitlement"), "{}", d.reason);
            assert!(d.reason.contains("charge.customer = \"cus_bob\""), "{}", d.reason);
            // More than the charge: denied.
            let d = decide(
                &facts,
                "stripe.refund",
                json!({"charge": "ch_alice_small", "amount": 41.0}),
            );
            assert_eq!(d.outcome, Outcome::Deny, "{}", d.reason);
            // Alice's own small charge: allowed, even on a tainted task (covered).
            let d = decide(
                &facts,
                "stripe.refund",
                json!({"charge": "ch_alice_small", "amount": 40.0}),
            );
            assert_eq!(d.outcome, Outcome::Allow, "tainted={tainted}: {}", d.reason);
            assert!(d.reason.contains("within the root's entitlement"), "{}", d.reason);
            // Alice's own large charge: over the auto-limit, so a human decides.
            let d = decide(
                &facts,
                "stripe.refund",
                json!({"charge": "ch_alice_big", "amount": 240.0}),
            );
            assert_eq!(d.outcome, Outcome::RequireSudo, "{}", d.reason);
            assert!(d.reason.contains("args.amount <= 100.00"), "{}", d.reason);
        }

        // A privileged tool with no entitlements isn't covered: taint needs a human.
        let clean = decide(&alice(&source, false), "stripe.add_credit", json!({}));
        assert_eq!(clean.outcome, Outcome::Allow);
        let tainted = decide(&alice(&source, true), "stripe.add_credit", json!({}));
        assert_eq!(tainted.outcome, Outcome::RequireSudo);
        assert!(tainted.reason.contains("tainted"), "{}", tainted.reason);
    }

    #[test]
    fn entitlements_fail_closed() {
        let p = Policy::from_yaml_str(REFUNDS).unwrap();
        let source = FileSource::from_yaml_str(SOURCE).unwrap();
        let args = json!({"charge": "ch_alice_small", "amount": 40.0});
        let ctx = |facts: &'static Facts| DecisionContext::new("stripe.refund", &args, facts);

        // No root principal.
        static NO_ROOT: std::sync::LazyLock<Facts> = std::sync::LazyLock::new(Facts::default);
        let d = p.evaluate(&ctx(&NO_ROOT).with_source(Some(&source)));
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(
            d.reason.contains("writ.root.entitled_customers is missing"),
            "{}",
            d.reason
        );

        // No source at all.
        let facts = alice(&source, false);
        let d = p.evaluate(&DecisionContext::new("stripe.refund", &args, &facts));
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reason.contains("no entitlement source"), "{}", d.reason);

        // An unknown charge.
        let unknown = json!({"charge": "ch_nope", "amount": 1.0});
        let d = p.evaluate(&DecisionContext::new("stripe.refund", &unknown, &facts).with_source(Some(&source)));
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(
            d.reason.contains("no `charges` entry for args.charge = \"ch_nope\""),
            "{}",
            d.reason
        );

        // A redacted key isn't echoed.
        let redacting = Policy::from_yaml_str(&REFUNDS.replace(
            "    privileged: true\n    lookup:",
            "    privileged: true\n    redact: [\"args.charge\"]\n    lookup:",
        ))
        .unwrap();
        let d = redacting.evaluate(&DecisionContext::new("stripe.refund", &unknown, &facts).with_source(Some(&source)));
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(!d.reason.contains("ch_nope"), "{}", d.reason);
    }

    #[test]
    fn approvals_block() {
        let base = "version: 1\nnamespace: t\n";
        assert_eq!(Policy::from_yaml_str(base).unwrap().approvals, None);
        let p = Policy::from_yaml_str(&format!("{base}approvals: {{}}\n")).unwrap();
        assert_eq!(p.approvals.unwrap().timeout, DEFAULT_APPROVAL_TIMEOUT);
        let p = Policy::from_yaml_str(&format!("{base}approvals:\n  timeout: 90s\n")).unwrap();
        assert_eq!(p.approvals.unwrap().timeout, Duration::from_secs(90));
        for bad in ["timeout: soon", "timeout: 0s", "approvers: [bob]"] {
            assert!(
                Policy::from_yaml_str(&format!("{base}approvals:\n  {bad}\n")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_invalid_policies() {
        for yaml in [
            "version: 2\nnamespace: t\n",
            "version: 1\nnamespace: t\nenforcement: mediated\n",
            "version: 1\nnamespace: t\ntypo: 1\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: \"*\"\n  - tool: \"*\"\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    action: deny\n    conditions: [\"args.a == 1\"]\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    conditions: [\"writ.taint == false\"]\n",
            "version: 1\nnamespace: t\ndata_flow:\n  untrusted_sources: [\"postgres:public.notes\"]\n",
            "version: 1\nnamespace: t\ndata_flow:\n  untrusted_sources: [\"mcp:bad name\"]\n",
            "version: 1\nnamespace: t\ndata_flow:\n  on_taint:\n    privileged_mutations: allow\n",
            "version: 1\nnamespace: t\nentitlements:\n  source: ldap\n  path: x\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    entitlements: [\"charge.c == 1\"]\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    lookup:\n      args: { table: t, key: args.a }\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    lookup:\n      c: { table: t, key: c.a }\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    on_entitlement_violation: deny\n",
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    action: deny\n    entitlements: [\"args.a == 1\"]\n",
        ] {
            assert!(Policy::from_yaml_str(yaml).is_err(), "accepted: {yaml}");
        }
    }
}
