//! Parser and evaluator for `writ.yaml`.
//!
//! This build implements a subset of the spec in `plan-v2.md` §7.1: tool
//! rules with conditions over the call's arguments (`args.*`) and the task's
//! facts (`writ.*`, see [`Facts`]), and the `max_tool_calls` limit. Fields the
//! spec defines but this build does not enforce are rejected at load time, so
//! a policy never appears to grant a guarantee it does not have.
//!
//! Rule precedence follows D9: every matching rule is evaluated and the most
//! restrictive outcome wins. A rule whose pattern is exactly `*` applies only
//! to tools no other rule matches, and a tool no rule matches is denied.

mod condition;
mod context;
mod glob;
mod redact;

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use condition::Condition;
use context::Scope;
pub use context::{DecisionContext, Facts, Root, SessionFacts, session_source, validate_session_name};
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
const UNIMPLEMENTED_TOP_LEVEL: &[&str] = &["entitlements", "approvals"];
const UNIMPLEMENTED_DATA_FLOW: &[&str] = &["secrets", "pii_fields", "declassify"];
const UNIMPLEMENTED_ON_TAINT: &[&str] = &["other_mutations", "egress_to_untrusted_sinks"];
const UNIMPLEMENTED_LIMITS: &[&str] = &["max_depth", "max_parallel_agents", "max_budget_usd", "loop_breaker"];
const UNIMPLEMENTED_RULE: &[&str] = &[
    "idempotency",
    "lookup",
    "entitlements",
    "preconditions",
    "classify",
    "deny_statements",
    "allow_functions",
    "pin_tenant_from_writ",
    "mutations",
    "sudo_approvers",
    "on_entitlement_violation",
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
}

#[derive(Debug, Clone, Default)]
pub struct Limits {
    pub max_tool_calls: Option<u64>,
}

#[derive(Debug, Clone)]
struct Rule {
    pattern: String,
    action: Action,
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
    capabilities: Vec<RawRule>,
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
            return Decision {
                outcome: Outcome::Deny,
                rule: None,
                reason: format!("no rule matches tool `{tool}` (deny by default)"),
            };
        }

        let recording = Self::recording(&candidates);
        let scope = Scope::new(ctx);
        let mut decisions = candidates.iter().map(|rule| rule.decide(&scope, &recording));
        let first = decisions.next().expect("candidates is non-empty");
        // `max_by_key` keeps the last maximum; fold keeps the first, so the
        // reported rule is the earliest of the most restrictive ones.
        let best = decisions.fold(first, |best, d| if d.outcome > best.outcome { d } else { best });

        // A privileged tool on a tainted task: the task has read content that
        // may be attacker-written, so its arguments may be attacker-steered.
        match candidates.iter().find(|r| r.privileged) {
            Some(rule) if ctx.facts.tainted && self.on_taint_privileged > best.outcome => Decision {
                outcome: self.on_taint_privileged,
                rule: Some(rule.pattern.clone()),
                reason: format!(
                    "`{tool}` is privileged and the task is tainted (it read from {})",
                    ctx.facts.taint_sources.join(", ")
                ),
            },
            _ => best,
        }
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
        if raw.action == Action::Deny && !raw.conditions.is_empty() {
            return Err(invalid(format!(
                "rule `{}`: conditions on a deny rule have no effect; remove them",
                raw.tool
            )));
        }
        let conditions = raw
            .conditions
            .iter()
            .map(|c| Condition::parse(c).map_err(|e| invalid(format!("rule `{}`: condition `{c}`: {e}", raw.tool))))
            .collect::<Result<_, _>>()?;
        let redact = raw
            .redact
            .iter()
            .map(|r| RedactPath::parse(r).map_err(|e| invalid(format!("rule `{}`: {e}", raw.tool))))
            .collect::<Result<_, _>>()?;
        Ok(Rule {
            pattern: raw.tool,
            action: raw.action,
            conditions,
            on_violation: raw.on_violation,
            redact,
            record_arguments: raw.record_arguments,
            privileged: raw.privileged,
        })
    }

    fn decide(&self, scope: &Scope, recording: &Recording) -> Decision {
        let rule = Some(self.pattern.clone());
        if self.action == Action::Deny {
            return Decision {
                outcome: Outcome::Deny,
                rule,
                reason: format!("denied by rule `{}`", self.pattern),
            };
        }
        for condition in &self.conditions {
            if let Err(reason) = condition.check(scope) {
                // Decision reasons are recorded, so they must not echo a redacted value.
                let reason = if condition.arg_paths().any(|p| recording.hides(p)) {
                    format!("`{condition}` failed (value redacted)")
                } else {
                    reason
                };
                let outcome = match self.on_violation {
                    Violation::Deny => Outcome::Deny,
                    Violation::RequireSudo => Outcome::RequireSudo,
                };
                return Decision { outcome, rule, reason };
            }
        }
        Decision {
            outcome: Outcome::Allow,
            rule,
            reason: format!("allowed by rule `{}`", self.pattern),
        }
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
            ("version: 1\nnamespace: t\napprovals: {}\n", "approvals"),
            (
                "version: 1\nnamespace: t\nlimits:\n  max_depth: 4\n",
                "limits.max_depth",
            ),
            (
                "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    lookup: {}\n",
                "lookup",
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
        ] {
            assert!(Policy::from_yaml_str(yaml).is_err(), "accepted: {yaml}");
        }
    }
}
