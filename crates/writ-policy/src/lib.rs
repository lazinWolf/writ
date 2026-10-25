//! Parser and evaluator for `writ.yaml`.
//!
//! This build implements a subset of the spec in `plan-v2.md` §7.1: tool
//! rules with argument conditions, and the `max_tool_calls` limit. Fields the
//! spec defines but this build does not enforce are rejected at load time, so
//! a policy never appears to grant a guarantee it does not have.
//!
//! Rule precedence follows D9: every matching rule is evaluated and the most
//! restrictive outcome wins. A rule whose pattern is exactly `*` applies only
//! to tools no other rule matches, and a tool no rule matches is denied.

mod condition;
mod glob;

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use condition::Condition;

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
const UNIMPLEMENTED_TOP_LEVEL: &[&str] = &["data_flow"];
const UNIMPLEMENTED_LIMITS: &[&str] = &["max_depth", "max_parallel_agents", "max_budget_usd", "loop_breaker"];
const UNIMPLEMENTED_RULE: &[&str] = &[
    "privileged",
    "idempotency",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    RequireSudo,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
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
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub namespace: String,
    pub enforcement: Enforcement,
    pub limits: Limits,
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
    capabilities: Vec<RawRule>,
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
}

impl Policy {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|source| PolicyError::Io { path: path.display().to_string(), source })?;
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
            limits: Limits { max_tool_calls: raw.limits.max_tool_calls },
            rules,
            fallback,
        })
    }

    /// Decides a single `tools/call`.
    pub fn evaluate(&self, tool: &str, args: &Value) -> Decision {
        let candidates = self.candidates(tool);
        if candidates.is_empty() {
            return Decision {
                outcome: Outcome::Deny,
                rule: None,
                reason: format!("no rule matches tool `{tool}` (deny by default)"),
            };
        }

        let mut decisions = candidates.into_iter().map(|rule| rule.decide(args));
        let first = decisions.next().expect("candidates is non-empty");
        // `max_by_key` keeps the last maximum; fold keeps the first, so the
        // reported rule is the earliest of the most restrictive ones.
        decisions.fold(first, |best, d| if d.outcome > best.outcome { d } else { best })
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
        if matching.is_empty() { self.fallback.iter().collect() } else { matching }
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
        Ok(Rule { pattern: raw.tool, action: raw.action, conditions, on_violation: raw.on_violation })
    }

    fn decide(&self, args: &Value) -> Decision {
        let rule = Some(self.pattern.clone());
        if self.action == Action::Deny {
            return Decision { outcome: Outcome::Deny, rule, reason: format!("denied by rule `{}`", self.pattern) };
        }
        for condition in &self.conditions {
            if let Err(reason) = condition.check(args) {
                let outcome = match self.on_violation {
                    Violation::Deny => Outcome::Deny,
                    Violation::RequireSudo => Outcome::RequireSudo,
                };
                return Decision { outcome, rule, reason };
            }
        }
        Decision { outcome: Outcome::Allow, rule, reason: format!("allowed by rule `{}`", self.pattern) }
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
        let d = policy().evaluate("postgres.query", &json!({}));
        assert_eq!(d.outcome, Outcome::Allow);
        assert_eq!(d.rule.as_deref(), Some("postgres.*"));
    }

    #[test]
    fn most_restrictive_matching_rule_wins() {
        let d = policy().evaluate("postgres.drop_table", &json!({}));
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(d.rule.as_deref(), Some("postgres.drop_table"));
    }

    #[test]
    fn fallback_applies_only_when_nothing_else_matches() {
        assert_eq!(policy().evaluate("shell.exec", &json!({})).outcome, Outcome::Deny);
        assert_eq!(policy().evaluate("stripe.refund", &json!({"amount": 5})).outcome, Outcome::Allow);
    }

    #[test]
    fn condition_violation_requires_sudo() {
        let d = policy().evaluate("stripe.refund", &json!({"amount": 240}));
        assert_eq!(d.outcome, Outcome::RequireSudo);
        assert!(d.reason.contains("args.amount = 240"), "{}", d.reason);
    }

    #[test]
    fn deny_by_default_without_fallback() {
        let p = Policy::from_yaml_str("version: 1\nnamespace: t\ncapabilities:\n  - tool: a\n").unwrap();
        let d = p.evaluate("b", &json!({}));
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
            ("version: 1\nnamespace: t\ndata_flow: {}\n", "data_flow"),
            ("version: 1\nnamespace: t\nlimits:\n  max_depth: 4\n", "limits.max_depth"),
            ("version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    privileged: true\n", "privileged"),
        ];
        for (yaml, field) in cases {
            let err = Policy::from_yaml_str(yaml).unwrap_err().to_string();
            assert!(err.contains(field) && err.contains("not enforced"), "{err}");
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
            "version: 1\nnamespace: t\ncapabilities:\n  - tool: x\n    conditions: [\"writ.tainted == false\"]\n",
        ] {
            assert!(Policy::from_yaml_str(yaml).is_err(), "accepted: {yaml}");
        }
    }
}
