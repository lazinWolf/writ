//! Conditions: `<path> <op> <operand>`.
//!
//! - A path starts with `args.` (the call's arguments) or `writ.` (facts about
//!   the task, see [`crate::Facts`]): `args.amount`, `writ.root.principal`.
//! - `op` is one of `<`, `<=`, `>`, `>=`, `==`, `!=`, or `in`.
//! - The operand is a JSON literal (`100.00`, `"usd"`, `true`, `null`; an
//!   array only after `in`) or another path:
//!   `args.amount <= writ.root.refund_limit`,
//!   `args.customer in writ.root.entitled_customers`.
//!
//! Evaluation fails closed: a missing path or a type mismatch makes the
//! condition fail rather than pass.

use std::cmp::Ordering;
use std::fmt;

use serde_json::Value;

use crate::context::{FACT_FIELDS, Scope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    In,
}

impl Op {
    fn symbol(self) -> &'static str {
        match self {
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Eq => "==",
            Op::Ne => "!=",
            Op::In => "in",
        }
    }

    fn is_ordering(self) -> bool {
        matches!(self, Op::Lt | Op::Le | Op::Gt | Op::Ge)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Operand {
    Literal(Value),
    Path(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    lhs: Vec<String>,
    op: Op,
    rhs: Operand,
    source: String,
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// Parses a path at the start of `s`. Returns it and the rest of `s`, or
/// `None` if `s` doesn't start with `args.`, `writ.`, or `<binding>.` for
/// one of `bindings` (the names a rule's `lookup:` binds).
fn parse_path<'s>(s: &'s str, bindings: &[String]) -> Option<Result<(Vec<String>, &'s str), String>> {
    let rooted = |root: &str| s.strip_prefix(root).is_some_and(|rest| rest.starts_with('.'));
    if !(rooted("args") || rooted("writ") || bindings.iter().any(|b| rooted(b))) {
        return None;
    }
    let end = s.find(|c: char| !is_path_char(c)).unwrap_or(s.len());
    let text = &s[..end];
    let path: Vec<String> = text.split('.').map(str::to_string).collect();
    if path.iter().any(String::is_empty) {
        return Some(Err(format!("invalid path `{text}`")));
    }
    if path[0] == "writ" && !FACT_FIELDS.contains(&path[1].as_str()) {
        return Some(Err(format!(
            "unknown fact `{text}` (known: {})",
            FACT_FIELDS
                .iter()
                .map(|f| format!("writ.{f}"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Some(Ok((path, &s[end..])))
}

/// Parses `s` as exactly one `args.` or `writ.` path (a lookup's `key`).
pub(crate) fn parse_key_path(s: &str) -> Result<Vec<String>, String> {
    let s = s.trim();
    let (path, rest) = parse_path(s, &[]).ok_or_else(|| format!("`{s}` is not an `args.` or `writ.` path"))??;
    if !rest.is_empty() {
        return Err(format!("unexpected `{rest}` after the path `{s}`"));
    }
    Ok(path)
}

impl Condition {
    /// Parses a condition that may read `args.*` and `writ.*`.
    pub fn parse(source: &str) -> Result<Self, String> {
        Self::parse_with(source, &[])
    }

    /// Parses a condition that may also read the names in `bindings`.
    pub fn parse_with(source: &str, bindings: &[String]) -> Result<Self, String> {
        let s = source.trim();
        let (lhs, rest) = parse_path(s, bindings).ok_or_else(|| {
            let mut roots = vec!["`args.`".to_string(), "`writ.`".to_string()];
            roots.extend(bindings.iter().map(|b| format!("`{b}.`")));
            format!("a condition must start with a path ({})", roots.join(", "))
        })??;

        let rest = rest.trim_start();
        let symbols = [
            ("<=", Op::Le),
            (">=", Op::Ge),
            ("==", Op::Eq),
            ("!=", Op::Ne),
            ("<", Op::Lt),
            (">", Op::Gt),
        ];
        let (op, rest) = symbols
            .iter()
            .find_map(|(sym, op)| rest.strip_prefix(sym).map(|r| (*op, r)))
            .or_else(|| {
                rest.strip_prefix("in")
                    .filter(|r| r.starts_with(char::is_whitespace))
                    .map(|r| (Op::In, r))
            })
            .ok_or_else(|| "expected one of <, <=, >, >=, ==, !=, in after the path".to_string())?;

        let rest = rest.trim();
        let rhs = match parse_path(rest, bindings) {
            Some(parsed) => {
                let (path, trailing) = parsed?;
                if !trailing.trim().is_empty() {
                    return Err(format!("unexpected `{}` after the right-hand path", trailing.trim()));
                }
                Operand::Path(path)
            }
            None => {
                let literal: Value = serde_json::from_str(rest).map_err(|_| {
                    format!("right-hand side `{rest}` is not a path or a JSON literal (use \"quoted\" strings)")
                })?;
                match (op, &literal) {
                    (Op::In, Value::Array(items)) if items.iter().all(is_scalar) => {}
                    (Op::In, _) => return Err("`in` needs an array of scalars or a path".to_string()),
                    (_, v) if !is_scalar(v) => {
                        return Err("right-hand side must be a number, string, boolean, or null".to_string());
                    }
                    (op, v) if op.is_ordering() && !v.is_number() => {
                        return Err(format!("`{}` needs a numeric right-hand side", op.symbol()));
                    }
                    _ => {}
                }
                Operand::Literal(literal)
            }
        };

        Ok(Condition {
            lhs,
            op,
            rhs,
            source: s.to_string(),
        })
    }

    /// The argument paths this condition reads, without the `args` prefix.
    /// Used to keep redacted values out of decision reasons.
    pub(crate) fn arg_paths(&self) -> impl Iterator<Item = &[String]> {
        let rhs = match &self.rhs {
            Operand::Path(p) => Some(p),
            Operand::Literal(_) => None,
        };
        std::iter::once(&self.lhs)
            .chain(rhs)
            .filter(|p| p[0] == "args")
            .map(|p| &p[1..])
    }

    /// Returns `Err(reason)` when the condition does not hold.
    pub(crate) fn check(&self, scope: &Scope) -> Result<(), String> {
        let missing = |path: &[String]| format!("`{self}` failed: {} is missing", path.join("."));
        let left = scope.get(&self.lhs).ok_or_else(|| missing(&self.lhs))?;
        let right = match &self.rhs {
            Operand::Literal(v) => v,
            Operand::Path(p) => scope.get(p).ok_or_else(|| missing(p))?,
        };

        let holds = match self.op {
            Op::In => {
                is_scalar(left)
                    && right
                        .as_array()
                        .is_some_and(|items| items.iter().any(|i| equal(left, i)))
            }
            Op::Eq => equal(left, right),
            // Type mismatch fails even for `!=`.
            Op::Ne => same_scalar_type(left, right) && !equal(left, right),
            op => numeric_order(left, right).is_some_and(|ord| op_holds(op, ord)),
        };
        if holds {
            return Ok(());
        }
        let mut reason = format!("`{self}` failed: {} = {left}", self.lhs.join("."));
        if let Operand::Path(p) = &self.rhs {
            reason.push_str(&format!(", {} = {right}", p.join(".")));
        }
        Err(reason)
    }
}

fn is_scalar(v: &Value) -> bool {
    !(v.is_array() || v.is_object())
}

/// Orders two numbers; anything else is incomparable, so the condition fails.
fn numeric_order(a: &Value, b: &Value) -> Option<Ordering> {
    a.as_f64()?.partial_cmp(&b.as_f64()?)
}

fn same_scalar_type(a: &Value, b: &Value) -> bool {
    is_scalar(a) && std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// Numbers are equal by value (`1 == 1.0`); other scalars only to a value of
/// the same type. Arrays and objects are never equal to anything.
fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(_), Value::Number(_)) => numeric_order(a, b) == Some(Ordering::Equal),
        _ => same_scalar_type(a, b) && a == b,
    }
}

fn op_holds(op: Op, ord: Ordering) -> bool {
    match op {
        Op::Lt => ord == Ordering::Less,
        Op::Le => ord != Ordering::Greater,
        Op::Gt => ord == Ordering::Greater,
        Op::Ge => ord != Ordering::Less,
        Op::Eq | Op::Ne | Op::In => unreachable!("not an ordering"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecisionContext, Facts, Root};
    use serde_json::json;

    fn check_with(expr: &str, args: Value, facts: &Facts) -> Result<(), String> {
        let ctx = DecisionContext::new("t", &args, facts);
        Condition::parse(expr).unwrap().check(&Scope::new(&ctx))
    }

    fn check(expr: &str, args: Value) -> Result<(), String> {
        check_with(expr, args, &Facts::default())
    }

    fn alice() -> Facts {
        let mut attributes = serde_json::Map::new();
        attributes.insert("entitled_customers".into(), json!(["cus_alice", "cus_alice_2"]));
        attributes.insert("refund_limit".into(), json!(100));
        Facts {
            root: Some(Root {
                principal: "alice@example.com".into(),
                verified: false,
                attributes,
            }),
            ..Facts::default()
        }
    }

    #[test]
    fn numeric_comparisons() {
        assert!(check("args.amount <= 100.00", json!({"amount": 100})).is_ok());
        assert!(check("args.amount <= 100.00", json!({"amount": 240.5})).is_err());
        assert!(check("args.amount<5", json!({"amount": 4})).is_ok());
        assert!(check("args.n != 0", json!({"n": 1})).is_ok());
    }

    #[test]
    fn nested_paths_and_arrays() {
        assert!(check("args.a.b == \"x\"", json!({"a": {"b": "x"}})).is_ok());
        assert!(check("args.items.0 == true", json!({"items": [true]})).is_ok());
    }

    #[test]
    fn fails_closed() {
        let missing = check("args.amount <= 100", json!({}));
        assert!(missing.unwrap_err().contains("missing"));
        // A numeric string must not satisfy a numeric bound.
        assert!(check("args.amount <= 100", json!({"amount": "50"})).is_err());
        // Type mismatch fails even for `!=`.
        assert!(check("args.env != \"prod\"", json!({"env": 1})).is_err());
        // Objects never compare, not even to themselves.
        assert!(check("args.a == args.a", json!({"a": {}})).is_err());
    }

    #[test]
    fn reads_task_facts() {
        assert!(check("writ.tainted == false", json!({})).is_ok());
        let tainted = Facts {
            tainted: true,
            ..Facts::default()
        };
        assert!(check_with("writ.tainted == false", json!({}), &tainted).is_err());
        assert!(check_with("writ.root.principal == \"alice@example.com\"", json!({}), &alice()).is_ok());
        assert!(check_with("writ.root.verified == true", json!({}), &alice()).is_err());
        // No root: every condition that reads it fails.
        let no_root = check("writ.root.principal != \"mallory\"", json!({}));
        assert!(no_root.unwrap_err().contains("writ.root.principal is missing"));
    }

    #[test]
    fn right_hand_paths() {
        let facts = alice();
        assert!(check_with("args.amount <= writ.root.refund_limit", json!({"amount": 40}), &facts).is_ok());
        let err = check_with("args.amount <= writ.root.refund_limit", json!({"amount": 240}), &facts).unwrap_err();
        assert!(
            err.contains("args.amount = 240") && err.contains("writ.root.refund_limit = 100"),
            "{err}"
        );
        assert!(check("args.a == args.b", json!({"a": 1, "b": 1.0})).is_ok());
        assert!(check("args.a <= args.missing", json!({"a": 1})).is_err());
        // Ordering needs numbers on both sides, even when the right side is a path.
        assert!(check("args.a < args.b", json!({"a": "x", "b": "y"})).is_err());
        assert!(check("args.a != args.b", json!({"a": "x", "b": 1})).is_err());
    }

    #[test]
    fn membership() {
        let facts = alice();
        let entitled = "args.customer in writ.root.entitled_customers";
        assert!(check_with(entitled, json!({"customer": "cus_alice"}), &facts).is_ok());
        assert!(check_with(entitled, json!({"customer": "cus_bob"}), &facts).is_err());
        // Not a scalar, or not a list: fail closed.
        assert!(check_with(entitled, json!({"customer": ["cus_alice"]}), &facts).is_err());
        assert!(check_with("args.c in writ.root.principal", json!({"c": "a"}), &facts).is_err());
        assert!(check("args.cur in [\"usd\", \"eur\"]", json!({"cur": "eur"})).is_ok());
        assert!(check("args.n in [1, 2]", json!({"n": 2.0})).is_ok());
        assert!(check("args.cur in [\"usd\"]", json!({"cur": "gbp"})).is_err());
    }

    #[test]
    fn bound_names() {
        let bindings = ["charge".to_string()];
        let c = Condition::parse_with("charge.customer in writ.root.entitled_customers", &bindings).unwrap();
        let args = json!({});
        let mut facts = alice();
        facts.tainted = true;
        let ctx = DecisionContext::new("t", &args, &facts);
        let mut scope = Scope::new(&ctx);
        // Unbound (the lookup found nothing): fail closed.
        assert!(c.check(&scope).unwrap_err().contains("charge.customer is missing"));
        scope.bind("charge", json!({"customer": "cus_alice"}));
        assert!(c.check(&scope).is_ok());
        scope.bind("charge", json!({"customer": "cus_bob"}));
        assert!(c.check(&scope).is_err());

        // A name is only a root when the rule binds it, and `charges.` isn't `charge.`.
        assert!(Condition::parse("charge.customer == 1").is_err());
        assert!(Condition::parse_with("charges.customer == 1", &bindings).is_err());
        assert!(parse_key_path("args.charge").is_ok());
        assert!(parse_key_path("charge.id").is_err());
        assert!(parse_key_path("args.charge extra").is_err());
    }

    #[test]
    fn parse_errors() {
        for bad in [
            "charge.customer == 1",
            "writ.bogus == false",
            "writ. == 1",
            "args.amount ~ 3",
            "args.name == bob",
            "args.name < \"bob\"",
            "args..x == 1",
            "args.a in 3",
            "args.a in [[1]]",
            "args.a == [1]",
            "args.a == args.b extra",
            "args.a inx [1]",
        ] {
            assert!(Condition::parse(bad).is_err(), "accepted: {bad}");
        }
    }
}
