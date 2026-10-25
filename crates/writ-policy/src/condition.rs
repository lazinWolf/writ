//! Argument conditions: `args.<path> <op> <json-literal>`.
//!
//! Evaluation fails closed: a missing path or a type mismatch makes the
//! condition fail rather than pass.

use std::cmp::Ordering;
use std::fmt;

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
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
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    path: Vec<String>,
    op: Op,
    literal: Value,
    source: String,
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl Condition {
    pub fn parse(source: &str) -> Result<Self, String> {
        let s = source.trim();
        let rest = s.strip_prefix("args.").ok_or_else(|| {
            "conditions must start with `args.` (writ.* and other context fields are not supported yet)".to_string()
        })?;

        let path_end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
            .unwrap_or(rest.len());
        let path: Vec<String> = rest[..path_end].split('.').map(str::to_string).collect();
        if path.iter().any(String::is_empty) {
            return Err(format!("invalid argument path `args.{}`", &rest[..path_end]));
        }

        let rest = rest[path_end..].trim_start();
        let (op, rest) = [
            ("<=", Op::Le),
            (">=", Op::Ge),
            ("==", Op::Eq),
            ("!=", Op::Ne),
            ("<", Op::Lt),
            (">", Op::Gt),
        ]
        .iter()
        .find_map(|(sym, op)| rest.strip_prefix(sym).map(|r| (*op, r)))
        .ok_or_else(|| "expected one of <, <=, >, >=, ==, != after the argument path".to_string())?;

        let literal: Value = serde_json::from_str(rest.trim()).map_err(|_| {
            format!(
                "right-hand side `{}` is not a JSON literal (use \"quoted\" strings)",
                rest.trim()
            )
        })?;
        if literal.is_array() || literal.is_object() {
            return Err("right-hand side must be a number, string, boolean, or null".to_string());
        }
        if matches!(op, Op::Lt | Op::Le | Op::Gt | Op::Ge) && !literal.is_number() {
            return Err(format!("`{}` needs a numeric right-hand side", op.symbol()));
        }

        Ok(Condition {
            path,
            op,
            literal,
            source: s.to_string(),
        })
    }

    pub(crate) fn path(&self) -> &[String] {
        &self.path
    }

    /// Returns `Err(reason)` when the condition does not hold.
    pub fn check(&self, args: &Value) -> Result<(), String> {
        let mut current = args;
        for segment in &self.path {
            current = match current {
                Value::Object(map) => map.get(segment),
                Value::Array(items) => segment.parse::<usize>().ok().and_then(|i| items.get(i)),
                _ => None,
            }
            .ok_or_else(|| format!("`{self}` failed: args.{} is missing", self.path.join(".")))?;
        }

        let holds = match (current, &self.literal) {
            (Value::Number(a), Value::Number(b)) => match (a.as_f64(), b.as_f64()) {
                (Some(a), Some(b)) => a.partial_cmp(&b).is_some_and(|ord| self.op_holds(ord)),
                _ => false,
            },
            (a, b) if std::mem::discriminant(a) == std::mem::discriminant(b) => match self.op {
                Op::Eq => a == b,
                Op::Ne => a != b,
                _ => false,
            },
            // Type mismatch: fail closed for every operator, including `!=`.
            _ => false,
        };

        if holds {
            Ok(())
        } else {
            Err(format!("`{self}` failed: args.{} = {current}", self.path.join(".")))
        }
    }

    fn op_holds(&self, ord: Ordering) -> bool {
        match self.op {
            Op::Lt => ord == Ordering::Less,
            Op::Le => ord != Ordering::Greater,
            Op::Gt => ord == Ordering::Greater,
            Op::Ge => ord != Ordering::Less,
            Op::Eq => ord == Ordering::Equal,
            Op::Ne => ord != Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(expr: &str, args: Value) -> Result<(), String> {
        Condition::parse(expr).unwrap().check(&args)
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
    }

    #[test]
    fn parse_errors() {
        assert!(Condition::parse("writ.tainted == false").is_err());
        assert!(Condition::parse("args.amount ~ 3").is_err());
        assert!(Condition::parse("args.name == bob").is_err());
        assert!(Condition::parse("args.name < \"bob\"").is_err());
        assert!(Condition::parse("args..x == 1").is_err());
    }
}
