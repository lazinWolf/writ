//! Argument redaction for the flight recorder.
//!
//! Paths look like condition paths (`args.card.number`) and may use `*` for
//! any object key or array index (`args.headers.*`, `args.items.*.token`).
//! Redacted values are replaced with a fixed marker, not a hash: a hash of a
//! low-entropy secret (a PIN, a short password) can be brute-forced.

use serde_json::Value;

pub const MARKER: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Key(String),
    Any,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RedactPath(Vec<Segment>);

impl RedactPath {
    pub fn parse(source: &str) -> Result<Self, String> {
        let rest = source
            .trim()
            .strip_prefix("args.")
            .ok_or_else(|| "redaction paths must start with `args.`".to_string())?;
        let segments = rest
            .split('.')
            .map(|s| match s {
                "*" => Ok(Segment::Any),
                "" => Err(format!("invalid redaction path `{source}`")),
                s if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') => {
                    Ok(Segment::Key(s.to_string()))
                }
                s => Err(format!("invalid segment `{s}` in redaction path `{source}`")),
            })
            .collect::<Result<_, _>>()?;
        Ok(RedactPath(segments))
    }

    /// True when this path covers `path` itself or one of its ancestors, so a
    /// value read from `path` would expose redacted data.
    pub fn covers(&self, path: &[String]) -> bool {
        self.0.len() <= path.len()
            && self.0.iter().zip(path).all(|(segment, key)| match segment {
                Segment::Any => true,
                Segment::Key(k) => k == key,
            })
    }

    pub fn apply(&self, args: &mut Value) {
        apply(&self.0, args);
    }
}

fn apply(segments: &[Segment], value: &mut Value) {
    let Some((first, rest)) = segments.split_first() else {
        *value = Value::String(MARKER.to_string());
        return;
    };
    match (first, value) {
        (Segment::Any, Value::Object(map)) => map.values_mut().for_each(|v| apply(rest, v)),
        (Segment::Any, Value::Array(items)) => items.iter_mut().for_each(|v| apply(rest, v)),
        (Segment::Key(key), Value::Object(map)) => {
            if let Some(v) = map.get_mut(key) {
                apply(rest, v);
            }
        }
        (Segment::Key(key), Value::Array(items)) => {
            if let Some(v) = key.parse::<usize>().ok().and_then(|i| items.get_mut(i)) {
                apply(rest, v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn redact(path: &str, mut args: Value) -> Value {
        RedactPath::parse(path).unwrap().apply(&mut args);
        args
    }

    #[test]
    fn redacts_exact_and_wildcard_paths() {
        assert_eq!(
            redact("args.card.number", json!({"card": {"number": "4242", "exp": "12/30"}})),
            json!({"card": {"number": MARKER, "exp": "12/30"}})
        );
        assert_eq!(
            redact("args.headers.*", json!({"headers": {"a": 1, "b": 2}, "body": "x"})),
            json!({"headers": {"a": MARKER, "b": MARKER}, "body": "x"})
        );
        assert_eq!(
            redact(
                "args.items.*.token",
                json!({"items": [{"token": "t1", "id": 1}, {"id": 2}]})
            ),
            json!({"items": [{"token": MARKER, "id": 1}, {"id": 2}]})
        );
        // Redacting a parent replaces the whole subtree.
        assert_eq!(
            redact("args.card", json!({"card": {"number": "4242"}})),
            json!({"card": MARKER})
        );
        // Missing paths are left alone.
        assert_eq!(redact("args.nope", json!({"a": 1})), json!({"a": 1}));
    }

    #[test]
    fn covers_descendants_only() {
        let path = RedactPath::parse("args.card").unwrap();
        let p = |s: &str| s.split('.').map(str::to_string).collect::<Vec<_>>();
        assert!(path.covers(&p("card")));
        assert!(path.covers(&p("card.number")));
        assert!(!path.covers(&p("cardholder")));
        assert!(RedactPath::parse("args.*.secret").unwrap().covers(&p("a.secret")));
    }

    #[test]
    fn parse_errors() {
        for bad in ["card.number", "args.", "args.a..b", "args.a b", "args"] {
            assert!(RedactPath::parse(bad).is_err(), "accepted {bad}");
        }
    }
}
