//! `writ replay`: what would a policy have decided for calls already made?
//!
//! Every `tool_call` in the flight log carries what it was decided from: the
//! tool, its arguments (redacted per policy) and the task's facts. Replay
//! re-decides each one under a candidate policy and reports the calls whose
//! outcome changes.
//!
//! It is faithful where it can be and says so where it can't:
//! - **Taint** is re-simulated per task under the candidate policy: if it
//!   declares a new untrusted source, calls after the first read from it see
//!   a tainted task. The root principal and session name come from the log.
//! - **`max_tool_calls`** is re-counted per task under the candidate policy.
//!   A narrowing (per-server) policy isn't replayed; the candidate stands in
//!   for the task's policy alone.
//! - **Redacted arguments** were recorded as a marker, so a decision that
//!   reads them is a guess: those calls are flagged `partial`.
//! - **Omitted arguments** (`record_arguments: false`) can't be replayed at
//!   all: those calls are counted as `skipped`.
//! - **Lookups** read the candidate's entitlement source as it is now, not as
//!   it was when the call was made.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use writ_policy::{Decision, DecisionContext, EntitlementSource, Facts, Outcome, Policy, REDACTED};
use writ_recorder::Entry;

/// One call whose outcome would change.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Flip {
    /// The `tool_call` entry's sequence number in the log.
    pub seq: u64,
    pub ts: String,
    pub task: String,
    pub tool: String,
    pub arguments: Value,
    pub before: Decision,
    pub after: Decision,
    /// How a paused call was settled, if it was (`approve`, `deny`, ...).
    pub settled: Option<String>,
    /// The arguments were partly redacted, so this outcome may be wrong.
    pub partial: bool,
}

impl Flip {
    /// True when the candidate policy is less restrictive for this call.
    pub fn loosens(&self) -> bool {
        self.after.outcome < self.before.decided()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Report {
    /// Calls re-decided.
    pub replayed: u64,
    /// Calls that couldn't be: arguments not recorded.
    pub skipped: u64,
    /// Replayed calls whose arguments were partly redacted.
    pub partial: u64,
    pub flips: Vec<Flip>,
}

impl Report {
    pub fn loosened(&self) -> usize {
        self.flips.iter().filter(|f| f.loosens()).count()
    }

    pub fn tightened(&self) -> usize {
        self.flips.len() - self.loosened()
    }
}

/// Replay state for one task, under the candidate policy.
#[derive(Default)]
struct TaskState {
    tainted: bool,
    taint_sources: Vec<String>,
    allowed: u64,
}

/// Re-decides every `tool_call` in `entries` (in log order) under `policy`.
/// `only` restricts it to one task or session id.
pub fn replay(
    entries: &[Entry],
    policy: &Policy,
    source: Option<&dyn EntitlementSource>,
    only: Option<&str>,
) -> Report {
    // How each paused call was eventually settled, by approval id.
    let settled: BTreeMap<&str, &str> = entries
        .iter()
        .filter(|e| e.kind == "approval")
        .filter_map(|e| Some((e.data["approval"].as_str()?, e.data["decision"].as_str()?)))
        .collect();

    let mut tasks: BTreeMap<String, TaskState> = BTreeMap::new();
    let mut report = Report::default();
    for entry in entries.iter().filter(|e| e.kind == "tool_call") {
        let d = &entry.data;
        let task_id = d["task"].as_str().unwrap_or(&entry.session).to_string();
        if only.is_some_and(|id| id != task_id && id != entry.session) {
            continue;
        }
        let (Some(tool), Ok(before)) = (
            d["tool"].as_str(),
            serde_json::from_value::<Decision>(d["decision"].clone()),
        ) else {
            continue;
        };
        if d["arguments_omitted"] == Value::Bool(true) {
            report.skipped += 1;
            continue;
        }
        let arguments = d.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));
        let partial = contains_marker(&arguments);

        // Logs written before facts were recorded replay with none.
        let recorded: Facts = serde_json::from_value(d["facts"].clone()).unwrap_or_default();
        let state = tasks.entry(task_id.clone()).or_default();
        let facts = Facts {
            tainted: state.tainted,
            taint_sources: state.taint_sources.clone(),
            ..recorded
        };

        let mut after = policy.evaluate(&DecisionContext::new(tool, &arguments, &facts).with_source(source));
        if after.outcome == Outcome::Allow
            && let Some(max) = policy.limits.max_tool_calls
            && state.allowed >= max
        {
            after = Decision::new(
                Outcome::Deny,
                None,
                format!("task max_tool_calls limit reached ({max})"),
            );
        }
        if after.outcome == Outcome::Allow {
            state.allowed += 1;
            if let Some(name) = &facts.session.name
                && policy.is_untrusted(name)
                && !state.taint_sources.contains(name)
            {
                state.tainted = true;
                state.taint_sources.push(name.clone());
            }
        }

        report.replayed += 1;
        if partial {
            report.partial += 1;
        }
        // Observe-mode calls compare what the policy decided, not what was let through.
        if after.outcome != before.decided() {
            report.flips.push(Flip {
                seq: entry.seq,
                ts: entry.ts.clone(),
                task: task_id,
                tool: tool.to_string(),
                arguments,
                settled: before
                    .approval
                    .as_deref()
                    .and_then(|id| settled.get(id))
                    .map(|s| s.to_string()),
                before,
                after,
                partial,
            });
        }
    }
    report
}

fn contains_marker(value: &Value) -> bool {
    match value {
        Value::String(s) => s == REDACTED,
        Value::Array(items) => items.iter().any(contains_marker),
        Value::Object(map) => map.values().any(contains_marker),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Authority, Engine, LoadedPolicy};
    use serde_json::json;
    use writ_recorder::Recorder;

    const RECORDED: &str = r#"
version: 1
namespace: replay
capabilities:
  - tool: "tickets.read"
  - tool: "stripe.refund"
    privileged: true
    redact: ["args.card"]
    conditions: ["args.amount <= 500"]
    on_violation: require_sudo
  - tool: "vault.read"
    record_arguments: false
  - tool: "db.query"
"#;

    /// Records a small session under `RECORDED` and returns the log.
    fn record() -> (Vec<Entry>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("flight.jsonl");
        let mut e = Engine::new(Recorder::open(&log).unwrap());
        let task = e
            .create_task(LoadedPolicy::parse(RECORDED).unwrap(), Authority::default(), json!({}))
            .unwrap();
        let tickets = e.open_session(Some(&task), None, None, "tickets", json!({})).unwrap();
        let stripe = e.open_session(Some(&task), None, None, "stripe", json!({})).unwrap();
        let mut call = |s: &str, tool: &str, args: Value| {
            e.decide(s, &json!(1), tool, &args).unwrap();
        };
        call(&stripe, "stripe.refund", json!({"amount": 50}));
        call(&tickets, "tickets.read", json!({}));
        call(&stripe, "stripe.refund", json!({"amount": 50}));
        call(&stripe, "stripe.refund", json!({"amount": 900, "card": "4242"}));
        call(&stripe, "vault.read", json!({"path": "secret"}));
        call(&stripe, "db.query", json!({}));
        (writ_recorder::read_entries(&log).unwrap(), dir)
    }

    fn policy(text: &str) -> Policy {
        Policy::from_yaml_str(text).unwrap()
    }

    #[test]
    fn the_same_policy_changes_nothing() {
        let (entries, _dir) = record();
        let report = replay(&entries, &policy(RECORDED), None, None);
        assert_eq!((report.replayed, report.skipped, report.partial), (5, 1, 1));
        assert!(report.flips.is_empty(), "{:#?}", report.flips);
    }

    #[test]
    fn a_new_untrusted_source_taints_later_calls_only() {
        let (entries, _dir) = record();
        let candidate = RECORDED.replace(
            "namespace: replay\n",
            "namespace: replay\ndata_flow:\n  untrusted_sources: [\"mcp:tickets\"]\n",
        );
        let report = replay(&entries, &policy(&candidate), None, None);
        // The refund before the ticket read is unchanged; the one after needs a human now.
        assert_eq!(report.flips.len(), 1, "{:#?}", report.flips);
        let flip = &report.flips[0];
        assert_eq!(flip.tool, "stripe.refund");
        assert_eq!(
            (flip.before.outcome, flip.after.outcome),
            (Outcome::Allow, Outcome::RequireSudo)
        );
        assert!(flip.after.reason.contains("tainted"), "{}", flip.after.reason);
        assert!(!flip.loosens());
        assert_eq!((report.loosened(), report.tightened()), (0, 1));
    }

    #[test]
    fn loosening_is_reported_and_redaction_flagged() {
        let (entries, _dir) = record();
        let candidate = RECORDED.replace("args.amount <= 500", "args.amount <= 1000");
        let report = replay(&entries, &policy(&candidate), None, None);
        assert_eq!(report.flips.len(), 1);
        let flip = &report.flips[0];
        assert!(flip.loosens() && flip.partial, "{flip:?}");
        assert_eq!(flip.arguments["card"], REDACTED, "replay sees what the log holds");
        assert_eq!(report.loosened(), 1);
    }

    #[test]
    fn limits_are_recounted_and_unknown_tools_denied() {
        let (entries, _dir) = record();
        let candidate = format!("{RECORDED}limits:\n  max_tool_calls: 2\n").replace("  - tool: \"db.query\"\n", "");
        let report = replay(&entries, &policy(&candidate), None, None);
        let reasons: Vec<&str> = report.flips.iter().map(|f| f.after.reason.as_str()).collect();
        // The third allowed call hits the limit; db.query has no rule any more.
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons[0].contains("max_tool_calls"), "{reasons:?}");
        assert!(reasons[1].contains("no rule matches"), "{reasons:?}");
    }

    #[test]
    fn filters_by_task_or_session() {
        let (entries, _dir) = record();
        let candidate = RECORDED.replace("args.amount <= 500", "args.amount <= 1000");
        assert_eq!(
            replay(&entries, &policy(&candidate), None, Some("tsk_none")).replayed,
            0
        );
        let task = entries.iter().find(|e| e.kind == "task_start").unwrap().session.clone();
        assert_eq!(replay(&entries, &policy(&candidate), None, Some(&task)).replayed, 5);
    }
}
