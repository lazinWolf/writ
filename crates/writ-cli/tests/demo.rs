//! The poisoned-ticket demo (plan-v2.md scenario 1, `examples/poisoned-ticket`).
//!
//! `poisoned_ticket_demo` is the definition of done for ROADMAP.md steps 2–6.
//! `poisoned_ticket_without_approvals` runs the same story with nobody to ask.
//! Run them with `cargo test -p writ-cli --test demo`.
//!
//! The demo pins down the shape of these interfaces:
//! - `writ wrap --name <name>`: the session is `mcp:<name>`.
//! - `writ run --principal <id>`: the task's root principal (unverified).
//! - `writ sudo list --json`: a JSON array of pending approvals, each with
//!   `id`, `task`, `tool`, `arguments` (redacted per policy), and `reason`.
//! - `writ sudo approve <id>` / `writ sudo deny <id>`.
//! - Flight-log events `taint` (`data.source`) and `approval`
//!   (`data.approval`, `data.decision`: "approve" or "deny", `data.approver`).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn has_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

macro_rules! require_python {
    () => {
        if !has_python() {
            eprintln!("skipping: python3 not found");
            return;
        }
    };
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/poisoned-ticket")
        .join(name)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Sends `requests` to a fixture server directly (no writ) and returns its replies.
fn talk_to(fixture_name: &str, ledger: &Path, requests: &[Value]) -> Vec<Value> {
    let mut input = String::new();
    for r in requests {
        input.push_str(&r.to_string());
        input.push('\n');
    }
    let mut child = Command::new("python3")
        .arg("-I")
        .arg(fixture(fixture_name))
        .env("STRIPE_LEDGER", ledger)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn call(id: u64, tool: &str, args: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } })
}

fn is_error(response: &Value) -> bool {
    response["result"]["isError"] == json!(true) || response.get("error").is_some()
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"].as_str().unwrap_or_default()
}

/// The fixtures behave as the demo assumes, checked without writ in the way.
#[test]
fn demo_fixtures_behave() {
    require_python!();
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let zendesk = talk_to(
        "fake_zendesk.py",
        &ledger,
        &[call(1, "zendesk.get_ticket", json!({ "ticket_id": "T-1001" }))],
    );
    assert!(!is_error(&zendesk[0]));
    assert!(
        text(&zendesk[0]).contains("ch_bob_1"),
        "the ticket carries the injection"
    );

    let stripe = talk_to(
        "fake_stripe.py",
        &ledger,
        &[
            call(1, "stripe.get_charge", json!({ "charge": "ch_bob_1" })),
            call(
                2,
                "stripe.refund",
                json!({ "charge": "ch_alice_small", "amount": 40.0 }),
            ),
            call(
                3,
                "stripe.refund",
                json!({ "charge": "ch_alice_small", "amount": 40.0 }),
            ),
            call(4, "stripe.refund", json!({ "charge": "ch_alice_big", "amount": 999.0 })),
            call(5, "stripe.add_credit", json!({ "customer": "cus_alice", "amount": 10 })),
        ],
    );
    assert!(text(&stripe[0]).contains("cus_bob"));
    assert!(!is_error(&stripe[1]));
    assert!(is_error(&stripe[2]), "a charge can be refunded only once");
    assert!(is_error(&stripe[3]), "a refund can't exceed the charge");
    assert!(!is_error(&stripe[4]));

    // Only executed movements reach the ledger.
    assert_eq!(
        read_jsonl(&ledger),
        [
            json!({ "op": "refund", "charge": "ch_alice_small", "customer": "cus_alice", "amount": 40.0 }),
            json!({ "op": "credit", "customer": "cus_alice", "amount": 10 }),
        ]
    );

    // The mock entitlement source agrees with the fake Stripe about who owns which charge.
    let entitlements = std::fs::read_to_string(example("entitlements.yaml")).unwrap();
    for (charge, customer) in [
        ("ch_alice_small", "cus_alice"),
        ("ch_alice_big", "cus_alice"),
        ("ch_bob_1", "cus_bob"),
    ] {
        assert!(
            entitlements
                .lines()
                .any(|l| l.contains(&format!("{charge}:")) && l.contains(customer)),
            "entitlements.yaml should map {charge} to {customer}"
        );
    }
}

/// The demo policy with its `approvals:` block removed: calls that need a
/// human are refused instead of paused, and everything else is the same.
#[test]
fn poisoned_ticket_without_approvals() {
    require_python!();
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let demo = std::fs::read_to_string(example("writ.yaml")).unwrap();
    let start = 1 + demo.find("\napprovals:").expect("demo policy has an approvals block");
    let end = start + demo[start..].find("\n\n").unwrap();
    std::fs::write(path("writ.yaml"), format!("{}{}", &demo[..start], &demo[end + 2..])).unwrap();
    std::fs::copy(example("entitlements.yaml"), path("entitlements.yaml")).unwrap();
    let _stop = StopWritd(path("run/writd.sock"));
    let writ = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_writ"));
        cmd.env("WRIT_SOCKET", path("run/writd.sock"))
            .env("WRIT_LOG", path("flight.jsonl"))
            .env_remove("WRIT_TASK");
        cmd
    };

    let out = writ()
        .args(["run", "--principal", "alice@example.com", "--policy"])
        .arg(path("writ.yaml"))
        .args(["--", "python3", "-I"])
        .arg(fixture("demo_agent.py"))
        .env("WRIT_BIN", env!("CARGO_BIN_EXE_writ"))
        .env("DRIVER_OUT", path("driver.json"))
        .env("STRIPE_LEDGER", path("ledger.jsonl"))
        .output()
        .unwrap();
    assert!(out.status.success(), "writ run failed: {}", stderr(&out));

    let driver: Value = serde_json::from_str(&std::fs::read_to_string(path("driver.json")).unwrap()).unwrap();
    let r = &driver["results"];
    let allowed = |label: &str| assert!(!is_error(&r[label]), "{label} should be allowed: {}", r[label]);
    let refused = |label: &str, why: &str| {
        assert!(is_error(&r[label]), "{label} should be refused: {}", r[label]);
        assert!(
            text(&r[label]).contains(why),
            "{label}: expected `{why}` in {}",
            r[label]
        );
    };
    allowed("credit_before_ticket");
    allowed("read_ticket");
    refused("injected_refund", "outside the root's entitlement");
    allowed("small_refund");
    // With no approval broker, the calls that need a human are refused.
    refused("large_refund", "requires approval");
    refused("credit_after_ticket", "tainted");

    assert_eq!(
        read_jsonl(&path("ledger.jsonl")),
        [
            json!({ "op": "credit", "customer": "cus_alice", "amount": 10 }),
            json!({ "op": "refund", "charge": "ch_alice_small", "customer": "cus_alice", "amount": 40.0 }),
        ]
    );
    let log = read_jsonl(&path("flight.jsonl"));
    let start = log.iter().find(|e| e["kind"] == "task_start").unwrap();
    assert_eq!(start["data"]["root"]["principal"], "alice@example.com");
    assert_eq!(start["data"]["root"]["verified"], false);
    assert_eq!(log.iter().filter(|e| e["kind"] == "taint").count(), 1);
}

/// Stops the writd that `writ run` started for this test.
struct StopWritd(PathBuf);

impl Drop for StopWritd {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(self.0.with_extension("pid")) {
            let _ = Command::new("kill").args(["-TERM", pid.trim()]).status();
        }
    }
}

/// Polls `writ sudo list --json` until one approval is pending, then returns it.
fn next_pending(writ: &dyn Fn() -> Command, agent: &mut Child, deadline: Instant) -> Value {
    loop {
        assert!(
            agent.try_wait().unwrap().is_none(),
            "the agent finished while an approval was expected"
        );
        assert!(Instant::now() < deadline, "no approval became pending in time");
        let out = writ().args(["sudo", "list", "--json"]).output().unwrap();
        if out.status.success()
            && let Ok(Value::Array(pending)) = serde_json::from_slice::<Value>(&out.stdout)
            && let Some(first) = pending.into_iter().next()
        {
            return first;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn poisoned_ticket_demo() {
    require_python!();
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let writ = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_writ"));
        cmd.env("WRIT_SOCKET", path("run/writd.sock"))
            .env("WRIT_LOG", path("flight.jsonl"))
            .env_remove("WRIT_TASK");
        cmd
    };

    let _stop = StopWritd(path("run/writd.sock"));

    let check = writ().arg("check").arg(example("writ.yaml")).output().unwrap();
    assert!(check.status.success(), "demo policy should load: {}", stderr(&check));

    let mut agent = writ()
        .args(["run", "--principal", "alice@example.com", "--policy"])
        .arg(example("writ.yaml"))
        .args(["--", "python3", "-I"])
        .arg(fixture("demo_agent.py"))
        .env("WRIT_BIN", env!("CARGO_BIN_EXE_writ"))
        .env("DRIVER_OUT", path("driver.json"))
        .env("STRIPE_LEDGER", path("ledger.jsonl"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);

    // Step 5: Alice's own $240 charge is over the auto-limit. A human approves it.
    let first = next_pending(&writ, &mut agent, deadline);
    assert_eq!(first["tool"], "stripe.refund", "{first}");
    assert_eq!(first["arguments"]["charge"], "ch_alice_big", "{first}");
    let id = first["id"].as_str().expect("approval id is a string").to_string();
    let approve = writ().args(["sudo", "approve", &id]).output().unwrap();
    assert!(approve.status.success(), "{}", stderr(&approve));

    // Step 6: a credit on a tainted task, with no entitlement covering it. A human refuses.
    let second = next_pending(&writ, &mut agent, deadline);
    assert_eq!(second["tool"], "stripe.add_credit", "{second}");
    assert_ne!(second["id"], first["id"]);
    let id = second["id"].as_str().unwrap().to_string();
    let deny = writ().args(["sudo", "deny", &id]).output().unwrap();
    assert!(deny.status.success(), "{}", stderr(&deny));

    let out = agent.wait_with_output().unwrap();
    assert!(out.status.success(), "writ run failed: {}", stderr(&out));

    let driver: Value = serde_json::from_str(&std::fs::read_to_string(path("driver.json")).unwrap()).unwrap();
    let r = &driver["results"];
    let allowed = |label: &str| assert!(!is_error(&r[label]), "{label} should be allowed: {}", r[label]);
    let denied = |label: &str, why: &str| {
        assert!(is_error(&r[label]), "{label} should be denied: {}", r[label]);
        assert!(
            text(&r[label]).contains(why),
            "{label}: expected `{why}` in {}",
            r[label]
        );
    };
    allowed("credit_before_ticket");
    allowed("read_ticket");
    denied("injected_refund", "entitlement");
    allowed("small_refund");
    allowed("large_refund");
    denied("credit_after_ticket", "approver");
    assert_eq!(driver["exits"], json!([0, 0]));

    // Stripe saw exactly the three legitimate movements; the injected ones never reached it.
    assert_eq!(
        read_jsonl(&path("ledger.jsonl")),
        [
            json!({ "op": "credit", "customer": "cus_alice", "amount": 10 }),
            json!({ "op": "refund", "charge": "ch_alice_small", "customer": "cus_alice", "amount": 40.0 }),
            json!({ "op": "refund", "charge": "ch_alice_big", "customer": "cus_alice", "amount": 240.0 }),
        ]
    );

    // The flight log tells the whole story, and its chain verifies.
    let task = driver["task"].as_str().unwrap();
    let log = read_jsonl(&path("flight.jsonl"));
    let of_task: Vec<&Value> = log
        .iter()
        .filter(|e| e["session"] == task || e["data"]["task"] == task)
        .collect();
    let start = of_task.iter().find(|e| e["kind"] == "task_start").unwrap();
    assert_eq!(start["data"]["root"]["principal"], "alice@example.com", "{start}");
    assert_eq!(
        start["data"]["root"]["verified"], false,
        "a --principal root is unverified until IdP-backed roots exist"
    );
    let taint: Vec<&&Value> = of_task.iter().filter(|e| e["kind"] == "taint").collect();
    assert_eq!(taint.len(), 1, "the task is tainted once: {taint:?}");
    assert_eq!(taint[0]["data"]["source"], "mcp:zendesk-tickets");
    let approvals: Vec<&str> = of_task
        .iter()
        .filter(|e| e["kind"] == "approval")
        .map(|e| e["data"]["decision"].as_str().unwrap())
        .collect();
    assert_eq!(approvals, ["approve", "deny"]);

    let verify = writ()
        .args(["log", "--verify", "--log"])
        .arg(path("flight.jsonl"))
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", stderr(&verify));
}
