//! End-to-end: paused calls don't block others, an agent can't approve its
//! own calls with `writ sudo`, approved calls reach the server, and
//! undecided ones time out.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const POLICY: &str = r#"
version: 1
namespace: approvals-e2e
approvals:
  timeout: 3s
capabilities:
  - tool: "postgres.query"
  - tool: "stripe.refund"
    conditions: ["args.amount <= 100"]
    on_violation: require_sudo
  - tool: "*"
    action: deny
"#;

fn has_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

struct StopWritd(PathBuf);

impl Drop for StopWritd {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(self.0.with_extension("pid")) {
            let _ = Command::new("kill").args(["-TERM", pid.trim()]).status();
        }
    }
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"].as_str().unwrap_or_default()
}

#[test]
fn paused_calls_wait_for_a_human_without_blocking_others() {
    if !has_python() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    std::fs::write(path("writ.yaml"), POLICY).unwrap();
    let _stop = StopWritd(path("run/writd.sock"));
    let writ = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_writ"));
        cmd.env("WRIT_SOCKET", path("run/writd.sock"))
            .env("WRIT_LOG", path("flight.jsonl"))
            .env_remove("WRIT_TASK");
        cmd
    };

    let mut agent = writ()
        .args(["run", "--policy"])
        .arg(path("writ.yaml"))
        .args(["--", "python3", "-I"])
        .arg(fixture("approvals_agent.py"))
        .env("WRIT_BIN", env!("CARGO_BIN_EXE_writ"))
        .env("DRIVER_OUT", path("driver.json"))
        .env("FAKE_MCP_LOG", path("server.log"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Approve the first refund once it's waiting, from outside the task.
    let deadline = Instant::now() + Duration::from_secs(20);
    let id = loop {
        assert!(Instant::now() < deadline, "no approval became pending");
        assert!(agent.try_wait().unwrap().is_none(), "agent exited early");
        let out = writ().args(["sudo", "list", "--json"]).output().unwrap();
        if let Ok(Value::Array(list)) = serde_json::from_slice::<Value>(&out.stdout)
            && let Some(first) = list.first()
        {
            assert_eq!(first["arguments"]["amount"], 240);
            break first["id"].as_str().unwrap().to_string();
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Give the agent time to try (and fail) to approve it itself.
    std::thread::sleep(Duration::from_millis(500));
    let show = writ().args(["sudo", "show", &id]).output().unwrap();
    let show = String::from_utf8_lossy(&show.stdout).to_string();
    assert!(show.contains("stripe.refund") && show.contains("mcp:stripe"), "{show}");
    let approve = writ().args(["sudo", "approve", &id]).output().unwrap();
    assert!(approve.status.success(), "{}", String::from_utf8_lossy(&approve.stderr));
    let again = writ().args(["sudo", "deny", &id]).output().unwrap();
    assert!(!again.status.success(), "an approval is decided once");

    let out = agent.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("waiting for approval") && stderr.contains(&id),
        "{stderr}"
    );

    let driver: Value = serde_json::from_str(&std::fs::read_to_string(path("driver.json")).unwrap()).unwrap();
    // The query was answered while the refund was paused.
    assert_eq!(driver["order"], json!([2, 1]), "{driver}");
    // The agent, inside the task, couldn't approve its own call.
    assert_eq!(driver["self_approve"]["code"], 2, "{driver}");
    assert!(
        driver["self_approve"]["stderr"]
            .as_str()
            .unwrap()
            .contains("inside a writ task")
    );
    let r = &driver["responses"];
    assert_eq!(r["1"]["result"]["isError"], json!(false), "approved refund: {}", r["1"]);
    assert!(text(&r["1"]).contains("executed stripe.refund"), "{}", r["1"]);
    // Nobody decided the second refund: it timed out after about 3s.
    assert_eq!(r["3"]["result"]["isError"], json!(true));
    assert!(text(&r["3"]).contains("no approver decided within 3s"), "{}", r["3"]);
    let waited = driver["timeout_waited_s"].as_f64().unwrap();
    assert!((2.5..10.0).contains(&waited), "waited {waited}s");

    let server_saw = std::fs::read_to_string(path("server.log")).unwrap();
    assert!(server_saw.contains("\"amount\":240"), "{server_saw}");
    assert!(
        !server_saw.contains("\"amount\":300"),
        "a timed-out call reached the server: {server_saw}"
    );

    let log: Vec<Value> = std::fs::read_to_string(path("flight.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let settled: Vec<(&str, Option<&str>)> = log
        .iter()
        .filter(|e| e["kind"] == "approval")
        .map(|e| {
            (
                e["data"]["decision"].as_str().unwrap(),
                e["data"]["approver"]["via"].as_str(),
            )
        })
        .collect();
    assert_eq!(settled, [("approve", Some("writ sudo")), ("timeout", None)]);
}
