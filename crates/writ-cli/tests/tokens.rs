//! End-to-end: signed task tokens, `writ fork`, and keeping the token away
//! from wrapped servers.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

const TASK_POLICY: &str = r#"
version: 1
namespace: tokens-e2e
limits:
  max_depth: 2
capabilities:
  - tool: "postgres.*"
  - tool: "stripe.refund"
  - tool: "*"
    action: deny
"#;

/// The billing sub-agent: small refunds only, two calls between all its servers.
const BILLING_POLICY: &str = r#"
version: 1
namespace: billing
limits:
  max_tool_calls: 2
capabilities:
  - tool: "stripe.refund"
    conditions: ["args.amount <= 50"]
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

fn reason(response: &Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn forks_narrow_a_task_and_the_token_never_reaches_a_server() {
    if !has_python() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    std::fs::write(path("task.yaml"), TASK_POLICY).unwrap();
    std::fs::write(path("billing.yaml"), BILLING_POLICY).unwrap();
    let log = path("flight.jsonl");

    let out = Command::new(env!("CARGO_BIN_EXE_writ"))
        .env("WRIT_SOCKET", path("run/writd.sock"))
        .env("WRIT_LOG", &log)
        .env("WRIT_BIN", env!("CARGO_BIN_EXE_writ"))
        .env("BILLING_POLICY", path("billing.yaml"))
        .env("DRIVER_OUT", path("driver.json"))
        .env("FAKE_MCP_LOG", path("server.log"))
        .env_remove("WRIT_TASK")
        .env_remove("WRIT_TOKEN")
        .args(["run", "--log"])
        .arg(&log)
        .arg("--policy")
        .arg(path("task.yaml"))
        .args(["--", "python3", "-I"])
        .arg(fixture("fork_agent.py"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // writd outlives `writ run`; stop it.
    if let Ok(pid) = std::fs::read_to_string(path("run/writd.pid")) {
        let _ = Command::new("kill").arg(pid.trim()).status();
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let r: Value = serde_json::from_str(&std::fs::read_to_string(path("driver.json")).unwrap()).unwrap();
    let server_log = std::fs::read_to_string(path("server.log")).unwrap();

    // The root token works, and the server never saw it.
    assert_eq!(r["root_query"]["result"]["isError"], false, "{}", r["root_query"]);
    let env_line = server_log.lines().find(|l| l.starts_with("ENV")).unwrap();
    assert!(!env_line.contains("WRIT_TOKEN"), "{env_line}");
    assert!(
        r["leak"]["error"]["message"].as_str().unwrap().contains("writ token"),
        "{}",
        r["leak"]
    );
    assert!(
        !server_log.contains("loot"),
        "the token-bearing call reached the server"
    );

    // The fork narrows: no queries, small refunds, two calls across both of its servers.
    assert!(
        reason(&r["fork_query"]).contains("fork `billing` policy"),
        "{}",
        r["fork_query"]
    );
    assert_eq!(r["fork_refund_1"]["result"]["isError"], false, "{}", r["fork_refund_1"]);
    assert_eq!(r["fork_refund_2"]["result"]["isError"], false, "{}", r["fork_refund_2"]);
    assert!(
        reason(&r["fork_refund_3"]).contains("fork `billing` max_tool_calls limit reached (2)"),
        "{}",
        r["fork_refund_3"]
    );
    // The parent keeps its own authority.
    assert_eq!(r["root_refund"]["result"]["isError"], false, "{}", r["root_refund"]);

    // Too deep, or tampered with: the wrap refuses to start its server.
    assert_eq!(r["too_deep"]["code"], 2, "{}", r["too_deep"]);
    assert!(
        r["too_deep"]["stderr"].as_str().unwrap().contains("max_depth 2"),
        "{}",
        r["too_deep"]
    );
    assert_eq!(r["tampered"]["code"], 2, "{}", r["tampered"]);
    assert!(!server_log.contains("refused"), "a refused wrap started its server");
    assert_eq!(r["exec_token_differs"], true);

    // The log records each session's lineage, never a token itself.
    let flight = std::fs::read_to_string(&log).unwrap();
    for token in r["tokens"].as_array().unwrap() {
        assert!(
            !flight.contains(token.as_str().unwrap()),
            "a token was written to the log"
        );
    }
    let forked: Vec<Value> = flight
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|e| e["kind"] == "session_start" && e["data"]["writ"]["depth"] == 1)
        .collect();
    assert_eq!(forked.len(), 2, "both billing sessions record their fork");
    assert_eq!(forked[0]["data"]["writ"]["forks"][0]["label"], "billing");
    assert_eq!(
        forked[0]["data"]["writ"]["forks"][0]["policy_sha256"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
