//! End-to-end: `writ wrap --name` and taint from a declared untrusted source.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

/// The wrapped server is declared untrusted, so its first allowed call taints the task.
const POLICY: &str = r#"
version: 1
namespace: taint-e2e
data_flow:
  untrusted_sources: ["mcp:tickets"]
capabilities:
  - tool: "postgres.query"
  - tool: "stripe.refund"
    privileged: true
  - tool: "*"
    action: deny
"#;

fn has_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_mcp_server.py")
}

fn call(id: u64, tool: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": tool, "arguments": {} } })
    .to_string()
}

/// Runs a standalone `writ wrap` with `extra` flags over `calls`.
fn wrap(dir: &Path, extra: &[&str], calls: &[String]) -> Output {
    let policy = dir.join("writ.yaml");
    std::fs::write(&policy, POLICY).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_writ"))
        .arg("wrap")
        .args(extra)
        .arg("--policy")
        .arg(&policy)
        .arg("--log")
        .arg(dir.join("flight.jsonl"))
        .args(["--", "python3", "-I"])
        .arg(fixture())
        .env("FAKE_MCP_LOG", dir.join("server.log"))
        .env_remove("WRIT_TASK")
        .env_remove("WRIT_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in calls {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    child.wait_with_output().unwrap()
}

/// Responses ordered by id. writ answers denials itself, so they can arrive
/// before the server's answers to earlier calls.
fn responses(out: &Output) -> Vec<Value> {
    let mut all: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    all.sort_by_key(|r| r["id"].as_u64());
    all
}

fn is_tool_error(response: &Value) -> bool {
    response["result"]["isError"] == json!(true)
}

#[test]
fn a_named_untrusted_server_taints_its_task() {
    if !has_python() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = wrap(
        dir.path(),
        &["--name", "tickets"],
        &[
            call(1, "stripe.refund"),
            call(2, "postgres.query"),
            call(3, "stripe.refund"),
        ],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let r = responses(&out);
    // The first call is decided before anything untrusted was read.
    assert!(!is_tool_error(&r[0]), "{}", r[0]);
    assert!(!is_tool_error(&r[1]), "{}", r[1]);
    // After that, the privileged refund needs a human.
    let text = r[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(is_tool_error(&r[2]) && text.contains("tainted"), "{}", r[2]);
    let server_saw = std::fs::read_to_string(dir.path().join("server.log")).unwrap();
    assert!(!server_saw.contains("\"id\":3"), "{server_saw}");

    let log = Command::new(env!("CARGO_BIN_EXE_writ"))
        .args(["log", "--log"])
        .arg(dir.path().join("flight.jsonl"))
        .output()
        .unwrap();
    let log = String::from_utf8(log.stdout).unwrap();
    assert!(log.contains("mcp:tickets"), "{log}");
    assert!(log.contains("tainted: stripe.refund read from mcp:tickets"), "{log}");
}

#[test]
fn unnamed_servers_get_a_derived_name_and_a_warning() {
    if !has_python() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = wrap(dir.path(), &[], &[call(1, "postgres.query")]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("`mcp:fake_mcp_server`") && stderr.contains("--name"),
        "{stderr}"
    );
    // A derived name isn't declared untrusted here, so nothing is tainted.
    assert!(!is_tool_error(&responses(&out)[0]));

    let bad = wrap(dir.path(), &["--name", "has space"], &[]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("invalid server name"));
}
