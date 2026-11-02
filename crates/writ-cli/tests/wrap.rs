//! End-to-end: the real `writ` binary wrapping a fake MCP server.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

const POLICY: &str = r#"
version: 1
namespace: e2e
limits:
  max_tool_calls: 2
capabilities:
  - tool: "postgres.*"
  - tool: "postgres.drop_*"
    action: deny
  - tool: "stripe.refund"
    conditions: ["args.amount <= 100.00"]
    on_violation: require_sudo
  - tool: "*"
    action: deny
"#;

struct Run {
    responses: HashMap<String, Value>,
    server_saw: String,
    log: PathBuf,
    status: std::process::ExitStatus,
    _dir: tempfile::TempDir,
}

fn python() -> Option<&'static str> {
    Command::new("python3")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| "python3")
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_mcp_server.py")
}

/// Sends `lines` to `writ wrap`, closes stdin, and collects every response by id.
fn wrap(python: &str, lines: &[String]) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("writ.yaml");
    std::fs::write(&policy, POLICY).unwrap();
    let log = dir.path().join("flight.jsonl");
    let server_log = dir.path().join("server.log");

    let mut child = Command::new(env!("CARGO_BIN_EXE_writ"))
        .arg("wrap")
        .arg("--policy")
        .arg(&policy)
        .arg("--log")
        .arg(&log)
        .arg("--")
        .args([python, "-I"])
        .arg(fixture())
        .env("FAKE_MCP_LOG", &server_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in lines {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();

    let mut responses = HashMap::new();
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let message: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("bad output line {line:?}: {e}"));
        responses.insert(message["id"].to_string(), message);
    }
    Run {
        responses,
        server_saw: std::fs::read_to_string(&server_log).unwrap_or_default(),
        log,
        status: output.status,
        _dir: dir,
    }
}

fn request(id: u64, method: &str, params: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
}

fn call(id: u64, tool: &str, args: Value) -> String {
    request(id, "tools/call", json!({ "name": tool, "arguments": args }))
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"].as_str().unwrap_or_default()
}

fn is_tool_error(response: &Value) -> bool {
    response["result"]["isError"] == json!(true)
}

#[test]
fn enforces_policy_end_to_end() {
    let Some(python) = python() else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let run = wrap(
        python,
        &[
            request(1, "initialize", json!({})),
            request(2, "tools/list", json!({})),
            call(3, "postgres.query", json!({ "sql": "select 1" })),
            call(4, "stripe.refund", json!({ "amount": 240 })),
            call(5, "shell.exec", json!({ "cmd": "printenv" })),
            call(6, "postgres.drop_table", json!({ "table": "invoices" })),
            call(7, "stripe.refund", json!({ "amount": 40 })),
            // Third allowed call: over max_tool_calls = 2.
            call(8, "postgres.query", json!({ "sql": "select 2" })),
        ],
    );
    let r = &run.responses;
    assert!(run.status.success(), "writ exited with {:?}", run.status);

    assert_eq!(r["1"]["result"]["serverInfo"]["name"], "fake");

    let listed: Vec<&str> = r["2"]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed, ["postgres.query", "stripe.refund"]);

    assert!(!is_tool_error(&r["3"]) && text(&r["3"]).starts_with("executed postgres.query"));

    assert!(
        is_tool_error(&r["4"]) && text(&r["4"]).contains("requires approval"),
        "{}",
        r["4"]
    );
    assert!(text(&r["4"]).contains("args.amount = 240"));

    assert!(is_tool_error(&r["5"]) && text(&r["5"]).contains("denied"));
    assert!(is_tool_error(&r["6"]) && text(&r["6"]).contains("postgres.drop_*"));
    assert!(!is_tool_error(&r["7"]), "{}", r["7"]);
    assert!(is_tool_error(&r["8"]) && text(&r["8"]).contains("max_tool_calls"));

    // Denied calls never reached the server.
    assert!(run.server_saw.contains("select 1"));
    for absent in ["printenv", "invoices", "240", "select 2"] {
        assert!(
            !run.server_saw.contains(absent),
            "server saw {absent}: {}",
            run.server_saw
        );
    }

    // The flight recorder has a verifiable chain with one decision per call:
    // task_start, session_start, 6 tool_call, 2 tool_result, tools_hidden, session_end, task_end.
    assert_eq!(
        writ_recorder_verify(&run.log),
        13,
        "{}",
        std::fs::read_to_string(&run.log).unwrap()
    );
    let log = std::fs::read_to_string(&run.log).unwrap();
    let kinds: Vec<String> = log
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    // A standalone wrap is an implicit task with one session.
    assert_eq!(kinds[..2], ["task_start", "session_start"]);
    assert_eq!(kinds[kinds.len() - 2..], ["session_end", "task_end"]);
    assert_eq!(kinds.iter().filter(|k| *k == "tool_call").count(), 6);
    assert_eq!(kinds.iter().filter(|k| *k == "tool_result").count(), 2);
}

#[test]
fn rejects_malformed_and_ambiguous_messages() {
    let Some(python) = python() else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let run = wrap(
        python,
        &[
            "this is not json".to_string(),
            format!("[{}]", call(20, "postgres.query", json!({}))),
            // Duplicate keys: the proxy decides on the value it parsed and
            // forwards its own serialization, so the server cannot see a
            // different tool than the one the policy checked.
            r#"{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"postgres.query","name":"shell.exec","arguments":{}}}"#
                .to_string(),
            request(22, "tools/call", json!({ "arguments": {} })),
        ],
    );
    let r = &run.responses;

    assert_eq!(r["null"]["error"]["code"], -32700);
    assert_eq!(r["20"]["error"]["code"], -32600);
    assert_eq!(r["22"]["error"]["code"], -32602);

    let dup = &r["21"];
    let reached_server = run.server_saw.contains("\"id\":21");
    if is_tool_error(dup) {
        assert!(!reached_server, "a denied call reached the server");
    } else {
        // If the proxy allowed it, the server must have seen only the allowed name.
        assert!(text(dup).starts_with("executed postgres.query"), "{dup}");
        assert!(!run.server_saw.contains("shell.exec"));
    }
    assert!(!run.server_saw.contains("\"id\":20"), "batched call reached the server");
}

#[test]
fn check_rejects_unenforced_fields() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("writ.yaml");
    std::fs::write(&policy, "version: 1\nnamespace: t\nlimits:\n  max_budget_usd: 1.5\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_writ"))
        .arg("check")
        .arg(&policy)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("limits.max_budget_usd") && stderr.contains("not enforced"),
        "{stderr}"
    );

    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/writ.yaml");
    let out = Command::new(env!("CARGO_BIN_EXE_writ"))
        .arg("check")
        .arg(example)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// Runs `writ log --verify` and returns the verified entry count.
fn writ_recorder_verify(log: &Path) -> u64 {
    let out = Command::new(env!("CARGO_BIN_EXE_writ"))
        .args(["log", "--verify", "--log"])
        .arg(log)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    stdout
        .split(": ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap()
        .parse()
        .unwrap()
}
