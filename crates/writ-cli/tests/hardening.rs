//! End-to-end: redaction, server-initiated requests, and shutdown behaviour.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const POLICY: &str = r#"
version: 1
namespace: hardening
capabilities:
  - tool: "stripe.refund"
    redact: ["args.card"]
    conditions: ["args.card.number == \"4242\""]
  - tool: "postgres.*"
    record_arguments: false
  - tool: "sample"
  - tool: "*"
    action: deny
"#;

struct Session {
    child: Child,
    dir: tempfile::TempDir,
}

impl Session {
    fn start(mode: &str, grace: &str) -> Session {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("writ.yaml"), POLICY).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_mcp_server.py");
        let child = Command::new(env!("CARGO_BIN_EXE_writ"))
            .args(["wrap", "--shutdown-grace", grace, "--policy"])
            .arg(dir.path().join("writ.yaml"))
            .arg("--log")
            .arg(dir.path().join("flight.jsonl"))
            .args(["--", "python3", "-I"])
            .arg(fixture)
            .env("FAKE_MCP_LOG", dir.path().join("server.log"))
            .env("FAKE_MCP_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Session { child, dir }
    }

    fn log_path(&self) -> PathBuf {
        self.dir.path().join("flight.jsonl")
    }

    fn entries(&self) -> Vec<Value> {
        std::fs::read_to_string(self.log_path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn entry(&self, kind: &str) -> Option<Value> {
        self.entries().into_iter().find(|e| e["kind"] == kind)
    }

    fn server_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("server.log")).unwrap_or_default()
    }

    /// Waits for writ to exit and returns its exit code and how long it took.
    fn wait(&mut self, limit: Duration) -> (Option<i32>, Duration) {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return (status.code(), start.elapsed());
            }
            if start.elapsed() > limit {
                let _ = self.child.kill();
                panic!("writ did not exit within {limit:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_entry(&self, kind: &str) -> Value {
        let start = Instant::now();
        loop {
            if let Some(entry) = self.entry(kind) {
                return entry;
            }
            assert!(start.elapsed() < Duration::from_secs(10), "no {kind} entry");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn has_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn alive(pid: u64) -> bool {
    // A zombie still has a /proc entry; check its state too.
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(')')
            .next()
            .is_some_and(|rest| !rest.trim_start().starts_with('Z'))
    })
}

fn eventually_dead(pid: u64) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn line(id: u64, tool: &str, args: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } })
        .to_string()
}

macro_rules! require_python {
    () => {
        if !has_python() {
            eprintln!("skipping: python3 not found");
            return;
        }
    };
}

#[test]
fn redacts_arguments_and_records_server_requests() {
    require_python!();
    let mut s = Session::start("", "2s");
    {
        let mut stdin = s.child.stdin.take().unwrap();
        for l in [
            line(
                1,
                "stripe.refund",
                json!({ "card": { "number": "1111-secret" }, "amount": 5 }),
            ),
            line(2, "postgres.query", json!({ "sql": "select ssn from people" })),
            line(3, "sample", json!({})),
        ] {
            writeln!(stdin, "{l}").unwrap();
        }
    }
    let (code, _) = s.wait(Duration::from_secs(10));
    assert_eq!(code, Some(0));

    let log = std::fs::read_to_string(s.log_path()).unwrap();
    for secret in ["1111-secret", "select ssn", "secret prompt"] {
        assert!(!log.contains(secret), "flight log contains {secret:?}:\n{log}");
    }

    let calls: Vec<Value> = s.entries().into_iter().filter(|e| e["kind"] == "tool_call").collect();
    assert_eq!(
        calls[0]["data"]["arguments"],
        json!({ "card": "[redacted]", "amount": 5 })
    );
    assert_eq!(calls[0]["data"]["decision"]["outcome"], "deny");
    assert!(
        calls[0]["data"]["decision"]["reason"]
            .as_str()
            .unwrap()
            .contains("value redacted")
    );
    assert_eq!(calls[1]["data"]["arguments_omitted"], true);
    assert!(calls[1]["data"].get("arguments").is_none());

    let request = s.entry("server_request").expect("server_request recorded");
    assert_eq!(
        request["data"],
        json!({ "id": "srv-1", "method": "sampling/createMessage" })
    );
}

#[test]
fn terminates_a_server_that_ignores_stdin_closing() {
    require_python!();
    let mut s = Session::start("linger", "300ms");
    drop(s.child.stdin.take());
    let (code, took) = s.wait(Duration::from_secs(10));
    assert!(took < Duration::from_secs(3), "took {took:?}");
    assert_eq!(code, Some(128 + 15), "server died from SIGTERM");
    assert_eq!(s.entry("session_end").unwrap()["data"]["termination"], "terminated");
}

#[test]
fn kills_a_server_that_ignores_sigterm() {
    require_python!();
    let mut s = Session::start("stubborn", "300ms");
    drop(s.child.stdin.take());
    let (code, took) = s.wait(Duration::from_secs(10));
    assert!(took < Duration::from_secs(5), "took {took:?}");
    assert_eq!(code, Some(128 + 9));
    assert_eq!(s.entry("session_end").unwrap()["data"]["termination"], "killed");
}

#[test]
fn ends_the_session_when_the_server_closes_stdout() {
    require_python!();
    // The client keeps stdin open; the server closes stdout and keeps running.
    let mut s = Session::start("close_stdout", "300ms");
    let (_, took) = s.wait(Duration::from_secs(10));
    assert!(took < Duration::from_secs(3), "took {took:?}");
    assert_eq!(s.entry("session_end").unwrap()["data"]["termination"], "terminated");
}

#[test]
fn reaps_grandchildren_that_hold_stdout_open() {
    require_python!();
    let mut s = Session::start("grandchild", "2s");
    drop(s.child.stdin.take());
    let (code, took) = s.wait(Duration::from_secs(10));
    // The server itself exits cleanly; its `sleep` keeps the pipe open until writ terminates the group.
    assert_eq!(code, Some(0));
    assert!(took < Duration::from_secs(5), "took {took:?}");
    let grandchild: u64 = s
        .server_log()
        .lines()
        .find_map(|l| l.strip_prefix("GRANDCHILD "))
        .expect("grandchild pid logged")
        .trim()
        .parse()
        .unwrap();
    assert!(eventually_dead(grandchild), "grandchild {grandchild} survived");
}

#[test]
fn forwards_sigterm_to_the_server() {
    require_python!();
    let mut s = Session::start("", "5s");
    let start = s.wait_for_entry("session_start");
    let server_pid = start["data"]["server_pid"].as_u64().unwrap();
    assert!(alive(server_pid));

    let killed = Command::new("kill")
        .args(["-TERM", &s.child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let (code, took) = s.wait(Duration::from_secs(10));
    assert_eq!(code, Some(128 + 15), "writ reports the signal it received");
    assert!(took < Duration::from_secs(3), "took {took:?}");
    assert!(eventually_dead(server_pid), "server {server_pid} outlived writ");
    let end = s.entry("session_end").unwrap();
    assert_eq!(end["data"]["writ_signal"], 15);
}
