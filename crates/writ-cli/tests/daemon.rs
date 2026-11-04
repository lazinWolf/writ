//! End-to-end: writd, `writ run`, task-scoped limits, narrowing, and failing closed.

use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const TASK_POLICY: &str = r#"
version: 1
namespace: daemon-e2e
limits:
  max_tool_calls: 3
capabilities:
  - tool: "postgres.*"
  - tool: "stripe.refund"
  - tool: "*"
    action: deny
"#;

/// Server B may not refund at all, even though the task allows it.
const NARROW_POLICY: &str = r#"
version: 1
namespace: narrow
capabilities:
  - tool: "postgres.*"
  - tool: "*"
    action: deny
"#;

/// A temp dir with its own writd socket and log; kills writd on drop.
struct Env {
    dir: tempfile::TempDir,
    /// A writd this test started directly (writ run starts its own).
    writd: RefCell<Option<Child>>,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("task.yaml"), TASK_POLICY).unwrap();
        std::fs::write(dir.path().join("narrow.yaml"), NARROW_POLICY).unwrap();
        Env {
            dir,
            writd: RefCell::new(None),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn socket(&self) -> PathBuf {
        self.path("run/writd.sock")
    }

    fn writ(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_writ"));
        cmd.env("WRIT_SOCKET", self.socket())
            .env("WRIT_LOG", self.path("flight.jsonl"))
            .env_remove("WRIT_TASK")
            .env_remove("WRIT_TOKEN");
        cmd
    }

    fn start_writd(&self) {
        let child = Command::new(env!("CARGO_BIN_EXE_writd"))
            .arg("--socket")
            .arg(self.socket())
            .arg("--log")
            .arg(self.path("flight.jsonl"))
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        *self.writd.borrow_mut() = Some(child);
        let start = Instant::now();
        while !self.socket().exists() {
            assert!(start.elapsed() < Duration::from_secs(5), "writd did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn writd_pid(&self) -> Option<String> {
        std::fs::read_to_string(self.socket().with_extension("pid"))
            .ok()
            .map(|p| p.trim().to_string())
    }

    fn stop_writd(&self) {
        if let Some(pid) = self.writd_pid() {
            let _ = Command::new("kill").args(["-TERM", &pid]).status();
            let start = Instant::now();
            while self.socket().exists() && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(mut child) = self.writd.borrow_mut().take() {
            let _ = child.wait();
        }
    }

    fn entries(&self) -> Vec<Value> {
        std::fs::read_to_string(self.path("flight.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop_writd();
    }
}

fn has_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"].as_str().unwrap_or_default()
}

fn denied(response: &Value) -> bool {
    response["result"]["isError"] == json!(true)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
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
fn run_shares_limits_across_servers_and_narrowing_only_restricts() {
    require_python!();
    let env = Env::new();
    let out = env
        .writ()
        .args(["run", "--policy"])
        .arg(env.path("task.yaml"))
        .args(["--", "python3", "-I"])
        .arg(fixture("agent_driver.py"))
        .env("WRIT_BIN", env!("CARGO_BIN_EXE_writ"))
        .env("NARROW_POLICY", env.path("narrow.yaml"))
        .env("DRIVER_OUT", env.path("driver.json"))
        .env("FAKE_MCP_LOG", env.path("server.log"))
        .output()
        .unwrap();
    assert!(out.status.success(), "writ run failed: {}", stderr(&out));
    assert!(env.writd_pid().is_some(), "writ run should have started writd");

    let driver: Value = serde_json::from_str(&std::fs::read_to_string(env.path("driver.json")).unwrap()).unwrap();
    let r: Vec<&Value> = driver["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| &pair[1])
        .collect();
    assert!(!denied(r[0]), "A query: {}", r[0]);
    assert!(!denied(r[1]), "B query: {}", r[1]);
    // The task allows refunds; B's own policy narrows them away.
    assert!(
        denied(r[2]) && text(r[2]).contains("session policy"),
        "B refund: {}",
        r[2]
    );
    // A has no narrowing policy, so the task's allow stands. That is the 3rd allowed call.
    assert!(!denied(r[3]), "A refund: {}", r[3]);
    // B's next call exceeds the task-wide limit of 3, even though B has made only 1 allowed call.
    assert!(
        denied(r[4]) && text(r[4]).contains("task max_tool_calls"),
        "B over limit: {}",
        r[4]
    );
    assert_eq!(driver["exits"], json!([0, 0]));

    let ps = driver["ps"].as_str().unwrap();
    let task = driver["task"].as_str().unwrap();
    let row = ps
        .lines()
        .find(|l| l.starts_with(task))
        .unwrap_or_else(|| panic!("task missing from ps:\n{ps}"));
    assert!(row.contains("daemon-e2e") && row.contains("3/3"), "{row}");

    // writd ended the task when writ run finished, and the whole story is in one verified chain.
    let ps_after = String::from_utf8(env.writ().arg("ps").output().unwrap().stdout).unwrap();
    assert!(
        !ps_after.contains(task),
        "task still live after writ run exited:\n{ps_after}"
    );
    let entries = env.entries();
    let kinds: Vec<&str> = entries
        .iter()
        .filter(|e| e["session"] == task || e["data"]["task"] == task)
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.first(), Some(&"task_start"));
    assert_eq!(kinds.last(), Some(&"task_end"));
    assert_eq!(kinds.iter().filter(|k| **k == "session_start").count(), 2);
    assert_eq!(kinds.iter().filter(|k| **k == "tool_call").count(), 5);
    let verify = env
        .writ()
        .args(["log", "--verify", "--log"])
        .arg(env.path("flight.jsonl"))
        .output()
        .unwrap();
    assert!(verify.status.success(), "{}", stderr(&verify));
}

#[test]
fn wrap_refuses_to_run_when_its_task_cannot_be_enforced() {
    require_python!();
    let env = Env::new();
    let wrap = |env: &Env, var: &str, value: &str| {
        env.writ()
            .env(var, value)
            .args(["wrap", "--", "python3", "-I"])
            .arg(fixture("fake_mcp_server.py"))
            .env("FAKE_MCP_LOG", env.path("server.log"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    // A bare task id (what earlier builds used) is refused, not ignored.
    let out = wrap(&env, "WRIT_TASK", "tsk_does_not_exist");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("no longer join a task"), "{}", stderr(&out));

    // No writd at all.
    let out = wrap(&env, "WRIT_TOKEN", "not-a-token");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("refusing to run the server"), "{}", stderr(&out));

    // writd is up, but the token isn't one.
    env.start_writd();
    let out = wrap(&env, "WRIT_TOKEN", "not-a-token");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("not a writ token"), "{}", stderr(&out));
    assert!(!env.path("server.log").exists(), "the server must not have started");
}

#[test]
fn calls_are_denied_once_writd_is_gone() {
    require_python!();
    let env = Env::new();
    env.start_writd();
    let mut child = env
        .writ()
        .args(["wrap", "--daemon", "--policy"])
        .arg(env.path("task.yaml"))
        .args(["--", "python3", "-I"])
        .arg(fixture("fake_mcp_server.py"))
        .env("FAKE_MCP_LOG", env.path("server.log"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut call = |id: u64| {
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
                           "params": { "name": "postgres.query", "arguments": {} } });
        writeln!(stdin, "{line}").unwrap();
        let mut reply = String::new();
        std::io::BufRead::read_line(&mut stdout, &mut reply).unwrap();
        serde_json::from_str::<Value>(&reply).unwrap()
    };

    assert!(!denied(&call(1)));
    // A standalone --daemon session is visible to `writ ps`.
    let ps = String::from_utf8(env.writ().arg("ps").output().unwrap().stdout).unwrap();
    assert!(ps.contains("(standalone wrap)"), "{ps}");

    env.stop_writd();
    let reply = call(2);
    assert!(denied(&reply) && text(&reply).contains("writd"), "{reply}");
    let server_saw = std::fs::read_to_string(env.path("server.log")).unwrap();
    assert!(
        server_saw.contains("\"id\":1"),
        "allowed call should reach the server: {server_saw}"
    );
    assert!(
        !server_saw.contains("\"id\":2"),
        "denied call reached the server: {server_saw}"
    );
    drop(stdin);
    child.wait().unwrap();
}
