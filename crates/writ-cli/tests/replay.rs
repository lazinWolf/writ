//! End-to-end: record calls with `writ wrap`, then `writ replay` them under
//! other policies.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

const RECORDED: &str = r#"
version: 1
namespace: replay-e2e
capabilities:
  - tool: "postgres.query"
  - tool: "stripe.refund"
    conditions: ["args.amount <= 100"]
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

fn call(id: u64, tool: &str, args: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } })
        .to_string()
}

fn writ(log: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_writ"));
    cmd.env("WRIT_LOG", log).env_remove("WRIT_TASK");
    cmd
}

#[test]
fn replay_shows_what_a_candidate_policy_would_change() {
    if !has_python() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let log = path("flight.jsonl");
    std::fs::write(path("recorded.yaml"), RECORDED).unwrap();

    let mut wrap = writ(&log)
        .args(["wrap", "--name", "stripe", "--policy"])
        .arg(path("recorded.yaml"))
        .args(["--", "python3", "-I"])
        .arg(fixture())
        .env("FAKE_MCP_LOG", path("server.log"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut stdin = wrap.stdin.take().unwrap();
        for line in [
            call(1, "stripe.refund", json!({ "amount": 40 })),
            call(2, "stripe.refund", json!({ "amount": 240 })),
            call(3, "postgres.query", json!({ "sql": "select 1" })),
            call(4, "shell.exec", json!({ "cmd": "printenv" })),
        ] {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    assert!(wrap.wait().unwrap().success());

    let replay = |candidate: &str, extra: &[&str]| {
        std::fs::write(path("candidate.yaml"), candidate).unwrap();
        writ(&log)
            .args(["replay", "--policy"])
            .arg(path("candidate.yaml"))
            .args(extra)
            .output()
            .unwrap()
    };

    // The same policy: nothing changes, exit 0.
    let out = replay(RECORDED, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("replayed 4 calls") && stdout.contains("0 would change"),
        "{stdout}"
    );

    // Stricter: a lower refund limit. Exit 0: nothing gets looser.
    let stricter = RECORDED.replace("args.amount <= 100", "args.amount <= 10");
    let out = replay(&stricter, &["--json"]);
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let flips = report["flips"].as_array().unwrap();
    assert_eq!(flips.len(), 1, "{report}");
    assert_eq!(flips[0]["arguments"]["amount"], 40);
    assert_eq!(flips[0]["after"]["outcome"], "deny");

    // Asking a human instead of denying is looser than deny: the $240 refund
    // could now run. Exit 1.
    let ask = RECORDED.replace(
        "    conditions: [\"args.amount <= 100\"]\n",
        "    conditions: [\"args.amount <= 100\"]\n    on_violation: require_sudo\n",
    );
    let out = replay(&ask, &["--json"]);
    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["flips"][0]["before"]["outcome"], "deny", "{report}");
    assert_eq!(report["flips"][0]["after"]["outcome"], "require_sudo");

    // Looser: shell access allowed. Exit 1, and the call is named.
    let looser = RECORDED.replace("  - tool: \"*\"\n    action: deny\n", "  - tool: \"*\"\n");
    let out = replay(&looser, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("shell.exec") && stdout.contains("DENY -> ALLOW  LOOSER"),
        "{stdout}"
    );
    assert!(stdout.contains("would be allowed more freely"), "{stdout}");

    // Filtering by an unknown task replays nothing.
    let out = replay(&looser, &["--task", "tsk_nope"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("replayed 0 calls"));
}
