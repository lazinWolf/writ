"""Checks `writ wrap` against the MCP reference "everything" server from npm.

Usage: real_server_check.py <path-to-writ>

Run it inside the dev container (ci/real-server-check.sh): it downloads and
executes a third-party npm package.
"""

import json
import os
import subprocess
import sys
import tempfile

from mcp_client import McpClient

PACKAGE = "@modelcontextprotocol/server-everything"
POLICY = """\
version: 1
namespace: real-server-check
capabilities:
  - tool: "echo"
  - tool: "trigger-log-messages"
  - tool: "*"
    action: deny
"""


def text_of(response):
    content = response.get("result", {}).get("content") or [{}]
    return content[0].get("text", "")


def main():
    writ = sys.argv[1]
    version = subprocess.run(
        ["npm", "view", PACKAGE, "version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    print(f"server: {PACKAGE}@{version}")

    work = tempfile.mkdtemp()
    policy = os.path.join(work, "writ.yaml")
    log = os.path.join(work, "flight.jsonl")
    with open(policy, "w") as f:
        f.write(POLICY)

    client = McpClient(
        [writ, "wrap", "--policy", policy, "--log", log, "--", "npx", "-y", f"{PACKAGE}@{version}", "stdio"]
    )
    failures = []

    def expect(ok, label, detail=""):
        print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(label)

    init = client.request(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "writ-check", "version": "0"}},
        timeout=240,  # first run downloads the package
    )
    expect("result" in init, "initialize passes through", json.dumps(init))
    client.notify("notifications/initialized")

    listed = client.request("tools/list")
    names = [t["name"] for t in listed.get("result", {}).get("tools", [])]
    expect(sorted(names) == ["echo", "trigger-log-messages"], "tools/list shows only allowed tools", f"got {names}")

    echoed = client.call_tool("echo", {"message": "hello through writ"})
    expect(
        not echoed.get("result", {}).get("isError") and "hello through writ" in text_of(echoed),
        "allowed call reaches the server and returns",
        json.dumps(echoed),
    )

    # Server-to-client notifications must pass through unchanged.
    client.request("logging/setLevel", {"level": "debug"})
    before = len(client.notifications)
    triggered = client.call_tool("trigger-log-messages", {})
    log_messages = [n for n in client.notifications[before:] if n.get("method") == "notifications/message"]
    expect(
        "result" in triggered and len(log_messages) > 0,
        "server notifications emitted during a call reach the client",
        f"response {json.dumps(triggered)}, {len(log_messages)} log notifications",
    )

    for tool, args in [("get-sum", {"a": 1, "b": 2}), ("add", {"a": 1, "b": 2})]:
        denied = client.call_tool(tool, args)
        expect(
            denied.get("result", {}).get("isError") is True and "writ denied" in text_of(denied),
            f"denied call `{tool}` is answered by writ",
            json.dumps(denied),
        )

    code = client.close()
    expect(code == 0, "writ wrap exits cleanly when the client closes stdin", f"exit {code}")

    verify = subprocess.run([writ, "log", "--verify", "--log", log], capture_output=True, text=True)
    expect(verify.returncode == 0, "flight log hash chain verifies", verify.stderr.strip())

    entries = [json.loads(line) for line in open(log)]
    kinds = [e["kind"] for e in entries]
    results = [e["data"]["tool"] for e in entries if e["kind"] == "tool_result"]
    hidden = next((e["data"]["tools"] for e in entries if e["kind"] == "tools_hidden"), [])
    expect(
        results == ["echo", "trigger-log-messages"], "only the allowed calls produced a tool_result", f"got {results}"
    )
    expect(kinds[0] == "session_start" and kinds[-1] == "session_end", "log brackets the session", str(kinds))

    print(f"tools hidden by policy: {len(hidden)} ({', '.join(sorted(hidden))})")
    print(f"server-originated messages passed through: {len(client.notifications)}")
    print(f"log entries: {len(entries)}")
    if failures:
        print(f"{len(failures)} check(s) failed")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
