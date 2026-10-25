"""Minimal stdio MCP server for writ's end-to-end tests.

Every line it receives is appended to the file named by $FAKE_MCP_LOG, so
tests can assert that denied calls never reached the server.

$FAKE_MCP_MODE selects misbehaviour for shutdown tests:
  linger        keep running after stdin closes (exits on SIGTERM)
  stubborn      keep running after stdin closes and ignore SIGTERM
  close_stdout  close stdout at startup but keep running
  grandchild    start a `sleep` that inherits stdout, then behave normally;
                its pid is written to the log as "GRANDCHILD <pid>"
"""

import json
import os
import signal
import subprocess
import sys
import time

TOOLS = ["postgres.query", "postgres.drop_table", "stripe.refund", "shell.exec", "sample"]


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def reply(msg_id, result):
    send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def log(line):
    with open(os.environ["FAKE_MCP_LOG"], "a") as f:
        f.write(line)


def handle(msg):
    method, msg_id = msg.get("method"), msg.get("id")
    if msg_id is None or method is None:
        return  # notifications, and responses to our own requests
    if method == "initialize":
        reply(msg_id, {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "0"},
        })
    elif method == "tools/list":
        reply(msg_id, {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in TOOLS]})
    elif method == "tools/call":
        name = msg["params"]["name"]
        if name == "sample":
            send({"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage",
                  "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "secret prompt"}}]}})
        text = f"executed {name} with {json.dumps(msg['params'].get('arguments', {}), sort_keys=True)}"
        reply(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})
    else:
        reply(msg_id, {})


def main():
    mode = os.environ.get("FAKE_MCP_MODE", "")
    if mode == "stubborn":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if mode == "grandchild":
        child = subprocess.Popen(["sleep", "300"])  # inherits our stdout
        log(f"GRANDCHILD {child.pid}\n")
    if mode == "close_stdout":
        sys.stdout.close()
        os.close(1)

    for line in sys.stdin:
        log(line)
        if mode != "close_stdout":
            handle(json.loads(line))

    if mode in ("linger", "stubborn", "close_stdout"):
        while True:
            time.sleep(60)


if __name__ == "__main__":
    main()
