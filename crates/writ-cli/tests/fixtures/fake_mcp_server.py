"""Minimal stdio MCP server for writ's end-to-end tests.

Every line it receives is appended to the file named by $FAKE_MCP_LOG, so
tests can assert that denied calls never reached the server.
"""

import json
import os
import sys

TOOLS = ["postgres.query", "postgres.drop_table", "stripe.refund", "shell.exec"]


def reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


def main():
    log_path = os.environ["FAKE_MCP_LOG"]
    for line in sys.stdin:
        with open(log_path, "a") as log:
            log.write(line)
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            continue
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
            text = f"executed {name} with {json.dumps(msg['params'].get('arguments', {}), sort_keys=True)}"
            reply(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})
        else:
            reply(msg_id, {})


if __name__ == "__main__":
    main()
