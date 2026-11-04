"""Plays an agent under `writ run`: starts two wrapped MCP servers, makes
calls through both, and writes every response to $DRIVER_OUT as JSON.

Server A joins the task as-is. Server B adds a narrowing policy
($NARROW_POLICY). Midway it captures `writ ps` output.
"""

import json
import os
import subprocess
import sys

WRIT = os.environ["WRIT_BIN"]
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_mcp_server.py")


class Server:
    def __init__(self, *extra):
        argv = [WRIT, "wrap", *extra, "--", sys.executable, "-I", FIXTURE]
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.next_id = 1

    def call(self, tool, args):
        msg_id = self.next_id
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        while True:
            message = json.loads(self.proc.stdout.readline())
            if message.get("id") == msg_id:
                return message

    def close(self):
        self.proc.stdin.close()
        return self.proc.wait(timeout=15)


def main():
    a = Server()
    b = Server("--policy", os.environ["NARROW_POLICY"])
    results = [
        ("a", a.call("postgres.query", {"sql": "select 1"})),
        ("b", b.call("postgres.query", {"sql": "select 2"})),
        ("b", b.call("stripe.refund", {"amount": 5})),
        ("a", a.call("stripe.refund", {"amount": 5})),
    ]
    ps = subprocess.run([WRIT, "ps"], capture_output=True, text=True).stdout
    results.append(("b", b.call("postgres.query", {"sql": "select 3"})))
    exits = [a.close(), b.close()]
    with open(os.environ["DRIVER_OUT"], "w") as f:
        json.dump({"results": results, "ps": ps, "exits": exits, "task": os.environ.get("WRIT_TASK_ID")}, f)


if __name__ == "__main__":
    main()
