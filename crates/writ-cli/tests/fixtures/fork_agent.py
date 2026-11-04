"""Plays an agent under `writ run` that forks its token for a sub-agent.

Writes what happened to $DRIVER_OUT as JSON. Expects $BILLING_POLICY (the
sub-agent's narrowing policy) and $WRIT_BIN.
"""

import json
import os
import subprocess
import sys

WRIT = os.environ["WRIT_BIN"]
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_mcp_server.py")
ROOT = os.environ["WRIT_TOKEN"]


class Server:
    def __init__(self, name, token, report_env=False):
        env = dict(os.environ, WRIT_TOKEN=token)
        if report_env:
            env["FAKE_MCP_REPORT_ENV"] = "1"
        argv = [WRIT, "wrap", "--name", name, "--", sys.executable, "-I", FIXTURE]
        self.proc = subprocess.Popen(
            argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        self.next_id = 1

    def call(self, tool, args):
        msg_id = self.next_id
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                return {"closed": True}
            message = json.loads(line)
            if message.get("id") == msg_id:
                return message

    def close(self):
        self.proc.stdin.close()
        code = self.proc.wait(timeout=15)
        return {"code": code, "stderr": self.proc.stderr.read()}


def fork(token, *args):
    out = subprocess.run([WRIT, "fork", *args], env=dict(os.environ, WRIT_TOKEN=token), capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def refused(token):
    """A wrap that should never get to start its server."""
    server = Server("refused", token)
    return server.close()


results = {}

root = Server("root", ROOT, report_env=True)
results["root_query"] = root.call("postgres.query", {"sql": "select 1"})
# An injected instruction gets the agent to pass its token to a server.
results["leak"] = root.call("postgres.query", {"sql": f"insert into loot values ('{ROOT}')"})

billing = fork(ROOT, "--policy", os.environ["BILLING_POLICY"], "--label", "billing", "--ttl", "10m")
one, two = Server("stripe-a", billing), Server("stripe-b", billing)
results["fork_query"] = one.call("postgres.query", {"sql": "select 2"})
results["fork_refund_1"] = one.call("stripe.refund", {"amount": 20})
results["fork_refund_2"] = two.call("stripe.refund", {"amount": 20})
# The fork's limit counts both sessions.
results["fork_refund_3"] = two.call("stripe.refund", {"amount": 10})
# The parent is unaffected by its child's narrowing.
results["root_refund"] = root.call("stripe.refund", {"amount": 900})

# max_depth is 2: a third fork is refused when it's used.
deep = fork(fork(billing, "--label", "audit"), "--label", "too-deep")
results["too_deep"] = refused(deep)
# One altered character breaks the signature.
middle = len(billing) // 2
tampered = billing[:middle] + ("A" if billing[middle] != "A" else "B") + billing[middle + 1:]
results["tampered"] = refused(tampered)

# With a command, `writ fork` runs it with the forked token.
shown = subprocess.run(
    [WRIT, "fork", "--label", "child", "--", sys.executable, "-c", "import os; print(os.environ['WRIT_TOKEN'])"],
    capture_output=True,
    text=True,
)
results["exec_token_differs"] = shown.returncode == 0 and shown.stdout.strip() not in ("", ROOT)

results["exits"] = [root.close(), one.close(), two.close()]
results["tokens"] = [ROOT, billing]
with open(os.environ["DRIVER_OUT"], "w") as f:
    json.dump(results, f)
