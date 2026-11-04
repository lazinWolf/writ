"""Plays an agent under `writ run` for the approvals end-to-end test.

1. Sends a refund that needs approval (id 1), then a query (id 2) right
   after, on the same wrapped server, and records the order the answers
   arrive in: the query must not wait behind the paused refund.
2. Tries `writ sudo approve` on its own paused call (it has WRIT_TASK set).
3. Waits for the refund's answer (the test approves it from outside).
4. Sends a second refund (id 3) that nobody decides, so it times out.

Results go to $DRIVER_OUT as JSON.
"""

import json
import os
import subprocess
import sys
import time

WRIT = os.environ["WRIT_BIN"]
HERE = os.path.dirname(os.path.abspath(__file__))

proc = subprocess.Popen(
    [WRIT, "wrap", "--name", "stripe", "--", sys.executable, "-I", os.path.join(HERE, "fake_mcp_server.py")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
)


def send(msg_id, tool, args):
    request = {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": tool, "arguments": args}}
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()


def read():
    return json.loads(proc.stdout.readline())


def sudo(*args, env=None):
    out = subprocess.run([WRIT, "sudo", *args], capture_output=True, text=True, env=env)
    return {"code": out.returncode, "stdout": out.stdout, "stderr": out.stderr}


def without_task_env():
    env = dict(os.environ)
    env.pop("WRIT_TASK", None)
    return env


send(1, "stripe.refund", {"amount": 240})
send(2, "postgres.query", {"sql": "select 1"})
first = read()
order = [first["id"]]

# Our own paused call is listed, but we must not be able to approve it.
pending = []
deadline = time.time() + 10
while not pending and time.time() < deadline:
    listed = sudo("list", "--json")
    pending = json.loads(listed["stdout"]) if listed["code"] == 0 else []
    time.sleep(0.05)
self_approve = sudo("approve", pending[0]["id"]) if pending else {"code": None}
# Hiding WRIT_TASK gets past the CLI's check; writd must still refuse, since we
# descend from the task's `writ run`.
self_approve_unset = sudo("approve", pending[0]["id"], env=without_task_env()) if pending else {"code": None}

responses = {first["id"]: first}
while 1 not in responses:
    message = read()
    order.append(message["id"])
    responses[message["id"]] = message

waited = None
if os.environ.get("SKIP_TIMEOUT") != "1":
    send(3, "stripe.refund", {"amount": 300})
    started = time.time()
    responses[3] = read()
    waited = time.time() - started

proc.stdin.close()
exit_code = proc.wait(timeout=15)
with open(os.environ["DRIVER_OUT"], "w") as f:
    json.dump({"order": order, "self_approve": self_approve, "self_approve_unset": self_approve_unset,
               "responses": responses,
               "timeout_waited_s": waited, "exit": exit_code}, f)
