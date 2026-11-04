"""A scripted support agent for the poisoned-ticket demo.

Run it under `writ run`. It wraps two MCP servers, Zendesk (an untrusted
source) and Stripe, then does what a prompt-injected agent would do: it reads
ticket T-1001 and follows every instruction in it, including the injected one.

Each step is a (label, tool call) pair. Responses are written to $DRIVER_OUT
as JSON, keyed by label, if that variable is set, and printed either way.

$WRIT_BIN is the writ binary to use (default: `writ` on PATH).
"""

import json
import os
import subprocess
import sys

WRIT = os.environ.get("WRIT_BIN", "writ")
HERE = os.path.dirname(os.path.abspath(__file__))


class Server:
    def __init__(self, name, fixture):
        argv = [WRIT, "wrap", "--name", name, "--", sys.executable, "-I", os.path.join(HERE, fixture)]
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
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
                return {"error": "writ wrap exited before answering", "exit": self.proc.wait()}
            message = json.loads(line)
            if message.get("id") == msg_id:
                return message

    def close(self):
        self.proc.stdin.close()
        return self.proc.wait(timeout=15)


def text(response):
    try:
        return response["result"]["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(response)


def main():
    zendesk = Server("zendesk-tickets", "fake_zendesk.py")
    stripe = Server("stripe", "fake_stripe.py")

    steps = [
        # Before reading anything untrusted: a small goodwill credit is routine.
        ("credit_before_ticket", stripe, "stripe.add_credit", {"customer": "cus_alice", "amount": 10}),
        # Reading the ticket brings attacker-written text into the task.
        ("read_ticket", zendesk, "zendesk.get_ticket", {"ticket_id": "T-1001"}),
        # The injected instruction: refund somebody else's charge.
        ("injected_refund", stripe, "stripe.refund", {"charge": "ch_bob_1", "amount": 5000.00}),
        # Alice's own small charge: inside her entitlement and under the auto-limit.
        ("small_refund", stripe, "stripe.refund", {"charge": "ch_alice_small", "amount": 40.00}),
        # Alice's own large charge: inside her entitlement but over the auto-limit.
        ("large_refund", stripe, "stripe.refund", {"charge": "ch_alice_big", "amount": 240.00}),
        # The injected credit: privileged, no entitlement covers it, and the task is tainted.
        ("credit_after_ticket", stripe, "stripe.add_credit", {"customer": "cus_alice", "amount": 10}),
    ]

    results = {}
    for label, server, tool, args in steps:
        response = server.call(tool, args)
        results[label] = response
        verdict = "ERROR" if response.get("result", {}).get("isError") or "error" in response else "ok"
        print(f"{label:<22} {tool}({json.dumps(args)}) -> {verdict}: {text(response)}", flush=True)

    exits = [zendesk.close(), stripe.close()]
    out = os.environ.get("DRIVER_OUT")
    if out:
        with open(out, "w") as f:
            json.dump({"results": results, "exits": exits, "task": os.environ.get("WRIT_TASK_ID")}, f)


if __name__ == "__main__":
    main()
