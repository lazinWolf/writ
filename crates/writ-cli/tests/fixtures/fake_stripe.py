"""Fake Stripe MCP server for the poisoned-ticket demo.

Tools: `stripe.get_charge`, `stripe.refund`, `stripe.add_credit`.

Every money movement this server actually performs is appended to the file
named by $STRIPE_LEDGER (one JSON object per line), so tests can prove that
a call writ denied, or that an approver rejected, never reached Stripe.

The charges below must match `examples/poisoned-ticket/entitlements.yaml`,
which plays the role of the entitlement source in the demo.
"""

import json
import os
import sys

CHARGES = {
    "ch_alice_small": {"id": "ch_alice_small", "customer": "cus_alice", "amount": 40.00, "refunded": False},
    "ch_alice_big": {"id": "ch_alice_big", "customer": "cus_alice", "amount": 240.00, "refunded": False},
    "ch_bob_1": {"id": "ch_bob_1", "customer": "cus_bob", "amount": 5000.00, "refunded": False},
}

TOOLS = [
    {
        "name": "stripe.get_charge",
        "description": "Look up a charge.",
        "inputSchema": {"type": "object", "properties": {"charge": {"type": "string"}}, "required": ["charge"]},
    },
    {
        "name": "stripe.refund",
        "description": "Refund part or all of a charge.",
        "inputSchema": {
            "type": "object",
            "properties": {"charge": {"type": "string"}, "amount": {"type": "number"}},
            "required": ["charge", "amount"],
        },
    },
    {
        "name": "stripe.add_credit",
        "description": "Add account credit to a customer.",
        "inputSchema": {
            "type": "object",
            "properties": {"customer": {"type": "string"}, "amount": {"type": "number"}},
            "required": ["customer", "amount"],
        },
    },
]


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def reply(msg_id, result):
    send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def tool_result(msg_id, payload, is_error=False):
    reply(msg_id, {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": is_error})


def ledger(entry):
    path = os.environ.get("STRIPE_LEDGER")
    if path:
        with open(path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")


def call(name, args):
    """Returns (payload, is_error)."""
    if name == "stripe.get_charge":
        charge = CHARGES.get(args.get("charge"))
        return (charge, False) if charge else ({"error": "no such charge"}, True)
    if name == "stripe.refund":
        charge = CHARGES.get(args.get("charge"))
        amount = args.get("amount")
        if charge is None:
            return {"error": "no such charge"}, True
        if charge["refunded"]:
            return {"error": "charge already refunded"}, True
        if not isinstance(amount, (int, float)) or amount <= 0 or amount > charge["amount"]:
            return {"error": "invalid amount"}, True
        charge["refunded"] = True
        entry = {"op": "refund", "charge": charge["id"], "customer": charge["customer"], "amount": amount}
        ledger(entry)
        return {"refund": entry, "status": "succeeded"}, False
    if name == "stripe.add_credit":
        amount = args.get("amount")
        if not isinstance(amount, (int, float)) or amount <= 0:
            return {"error": "invalid amount"}, True
        entry = {"op": "credit", "customer": args.get("customer"), "amount": amount}
        ledger(entry)
        return {"credit": entry, "status": "succeeded"}, False
    return {"error": f"unknown tool {name}"}, True


def handle(msg):
    method, msg_id = msg.get("method"), msg.get("id")
    if msg_id is None or method is None:
        return
    if method == "initialize":
        reply(msg_id, {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-stripe", "version": "0"},
        })
    elif method == "tools/list":
        reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        payload, is_error = call(msg["params"]["name"], msg["params"].get("arguments", {}))
        tool_result(msg_id, payload, is_error)
    else:
        reply(msg_id, {})


def main():
    for line in sys.stdin:
        if line.strip():
            handle(json.loads(line))


if __name__ == "__main__":
    main()
