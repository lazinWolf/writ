# writ

Policy and lineage layer for agent tool calls. See `plan-v2.md` for the full plan.

This is the first Phase 0 slice: **`writ wrap`**, a cooperative-mode stdio MCP proxy.

## What this build enforces

- **Tool rules** from `writ.yaml`: glob patterns, `allow`/`deny`, and argument conditions (`args.amount <= 100.00`). Every matching rule is evaluated and the most restrictive outcome wins (D9). `tool: "*"` applies only to tools no other rule matches. A tool no rule matches is denied.
- **`limits.max_tool_calls`** per wrapped session.
- **`on_violation: require_sudo`** is recognized, but this build has no approval broker yet, so those calls are refused with an explanation.
- **Flight recorder:** every decision is written to a hash-chained JSONL log before the call is forwarded. If the log can't be written, the call is denied.
- **`tools/list` filtering:** tools the policy always denies are hidden from the agent. This is a usability aid; enforcement happens on every `tools/call`.

Any writ.yaml field from the spec that this build doesn't enforce (`data_flow`, `entitlements`, `max_depth`, `max_budget_usd`, …) is **rejected at load time**, so a policy never appears to grant a guarantee it doesn't have.

## What it does not do yet

No writ tokens or lineage, no taint, no approvals, and no external anchoring of the log. In cooperative mode, an agent that has a shell or direct network access can bypass writ entirely (plan-v2.md §5.2).

## Usage

```sh
cargo build --release
writ check examples/writ.yaml
```

In an MCP client config:

```json
{
  "mcpServers": {
    "postgres-prod": {
      "command": "writ",
      "args": ["wrap", "--policy", "./writ.yaml", "--", "npx", "-y", "@modelcontextprotocol/server-postgres"]
    }
  }
}
```

```sh
writ log                 # human-readable flight log
writ log --verify        # check the hash chain
writ log --session ses_… --json
```

The log path defaults to `$WRIT_LOG`, then `$XDG_STATE_HOME/writ/flight.jsonl`, then `~/.local/state/writ/flight.jsonl`. Tool arguments are recorded in full.

## Layout

| Crate | Purpose |
|---|---|
| `writ-policy` | `writ.yaml` parsing, validation, and evaluation |
| `writ-recorder` | Append-only, hash-chained flight log (multi-process safe via file locks) |
| `writ-proxy` | stdio JSON-RPC interception |
| `writ-cli` | The `writ` binary: `wrap`, `check`, `log` |

`cargo test --workspace` runs unit tests and an end-to-end suite against a fake MCP server (`crates/writ-cli/tests/fixtures/fake_mcp_server.py`; needs `python3`).
