# writ

Policy and lineage layer for agent tool calls. See `plan-v2.md` for the full plan.

This is the first Phase 0 slice: **`writ wrap`**, a cooperative-mode stdio MCP proxy.

## What this build enforces

- **Tool rules** from `writ.yaml`: glob patterns, `allow`/`deny`, and argument conditions (`args.amount <= 100.00`). Every matching rule is evaluated and the most restrictive outcome wins (D9). `tool: "*"` applies only to tools no other rule matches. A tool no rule matches is denied.
- **`limits.max_tool_calls`** per wrapped session.
- **`on_violation: require_sudo`** is recognized, but this build has no approval broker yet, so those calls are refused with an explanation.
- **Flight recorder:** every decision is written to a hash-chained JSONL log before the call is forwarded. If the log can't be written, the call is denied. With `--fsync`, each decision reaches stable storage before the call is forwarded (see Latency).
- **Redaction:** per rule, `redact: ["args.card", "args.headers.*"]` replaces values with `[redacted]` in the log, and `record_arguments: false` omits arguments entirely. When several rules apply, their settings combine and the most protective wins. Decision reasons never echo a redacted value.
- **`tools/list` filtering:** tools the policy always denies are hidden from the agent. This is a usability aid; enforcement happens on every `tools/call`.
- **Server-initiated requests** (sampling, elicitation) are recorded by method only, and are not yet governed by policy.
- **Shutdown:** the server runs in its own process group. If it outlives the client by more than `--shutdown-grace` (default 5s), writ sends SIGTERM to the group, then SIGKILL. This also covers launcher chains like `npx` → `node`, where a grandchild keeps stdout open. SIGTERM, SIGINT and SIGHUP sent to writ are forwarded to the server, so killing writ doesn't leave the server running.

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

The log path defaults to `$WRIT_LOG`, then `$XDG_STATE_HOME/writ/flight.jsonl`, then `~/.local/state/writ/flight.jsonl`. Tool arguments are recorded in full unless a rule redacts or omits them.

## Layout

| Crate | Purpose |
|---|---|
| `writ-policy` | `writ.yaml` parsing, validation, and evaluation |
| `writ-recorder` | Append-only, hash-chained flight log (multi-process safe via file locks) |
| `writ-proxy` | stdio JSON-RPC interception |
| `writ-cli` | The `writ` binary: `wrap`, `check`, `log` |

`cargo test --workspace` runs unit tests and an end-to-end suite against a fake MCP server (`crates/writ-cli/tests/fixtures/fake_mcp_server.py`; needs `python3`).

## Checks

Everything runs in a Fedora 43 dev container (`ci/Containerfile`). The source is copied into the image rather than bind-mounted, so code run by checks can't touch the host checkout. Set `CONTAINER_ENGINE=docker` to use Docker instead of Podman.

```sh
ci/container.sh ci/check.sh              # rustfmt, clippy -D warnings, tests
ci/container.sh ci/real-server-check.sh  # wrap @modelcontextprotocol/server-everything from npm
ci/container.sh ci/bench.sh              # per-call latency overhead
```

`real-server-check` downloads and runs a third-party npm package. Run it only in the container.

### Latency (Oct 2026, release build, in the container)

Overhead is the latency added to each sequential `tools/call` round trip by evaluating the policy, appending to the flight log, and forwarding. Three runs of 3,000–5,000 calls each, with flight logs on a btrfs volume (`ci/bench.sh --log-dir /target/bench`):

| | p50 | p99 |
|---|---|---|
| Added by `writ wrap` (default) | 55–73 µs | 83–156 µs |
| Added by `writ wrap --fsync` | 0.7–0.8 ms | 1.1–1.2 ms |
| Denied call, answered by writ (total) | ~44 µs | ~105 µs |

Both modes are within the Phase 0 target (low single-digit milliseconds at p99). `--fsync` syncs only decision entries: `fdatasync` also persists everything before them, so a machine crash can lose only trailing result entries, never a decision whose call was forwarded. Syncing every entry cost about twice as much (1.4 ms p50, 2.1–2.5 ms p99).

When measuring fsync, put the logs on a real filesystem. Podman mounts the container's own root overlay `volatile`, which turns fsync into a no-op: logs in the container's `/tmp` showed fsync as free. The fake server is trivial, so these figures measure writ, not a realistic tool. Rerun `ci/bench.sh` after any change to the recorder or proxy.
