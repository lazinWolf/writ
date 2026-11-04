# writ

Policy and lineage layer for agent tool calls. See `plan-v2.md` for the full plan and `OBSERVATIONS.md` for where things stand.

This is cooperative-mode work: `writ wrap` (a stdio MCP proxy), `writd` (the local daemon that owns tasks and decisions), `writ run` (start an agent as a task), `writ ps`, and `writ sudo` (decide calls waiting for a human). The poisoned-ticket demo in `examples/poisoned-ticket` runs end to end.

## Tasks: authority belongs to the task, not the server

```sh
writ run --policy writ.yaml -- my-agent --flags
```

`writ run` asks writd (starting it if needed) to create a **task** from the policy. It then runs the agent with `WRIT_TASK` set. Every `writ wrap` the agent starts, one per MCP server, inherits that variable and joins the task:

- **One policy, shared limits.** `max_tool_calls` counts calls across all of the agent's servers, not per server.
- **Narrowing only.** A `writ wrap --policy narrow.yaml` inside a task adds its own policy, and both are evaluated with the most restrictive outcome winning. A wrapped server can lose authority the task grants. It can never gain authority the task doesn't grant.
- **Revocation.** When `writ run` exits, or dies, writd ends the task, and every later call in its sessions is denied.
- **Fails closed.** If `WRIT_TASK` is set but writd is unreachable, or the task is unknown, `writ wrap` refuses to start the server. If writd goes away mid-session, every call is denied.

`writ ps` lists live tasks:

```text
TASK                          USER        NAMESPACE           SESSIONS        CALLS  DENIED  TAINTED       AGE  SERVERS                   COMMAND
tsk_18e45a…                   dividh      prod-customer-ops          2       41/200       3  YES           12m  mcp:zendesk,mcp:stripe    my-agent --flags
```

**Not yet a security boundary between processes.** `WRIT_TASK` is an unsigned ID: any process running as the same user can claim any task. Cooperative mode already trusts the agent framework to route calls through writ (plan-v2.md §5.2). Signed, attenuating writ tokens replace this ID next.

## Modes of `writ wrap`

| Invocation | Decisions made by | Policy |
|---|---|---|
| under `writ run` (`WRIT_TASK` set) | writd | the task's, narrowed by `--policy` if given |
| `writ wrap --daemon --policy p.yaml` | writd (started if needed) | `p.yaml`, as its own task; visible in `writ ps` |
| `writ wrap --policy p.yaml` | this process | `p.yaml`, as its own task |

All three run the same engine (`writ-daemon`) and write the same log format.

## What is enforced

- **Tool rules** from `writ.yaml`: glob patterns, `allow`/`deny`, and conditions over the call's arguments and the task's facts: `args.amount <= 100.00`, `args.customer in writ.root.entitled_customers`, `writ.tainted == false`. Facts are computed by writ, never supplied by the agent or server, and are recorded with every decision. In this build no task has a root principal or taint yet (they arrive with the demo, see `ROADMAP.md`), so `writ.tainted` is always `false` and any condition reading `writ.root.*` fails closed. Every matching rule is evaluated and the most restrictive outcome wins (D9). `tool: "*"` applies only to tools no other rule matches. A tool no rule matches is denied.
- **Server names:** `writ wrap --name zendesk` makes the session `mcp:zendesk`, the name policies match in `data_flow.untrusted_sources` and see as `writ.session.name`. Without `--name`, writ derives one from the command (`npx -y @scope/server-postgres` → `mcp:server-postgres`) and warns. Name servers explicitly whenever a policy refers to them.
- **Taint (coarse, per task):** list servers whose content may be attacker-written in `data_flow.untrusted_sources: ["mcp:zendesk"]`. The first **allowed** call to one of them taints the whole task, across all its servers, before the call is forwarded. Denied calls don't taint, and taint is never cleared. On a tainted task, a tool whose rule says `privileged: true` gets `data_flow.on_taint.privileged_mutations` (`require_sudo` by default, or `deny`); other tools are unaffected. The flight log records a `taint` event, every decision records the facts it saw, and `writ ps` shows a TAINTED column. Either the task's policy or a narrowing policy can declare a source untrusted.
- **Entitlements (who the task acts for):** `writ run --principal alice@example.com` gives the task a root principal, recorded as **unverified** (it's asserted by whoever runs the command, until roots are minted from an identity proof). The policy names an entitlement source, `entitlements: {source: file, path: entitlements.yaml}` (a mock; the path is relative to the policy). Its `principals.<id>` become `writ.root.*`. A rule can `lookup:` a record, such as `charge: {table: charges, key: args.charge}`, and state `entitlements:`, such as `charge.customer in writ.root.entitled_customers` and `args.amount <= charge.amount`. A call that breaks one gets `on_entitlement_violation` (`deny` by default), whatever else applies. A call whose entitlements all hold is **covered**: it's within the root's own authority, so taint doesn't add an approval requirement. Unknown principals, unknown records and a missing source all fail closed. Both files are read once when the task starts, and their hashes are recorded. A narrowing policy can't bring its own source.
- **`limits.max_tool_calls`**, per task, and also per session when a narrowing policy sets it.
- **Approvals (`require_sudo`):** with an `approvals:` block in the task's policy (`approvals: {timeout: 15m}`; 15m is the default), a call that needs a human **pauses**. The agent gets no placeholder: its call simply hasn't returned yet, and other calls, on that server and others, keep flowing. writ prints the approval id on stderr. A human decides from their own shell:

  ```sh
  writ sudo list            # waiting calls, oldest first (--json for scripts)
  writ sudo show apr_…      # tool, arguments (redacted per policy), principal, taint, why
  writ sudo approve apr_…   # the call is re-checked, then forwarded; the agent gets the real result
  writ sudo deny apr_…      # the agent gets a policy denial
  ```

  An approved call is re-checked first: if its task ended or a `max_tool_calls` limit was reached while it waited, it's still refused. No decision before the timeout means denial. Ending the task or closing the server also denies its waiting calls, and so does stopping writd (recorded as `cancelled` before it exits; if writd is killed outright, a `tool_call` with an approval id and no `approval` entry means the call was never forwarded). Each settlement (`approve`, `deny`, `timeout`, `cancelled`) is recorded durably as an `approval` event with the approver (`$USER`, plus the pid and uid writd sees), and an approved call is forwarded only after that. A narrowing policy can shorten the timeout. Without an `approvals:` block, or in a standalone `writ wrap` (there's no writd to ask), `require_sudo` calls are refused with an explanation, as before.

  **Approvals are guarded, but not yet a boundary against the agent itself.** Two checks stop an agent from approving its own calls. `writ sudo` refuses to run inside a writ task (`WRIT_TASK` set). And on Linux, writd refuses an approve or deny that comes from a descendant of the task's `writ run` (the agent and anything it starts) or of one of its `writ wrap`s (a wrapped MCP server), so hiding `WRIT_TASK` doesn't help. A same-user process that has detached from its parent (double-forked, reparented to init) escapes the second check, and neither applies to a standalone `writ wrap --daemon`, whose agent isn't writd's to know. Signed approvals (passkeys) are planned.
- **Flight recorder:** every decision is written to a hash-chained JSONL log before the call is forwarded, and an **allowed** decision reaches stable storage (fdatasync) first. Denials are written but not synced individually, so a flood of denied calls can't force a sync per call; the next sync persists them. If a decision can't be recorded, the call is denied. Use `--no-fsync` (on `writ wrap` or `writd`) to trade crash durability for latency.
- **Redaction:** per rule, `redact: ["args.card", "args.headers.*"]` replaces values with `[redacted]` in the log, and `record_arguments: false` omits arguments entirely. When several rules apply, including a narrowing policy, their settings combine and the most protective wins. Decision reasons never echo a redacted value.
- **`tools/list` filtering:** tools the policies always deny are hidden. This is a usability aid; enforcement happens on every `tools/call`.
- **Server-initiated requests** (sampling, elicitation) are recorded by method only, and are not yet governed by policy.
- **Shutdown:** the server runs in its own process group. If it outlives the client by more than `--shutdown-grace` (default 5s), writ sends SIGTERM to the group, then SIGKILL. That covers `npx` → `node` style launcher chains. Signals sent to writ are forwarded to the server.

Any writ.yaml field from the spec that this build doesn't enforce (`approvals`, `data_flow.declassify`, `preconditions`, `max_depth`, `max_budget_usd`, …) is **rejected at load time**, so a policy never appears to grant a guarantee it doesn't have.

## Not yet

Signed writ tokens and lineage across hops, verified root principals, a real entitlement source (Stripe, CRM, IdP), approvals over Slack and signed approver identities, precondition revalidation for approved calls, finer-grained taint (per branch, per value), and external anchoring of the log. In cooperative mode, an agent with a shell or raw network access can bypass writ (plan-v2.md §5.2).

## Usage

```sh
cargo build --release          # builds `writ` and `writd`
writ check examples/writ.yaml
```

In an MCP client config:

```json
{
  "mcpServers": {
    "postgres-prod": {
      "command": "writ",
      "args": ["wrap", "--name", "postgres-prod", "--policy", "./writ.yaml", "--", "npx", "-y", "@modelcontextprotocol/server-postgres"]
    }
  }
}
```

```sh
writ log                       # human-readable flight log
writ log --verify              # check the hash chain
writ log --session tsk_… --json   # one task or session
```

Defaults:
- **Log:** `$WRIT_LOG`, then `$XDG_STATE_HOME/writ/flight.jsonl`, then `~/.local/state/writ/flight.jsonl`.
- **writd socket:** `$WRIT_SOCKET`, then `$XDG_RUNTIME_DIR/writ/writd.sock`. Its directory is created 0700, the socket is 0600, and peers must run as the same user.

## Layout

| Crate | Purpose |
|---|---|
| `writ-policy` | `writ.yaml` parsing, validation, evaluation, redaction |
| `writ-recorder` | Append-only, hash-chained flight log (multi-process safe via file locks) |
| `writ-daemon` | The engine (tasks, sessions, decisions), writd's socket protocol, client, and server |
| `writ-proxy` | stdio JSON-RPC interception and server lifetime supervision |
| `writ-cli` | The `writ` and `writd` binaries |

## Checks

Everything runs in a Fedora 43 dev container (`ci/Containerfile`). The source is copied into the image rather than bind-mounted, so code run by checks can't touch the host checkout. Set `CONTAINER_ENGINE=docker` to use Docker instead of Podman.

```sh
ci/container.sh ci/check.sh              # rustfmt, clippy -D warnings, tests
ci/container.sh ci/real-server-check.sh  # wrap @modelcontextprotocol/server-everything from npm
ci/container.sh ci/bench.sh --log-dir /target/bench   # per-call latency overhead
```

`real-server-check` downloads and runs a third-party npm package. Run it only in the container.

### Latency (Nov 2026, release build, in the container, logs on btrfs)

The latency each mode adds to a sequential `tools/call` round trip, against a trivial fake server. Three runs of 3,000 calls each:

| Mode | p50 | p99 |
|---|---|---|
| standalone (default: allowed decisions fsynced) | 0.8–1.1 ms | 1.6–1.8 ms |
| standalone `--no-fsync` | 0.06–0.26 ms | 0.07–0.43 ms |
| writd (default: fsync) | 0.9–1.3 ms | 1.6–1.9 ms |
| writd `--no-fsync` | 0.07–0.21 ms | 0.11–0.26 ms |
| denied call (answered by writ) | ≈0 | ≈0.05 ms |

All modes are within the Phase 0 target (low single-digit milliseconds at p99). fsync dominates; the hop to writd is within run-to-run noise. Recording a result is one-way, so it stays off the call's critical path. Recent runs are noisier than earlier ones (no-fsync standalone measured 0.06 ms in October), so treat these as ranges, not points.

When measuring fsync, put the logs on a real filesystem. Podman mounts the container's own root overlay `volatile`, which turns fsync into a no-op.
