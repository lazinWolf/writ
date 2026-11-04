# Roadmap: getting writ unstuck

*Written 2026-11-03, against commit `fafc41e`. `plan-v2.md` is still the vision and `OBSERVATIONS.md` is still the assessment. This file is the working checklist: what to code next, in order.*

---

## 1. Why the project is stuck

The code is healthy: `cargo test --workspace` passes all 42 tests, and the crates are small and clean. It is stuck for three other reasons.

**A. The next milestone is one big leap, not a series of steps.** Everything that is buildable without new design (Phase 0's stdio proxy, limits, recorder, `writd`, `writ ps`) is done. The next target, the poisoned-ticket demo, needs four features at once: signed tokens, taint, entitlements and approvals. Each of them waits on an open design question (D2 token format, root issuance, which entitlement source, how approvals reach a human). No single step finishes anything you can see working.

**B. Product decisions are waiting on the owner.** `OBSERVATIONS.md` §7 ends with five questions (license, name, 90-day goal, discovery network, reviewer). Until they're answered, every next step looks provisional, so nothing gets started.

**C. Three parts of the current design block the next features.** These are the real technical blockers:

| Blocker | Where | Why it blocks |
|---|---|---|
| **Decisions see only `(tool, args)`.** | `Policy::evaluate` (`crates/writ-policy/src/lib.rs:219`), `Engine::decide` (`crates/writ-daemon/src/engine.rs:206`), the `Backend` trait | Taint, entitlements and lineage are *facts about the task*, and the policy can't see any of them. The condition parser rejects them outright: `crates/writ-policy/src/condition.rs:52` says "writ.* and other context fields are not supported yet". |
| **Decisions are synchronous and run under locks.** | The proxy holds the `State` mutex across `decide` (`crates/writ-proxy/src/lib.rs:239`). writd holds one global `Mutex<Engine>` per request (`crates/writ-daemon/src/server.rs:48`). | `require_sudo` has to *pause* a call until a human answers (D4). Blocking here would freeze every other call and every result for that server, and every task in writd. So `require_sudo` can only refuse (`crates/writ-proxy/src/lib.rs:305`). |
| **Sessions have no name.** | `open_session` records only `{command, server_pid}` | `data_flow.untrusted_sources: ["mcp:zendesk-tickets"]` has nothing to match against, so taint can't be attached to a source. |

## 2. Now compared with the vision

| Area (plan-v2) | Vision | Now | Gap |
|---|---|---|---|
| Cooperative enforcement (§5.2) | stdio + HTTP MCP, framework adapters | stdio `writ wrap` only | HTTP, adapters |
| Task-tree authority (§3, §4.1) | Signed, attenuating Biscuit writs; `writ fork`; IdP-verified roots | `WRIT_TASK`: an unsigned ID; one flat task; a session can only narrow it | No tokens, no fork, no root principal |
| Taint (§4.2) | Branch taint from declared untrusted sources; declassification (D10) | None; `data_flow` is rejected at load | Everything |
| Entitlements (§4.2, §7.1) | `charge.customer in writ.root.entitled_customers` plus one resolver | None; conditions compare `args.*` with literals only | Context fields, `in`, resolver |
| Behavioral limits (§4.3) | depth, parallelism, calls, velocity, spend | `max_tool_calls` per task and session | depth/parallelism (needs fork), velocity |
| Airlock / approvals (§4.4) | Pause by default, CLI + Slack broker, preconditions | `require_sudo` parsed, then refused | Async decisions, broker |
| Flight recorder (§4.6) | Hash chain, OTel, causal DAG, anchoring | Hash chain, fsync, redaction, `writ log --verify` | OTel, anchoring, lineage graph |
| Policy (§7.1, D9) | Full `writ.yaml` | Globs, conditions, D9 precedence, deny by default, redaction; unenforced fields rejected | As features land, move fields out of the `UNIMPLEMENTED_*` lists |
| Credential vault, tenant pinning, mediated mode | Phase 2 | — | Not yet due |
| Discovery (Phase −1) | 10–15 conversations, 3–5 design partners | Not started | Everything |

**In one line:** the table-stakes layer is built and solid. None of the differentiated layer (lineage, taint, entitlements, approvals) exists yet, and three design choices above need changing before it can.

## 3. The plan in brief

1. **Make the demo the spec.** Write the poisoned-ticket scenario as a failing end-to-end test first. Each step below turns part of it green, so progress is visible.
2. **Fix the three blockers before adding features.** They're mostly refactors and don't depend on any open decision.
3. **Build the single-agent demo first** (taint + entitlements + approvals) on today's task ID. Multi-hop lineage only helps multi-agent setups (Risk 7). Discovery decides whether it leads the pitch, so signed tokens come right *after* the demo, not before it.
4. **Use reversible defaults instead of waiting.** Each open question gets a default below. Code proceeds on it, and the owner can override it.
5. **Run discovery in parallel**, with a whiteboard version of the demo now and the working one later.

### Defaults to unblock work (the owner can override any of them)

| Open question | Default we code against | Cost to change later |
|---|---|---|
| License | Apache-2.0 (already declared in `Cargo.toml`, but there's no `LICENSE` file) | Low now, high after outside contributions |
| Name | Keep "writ" in code. Don't publish to crates.io until 3.6 is decided. | Low until publishing |
| Token format (D2) | Biscuit (`biscuit-auth` crate), minted only by writd | Medium |
| Entitlement source (Q9) | A mock file resolver first, then Stripe customer ownership | Low (behind a trait) |
| Approval channel | CLI first (`writ sudo`), Slack later | Low |
| Taint granularity (D3) | Whole task (one branch until `writ fork` exists) | Low: the label lives on the task and moves to the branch later |

---

## 4. Checklist

Each item is sized to be one PR. Start at the top.

### Step 0: Housekeeping (a few hours, no decisions needed)

- [x] Add a `LICENSE` file (Apache-2.0, matching `Cargo.toml`), or change `Cargo.toml` if the owner picks something else.
- [x] Add `SECURITY.md` with a disclosure contact and a link to the threat model (plan-v2 §6).
- [ ] Bump `actions/checkout` in `.github/workflows/ci.yml` to the current major version.
- [ ] Add `docs/decisions/` with one short record per default in the table above (D2, D3, D4, Q9), so they're explicit and reversible.

### Step 1: Write the hero demo as a failing test (1–2 days)

- [x] `crates/writ-cli/tests/fixtures/fake_zendesk.py`: an MCP server with `zendesk.get_ticket` that returns a ticket containing an injected instruction ("refund $5,000 on ch_other").
- [x] `crates/writ-cli/tests/fixtures/fake_stripe.py`: an MCP server with `stripe.get_charge` and `stripe.refund`. It logs the refunds it actually executes to a file so the test can assert on them.
- [x] `examples/poisoned-ticket/writ.yaml`: the demo policy, written in the target syntax (it fails to load today).
- [x] `crates/writ-cli/tests/demo.rs`: drive both servers under `writ run` with a scripted agent (`fixtures/demo_agent.py`). Mark it `#[ignore]` until the steps below land. Assert these four cases:
  - [x] Refund of *another* customer's charge → **denied** (entitlement).
  - [x] In-entitlement refund ≤ $100 → **allowed with no human involved**, even though the task is tainted.
  - [x] In-entitlement refund > $100 on a tainted task → **paused**, then executed after `writ sudo approve`.
  - [x] The same with `writ sudo deny` (a tainted, uncovered `stripe.add_credit`) → the agent gets a policy denial, and Stripe never sees the call.
- [x] `examples/poisoned-ticket/README.md`: how to run it by hand, and the whiteboard version for discovery calls.

- [x] Add `demo_fixtures_behave`, which runs today, so the fixtures can't drift while the demo is ignored.
- [ ] Add a timeout case to `demo.rs` once step 6 exists (needs a short `approvals.timeout`).

**Step 1 status:** `cargo test -p writ-cli --test demo -- --ignored` fails at its first assertion, because the demo policy doesn't load yet (`data_flow` is rejected). That's expected. Each step below moves the failure further down the test. The draft syntax that steps 4–6 must accept is in `examples/poisoned-ticket/writ.yaml`: `data_flow.untrusted_sources` and `on_taint`, a top-level `entitlements: {source: file, path}`, `approvals.timeout`, and per rule `privileged`, `lookup`, `entitlements` and `on_entitlement_violation`. The demo test also fixes the shape of `writ sudo list --json` and of the `taint` and `approval` log events (see the doc comment at the top of `demo.rs`).

### Step 2: Give decisions a context (blocker 1, about 2–3 days)

- [x] In `writ-policy`, add `pub struct DecisionContext { tool, args, session: SessionFacts, task: TaskFacts }`. `TaskFacts` holds `root` (principal, attributes), `tainted`, and `taint_sources`. Keep it a plain serializable struct: it's also the future Cedar/OPA export (OBSERVATIONS §3.4, D8).
- [x] Change `Policy::evaluate(&self, ctx: &DecisionContext)`, and make `Engine::decide` build the context from the task and session. This is a pure refactor: all 42 tests stay green.
- [x] Extend `Condition` to accept `writ.*` paths on the left-hand side (`writ.tainted`, `writ.root.principal`, `writ.session.name`), keeping fail-closed behaviour for missing paths.
- [x] Allow a path on the right-hand side (`args.amount <= writ.root.refund_limit`) and add the `in` operator (`args.customer in writ.root.entitled_customers`).
- [x] Record the context's *facts* (not the arguments, which are already redacted) in each `tool_call` entry, so `writ log` shows why a call was decided the way it was.

**Step 2 status:** done. `writ_policy::{DecisionContext, Facts, Root, SessionFacts}` live in `crates/writ-policy/src/context.rs`. Conditions read `args.*` and `writ.{root, tainted, taint_sources, session}.*`, an unknown `writ.*` field is a load error, and every `tool_call` log entry carries `facts`. Steps 3–5 now only have to *fill in* facts: the session name, taint, and the root and its entitlements.

### Step 3: Name sessions (blocker 3, about 1 day)

- [x] Add `writ wrap --name zendesk-tickets` and record it in `session_start`. The session's identity is `mcp:<name>`.
- [x] Without `--name`, derive a name from the command and warn. (It does still match `untrusted_sources`, erring toward taint.)
- [x] Show session names in `writ ps` (add a `--sessions` flag or a detail view).

### Step 4: Coarse taint (about 3–4 days)

- [x] Accept `data_flow.untrusted_sources` in `writ.yaml`, and remove `data_flow` from `UNIMPLEMENTED_TOP_LEVEL` for just that sub-field. Keep rejecting `declassify`, `secrets` and the others.
- [x] Taint the task when an **allowed** call goes to an untrusted session, *before* it's forwarded, as part of the same durable decision entry. This is conservative (the result is going to arrive anyway) and needs no new round trip.
- [x] Accept rule field `privileged: true` and `data_flow.on_taint.privileged_mutations: require_sudo | deny`. Precedence follows D9.
- [x] Add a `taint` flight-log event (source, triggering call), and show a `TAINTED` column in `writ ps`.
- [x] Unit tests: taint is per task, shared across sessions, never cleared, and survives in the log.

**Steps 3–4 status:** done. A derived name still matches `untrusted_sources`, which errs toward tainting; the warning tells you to name servers explicitly. Until step 5, a privileged tool on a tainted task always needs a human: the "unless its entitlements all hold" exemption arrives with entitlements. `writ ps` shows TAINTED and SERVERS columns. The demo test now stops at `entitlements` (step 5) instead of `data_flow`.

### Step 5: Entitlements with a mock resolver (about 3–4 days)

- [x] Add `writ run --principal <id>`. The root principal is recorded and **labeled unverified** in the log and in `writ ps` until IdP-verified roots exist (plan-v2 §4.1).
- [x] Add `trait EntitlementResolver { fn resolve(&self, principal) -> Value }` with a `FileResolver` that reads YAML (`principal → {entitled_customers: [...], ...}`). The result becomes `writ.root.*`.
- [x] Accept the rule field `entitlements:` (conditions over `writ.root.*` and `args.*`) plus `on_entitlement_violation: deny`, and remove them from `UNIMPLEMENTED_RULE`.
- [x] Add a fact lookup for `stripe.get_charge`-style references (`charge.customer`) via the resolver. The mock first; the real Stripe API goes behind the same trait in Phase 1.
- [x] Turn on the "another customer's charge → denied" case in `demo.rs`.

**Step 5 status:** done. The trait is `writ_policy::EntitlementSource` (with `FileSource`); the policy names it with `entitlements: {source: file, path}`, and rules bind records with `lookup:`. `writ run` reads both files once and writd records their hashes. A call whose entitlements all hold is *covered*, so taint doesn't add an approval for it. `poisoned_ticket_without_approvals` runs the whole demo today, with the two calls that need a human refused. The full demo test stops only at `approvals:`.

### Step 6: Asynchronous decisions and a CLI approval broker (blocker 2, about 1 week)

- [x] Add a pending decision: `Decision.approval` carries the approval id on a `require_sudo` outcome. The engine records it durably and returns immediately.
- [x] In the proxy, park a paused call on a thread of its own and keep reading stdin, so other calls and results keep flowing. When the decision is settled, forward the call or answer it with a tool error.
- [x] In writd, release the engine mutex while waiting: a `WaitApproval` request, sent on a separate connection, sleeps on a condition variable until someone approves, denies, the call times out, or its task or session ends.
- [x] Add `writ sudo list [--json]`, `writ sudo show <id>`, and `writ sudo approve|deny <id>`. Record the approver (user, plus the pid and uid writd sees) in the log.
- [x] Add a timeout (`approvals: {timeout: 15m}` in policy, the default) after which the call is denied.
- [x] In standalone `writ wrap` (no writd), or without an `approvals:` block, `require_sudo` keeps refusing. Document that approvals need writd.
- [x] Turn on the remaining `demo.rs` cases. **The hero demo now runs end to end.**

**Step 6 status:** done. Approvals are opt-in per policy (`approvals:`), so an existing policy never starts hanging. An approved call is re-checked (task live, limits) before it's forwarded, and each settlement (`approve`, `deny`, `timeout`, `cancelled`) is recorded durably. `writ sudo` refuses to run inside a task; that's a guard, not a boundary: same-user processes are trusted in cooperative mode. A simulated first-time operator and a simulated adversary exercised the flow by hand; their findings are folded in below.

Follow-ups found while testing:
- [ ] `writ sudo show` should keep answering after a decision (the outcome, who decided), not just "not waiting".
- [ ] Show the looked-up record (e.g. the charge's customer) and which entitlements held in `writ sudo show`.
- [ ] Approver identity is the local OS user, unauthenticated. Signed approvals (passkeys) and a Slack broker are Phase 2.
- [ ] Precondition revalidation at approval time (plan-v2 §4.4: "charge not already refunded").

### Step 7: Policy replay (about 2 days; can run in parallel with steps 2–6)

- [x] `writ replay --policy new.yaml [--log …] [--task …] [--json]` re-evaluates every recorded `tool_call` and prints the calls whose outcome would flip, with both reasons.
- [x] Warn when a recorded call's arguments were redacted or omitted, since its replay is then partial.
- [x] Exit non-zero when anything gets looser (deny → allow, deny → require_sudo, require_sudo → allow), so it can gate policy changes in CI.

**Step 7 status:** done. The logic is `writ_daemon::replay` (unit-tested). Taint and `max_tool_calls` are re-simulated per task under the candidate, so adding an untrusted source changes only the calls after the first read. Checked against a real demo log: deleting `privileged: true` from `stripe.add_credit` is reported as letting the injected credit, which a human denied at the time, through.

Follow-ups:
- [ ] Replay narrowing (per-server) policies too, from their recorded hashes (needs the policy text stored, not just its hash).
- [ ] Record lookup results with each decision, so replay uses what the source said then, not now.

### Step 8: Signed task tokens (after the demo, about 1–2 weeks)

- [x] Replace `WRIT_TASK` with a Biscuit token minted by writd, carrying task ID, namespace, policy hash, root principal and expiry.
- [x] `writ wrap` presents the token, and writd verifies it. Unsigned IDs are rejected.
- [x] Add `writ fork` (CLI first): attenuate a token with a narrower policy. This is the basis for `max_depth`.
- [x] Strip writ material from anything forwarded to a wrapped server (plan-v2 §4.1, token exposure).
- [x] Update the README's "Not yet a security boundary between processes" section to match what's true after this change.

**Step 8 status:** done, pending an outside review of the token design (owner track). The token is `biscuit-auth` 6 (`crates/writ-daemon/src/token.rs`):
- **Minting and verifying.** writd signs the authority block with an Ed25519 key held only in memory, so restarting writd invalidates every token. `writ run` passes the token as `WRIT_TOKEN` and the id as `WRIT_TASK_ID`, which is for display only. writd refuses `OpenSession` with a bare task id, and `writ wrap` refuses a leftover `WRIT_TASK`. Only the authority block is trusted for the task, namespace, policy hash and principal; a fork that claims another task is ignored (unit-tested). `EndTask` now only works on the connection that created the task.
- **Forking.** `writ fork` works offline. It appends a block carrying `writ_fork(depth, label, policy-bytes)`, plus a `check if time` when given `--ttl`. writd uses fork blocks only to narrow:
  - Each fork's policy joins the D9 evaluation.
  - A fork's `max_tool_calls` is counted per fork, by the block's revocation id, across all of that fork's sessions.
  - `limits.max_depth` is implemented and checked when a session opens.
  - The session's expiry is the earliest of all its blocks.
- **Exposure.**
  - `writ wrap` drops `WRIT_TOKEN` and `WRIT_TASK` from the server's environment and strips `_meta` keys under `writ/`.
  - A message containing the token is refused rather than forwarded.
  - The log records the token's fingerprint and lineage, never the token itself.
- **Tested** end to end in `tests/tokens.rs`:
  - forked narrowing, and the fork limit shared across two servers;
  - the parent keeping its own authority;
  - `max_depth`;
  - a one-character tamper;
  - the server's environment;
  - the leak refusal;
  - no tokens in the log.

Follow-ups:
- [ ] Outside security review of the token design (owner track, §6).
- [ ] Replay doesn't apply fork policies: the log stores their hashes, not their text (same fix as the step 7 narrowing follow-up).
- [ ] Carry tokens per call in MCP `_meta` for in-process sub-agents that share one server connection, verified by `writ wrap`.
- [ ] Proof of possession, and audience-bound edge tokens (RFC 8693) for anything that leaves the machine.
- [ ] The token-in-message check matches the exact token only. An agent that splits or re-encodes the token gets past it. A boundary needs mediated mode.

---

## 5. After the demo (order decided by discovery)

- [ ] HTTP MCP transport (a reverse proxy) — the first item after the demo (OBSERVATIONS §3.7).
- [ ] A public bypass test suite built from `demo.rs` plus the injection cases.
- [ ] OpenTelemetry export of decisions and task facts.
- [ ] A real Stripe entitlement resolver, then IdP-verified roots (OIDC).
- [ ] A Slack approval broker.
- [ ] One framework adapter with automatic `writ fork`.
- [ ] macOS peer-credential check (`getpeereid`).
- [ ] Policy over MCP sampling and elicitation (open question 12).

## 6. Owner track (in parallel, not code)

- [ ] Confirm or override the defaults table in §3. Most urgent: the license, before any outside PR.
- [ ] Decide on the name (OBSERVATIONS §3.6) before anything is published or announced.
- [ ] Discovery: list 15 target teams, book 5 conversations using `examples/poisoned-ticket/README.md`, and record each team's topology, privileged tools and entitlement source.
- [ ] Source or remove the unsourced market figures in `plan-v2.md` §11.2.
- [ ] Find one security reviewer for the token design before step 8 ships.

## 7. Definition of "unstuck"

- `cargo test -- --ignored demo` passes: the poisoned-ticket scenario is blocked, allowed or paused exactly as plan-v2 §7.1 describes.
- At least 3 discovery conversations have been held, and their findings are recorded next to this file.
- The defaults table has been confirmed or overridden by the owner.
