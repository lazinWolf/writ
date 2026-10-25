# writ & writd — Master Plan

> The capability, sandboxing, and compliance substrate for agent-centric computing.

**Document status:** Living plan. Last revised Oct 2026.
**Purpose:** Hold the full vision, the honest technical analysis, the key architectural decisions, and the phased path to get there. This doc is written to be shown to design partners, investors, and security reviewers, so it separates *vision* from *present guarantees*.

### Conventions used in this doc

| Label | Meaning |
|---|---|
| **[V1]** | In scope for the first shippable release |
| **[V2]** | Next phase, after the wedge is proven |
| **[VISION]** | Long-term north star; not a current claim |
| **Guarantee** | A property that holds given the stated enforcement mode and trust assumptions |
| **Goal** | A property we are designing toward but do not yet promise |

---

## 0. TL;DR

- Agents are non-deterministic actors running on primitives (OS permissions, cloud IAM) designed for deterministic code and slow humans.
- **writ** is a capability protocol, policy manifest (`writ.yaml`), and CLI. **writd** is the enforcement daemon.
- The core new idea: **the task tree, not the individual agent, is the unit of authority.** Authority starts at a root intent (a human, cron job, webhook, or partner) and can only *shrink* as it flows to sub-agents, like a Unix process tree with privileges that can be dropped but never raised.
- The moat: **lineage + taint as inputs to every policy decision.** "This request descends from an external, untrusted origin, so this privileged action requires a co-signer." Per-agent IAM and today's gateways cannot express this.
- Long-term, writd covers six primitives (capability tokens, out-of-band memory and taint, behavioral limits, a staging airlock, credential and tenant pinning, and a flight recorder). We will not build all six at once.
- **Proposed wedge:** confused-deputy prevention (origin-bound writ propagation, coarse taint, and approval for privileged mutations), sold to platform teams at B2B SaaS companies shipping customer-facing agents.

---

## 1. Core Thesis

Computing is shifting from human-driven, deterministic software to autonomous, multi-agent execution. Yet we run agent swarms on 1970s OS primitives and 2010s cloud IAM.

writ aims to be for agents what Unix process isolation, `chmod`, cgroups, `sudo`, and audit logs were for programs: the runtime substrate that gives developers precise execution control and gives organizations verifiable, auditable trust in what their agents did and why.

---

## 2. The Problem: Three Assumptions That Collapse in the Agentic Era

Operating systems, cloud IAM, and compliance frameworks rest on three assumptions that no longer hold.

**2.1 The Actor Assumption (deterministic code vs. non-deterministic agency).**
Legacy security assumes that if a process may `DELETE` a row or transfer funds, it only does so when reviewed code triggers it. An agent's control flow is written on the fly by an LLM. It can hallucinate, loop, or be manipulated at machine speed.

**2.2 The Identity Assumption (static principals vs. ephemeral swarms).**
Humans and microservices have stable identities and roles. Agents operate in fluid task trees: a supervisor may spawn 50 sub-agents for 12 seconds across LangGraph, CrewAI, or A2A, then terminate them. Static IAM either blocks agents from working or pushes teams to share one over-privileged credential across the whole swarm, which destroys least privilege and non-repudiation.

**2.3 The Boundary Assumption (compute isolation vs. cognitive isolation).**
Reading an untrusted file (`cat untrusted.txt`) cannot rewrite the binary of the program reading it. In agentic systems, **cognition = code**: reading an untrusted email, webpage, or agent message directly changes the agent's behavior. Container isolation is insufficient without information-flow and context isolation.

---

## 3. What Is Genuinely New Here

The market already offers several of the individual pieces (see §11). These two ideas are what's new.

1. **Task-tree authority.** A root writ binds principal, tenant, intent, policy, and budget. Every sub-agent spawn (`writ fork`) appends a signed, attenuating block. Authority is a property of *where a request came from*, not just *which agent is asking*.
2. **Lineage and taint as policy inputs.** Policies can condition on the full causal chain ("root principal is `external_user_99`, the branch ingested Zendesk ticket content, and the request reached the Finance agent via two hops") rather than only on the immediate caller's identity.

Everything else (budgets, credential brokering, audit logs, staging) is valuable and expected, but it is not the moat on its own.

---

## 4. The Six Primitives

Each primitive pairs a developer benefit with a compliance or security property. This pairing matters: the product fails if developers see it as red tape or if security teams see it as an unverified dev toy. For each primitive, we also record what we can honestly guarantee and the known hard problems.

### Summary table

| Primitive | Developer benefit | Security / compliance property | Phase |
|---|---|---|---|
| Cryptographic Writs (`writ fork`) | Spawn sub-agents without hand-wiring tool subsets per node | Least privilege across hops; signed delegation lineage back to a human or system trigger | **[V1]** |
| Taint tracking & out-of-band memory (`ref://`) | Pass large payloads between agents without stuffing them into context | Untrusted inputs cannot directly trigger privileged actions; secrets never enter prompts | Taint (coarse) **[V1]**, secrets-only `ref://` **[V2]**, PII `ref://` **[VISION]** |
| Behavioral limits ("cgroups for agency") | Runaway loops and wallet drains stop automatically | Hard, auditable bounds on depth, spend, velocity, and blast radius | **[V1]** (tool-call limits), LLM spend **[V2]** |
| Speculative Airlock (`writ diff` / `writ commit` / `writ sudo`) | Run agents against real systems with a reviewable plan before effects land | Dual control and change management for high-risk mutations | Approval gating **[V1]**, native staging adapters **[V2]** |
| Credential vault & tenant pinning | Build multi-tenant agents without trusting LLM-written filters; no keys in `.env` | Agents hold no raw credentials; tenant boundaries enforced below the LLM | Credential brokering **[V2]**, Postgres pinning **[V2]**, vector/S3 **[VISION]** |
| Flight Recorder | Replay and debug any swarm run as a causal graph | Tamper-evident audit trail answering who authorized what, with which data, and why | Basic **[V1]**, anchored + compliance exports **[V2]** |

### 4.1 Cryptographic Writs & Hop Decay (`writ fork`)

**What it is.** Attenuating capability tokens (Biscuit) carried in MCP `_meta` fields and A2A headers. Each hop appends a signed block:
`Root(User: Alice) → Hop1(Orchestrator) → Hop2(BillingSubAgent)`.
A child's capabilities are the intersection of the parent's writ and the declarative `writ.yaml` policy.

**Honest guarantee.** A holder can only narrow a writ, never broaden it. Verification is offline and deterministic (Datalog checks).

**Hard problems.**
- **Isolation of token holders.** Attenuation only enforces anything if a child cannot read its parent's token. Sub-agents running in the same Python process share memory, so in cooperative mode `writ fork` is a strong convention, not a hard boundary. The hard boundary arrives with mediated or isolated enforcement modes (§5.2).
- **Semantic attenuation is not a security boundary.** If an LLM interprets "the sub-task" to decide which tools a child sees, that decision is probabilistic. Semantic scoping is a usability feature that hides irrelevant tools. **Only declarative caveats carry security weight.**
- **"Intent binding" binds a string, not its meaning.** The writ cryptographically records the stated intent for audit, but cryptography cannot verify that an action matches that intent. We say "intent-recorded," not "intent-enforced."
- **Interop.** The industry standard for delegation chains is OAuth 2.0 Token Exchange (RFC 8693) with the `act` claim. We use Biscuit internally for offline attenuation and Datalog caveats, and we emit standards-compatible tokens at system edges (see D2).

### 4.2 Taint Tracking & Out-of-Band Memory (`ref://`)

**What it is.** Every data source carries a trust class (`SYSTEM_TRUSTED`, `INTERNAL`, `EXTERNAL_UNTRUSTED`). Ingesting untrusted data marks the active writ branch as tainted, and policies can then require approval, block egress, or restrict privileged tools. Sensitive or heavy payloads are stored out of band, and the LLM receives a typed handle such as
`ref://db_result_91 [Rows: 10000, Schema: {id, email, ssn: REDACTED}]`.
When an authorized downstream tool receives the handle, writd substitutes the real payload on the wire.

**Honest guarantee.** With wire-level tracking, taint is *branch-granular*: once untrusted content enters a branch, the whole branch is treated as tainted. `ref://` keeps raw values out of the LLM context only for data the agent passes through without needing to read it.

**Hard problems.**
- **Taint spreads to almost everything.** The FIDES paper identifies this limitation directly: untrusted tool output taints the conversation and restricts later tool use. Most real workflows read a ticket, email, or webpage in step one. If tainting triggers "stage all mutations," every action needs approval, approvers start approving without reading, and the airlock becomes theater.
- **The `ref://` trade-off.** If the LLM must reason about content (e.g., "is this invoice a duplicate?"), that content must enter its context. `ref://` savings apply to pass-through data, not to data the agent must judge. We will publish token-savings numbers only after benchmarking real workloads.
- **PII detection by field name misses free text** (an SSN pasted into a `notes` field). PII handling via `ref://` stays **[VISION]** until we have a credible detection story. In V2, `ref://` covers secrets and credentials only, where detection is reliable because we issue them.

**Mitigation design (V1/V2).**
- Apply approval requirements to *privileged* mutations only, not all mutations (see `writ.yaml` in §7).
- **Quarantined reader pattern:** a sub-agent reads untrusted content and must return output that matches a strict schema (e.g., `{invoice_id: string, amount: number, is_duplicate: bool}`). Schema validation acts as an explicit declassification step, so the parent branch can stay untainted. This approximates CaMeL/FIDES-style separation without owning the planner.
- **[VISION]** Planner-level information-flow control (CaMeL/FIDES-grade), offered as an opt-in runtime for teams willing to adopt it.

### 4.3 Behavioral Limits ("cgroups for Agency")

**What it is.** Each root writ defines `max_depth`, `max_parallel_agents`, `max_tool_calls`, `max_spend_usd`, and mutation velocity (e.g., at most 5 deletes per task). Exceeding a limit interrupts the branch and returns control to the supervisor.

**Honest guarantee.** Tool-call counts, depth, and parallelism are enforced deterministically for all traffic writd mediates.

**Hard problems.**
- **LLM spend requires owning the model gateway.** Tool-call interception alone cannot meter token spend. Full `max_spend_usd` enforcement needs writd (or an integrated model gateway) on the path to model APIs. **[V2]**
- **Hash-based loop detection** misses semantically identical loops with varying arguments and can flag legitimate polling. Budgets are the robust backstop. The loop breaker is a heuristic early warning, not a guarantee.

### 4.4 The Speculative Airlock (`writ diff`, `writ commit`, `writ sudo`)

**What it is.** Reads execute against live systems. Mutations matching staging rules are held for policy or human approval, then executed.

**Revised semantics: deferred execution with precondition revalidation.**
The original design promised generic copy-on-write staging, synthetic receipts, and atomic commits. Those promises do not hold:
- **Synthetic receipts make agents reason about effects that haven't happened** (e.g., emailing "your refund was issued" while the refund is still staged).
- **Read-your-writes breaks.** A staged `UPDATE` followed by a `SELECT` returns old data.
- **Some effects cannot be staged or undone:** sent emails, Slack messages, third-party API side effects.
- **Atomic commit across heterogeneous systems is impossible.** Stripe and Postgres share no transaction protocol.
- **Delayed approval creates time-of-check/time-of-use gaps.** A diff approved hours later executes against a changed world.
- **Read vs. mutate cannot be reliably classified from the wire.** MCP `readOnlyHint` and `destructiveHint` annotations are self-reported by possibly untrusted servers.

So the airlock works like this:
1. **Default behavior is pause, not fake.** When a staged action's result is needed downstream, the branch pauses until approval. Synthetic receipts are opt-in, only for tools explicitly marked as safe to defer, and the receipt is labeled as pending so the agent knows the effect hasn't happened.
2. **Preconditions are recorded at staging time and revalidated at commit time** (e.g., "charge `ch_x` is not already refunded," "row version = 17").
3. **Execution is ordered, not atomic.** Staged actions run in dependency order with idempotency keys. If a later step fails, writd records the failure and any required compensating action in the flight recorder rather than claiming a rollback it cannot perform.
4. **Use native staging wherever it exists** instead of building generic copy-on-write. Examples: Postgres transactions and database branches (e.g., Neon), GitHub pull requests, `terraform plan`, `kubectl --dry-run=server` and `kubectl diff`, Stripe test mode.
5. **Classify read vs. mutate by policy, not server hints.** `writ.yaml` declares classifications per tool and per argument pattern, with deny-by-default for unknown tools in production namespaces.

**Research note.** TomasuLLM (Sept 2026) shows copy-on-write speculative execution of tool calls in isolated sandboxes, committing in order after validation. Its guarantee is about *withholding* speculative results and external effects until they are justified by committed state. It shows that local speculation is feasible; it does not show that external effects can be staged and committed atomically later.

### 4.5 Credential Vault & Protocol-Level Tenant Pinning

**What it is.** Agents hold no raw keys or database passwords. writd injects credentials into outbound requests only after verifying the writ. For multi-tenant systems, `tenant_id` is bound into the writ and enforced below the LLM (Postgres row-level security session variables, vector metadata filters, S3 prefix restrictions).

**Honest guarantee (Postgres, V2).** Agent-generated SQL cannot read or write rows outside the pinned tenant, *provided the RLS policies themselves are correct.* "Provable" applies relative to the policy, not absolutely.

**Requirements to make this real.**
- Parse agent SQL (e.g., `pg_query`) and deny `SET`, `RESET`, `SET ROLE`, DDL, and `GRANT` from agent-originated queries.
- Use `SET LOCAL app.tenant = ...` inside each transaction, never connection-wide settings on pooled connections.
- Connect as a role that does not own the tables (so RLS cannot be bypassed) and has `FORCE ROW LEVEL SECURITY` where needed.
- Enforce `max_rows_affected` by executing inside a transaction, checking the affected row count, and rolling back if it exceeds the limit.
- For S3, use short-lived STS credentials with session policies scoped to the tenant prefix.

**Hard problem: local stdio MCP servers.** The *server* calls Stripe, not the agent. Injecting credentials into the server's outbound traffic requires writd to proxy its egress, including TLS interception with a local CA, or to run the server inside a writd-controlled environment. This is a V2 problem tied to mediated mode.

### 4.6 The Flight Recorder

**What it is.** An append-only, hash-chained log of every tool call, `ref://` movement, taint transition, policy decision, and approval, exportable via OpenTelemetry and viewable as a causal graph.

**Honest guarantee.** The log is tamper-evident to the extent it is externally anchored. A hash chain held only by the operator can be fully rewritten by that operator, so non-repudiation requires anchoring (RFC 3161 timestamps or a transparency log) and approver signatures (WebAuthn/passkeys).

**Compliance framing.** The recorder produces *evidence* that supports SOC 2, ISO 27001, HIPAA, GDPR, and NIST AI RMF controls. It does not make an organization compliant on its own; those frameworks are organizational controls.

---

## 5. System Architecture

### 5.1 Component diagram

```text
[ Human / Cron / Webhook / B2B Partner ]
        │  Issues Root Writ: principal + tenant + intent (recorded) + policy + budget
        ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          writd (enforcement daemon)                      │
│                                                                          │
│  1. Writ & Lineage Engine        2. Taint & Out-of-Band Store (ref://)   │
│     • Biscuit mint/attenuate        • Branch-level taint propagation     │
│     • Datalog verification          • Secrets vault (V2), PII (VISION)   │
│     • RFC 8693 edge tokens          • Schema-validated declassification  │
│                                                                          │
│  3. Behavioral Limits            4. Airlock                              │
│     • Depth / calls / velocity      • Policy-based read/mutate classes   │
│     • LLM spend (via model gw)      • Pause / precondition revalidation  │
│     • Loop heuristics               • Native staging adapters            │
│                                                                          │
│  5. Credential Broker & Pinner   6. Flight Recorder                      │
│     • Last-moment injection         • Hash-chained, externally anchored  │
│     • Postgres RLS / S3 STS         • OTel export, causal DAG view       │
│                                                                          │
│  Policy Decision Point: native writ.yaml evaluator, plus optional        │
│  export of lineage/taint context to Cedar, OPA, or AgentCore Policy      │
└──────────────────────────────────────────────────────────────────────────┘
        │  Intercepts: stdio JSON-RPC, MCP over HTTP, A2A, model API traffic
        │  (mediated mode adds egress control; isolated mode adds per-agent sandboxes)
        ▼
[ Databases · Cloud infra · SaaS APIs · Filesystem · Model APIs · External agents ]
```

### 5.2 Enforcement modes

Guarantees depend on how much of the execution path writd controls. Every guarantee in this doc is stated relative to a mode.

| Mode | How it works | What it can guarantee | What it cannot | Phase |
|---|---|---|---|---|
| **Cooperative** | SDK hooks in frameworks; `writ wrap` around MCP servers | Policy on all *routed* tool calls; lineage; audit; tool-call limits | Agents with a shell can bypass by calling the network directly; in-process sub-agents can share tokens | **[V1]** |
| **Mediated** | writd owns network egress (network namespace or proxy) and the model gateway | All network effects pass through writd; LLM spend metering; credential injection for stdio servers | In-process token sharing between sub-agents | **[V2]** |
| **Isolated** | Each sub-agent runs in its own sandbox (container or microVM) with only its attenuated writ | Hard capability boundaries between agents; full reference-monitor properties | Higher latency and operational cost | **[VISION]** / enterprise tier |

The "kernel" framing is earned at mediated mode and fully true at isolated mode. Marketing for V1 must describe cooperative mode accurately.

### 5.3 Engineering layers

**Layer 1: writd core (Rust).** Transport multiplexer (stdio, HTTP, A2A, model API), Biscuit engine, taint and out-of-band store, airlock queue with precondition tracking, credential broker, recorder.

**Layer 2: Framework & protocol adapters (Python / TypeScript).** Orchestrator hooks that call `writ fork` on sub-agent spawn: start with one or two frameworks (candidates: LangGraph, Claude Code hooks, OpenAI Agents SDK), expand later. Protocol pinners: Postgres first; vector DBs and REST adapters later.

**Layer 3: Governance control plane.** `writ.yaml` compiler and validator, approval broker (CLI and Slack first; Teams and passkey signing next), recorder UI and compliance exports.

---

## 6. Threat Model

### In-scope adversaries
1. **Injected content:** untrusted emails, tickets, webpages, documents, or agent messages that try to steer an agent (prompt injection).
2. **Faulty agents:** hallucinated arguments, misread logs, runaway loops, accidental destructive calls.
3. **Malicious or compromised MCP servers:** returning manipulated results, smuggling instructions, or exfiltrating data passed to them.
4. **Compromised sub-agents:** a sub-agent whose behavior has been subverted and that tries to escalate via other agents (confused deputy).
5. **Credential theft from agent environments:** e.g., `printenv` in a coding agent.

### Trust assumptions
- The writd host and its signing keys are trusted.
- `writ.yaml` policies and RLS policies are correct as written. writd enforces policy; it cannot fix a wrong policy.
- In cooperative mode, framework adapters are trusted to route traffic through writd.

### Out of scope (for now)
- A malicious developer who controls the agent code and the writd configuration.
- Side channels and covert channels between agents.
- Correctness of upstream model behavior.
- Implicit information flows through control flow (a known limitation shared with practical IFC systems).

---

## 7. Developer & Operator Experience

### 7.1 `writ.yaml`

```yaml
version: 1
namespace: prod-customer-ops
enforcement: cooperative        # cooperative | mediated | isolated

# 1. Task-tree limits
limits:
  max_depth: 4
  max_parallel_agents: 8
  max_tool_calls: 200
  max_budget_usd: 1.50          # LLM spend requires mediated mode (model gateway)
  loop_breaker: strict          # heuristic early warning; budgets are the backstop

# 2. Data flow & taint
data_flow:
  untrusted_sources: ["mcp:web-scraper", "mcp:zendesk-tickets"]
  secrets: out_of_band_ref      # V2: credentials never enter LLM context
  # pii_fields: ["ssn", "credit_card"]   # VISION
  on_taint:
    privileged_mutations: require_sudo
    other_mutations: allow_within_limits
    egress_to_untrusted_sinks: deny
  declassify:
    - from: "agent:ticket-reader"
      schema: "./schemas/ticket_summary.json"   # validated output clears taint

# 3. Capabilities & blast radius
capabilities:
  - tool: "postgres.*"
    classify:                    # server hints are not trusted
      reads: ["SELECT"]
      mutations: ["INSERT", "UPDATE", "DELETE"]
      deny: ["SET", "RESET", "DROP", "ALTER", "GRANT", "TRUNCATE"]
    pin_tenant_from_writ: true   # SET LOCAL inside each transaction
    mutations:
      max_rows_affected: 10      # checked in-transaction; rolled back if exceeded
      exceed_action: stage

  - tool: "stripe.refund"
    privileged: true
    idempotency: required
    conditions:
      - "args.amount <= 100.00"
      - "writ.tainted == false"
    preconditions:
      - "charge.refunded == false"
    on_violation: require_sudo
    sudo_approvers: ["group:finance-leads"]

  - tool: "*"
    default: deny                # unknown tools denied in prod namespaces
```

### 7.2 Wrapping an MCP server (`writ wrap`)

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

### 7.3 SDK

```python
from writ import Writ, Sandbox

root_writ = Writ.issue(
    principal="user:alice@acme.com",
    tenant="tenant_882",
    intent="Audit Q3 disputed invoices and refund duplicate charges",  # recorded, not enforced
    policy="./writ.yaml",
)

with Sandbox(writ=root_writ) as sb:
    swarm.run()   # framework adapter calls writ fork on each sub-agent spawn

if sb.has_staged_actions():
    print(sb.diff())
    sb.request_sudo(channel="#finance-approvals")
```

### 7.4 Operator CLI

```text
$ writ ps
WRIT ID       PRINCIPAL        TENANT       DEPTH  TAINTED  CALLS   STATUS
wrt_01j9x8a   alice@acme.com   tenant_882   3/4    YES      41/200  AWAITING_SUDO (2 staged)

$ writ diff wrt_01j9x8a
STAGED ACTIONS FOR wrt_01j9x8a
  Lineage: alice@acme.com -> SupervisorAgent -> ZendeskAgent [TAINT: mcp:zendesk-tickets] -> BillingAgent

  [1] stripe.refund(customer="cus_991", amount=240.00)
      Staged because: amount > auto-limit ($100.00); branch tainted; tool is privileged
      Preconditions:  charge ch_3x… not already refunded
  [2] postgres: UPDATE invoices SET status='refunded' WHERE id=991
      Tenant pin:     tenant_882 (RLS via SET LOCAL)
      Depends on:     [1]

$ writ sudo approve wrt_01j9x8a --sign-passkey
✓ Approver verified: bob@acme.com (WebAuthn)
✓ Preconditions revalidated
✓ [1] stripe.refund executed (idempotency key wrt_01j9x8a-1)
✓ [2] postgres UPDATE executed in transaction (1 row)
✓ Recorded: audit entry sha256:8f9d2a… (anchored)
  Note: actions execute in order, not atomically across systems.
```

---

## 8. Target Scenarios

| # | Scenario | Failure today | writd enforcement | Phase |
|---|---|---|---|---|
| 1 | **Confused deputy** | Low-privilege support agent reads a poisoned ticket and asks a high-privilege finance agent to issue a $5k refund | Origin-bound writ propagation: finance agent sees root = external user + tainted branch; `stripe.refund` requires a co-signer | **[V1] hero demo** |
| 2 | **DevOps blast radius** | SRE agent misreads a log at 3 AM and scales production to 0 nodes | Parameter limits (`delta(nodes) <= 2`) plus native staging via `kubectl diff` / server-side dry run, routed for approval | **[V2]** |
| 3 | **Runaway swarm** | 50 sub-agents hit an error loop and burn $4,000 in API credits | Per-root budgets on depth, calls, and parallelism (V1); LLM spend via model gateway (V2); loop heuristics | **[V1]/[V2]** |
| 4 | **Multi-tenant data bleed** | Agent omits `WHERE tenant_id = 'A'` and leaks tenant B's data | Postgres RLS pinning with `SET LOCAL`, SQL parsing to block session changes, non-owner role | **[V2]** |
| 5 | **Credential sprawl** | Coding agent runs `printenv` and leaks keys from `.env` | Agent holds no keys; writd injects credentials at egress (requires mediated mode for shell-capable agents) | **[V2]** |
| 6 | **Cross-company mandates** | Procurement agent negotiates without provable corporate authority | Verifiable writs in A2A headers; interoperate with AP2 mandates for payments rather than compete | **[VISION]** |

---

## 9. Key Architectural Decisions

These are decisions that the first release will lock in, even if the related features ship later. Each needs a written decision record before V1 code freezes.

**D1. Enforcement boundary.**
Options: cooperative proxy only / design for mediated from day one / isolated-first.
Lean: ship cooperative, but design the transport layer so writd can sit on the egress path without a rewrite.
Why now: retrofitting full mediation into a proxy architecture is a rebuild.

**D2. Token format and interop.**
Options: Biscuit only / OAuth token exchange only / Biscuit internally, RFC 8693 at edges.
Lean: Biscuit internally (offline attenuation, Datalog caveats), standards-compatible tokens at system boundaries.
Why now: early users wire the token format into their stacks; changing it later is painful.

**D3. Where taint lives.**
Options: wire-level branch taint / planner-level variable taint / both, tiered.
Lean: wire-level branch taint plus schema-based declassification in V1; planner-level as an opt-in runtime later.
Why now: the lineage data model must carry taint labels in a shape that supports finer granularity later.

**D4. Airlock semantics.**
Options: synthetic receipts by default / pause by default / per-tool choice.
Lean: pause by default; synthetic receipts opt-in per tool and clearly labeled as pending.
Why now: developers build agent logic around whichever behavior ships first.

**D5. Read/mutate classification.**
Options: trust MCP annotations / policy-declared classes / learned classifier.
Lean: policy-declared, deny-by-default for unknown tools in production; annotations used only as suggestions during policy authoring.

**D6. Semantic vs. declarative attenuation.**
Decision: declarative caveats are the only security boundary. Semantic tool-hiding is a usability layer and is documented as such.

**D7. Audit anchoring.**
Options: local hash chain / RFC 3161 timestamping / transparency log.
Lean: local chain in V1 with a pluggable anchor; external anchoring in V2 before any non-repudiation claims.

**D8. Policy engine strategy.**
Options: own policy language only / own language plus export of context to Cedar, OPA, and AgentCore.
Lean: native `writ.yaml` for developers, plus a context-export interface so lineage and taint become attributes in other policy engines.

---

## 10. Developer Superpowers vs. Compliance Guarantees (revised dual mandate)

| Primitive | Developer benefit | Compliance property | Honest scope |
|---|---|---|---|
| Airlock | Review an agent's planned mutations against real data before they land | Dual control for high-risk changes | Ordered execution with revalidated preconditions; not atomic across systems |
| `ref://` handles | Move large data between agents without context bloat | Secrets never enter prompts or model-provider logs | Secrets first; PII is vision; savings only for pass-through data |
| Writs | Zero-config sub-agent scoping | Signed delegation lineage and least privilege | Hard boundary requires mediated/isolated mode |
| Taint | External content can't silently drive privileged actions | Prompt-injection containment for privileged tools | Branch-granular; mitigated by declassification |
| Tenant pinning | Multi-tenant agents without trusting LLM-written filters | Tenant isolation enforced below the LLM | Correct relative to RLS policy correctness |

---

## 11. Ecosystem & Competitive Landscape (as of Oct 2026)

### 11.1 Protocols
- **MCP:** The 2026-07-28 spec is final. It moves MCP to a stateless request/response core, hardens authorization (RFC 9207 issuer validation, credentials bound to their authorization server, a shift from Dynamic Client Registration to client metadata documents), and adds an Enterprise Managed Authorization extension. Remaining gaps relevant to writ: transport auth verifies identity, not action safety; local stdio servers still commonly rely on `.env` secrets; no native multi-hop attenuation or lineage.
- **A2A:** Standardizes agent cards and task lifecycles; no native cryptographic delegation or mandate verification layer.
- **AP2 (Agent Payments Protocol):** Google-led, with Intent, Cart, and Payment mandates carried as W3C Verifiable Credentials. Covers scenario 6 for payments. Published red-teaming shows AP2 remains exposed to prompt injection, which supports writ's thesis that signed intent alone does not stop injection; taint and lineage are the missing layer.

### 11.2 Competitors and adjacent players

| Category | Examples | Overlap | writ's stance |
|---|---|---|---|
| Cloud-native agent policy | AWS AgentCore Gateway + Policy (Cedar, deterministic, argument-aware, natural-language authoring) | Deterministic gateway policy on tool calls | Complement: export lineage/taint as policy context; don't compete as "another gateway" |
| MCP gateways / policy layers | Bifrost, Solo.io agentgateway, Lunar MCPX, MintMCP, PolicyLayer | Per-call allow-lists, argument rules, approval gates, audit | Differentiate on multi-hop lineage + taint, which they lack |
| Agent identity & task-scoped tokens | Keycard, Astrix (Cisco), Token Security, P0 Security, Arcade, Akeyless, Defakto | Per-agent identity, task-scoped credentials, delegated context | Table stakes; interoperate via RFC 8693 rather than replace |
| Enterprise IAM | Okta, Microsoft Entra, Ping, SailPoint | Agent identity governance | Integrate as identity sources for root writs |
| Credential brokering | 1Password, Akeyless, CyberArk (Palo Alto Networks) | Keys never reach the agent | Table stakes; necessary but not differentiating |
| Model gateways | LiteLLM, Portkey and similar | Spend tracking, routing | Integrate for LLM spend limits rather than rebuild |
| Sandboxes | E2B, Daytona, Modal, cloud sandboxes | Process/VM isolation | Potential substrate for isolated mode |

**Market signals.** Agent and AI security drew roughly a quarter of cybersecurity seed funding in Q2 2026. Consolidation is fast: Palo Alto Networks closed its CyberArk acquisition (Feb 2026), ServiceNow closed Veza (Mar 2026), Snowflake acquired Natoma (May 2026), and Cyera announced an Oasis acquisition (Jul 2026, pending).

### 11.3 What is table stakes vs. differentiated

**Table stakes now:** task-scoped credentials, deterministic gateway policy on tool calls, argument-level rules, approval gates, audit logs, credential brokering.

**Differentiated:** cross-framework multi-hop lineage; taint and lineage as policy inputs; precondition-revalidated staging that orchestrates native staging mechanisms.

**Positioning:** writ is the *context layer* that makes everyone's policy decisions aware of where a request came from and what it has read, plus a reference runtime for teams that want writ end to end.

---

## 12. Research Foundations

- **CaMeL (Google DeepMind / ETH Zurich):** Separates trusted control flow from untrusted data flow using a privileged planner and quarantined LLM with capability tags. Strong guarantees come from owning the planner and interpreter.
- **FIDES (Microsoft):** Information-flow control for agent planners with confidentiality and integrity labels, selective variable hiding, and constrained-decoding inspection. Explicitly documents the taint-creep limitation writ must design around. Open source at github.com/microsoft/fides.
- **TomasuLLM (HKUST et al., Sept 2026):** Out-of-order speculative tool execution in copy-on-write sandboxes with in-order commit after validation. Relevant to local speculation; not evidence for staging external effects.
- **PC2 (Proof-Carrying Contracts):** Cited in the original vision for airlocks that escrow state changes until post-conditions verify. **Citation to verify before external use.**

---

## 13. Wedge & Roadmap

The vision covers six primitives. The plan below proves one wedge first. Phase boundaries have exit criteria, not dates.

### Phase 0: Foundations
- Writ token spec (Biscuit internal format, edge-token mapping draft).
- `writd` cooperative mode: stdio and HTTP MCP interception, `writ wrap`.
- One framework adapter with automatic `writ fork` on sub-agent spawn.
- Tool-call, depth, and parallelism limits.
- Basic flight recorder (local hash chain, OTel export).
- `writ ps`, `writ log`.

**Exit criteria:** a design partner runs a real multi-agent workflow through writd with acceptable latency overhead (target: low single-digit milliseconds p99 per call; to be benchmarked) and can reconstruct the full lineage of any action.

### Phase 1: The Wedge (confused-deputy prevention)
- Origin-bound writ propagation across agents and A2A hops.
- Branch-level taint from declared untrusted sources.
- Privileged-tool marking and `require_sudo` on tainted or out-of-policy calls.
- Approval broker: CLI and Slack.
- Schema-based declassification (quarantined reader pattern).
- Bypass test suite: a published set of injection scenarios writd must block in cooperative mode.

**Exit criteria:** scenario 1 is blocked end to end in a design partner's production workflow; approval volume stays manageable (track the share of privileged calls needing human approval and the median approval time); at least one partner willing to pay.

### Phase 2: Production hardening
- Mediated mode: egress control and model gateway integration (LLM spend limits).
- Airlock with precondition revalidation and native staging adapters (Postgres transactions/branches, GitHub PRs, Kubernetes dry-run/diff).
- Credential broker, including stdio servers in mediated mode.
- Postgres tenant pinning.
- External audit anchoring; approver signatures via passkeys.
- Context export to Cedar/OPA/AgentCore.
- Second and third framework adapters.

### Phase 3: Enterprise
- Isolated mode (per-agent sandboxes).
- Compliance evidence exports mapped to SOC 2, ISO 27001, HIPAA, GDPR, NIST AI RMF controls.
- Teams integration, recorder UI with causal DAG view.

### Phase 4: Vision
- `ref://` for PII with credible detection.
- Vector DB and S3 pinning adapters.
- Cross-organization verifiable writs over A2A, interoperating with AP2.
- Opt-in planner-level IFC runtime (CaMeL/FIDES-grade).

### Alternative wedge (keep in reserve)
**"terraform plan for agents":** a developer-first airlock limited to systems with real native staging (Postgres, GitHub, Kubernetes). Stronger bottom-up developer pull, weaker security-buyer story. Revisit if Phase 1 design-partner conversations show more pull for staging than for injection containment.

---

## 14. Go-To-Market

- **Model:** open core, similar to Teleport. Open-source the writ spec, CLI, local daemon, and basic adapters. Sell the control plane: approval broker, anchored flight recorder, compliance exports, central policy management, and isolated mode.
- **First buyer:** platform engineering teams at B2B SaaS companies shipping customer-facing agents. Their pain (tenant bleed, confused deputy, customer security questionnaires asking how agents are scoped and audited) is concrete, and they have budget.
- **Dual-buyer risk:** developers adopt, security teams pay. Lead with developer adoption through the open-source daemon; convert through security requirements surfaced in customers' vendor reviews.
- **Design partners:** target 3–5 for Phase 0/1, selected for real multi-agent workflows that touch privileged tools.
- **Distribution:** listings in MCP registries, framework integrations, and cloud marketplaces; publish the bypass test suite as a credibility asset.

---

## 15. Claims & Language Policy

Security buyers read overclaiming as a sign the team doesn't understand security. All external material follows this table.

| Avoid | Use instead |
|---|---|
| "Mathematical compliance" | "Verifiable, tamper-evident evidence for compliance controls" |
| "Guarantees DLP / HIPAA / GDPR compliance" | "Keeps secrets (and, in future, regulated fields) out of LLM context; produces audit evidence" |
| "Committed atomically" | "Executed in order with revalidated preconditions and idempotency keys" |
| "Intent-bound tokens" | "Tokens that record the stated intent and enforce declared caveats" |
| "Runtime kernel" (for V1) | "Policy and lineage layer for agent tool calls" (kernel framing reserved for mediated/isolated modes) |
| "Cuts token costs by 80%" | Benchmarked figures for specific workload types only |
| "Pass 50MB in 1ms" | Measured latency figures with methodology |
| ">100:1 machine-to-human identities" | Cite a specific source; published estimates vary (roughly 50:1 in some recent surveys) |
| "Provable tenant isolation" | "Tenant isolation enforced below the LLM, relative to your RLS policies" |

---

## 16. Success Metrics

- **Security efficacy:** bypass test suite pass rate per enforcement mode; injection scenarios blocked in partner environments.
- **Approval health:** share of privileged calls auto-decided by policy vs. sent to humans; median human approval time; approvals overturned on review (a signal of rubber-stamping).
- **Developer friction:** time to first wrapped MCP server; lines of integration code per framework; p50/p99 latency overhead.
- **Taint quality:** share of tainted branches cleared via declassification; false-positive taint rate reported by partners.
- **Business:** design partners converted to paid; security-review wins attributable to writ.

---

## 17. Risks

1. **Platform absorption.** Cloud providers and IAM incumbents add lineage-aware policy. Mitigation: be the cross-cloud, cross-framework context layer and integrate with their policy engines rather than compete head-on.
2. **Standard capture.** A competing delegation format becomes the MCP/A2A standard. Mitigation: edge interop from day one (D2); participate in standards work.
3. **Approval fatigue.** Taint spread makes the airlock noisy and unused. Mitigation: privileged-only gating, declassification, approval-health metrics as a first-class product signal.
4. **Adapter treadmill.** Frameworks and protocols change faster than adapters can keep up. Mitigation: limit to 1–2 frameworks until the wedge is proven; prefer protocol-level interception over framework-level hooks where possible.
5. **Dual-buyer drift.** Trying to satisfy developers and security teams equally satisfies neither. Mitigation: explicit first-buyer choice (§14).
6. **Credibility.** Overclaiming in early material. Mitigation: §15 language policy, published threat model.

---

## 18. Open Questions

1. Confirm the first slice: confused-deputy wedge (proposed) vs. "terraform plan for agents."
2. Which one or two frameworks get first-class adapters?
3. How far does V1 go toward mediated mode? Is egress control needed to win the first design partners?
4. Biscuit vs. RFC 8693 at the edges: what exact mapping, and what is lost in translation?
5. Declassification: who authors schemas, and how do we prevent schemas so loose they launder taint?
6. Pricing unit for the control plane: per root writ, per protected tool, per seat, or per environment?
7. Self-hosted vs. managed control plane for the first customers?
8. Verify the PC2 citation and add a full reference.

---

## References

- MCP 2026-07-28 specification announcement: https://blog.modelcontextprotocol.io/posts/2026-07-28/
- Securing AI Agents with Information-Flow Control (FIDES), Microsoft: https://arxiv.org/abs/2505.23643
- TomasuLLM: Out-of-Order Speculative Execution for LLM Agents: https://arxiv.org/abs/2609.38201
- Policy in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- The State of AI Agent Identity 2026 (IDSync): https://idsync.com/reports/state-of-ai-agent-identity-2026
- Arcade, AI agent authentication platforms (2026): https://www.arcade.dev/blog/best-ai-agent-authentication-platforms/
- AI Agent Identity Management: A 2026 CISO Playbook (Security Boulevard): https://securityboulevard.com/2026/05/ai-agent-identity-management-a-2026-ciso-playbook/
- Agent Payments Protocol (AP2) overview: https://www.vellum.ai/blog/googles-ap2-a-new-protocol-for-ai-agent-payments
- Red-teaming AP2 via prompt injection: https://arxiv.org/abs/2601.22569
