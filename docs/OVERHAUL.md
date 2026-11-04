# The overhaul: from an MCP proxy to authorization for agent actions

Status: proposal, on branch `real`. It builds on [`docs/research/real-usage.md`](research/real-usage.md), the research report, and on `ROADMAP.md`, which tracks the work through step 8. Section 9 lists decisions that are yours to make. Each one has a recommendation.

---

## 1. The diagnosis in one paragraph

writ's engine is good, and it's aimed at the right problem: an agent reads untrusted content and then makes a privileged call. The GitHub MCP and Supabase leaks happened that way. Three things keep it from being used for real.

- **It sits in only one place.** writ sees stdio MCP calls only. The worst incidents went through other channels: Replit's database deletion, `terraform destroy` through Claude Code, the Amazon Q payload. Those ran through shell, file and native framework tools that an MCP proxy never sees.
- **It is too hard to start using.** A new user has to write a policy, rewrite every client config by hand, and accept a new daemon before getting any value.
- **It doesn't plug into what enterprises already run.** It has no HTTP transport, no identity provider, no SIEM export and no Slack approvals, and those are what buyers check for.

The overhaul fixes all three. It turns writ into one **decision core** that serves many **insertion points**, and gives it an adoption loop that starts by watching, not blocking.

## 2. The new shape

**One-line pitch:** *writ decides what your agents may do, and proves what they did.* Rules are deterministic and tied to the human the agent acts for. It escalates to a human only when the agent was exposed to untrusted content or exceeds that human's entitlements, so the agent isn't stopped on every call.

```
             insertion points (enforcement)                      decision core
 ┌───────────────────────────────────────────────┐        ┌──────────────────────────────┐
 │ writ wrap        stdio MCP          (today)   │        │ policy · facts · taint       │
 │ writ gateway     Streamable HTTP MCP          │        │ entitlements · tokens/forks  │
 │ writ hook        Claude Code / Agent SDK      │──Check─▶ approvals · limits · pinning │
 │ writ authz       Envoy ext_authz, Docker      │◀─Decide─ flight recorder · replay     │
 │ SDKs             Python/TS: LangGraph, OpenAI │        └──────────────┬───────────────┘
 └───────────────────────────────────────────────┘                       │ exporters
                                                     OTel · SIEM · anchored log · Slack · OpenFGA
```

The change that holds it together is a **generic action model**. Today a decision is about an MCP `tools/call`. After the overhaul, every insertion point turns what it sees into an **action** with the same shape: `{source, tool, arguments, resource?}`, plus facts that writd computes.

| Insertion point | What it sees | Becomes |
|---|---|---|
| stdio or HTTP MCP | `tools/call stripe.refund {...}` | `tool: stripe.refund`, `source: mcp:stripe` |
| Claude Code hook | `Bash {command: "terraform destroy"}` | `tool: shell.exec`, `args.command`, `args.argv[0]` |
| Claude Code hook | `Write {file_path: ".mcp.json"}` | `tool: fs.write`, `args.path` |
| Claude Code hook | `WebFetch {url}` | `tool: web.fetch`, `source: web` (an untrusted source) |
| Agent SDK spawn | `Task {subagent_type}` | runs `writ fork` automatically, label = sub-agent |
| ext_authz | MCP-over-HTTP metadata | same as HTTP MCP |

The policy language, taint, approvals, tokens, the recorder and replay don't change. They become reachable from everywhere.

## 3. The adoption loop: watch, suggest, enforce

This matters more for adoption than any single feature. Mature authorization tools use the same pattern. AWS IAM Access Analyzer generates policies from activity, Kyverno lets each rule run in audit or enforce mode, and OPA has decision logs.

1. **`writ init`.** It finds the client configs on the machine: Claude Code (`.mcp.json` and `~/.claude.json`), Claude Desktop, Cursor and VS Code. It rewrites each server entry to `writ wrap --name <server> -- <original>`, keeping a backup and offering `writ init --undo`. If asked, it installs the Claude Code hook. It writes a starter `writ.yaml` that applies the default policy packs in **observe mode** (section 4). This should take five minutes from install to first value, with nothing blocked.
2. **Observe.** Every action is recorded with what the policy *would* have decided. `writ report` summarizes what it saw:
   - which servers and tools were used, and which ones read untrusted content;
   - the "trifecta moments": a privileged call made after reading untrusted content;
   - what would have been denied.
3. **`writ policy suggest`.** It drafts a least-privilege policy from the log: the tools actually used, argument ranges, and the paths and commands seen. The user reviews the draft; nothing is applied automatically.
4. **Enforce per rule.** Each rule gets `mode: enforce | observe`. Switching a rule from observe to enforce is a `writ replay` diff in CI. Replay already exits 1 when anything loosens.
5. **Ratchet.** `writ replay` runs as a GitHub Action on every policy change, so regressions in safety fail CI. This is already built; it needs packaging.

**Success metric:** a new user sees a real "trifecta moment" from their own traffic within one day, without anything being blocked.

## 4. Policy packs and the policy language

**Packs are policy fragments maintained alongside writ, which users opt into one at a time.** Defaults matter more than syntax.

| Pack | What it does |
|---|---|
| `writ/self-protect` | Denies writes to agent config: `.mcp.json`, `.claude/settings*.json`, `.vscode/settings.json`, `.cursor/*`, `AGENTS.md`, `CLAUDE.md`, and `writ.yaml` itself. The CurXecute and Copilot YOLO-mode CVEs worked by rewriting these files. |
| `writ/destructive-shell` | Requires a human for `rm -rf` outside the workspace, `git push --force`, `terraform destroy` or `apply`, `kubectl delete`, `DROP` and `TRUNCATE`, and `aws ... delete-*`. |
| `writ/trifecta` | Marks `web.fetch`, issue and ticket readers, and email readers as untrusted sources. Marks outbound writes (PR creation, comments, email send, `curl` to non-allowlisted hosts) as privileged. |
| `writ/github` | Keeps writes inside the current repo. After taint, cross-repo writes and making a repo public need a human. |
| `writ/postgres`, `writ/supabase` | Read-only by default. Write verbs and any query touching tables tagged secret need a human (this uses the SQL matcher below). |
| `writ/stripe` | Sets refund and credit caps per principal, uses the entitlement lookups from the demo, and requires a human after taint. |

**Additions to the language.** Each one comes from a documented incident.
- **`mode: observe`** on a rule or a whole policy, recorded with every decision (section 3).
- **Matchers beyond globs:**
  - `args.command matches shell("terraform destroy*")`, using a tokenized argv rather than raw-string regex.
  - `args.path within "${workspace}"`, which resolves symlinks.
  - `args.sql reads table("integration_tokens")`, which parses SQL.
  - `args.url host in [...]`.
- **Velocity limits:** for example `limits: {per_tool: {"stripe.refund": "5/hour"}}`. The plan specified mutation velocity, and runaway loops are a real failure mode.
- **Tool pinning.** writ hashes tool definitions the first time it sees them. If a server changes a definition later, the change is denied or needs a human, which closes the "rug pull" attack. A `servers:` allowlist can also pin servers by package and version (the postmark-mcp impostor).
- **`writ policy test`.** Tests are written in YAML (`given: {tool, args, facts} expect: deny`) and the output is JUnit for CI. `writ policy validate` checks rules against each server's `tools/list` schemas, catching typos like `args.ammount`.
- **Keep the YAML format.** A later step can compile it to Cedar, for AgentCore and for formal analysis. Don't switch the authoring format.

## 5. Approvals people won't rubber-stamp

The worst outcome is approval fatigue that pushes people back to YOLO mode. Anthropic cut prompts 84% with sandboxing. writ should be at least as quiet.

- **Escalate rarely, and by design.** Ask a human only when taint meets a privileged sink, when an entitlement is violated, or when an observe-mode rule would block. Never ask "may I call this tool?"
- **The approval is bound to the call.** It covers a hash of the exact arguments, can be decided once, and is denied on timeout. Self-approval is refused, which is already built.
- **Context, not a bare yes/no.** Each request shows four things:
  - the call itself;
  - why it's paused (which untrusted source tainted the task, which entitlement it would violate);
  - the lineage (task, fork labels, principal);
  - what this policy has allowed for this agent before.

  High-risk values need typed confirmation, for example typing "240" to approve a $240 refund. This is the agent equivalent of number matching.
- **Grants.** "Approve this and allow similar calls for 15 minutes" creates a narrow, time-boxed, recorded grant (same tool, arguments within bounds). A human widens the task explicitly, the grant is logged, and replay accounts for it.
- **Brokers.** Approvals go through a pluggable backend:
  - CLI (`writ sudo`, built);
  - Slack (interactive buttons) and generic webhooks;
  - later Teams, PagerDuty, and CIBA through Auth0 or Okta;
  - mobile push with passkey step-up for critical calls.
- **Guard against flooding.** A burst of pending approvals from one task suspends that task instead of paging someone 40 times.

## 6. Making it enterprise-real

These are ordered by what unblocks a pilot first.

1. **Streamable HTTP gateway** (`writ gateway`).
   - **What it does:** reverse-proxies remote MCP servers and serves stdio servers over HTTP.
   - **Auth:** it acts as an RFC 9728 protected resource, never passes the client's token upstream, and uses its own credential or token exchange instead.
   - **Spec tracking:** it follows the 2025-11-25 and 2026-07-28 revisions, including checking that the `Mcp-Method`/`Mcp-Name` headers match the body. Verify the details against the spec first.
   - **Why first:** remote-only clients (ChatGPT connectors, hosted agents) and gateways can't use writ without it.
2. **Verified principals.**
   - `writ run` and the gateway accept OIDC or JWT tokens, Okta Cross App Access (ID-JAG), and Entra on-behalf-of (OBO) tokens.
   - The verified `sub`, `act` and agent id go into the token's authority facts, and `writ.root.verified` becomes true.
   - SPIFFE workload identities cover agents running as services.
3. **Real entitlement sources.**
   - OpenFGA first: `Check` and `ListObjects` map directly onto `lookup:` and `in`. Then Stripe customer ownership, then identity-provider groups.
   - Lookup results are recorded with each decision, so replay is faithful to what the source said at the time (a step 7 follow-up).
4. **Evidence pipeline.**
   - OpenTelemetry spans following the MCP and GenAI semantic conventions, with `writ.*` attributes.
   - JSON forwarding to Splunk, Datadog, Elastic and Sentinel.
   - **Log anchoring:** signed chain-head checkpoints to S3 Object Lock or another write-once store. This catches a truncated log, which the local chain can't.
   - Retention tiers.
   - A **logging-failure alarm**, which DORA requires, optionally failing closed.
   - These are the controls auditors ask for under SOC 2, PCI DSS 10.5.1 and EU AI Act Articles 12 and 19.
5. **Gateway modes.**
   - An Envoy `ext_authz` gRPC server that reads the MCP filter's metadata, so writ plugs into Envoy, agentgateway and Istio.
   - A Docker MCP Gateway interceptor.
   - A Helm chart that runs writ as a sidecar sharing a Unix socket.
6. **Control plane (the commercial layer, later).**
   - signed policy bundles distributed by GitOps;
   - a fleet view of tasks, agents and servers;
   - aggregated audit;
   - multi-tenancy (keys, chains, and RBAC over who may approve, per tenant);
   - high availability for approval and revocation state.
7. **Mediated mode (V2).** writ holds the tool credentials, through Vault, OpenBao or a KMS, so the agent never sees them. Combined with a sandbox and an egress allowlist, this turns cooperative enforcement into a real boundary. It is the only fix for "a same-user process can read `/proc/<pid>/environ`".

## 7. Trust and honesty as features

Buyers in this category have been burned by "AI firewall" claims, and classifiers have been bypassed (EchoLeak beat Microsoft's injection classifier). writ's deterministic design is its credibility, so publish the evidence.

- **A public bypass suite.** The incident matrix from the research report becomes runnable tests. Each test ships with what it proves and what it doesn't. This is ROADMAP §5 item 2, now promoted.
- **A scope page.** List what writ does not see: raw shell outside the hook, data sent out through rendered output, code inside a server, client-side RCE. For each, say what to pair writ with: a sandbox, an egress allowlist, scoped keys.
- **Supply-chain and security hygiene:** signed releases, an SBOM, reproducible builds, fuzzing of the policy parser and the proxy's JSON handling, and an outside review of the token design (already on the owner track).
- **License and governance:** keep the core Apache-2.0 for good. The research shows the HashiCorp BSL switch spawned OpenTofu and OpenBao. Consider moving to a foundation later.

## 8. Phased plan

Each phase ends with something demoable and a measurable exit condition.

### Phase A: "Works on my laptop in five minutes" (about 4–6 weeks)
The goal is developer adoption, focused on coding agents first.
- [ ] Introduce the `Action` model and refactor the engine around it. MCP keeps working unchanged.
- [ ] `writ hook claude-code`: a PreToolUse and PostToolUse adapter. It maps allow, deny and approve to the hook's `allow`, `deny` and `ask`, handles Bash, Write, Edit and WebFetch, and runs `writ fork` automatically on `Task`.
- [ ] `writ init` and `writ init --undo`, for Claude Code, Claude Desktop and Cursor.
- [ ] `mode: observe`, plus `writ report`.
- [ ] Packs: `self-protect`, `destructive-shell`, `trifecta`, `github`.
- [ ] Shell, path and URL matchers.
- [ ] Tool-definition pinning.
- [ ] Packaging: Homebrew, `cargo install`, prebuilt binaries for Linux and macOS (with the `getpeereid` peer check), and a 60-second demo video of the poisoned ticket and of `terraform destroy` being caught.
- **Exit:** five outside developers run it for a week. At least three keep it on, and it catches at least one real trifecta moment or destructive command.

### Phase B: "My team can pilot it" (about 6–8 weeks)
- [ ] Slack and webhook approval brokers, with call-bound approvals, grants, typed confirmation and flood protection.
- [ ] `writ policy suggest`, `writ policy test` and `writ policy validate`, plus a replay GitHub Action.
- [ ] Velocity limits, and the SQL matcher with the `postgres` and `supabase` packs.
- [ ] OTel export and JSON log forwarding.
- [ ] A Python SDK (for LangGraph and the OpenAI Agents SDK) that calls writd's decision API, with an automatic `fork` on sub-agent spawn.
- [ ] Public bypass suite and scope page.
- **Exit:** one design partner team runs it in observe mode on a real workflow, such as support refunds or a data agent, and flips at least one rule to enforce based on replay.

### Phase C: "Security signs off" (about 8–12 weeks)
- [ ] `writ gateway` with Streamable HTTP and the OAuth protected-resource role.
- [ ] Verified principals (OIDC, ID-JAG, Entra OBO).
- [ ] OpenFGA entitlement source, with lookup results recorded.
- [ ] Anchored log, retention tiers and the logging-failure alarm.
- [ ] `ext_authz` server and the Helm chart.
- [ ] Compliance mapping guide covering EU AI Act Articles 12, 14, 19 and 26, SOC 2, PCI DSS 10.5.1, HIPAA and DORA.
- [ ] Outside review of the token design completed.
- **Exit:** one organization's security team approves writ for a production agent.

### Phase D: "It's a product" (later)
- [ ] The control plane (section 6, item 6), as the open-core commercial layer.
- [ ] Mediated mode with a credential vault.
- [ ] Compiling the YAML to Cedar; delegating decisions to OPA or Cerbos.
- [ ] Per-branch and per-value taint with declassification, plus passkey and N-of-M approvals.

### Architecture refactor, done incrementally during Phase A

| Crate | Becomes |
|---|---|
| `writ-policy` | Unchanged, plus matchers, modes and pinning |
| `writ-daemon` | Split into `writ-core` (engine, tokens, approvals; no I/O) and `writd`, which serves a **versioned decision API** (`Check`, `Record`, `Approve`) over the Unix socket now and HTTP/gRPC later |
| `writ-proxy` | `writ-mcp`: the stdio adapter now, Streamable HTTP later |
| new `writ-hook` | Claude Code and Agent SDK adapter |
| new `writ-authz` | Envoy `ext_authz` adapter (Phase C) |
| `writ-recorder` | Plus exporters and anchoring |
| `sdk/python` | A thin client of the decision API |

The decision API is the stable contract. Adapters and SDKs are cheap to add once it exists.

## 9. Decisions for you

| # | Decision | Recommendation | Why |
|---|---|---|---|
| 1 | **Wedge:** coding agents first, or enterprise MCP gateway first? | **Coding agents first** (Phase A), with the gateway in Phase C | Bottom-up adoption is free and fast. The research found that 86% of MCP servers run on developer machines (an aggregator figure). The incidents that went viral (Replit, `terraform destroy`) were coding-agent incidents. |
| 2 | **Name.** `writ` is taken on crates.io. | Decide before Phase A ships packages | Renaming after a launch is expensive |
| 3 | **Lead message:** taint ("stops prompt-injection fallout") or lineage ("prove what your agents did")? | **Taint for developers, lineage and audit for buyers.** Test both in discovery calls | The research couldn't find which one buyers weigh more. Discovery decides. |
| 4 | **Open-core boundary** | The core, all adapters, packs, replay and single-node approvals stay Apache-2.0. Paid: control plane, multi-tenancy, SSO admin, hosted anchoring, compliance packs, support | This follows the OPA/Styra and Teleport precedents and avoids a BSL-style backlash |
| 5 | **SDK language after Rust** | **Python first**, then TypeScript | Most agent frameworks are Python-first |
| 6 | **Keep YAML, or move to Cedar or Rego?** | **Keep YAML** and compile to Cedar later | The YAML format is readable, and entitlement lookups written in the policy set writ apart |

## 10. What not to do

- **Don't build a content classifier** (PII or injection detection). That is the crowded, acquired part of the market, and classifiers get bypassed. Integrate with one if a buyer asks.
- **Don't build a dashboard before the decision API and exporters exist.** Datadog, Grafana and a SIEM already give a fleet view once writ exports OTel.
- **Don't compete with identity providers or gateways.** Plug into them, through ID-JAG, Entra OBO, ext_authz and the Docker interceptor.
- **Don't add per-call confirmations.** Every prompt writ adds pushes users toward YOLO mode.
