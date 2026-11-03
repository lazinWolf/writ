# Observations: state, crossroads, and options

*Snapshot as of 2026-11-03, after commit `c90f305`. This is an assessment, not a plan: `plan-v2.md` is still the plan. Where this file disagrees with the plan, treat the disagreement as a question to resolve, not as a decision.*

---

## 1. Where we are

**Built (Phase 0, cooperative mode, Linux):**

| Piece | What it does today |
|---|---|
| `writ wrap` | stdio MCP proxy. Every `tools/call` is checked against `writ.yaml` before it reaches the server. Denials come back as MCP tool errors, and `tools/list` hides tools the policy always denies. |
| `writ-policy` | Glob tool rules, argument conditions, most-restrictive-wins precedence (D9), deny by default, redaction. A policy that uses a feature we don't enforce yet is **rejected when it loads**. |
| Flight recorder | Hash-chained JSONL log, safe for several processes at once. An allowed decision is written to disk (fdatasync) before the call is forwarded. `writ log --verify` checks the chain. |
| `writd` + `writ run` | A local daemon that owns **tasks**. An agent started with `writ run` is one task: its limits are shared across all of its MCP servers, a server's own policy can only narrow them, and ending the task revokes them. It fails closed when writd is unreachable. |
| `writ ps` | Lists live tasks with their call counts, denials, and age. |
| Supervision | Each server runs in its own process group, with escalation from SIGTERM to SIGKILL. Signals are forwarded, and `npx`-style launcher chains are cleaned up. Two hangs that were reproduced on old builds are fixed and tested. |
| CI | 42 tests plus a check against the real `@modelcontextprotocol/server-everything` from npm. It runs in a Fedora container locally and on GitHub Actions. Both pass. |

**Measured:** writ adds about 1–1.8 ms p99 per call with durable logging (dominated by fsync), and under 0.3 ms without it. Denied calls cost nothing measurable. Latency is not a reason anyone will reject this.

**Size:** about 4,100 lines of Rust across 5 crates, plus Python fixtures and CI scripts.

**Public:** https://github.com/lazinWolf/writ. There is no license yet.

## 2. What it is, and what it isn't yet

Read honestly against `plan-v2.md` §11.3, **everything built so far is table stakes**: tool allow/deny, argument rules, limits, an audit log, a gateway. Bifrost, agentgateway, MCPX, MintMCP and AWS AgentCore cover much of this already, some with more polish.

None of the differentiated layer exists yet:
- **Lineage:** signed, attenuating writ tokens that carry *where a request came from* across hops. Today's task ID is an unsigned string that any same-user process can claim.
- **Taint:** a branch that has read untrusted content can't trigger privileged actions.
- **Entitlements:** the agent acts with the requester's authority ("may refund only this customer's own charges").
- **Approvals:** `require_sudo` is parsed, but with no broker it simply refuses.

So the right description today is **credible infrastructure, not yet a product.** It's a solid base for the wedge, but it shouldn't be shown as "what's new".

Known technical limits, all documented in the README:
- Cooperative mode can be bypassed by any agent with a shell or raw network access.
- The task ID can be forged by same-user processes.
- Only the stdio transport is supported. Production MCP is moving to HTTP.
- Only Linux is supported. On other Unixes the daemon's peer-credential check is a no-op, and only the 0700 directory protects the socket.
- Sampling and elicitation requests from servers are logged but not governed by policy.
- No human has reviewed the code. For a security product, that matters.

---

## 3. The crossroads

These are the decisions that will shape the next six months. Several are product decisions rather than engineering ones. For each I give the options and a recommendation.

### 3.1 Validate first, or build the demo first?
Engineering is ahead of validation. Phase −1 (10–15 discovery conversations) hasn't started, yet it is what tells us whether the wedge is real.

- **Discovery first:** pause the build and talk to teams. It's slower to show anything, but nothing gets built on a wrong assumption.
- **Demo first:** build tokens, taint, entitlements and approvals, then show the demo. It's a much better conversation-starter, at the risk of polishing the wrong thing.
- **Recommendation: both in parallel, with the demo as a discovery tool.** The demo is about 3–5 focused steps away. Conversations can start now with a whiteboard version of the poisoned-ticket refund scenario, and the working demo replaces the whiteboard once it's ready.

### 3.2 Which wedge?
- **Confused-deputy prevention** (current plan): stops an injected ticket from triggering a $5k refund. It's the strongest security story and fits a security budget. It needs entitlement integrations, and its multi-hop lineage only pays off if teams run multi-agent setups with different privileges per agent.
- **"terraform plan for agents"** (reserve): a preview-and-approve step before agent actions on Postgres, GitHub or Kubernetes. Developers would want it bottom-up, but the security-buyer story is weaker.
- **Audit and compliance evidence for MCP** (new option, not in the plan): "prove to your customer's security questionnaire what your agents did, and under which policy". This is closest to what we've already built and the fastest to sell, but it is the least defensible: it's table stakes.
- **Recommendation:** keep confused-deputy as the headline. Use audit evidence as the **door-opener in conversations**, because it's the pain teams can name today. Let discovery decide whether multi-hop lineage leads the pitch or is held back as depth.

### 3.3 Single-agent or multi-agent?
Many customer-facing agents today are one agent with tools. Taint plus entitlement checks help that case. Multi-hop lineage helps only the multi-agent case. **The build order already hedges this:** taint and entitlements come before cross-agent forking. Discovery should answer it before we invest in framework adapters.

### 3.4 Standalone runtime or context layer?
- **Runtime:** writd decides everything itself. We'd compete head-on with the gateways.
- **Context layer:** writ computes lineage, taint and entitlement facts and *feeds them* to policy engines teams already use (AgentCore/Cedar, OPA, the gateways). That makes us a complement, not a rival.
- **Recommendation:** build the runtime now (it's needed for the demo and for teams without a gateway), and keep the *decision inputs* cleanly separable so a Cedar or OPA export is a small step later. This mostly affects how we design the engine's decision context. It costs little now and is expensive to retrofit.

### 3.5 Open source posture, now that the repo is public
The repo went public before a license or a contribution policy was chosen. Decisions in order of urgency:
1. **License.** Without one, the code is "all rights reserved", which blocks adoption. Options:
   - **Apache-2.0:** the most adoption, a patent grant, standard for infrastructure.
   - **AGPL-3.0:** protects against cloud resale, but some enterprises won't touch it.
   - **FSL or BSL:** source-available, converting to open source later. That's not "open source" under the OSI definition, and some developers object to it.

   For an open-core security tool whose paid layer is the control plane, **Apache-2.0 for the core** is the conventional, low-friction choice.
2. **Contribution terms.** If open core with a commercial control plane is the plan, decide on a DCO or a CLA *before* accepting the first outside PR.
3. **`SECURITY.md`** with a disclosure contact. A security project without one looks unserious.
4. **Strategy docs in a public repo.** `plan.md` and `plan-v2.md` publish the full strategy, the competitor analysis and the market figures (some still unsourced, per §11.2). Being open has upsides: it builds credibility with security buyers, and few competitors will act on it. But unsourced market numbers in public go against our own §15 language policy. **Either source them or move the business sections out.**

### 3.6 The name
"writ" is crowded **in this exact space**. On crates.io, `writ-client` is "Official Rust SDK for Writ — drive the local writ-agentd daemon", from a company called usewrit. `writ-cli` is already taken there by "a local-first ledger of the steering you give coding agents", and `writ` itself is taken by a markdown editor.

This affects package publishing (we can't use our crate names on crates.io), search, and possibly trademarks. **It's cheap to rename now and expensive later.** Options:
- Keep "writ" as the concept name and use a distinct product or package name.
- Rename entirely before any public launch.

This is a product and brand decision. A trademark search is worth doing before any launch.

### 3.7 Transport priority: stdio or HTTP?
stdio covers local tools (Claude Code, Cursor, desktop agents), where developers will try us first. HTTP covers remote MCP servers, where enterprise traffic is heading. **Recommendation:** finish the demo on stdio, and make HTTP MCP the first item after the demo. It's also a prerequisite for most design-partner environments.

### 3.8 How far toward mediated mode?
Cooperative mode is honest about its limits, but a security reviewer will press on "an agent with a shell bypasses you". Mediated mode (writd controls network egress) answers that, and it's a large build. **Recommendation:** don't pull it forward until discovery says it blocks a sale. Meanwhile, the bypass suite and threat model should state the boundary plainly. That's a credibility asset, not a weakness.

### 3.9 What kind of venture is this?
This isn't an engineering decision, but every other choice depends on it:
- **Funded startup:** needs design partners and a demo within a short runway, a co-founder with security or GTM depth, and investor material with sourced numbers.
- **Open-source project first:** optimize for adoption and community, and commercialize later.
- **Research or standards play:** push lineage and taint into MCP or A2A as a spec, with writ as the reference implementation.

They aren't mutually exclusive, but they rank the next 90 days differently.

---

## 4. Where we can expand

### 4.1 Product and engineering (roughly in order of leverage)
1. **The hero demo path:** signed writ tokens → taint from declared untrusted sources → entitlement conditions (`writ.root.*`) → a CLI approval broker. This is the moat and the demo.
2. **Policy replay ("what would this policy have done?"):** run a new or changed `writ.yaml` against an existing flight log, and show which past calls would flip between allow and deny. It's cheap because we already log every decision with its arguments. It's very useful for policy authors, and it's a strong answer to "who reviews policy changes" (plan gap). **It has high value for little effort.**
3. **HTTP MCP transport**, as a reverse proxy in front of remote MCP servers.
4. **The bypass test suite as a public benchmark:** published injection scenarios that any MCP gateway can be run against. It's a credibility asset and a marketing channel, and it makes the comparison with competitors concrete instead of rhetorical.
5. **OpenTelemetry export** of decisions and lineage, so writ shows up in the dashboards teams already have.
6. **Coding-agent use case:** developers wrapping MCP servers for Claude Code, Cursor and similar tools, with a ready-made "safe defaults" policy pack. It's the fastest path to bottom-up users, but it isn't the paying buyer. Treat it as distribution, not revenue.
7. **Governing sampling and elicitation** (open question 12): a malicious server can use sampling to inject prompts *into the client*. It's a real gap that few gateways address.
8. **Policy packs** for common servers (Postgres, Stripe, GitHub, Slack, filesystem), so policy isn't written from scratch.
9. **One framework adapter** (Claude Agent SDK, OpenAI Agents SDK or LangGraph, chosen by discovery). It enables automatic `writ fork` on sub-agent spawn.
10. **macOS support** (`getpeereid`), since many developers are on Macs.
11. **Context export** to Cedar, OPA or AgentCore, once 3.4 is settled.

### 4.2 Customers and discovery
- **Who:** platform or security engineers at B2B SaaS companies that ship customer-facing agents with privileged tools (refunds, account changes, data export).
- **What to learn:**
  - Their topology: one agent or many.
  - Their real privileged tools.
  - Where entitlement data lives (billing system, CRM, IdP).
  - Which security-questionnaire questions about agents they can't answer today.
  - Whether they already run a gateway.
  - What a blocked or approved call would need to look like for them to trust it.
- **Signal to watch:** someone asking "can we try it on our workflow?" That is the design-partner trigger. Polite interest is not.

### 4.3 Go-to-market and community
- A launch write-up on the confused-deputy problem in agents, with the working demo and the bypass suite, aimed at developer and security audiences.
- Listings in MCP server registries and directories once HTTP support exists.
- Standards participation: propose lineage and taint conventions for MCP `_meta` and A2A. Doing it early makes "standard capture" (Risk 2) an opportunity instead of a threat.
- Research ties: CaMeL and FIDES are the closest academic work. A conversation with those authors could sharpen D10 (declassification integrity), and their endorsement would carry weight with security buyers.

### 4.4 Business model
- Open core, as planned: the CLI, the daemon and the spec are open. The control plane (approval broker UI, anchored recorder, compliance exports, central policy) is paid.
- **Pricing unit** is still open (§18 Q6). Per *protected privileged tool* or per *environment* fits how security budgets think better than per seat.
- **Compliance evidence** (SOC 2 / ISO mapping of the flight log) is probably the first thing a buyer pays for, before lineage. Plan a minimal version early.

### 4.5 Trust and credibility (specific to a security product)
- **External review** of the token and lineage design before we claim anything about it. Even one respected reviewer counts.
- **Signed releases and reproducible builds** once binaries ship.
- **Keep the §15 language policy in force for all public material,** now that the repo is visible.

### 4.6 Team and resourcing
- Today it's one person setting the vision, with AI doing the engineering. That is fast, but there's **no human code review**, which a security buyer *will* ask about.
- The highest-value addition is someone with **applied security credibility** (they review the threat model and token design, and they can talk to security buyers), followed by GTM capacity once design partners exist.

---

## 5. Top risks right now

1. **Building ahead of evidence.** Without discovery, we risk perfecting a wedge nobody is pulling for.
2. **Looking like "another MCP gateway"** if the work is shown before the differentiated layer exists.
3. **Name collision** with an existing "Writ" in the agent-tooling space.
4. **Public repo without a license, `SECURITY.md`, or sourced market claims.** Each is small. Together they undercut credibility.
5. **Consolidation pace.** Incumbents are buying agent-security startups. That's both a risk (the window narrows) and a possible outcome (acquisition). Either way, it argues for speed on the differentiated layer.
6. **Unreviewed security code**, until a human expert has looked at it.

---

## 6. Suggested next 30 days

**Engineering track (continues by default):**
1. Signed writ tokens replacing the unsigned task ID.
2. Taint from declared untrusted sources.
3. Entitlement conditions plus one resolver (a mock first, then Stripe customer ownership).
4. A CLI approval broker for `require_sudo`, so the poisoned-ticket demo runs end to end.
5. Policy replay (`writ replay`), a small but high-leverage step.
6. Small fixes: CI action versions, a `SECURITY.md` skeleton.

**Vision and product track (needs the owner):**
1. Choose a license, and decide whether the plan docs stay public.
2. Decide on the name (3.6), before any announcement.
3. Start discovery: a list of 15 target teams, 5 conversations, using the whiteboard version of the demo.
4. Decide what kind of venture this is (3.9), because it sets the pace for everything above.

---

## 7. Questions for the vision owner

1. What license should the core ship under, and do the plan docs stay in the public repo?
2. Keep the name "writ", or rename before launch?
3. Is the 90-day goal design partners, open-source adoption, or a standards proposal?
4. Is there an existing network of platform or security teams to start discovery with?
5. Is a security-minded collaborator or reviewer available, even part-time?
