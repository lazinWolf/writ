# Competitive and adjacent landscape: security and policy layers for AI agent tool calls and MCP (as of 2026-11-04)

Method note: this was compiled mostly from web search result summaries. Direct page fetches failed for several hosts (pulse.latio.tech, datapace.ai and mastra.ai do not resolve in this sandbox), and the GitHub API was blocked for this session, so **no GitHub star counts could be collected**. Where a claim rests on a search summary of a page, that page is cited, but the report writer should treat figures (prices, dates) as "reported". Vendors named in the brief that turned up no results appear under Gaps rather than being described from memory.

## 1. Vendor and project landscape (what each does, deployment, funding, traction)

### Takeaway
The market splits into four layers: (a) classifier and guardrail runtime security, now mostly owned by large security platforms; (b) MCP gateways and proxies, which focus on routing, SSO/OAuth and coarse per-tool RBAC; (c) agent identity and credential vendors, which are well funded and focus on who the agent is and on short-lived credentials; and (d) general-purpose authorization engines (Cerbos and others) that are adding MCP integrations. Few vendors combine argument-level deterministic policy, principal entitlements, taint and replay in one layer.

### Cited Findings

**Guardrails and runtime agent security**
- Invariant Labs: acquired by Snyk on 2025-06-24 — [Forrester](https://www.forrester.com/blogs/securing-ais-ma-feeding-frenzy-is-on/), [Senthex](https://senthex.com/en/blog/why-independent-ai-firewall/).
- Invariant's mcp-scan statically scans installed MCP servers for tool poisoning, cross-origin escalation, rug pulls and "toxic flows". It can also run as a dynamic proxy that rewrites the MCP client config to point at a local proxy and applies guardrails — [PyPI mcp-scan 0.4.2](https://pypi.org/project/mcp-scan/0.4.2/), [darknet.org.uk](https://www.darknet.org.uk/2025/11/mcp-scan-real-time-guardrail-monitoring-and-dynamic-proxy-for-mcp-servers/).
- mcp-scan's guardrails and proxying run locally, but tool descriptions are still sent to invariantlabs.ai for scanning. Newer releases also inventory "harnesses, MCP servers, skills" — [PyPI mcp-scan 0.4.2](https://pypi.org/project/mcp-scan/0.4.2/).
- Invariant Guardrails rules support PII detection, secrets detection, tool restrictions and custom policies — [PyPI mcp-scan](https://pypi.org/project/mcp-scan/0.4/).
- One GitHub mirror says mcp-scan "can currently no longer accept external contributions". This is unverified on the official repo — [mirror](https://scriptagc.wasmer.app/https_github_com/invariantlabs-ai/mcp-scan).
- Invariant introduced "toxic flow analysis" in July 2025. It builds potential attack scenarios from the agent's tool flows and their trust and sensitivity properties, and shipped as an early preview inside mcp-scan — [Invariant blog](https://invariantlabs.ai/blog/toxic-flow-analysis).
- Lakera: Check Point announced the acquisition on 2025-09-16. The reported price is about $300M, and the closing date is reported as Q4 2025 in one source and early 2026 in another — [Forrester](https://www.forrester.com/blogs/securing-ais-ma-feeding-frenzy-is-on/), [Senthex](https://senthex.com/en/blog/why-independent-ai-firewall/), [onepc.org](https://onepc.org/en/track/ai-security-and-red-team).
- Prompt Security: SentinelOne agreed to acquire it on 2025-08-05. The price is reported as about $180M in cash and stock by one source and about $250M by others — [Forrester](https://www.forrester.com/blogs/securing-ais-ma-feeding-frenzy-is-on/), [Senthex](https://senthex.com/en/blog/why-independent-ai-firewall/).
- Protect AI: Palo Alto Networks announced the deal in April 2025 and closed it on 2025-07-22. Reported prices conflict: about $500M, about $650M or about $700M — [Forrester](https://www.forrester.com/blogs/securing-ais-ma-feeding-frenzy-is-on/), [wetheflywheel](https://wetheflywheel.com/en/guides/ai-security-2026/), [Senthex](https://senthex.com/en/blog/why-independent-ai-firewall/).
- Aim Security: Cato Networks acquired it in September 2025 for a reported $300M–$350M — [Senthex](https://senthex.com/en/blog/why-independent-ai-firewall/), [aioutlooks](https://aioutlooks.com/compare-ai-security-solutions/).
- Zenity: $125M Series C led by Norwest, announced 2026-08-03, with more than 230 employees. One roundup says $115M, which conflicts with the company's own release — [Zenity press release](https://zenity.io/press-release/zenity-raises-125-million-to-secure-the-era-of-1-billion-ai-agents), [fintech.global](https://fintech.global/2026/08/04/zenity-lands-125m-as-ai-agent-security-race-heats-up/).
- Noma Security: $100M Series B led by Evolution Equity Partners in July 2025, $132M raised in total. Self-reported traction: "1,300% ARR growth" and "dozens of enterprise customers" — [appsecsanta](https://appsecsanta.com/noma-security), [nhigovernance](https://nhigovernance.com/companies/noma-security.html).
- Lasso Security: about $36M total funding reported, with no 2026 round found — [newmarketpitch](https://newmarketpitch.com/blogs/news/ai-trism-top-startups-fundraising).
- Pillar Security: only a $9M seed has been disclosed, and it is described as independent — [nhigovernance](https://nhigovernance.com/companies/pillar-security.html).
- HiddenLayer: $100M Series B on 2026-09-02 led by Delta-v Capital, with participation from Ten Eleven, Morgan Stanley, M12 (Microsoft) and Booz Allen Ventures. Total funding is about $156M. The stated focus is "Agentic Runtime Security" and "Agent Harness Security" — [SecurityWeek](https://www.securityweek.com/hiddenlayer-raises-100-million-for-ai-runtime-security/), [HiddenLayer](https://www.hiddenlayer.com/news/hiddenlayer-100m-series-b-ai-security), [FinSMEs](https://www.finsmes.com/2026/09/hiddenlayer-raises-100m-in-series-b-funding.html).
- Combined AI TRiSM fundraising: Alice, Zenity, HiddenLayer, Onyx and Noma have raised a combined $896M — [newmarketpitch](https://newmarketpitch.com/blogs/news/ai-trism-top-startups-fundraising).
- Operant AI: launched MCP Gateway on 2025-06-16 as part of its AI Gatekeeper platform, with MCP Discovery, Detections and Defense. It enforces access policies and rate limits and supports redaction. Backers include Felicis and SineWave, and no amount was found — [SiliconANGLE](https://siliconangle.com/2025/06/16/operant-ai-expands-gatekeeper-platform-mcp-gateway-ai-runtime-security/), [Operant](https://www.operant.ai/art-kubed/deploy-ai-agents-with-confidence-introducing-ai-gatekeepers-mcp-gateway).
- Meta LlamaFirewall: an open-source framework (arXiv:2505.03574, May 2025) with three parts. PromptGuard 2 is a BERT-style jailbreak classifier, reportedly DeBERTa at 86M and 22M parameters. AlignmentCheck is an experimental chain-of-thought auditor for goal hijacking. CodeShield is a static analyzer using Semgrep and regex — [arXiv](https://arxiv.org/html/2505.03574v1), [The Batch](https://deeplearning.ai/the-batch/meta-releases-llamafirewall-an-open-source-defense-against-ai-hijacking/).
- LlamaFirewall results: PromptGuard plus AlignmentCheck reportedly cut AgentDojo attack success from 17.6% to about 1.7% — [The Batch](https://deeplearning.ai/the-batch/meta-releases-llamafirewall-an-open-source-defense-against-ai-hijacking/).
- Microsoft Prompt Shields: detects direct (user) and indirect ("document") prompt attacks in Azure AI Content Safety and Foundry. Spotlighting is part of it: documents are base64-encoded so the model treats them as less trusted. It is off by default and adds tokens — [Microsoft Learn](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter-prompt-shields), [Microsoft Tech Community](https://techcommunity.microsoft.com/t5/ai-azure-ai-services-blog/azure-ai-announces-prompt-shields-for-jailbreak-and-indirect/ba-p/4099140).
- The Spotlighting paper (March 2024) reported indirect injection attack success falling from over 50% to under 2% on GPT-family models — [Microsoft Tech Community](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/-/4458404).

**MCP gateways and proxies**
- Pomerium: puts an identity-aware proxy in front of MCP servers. Pomerium Policy Language (PPL) controls which tools each user or group can call, and every tool call is logged with method, tool name and parameters. MCP support is labeled experimental — [Pomerium docs](https://www.pomerium.com/docs/capabilities/mcp), [Pomerium changelog](https://www.pomerium.com/changelog/experimental-mcp-support).
- Docker MCP Gateway: open source, runs MCP servers in isolated containers and handles routing, credentials and lifecycle. Comparisons disagree on its policy features: one lists "none built-in" for RBAC and audit, while another cites Cedar policies for Docker organizations — [Tyk](https://tyk.io/learning-center/best-enterprise-mcp-gateways/), [StackOne](https://www.stackone.com/blog/best-mcp-gateways/), [TrueFoundry](https://www.truefoundry.com/blog/best-mcp-gateways).
- Lunar.dev MCPX: described as a policy gateway with per-agent and per-user RBAC, approval workflows, DLP redaction and an immutable audit trail — [Arcade comparison](https://www.arcade.dev/blog/best-mcp-gateways-enterprise/), [Speakeasy](https://www.speakeasy.com/blog/best-mcp-gateways-for-enterprise-2026).
- Kong: the core is Apache 2.0, but the MCP plugins require AI Gateway Enterprise. The AI MCP OAuth2 plugin supports token introspection or JWKS — [Tyk](https://tyk.io/learning-center/best-enterprise-mcp-gateways/), [NetFoundry](https://netfoundry.io/for-agents/mcp-gateway-vendors-for-policy-based-tool-access/).
- Amazon Bedrock AgentCore Gateway: enforces Cedar rules on which tools a principal can invoke — [NetFoundry](https://netfoundry.io/for-agents/mcp-gateway-vendors-for-policy-based-tool-access/), [vdf.ai](https://vdf.ai/blog/mcp-gateway-comparison/).
- Tyk: open-source MCP proxies with per-tool, resource, prompt and method access policies and rate limits — [Tyk](https://tyk.io/learning-center/best-enterprise-mcp-gateways/).
- Comparison articles note that a standalone gateway mainly routes traffic and leaves per-user authorization to the tools — [Speakeasy](https://www.speakeasy.com/blog/best-mcp-gateways-for-enterprise-2026), [NetFoundry](https://netfoundry.io/for-agents/mcp-gateway-vendors-for-policy-based-tool-access/).
- agentgateway: started at Solo.io and was donated to the Linux Foundation in 2025 (one source says August 2025). It became an Agentic AI Foundation (AAIF) project in 2026 and was described in June 2026 as the fourth AAIF-hosted initiative — [agentgateway blog](https://agentgateway.dev/blog/2026-06-04-agentgateway-joins-aaif/), [Solo.io](https://www.solo.io/blog/aaif-announcement-agentgateway).
- agentgateway capabilities: CEL-based RBAC, Entra and Keycloak OAuth for MCP, and integrations with OPA, OpenFGA and SpiceDB. One source also mentions Cedar — [agentgateway SSO blog](https://agentgateway.dev/blog/2026-01-26-enterprise-mcp-sso/), [AAIF](https://aaif.io/blog/exposing-openapi-operations-as-authorized-mcp-tools-with-agentgateway-and-keycloak), [shanedeconinck.be](https://shanedeconinck.be/explainers/agentgateway/).
- Arcade.dev: $60M Series A led by SYN Ventures (June 2026), with strategic investment from Morgan Stanley and Wipro and about $72M raised in total. It describes itself as the "secure action layer". It also claims to have authored the MCP authorization spec, which is a self-reported claim — [BusinessWire](https://www.businesswire.com/news/home/20260615229631/en/Arcade-Raises-$60M-to-Become-the-Secure-Action-Layer-Behind-Every-Production-AI-Agent).
- Arcade acquired Smithery, the MCP registry, in August 2026. No deal terms were found — [Forbes](https://www.forbes.com/sites/janakirammsv/2026/08/10/arcade-acquires-smithery-to-own-the-agent-tool-supply-chain/), [runtimewire](https://runtimewire.com/article/arcade-acquires-smithery-agent-tool-supply-chain).
- Composio: 1,600+ toolkits. Each request is keyed by user_id, and Composio stores and refreshes credentials per user — [Scalekit](https://www.scalekit.com/blog/best-managed-mcp-server-platforms), [Truto](https://truto.one/blog/top-arcadedev-alternatives-for-building-and-managing-mcp-servers/).
- MintMCP: reportedly rebranded as "Mintive" and positioned as governance-first MCP for IT and security teams. This is a single-source claim — [Scalekit](https://www.scalekit.com/blog/best-managed-mcp-server-platforms).

**Agent identity and authorization**
- Keycard: emerged from stealth with $38M (seed plus Series A) led by a16z, Boldstart and Acrew. It was founded in 2025 by former Snyk and Okta leaders and issues per-agent identities with short-lived, task-scoped credentials — [SecurityWeek](https://www.securityweek.com/keycard-emerges-from-stealth-mode-with-38-million-in-funding/), [Boldstart](https://boldstart.vc/news/keycard-solving-the-ai-agent-identity-and-access-problem-welcome-to-boldstart/).
- Astrix: $85M raised in total, including a $45M Series B in December 2024 (CRV, Menlo), with an "Agent Control Plane" product. CB Insights lists Astrix among discovery startups "already acquired" but does not name the acquirer in the snippet seen — [checkthat.ai](https://checkthat.ai/brands/astrix-security), [CB Insights](https://www.cbinsights.com/research/ai-agent-identity-acquisitions-targets/).
- Token Security: described by CB Insights as one of the few independent non-human identity (NHI) discovery startups of its size left — [CB Insights](https://www.cbinsights.com/research/ai-agent-identity-acquisitions-targets/).
- Aembit: backed by CrowdStrike Falcon Fund and Okta Ventures, and has raised at least $25M — [CB Insights](https://www.cbinsights.com/research/ai-agent-identity-acquisitions-targets/).
- Okta Cross App Access (XAA, based on ID-JAG) is incorporated into MCP as the "Enterprise-Managed Authorization" extension — [Okta newsroom](https://www.okta.com/newsroom/articles/cross-app-access-extends-mcp-to-bring-enterprise-grade-security-to-ai-agents/), [Okta developer blog](https://developer.okta.com/blog/2025/06/23/enterprise-ai).
- XAA status: one integrator says it was Early Access in mid-2026 with GA targeted for FY27, and that "Okta for AI Agents" is a separate paid product that reached GA in April 2026. Auth0 docs still call XAA an in-progress OAuth extension — [TrueFoundry docs](https://www.truefoundry.com/docs/agent-platform/agent-governance/scenarios/okta), [Auth0 XAA docs](https://auth0.com/docs/ai-agents-mcp/cross-app-access).
- Auth0 "Auth for MCP": helps developers implement MCP authorization with OAuth 2.1 and OIDC — [Auth0](https://auth0.com/ai/docs/auth-for-mcp).
- NIST published a concept paper on software and AI agent identity and authorization on 2026-02-05 — [CB Insights](https://www.cbinsights.com/research/ai-agent-identity-acquisitions-targets/).
- Cerbos: open-source engine with YAML policies. The MCP server sends agent identity, tool and user context and gets a decision back. It offers FastMCP middleware that checks every tool call, and its audit log records principal, resource, action and result — [Cerbos blog](https://www.cerbos.dev/blog/dynamic-authorization-for-ai-agents-guide-to-fine-grained-permissions-mcp-servers), [Cerbos FastMCP](https://www.cerbos.dev/ecosystem/fastmcp), [Cerbos MCP](https://www.cerbos.dev/ecosystem/mcp).

**Human-in-the-loop**
- HumanLayer: an SDK and API whose approval decorator blocks a function or tool call until a human approves, with escalations and timeouts; a denial's feedback goes back to the LLM. Funding sources conflict: one says a $500K YC pre-seed in December 2024, another says more than $3M company-reported. The company now also markets itself as an AI coding IDE — [everydev](https://www.everydev.ai/tools/humanlayer), [extruct](https://www.extruct.ai/hub/humanlayer-dev-funding/), [ai.engineer](https://ai.engineer/orgs/humanlayer).

### Inferences
- The guardrail vendors (Lakera, Prompt Security, Protect AI, Aim, LlamaFirewall, Prompt Shields) mainly classify text: prompts, retrieved documents and tool outputs. Classification is probabilistic. None of the sources describes them evaluating deterministic, argument-level rules against a principal's entitlements.
- MCP gateway policy is mostly "which user or group may call which tool" (Pomerium PPL, Kong, AgentCore Cedar, Tyk, MCPX RBAC). Conditions over argument values combined with principal entitlement data are rarely described.
- Identity vendors (Keycard, Okta, Auth0, Aembit) solve authentication and credential issuance. They leave per-call business-rule authorization to the resource or to a policy engine, which is where writ sits.

### Gaps
- No results were found for Lasso, Pillar or Noma product mechanics; MCP Manager; Obot; Cloudflare's MCP offerings; TrueFoundry and Portkey pricing; Golf; Klavis; Descope; Stytch; Oso; Permit.io; Styra; AuthZed; Token Security funding; or Composio and Klavis funding. These need follow-up.
- No pricing pages were retrieved for any vendor.
- No authoritative primary source was found for the final prices of any 2025 acquisition, and the reported figures conflict.
- Langfuse and Arize were not researched for tool-call audit specifically.

## 2. Who does deterministic, entitlement-aware authorization (not just prompt-injection classifiers)?

### Takeaway
Deterministic per-tool authorization is common in gateways and policy engines (PPL, Cedar, CEL, Cerbos YAML, OPA, ReBAC via SpiceDB and OpenFGA). Binding it to the human principal's entitlements at the argument level ("this customer_id is in alice's set") is possible with general engines like Cerbos, SpiceDB or OpenFGA, but it is integration work, not an MCP-native default.

### Cited Findings
- Pomerium PPL authorizes tool calls by user and group and applies the same policy to humans, LLMs and CI — [Pomerium docs](https://www.pomerium.com/docs/capabilities/mcp).
- AgentCore Gateway uses Cedar for principal-to-tool rules — [NetFoundry](https://netfoundry.io/for-agents/mcp-gateway-vendors-for-policy-based-tool-access/).
- agentgateway offers CEL RBAC plus OPA, OpenFGA and SpiceDB integration — [shanedeconinck.be](https://shanedeconinck.be/explainers/agentgateway/).
- Cerbos evaluates YAML policies over agent identity, tool and user context per call — [Cerbos blog](https://www.cerbos.dev/blog/dynamic-authorization-for-ai-agents-guide-to-fine-grained-permissions-mcp-servers).
- Progent (academic) puts a reference monitor between the agent and its tools that enforces fine-grained, argument-level privilege policies. It reports cutting AgentDojo injection success from 39.9% to 1.0% (figure from a secondary summary) — [arXiv 2504.11703](https://arxiv.org/pdf/2504.11703).
- A 2026 evaluation groups CaMeL, FIDES and Progent as "out-of-band" defenses that enforce deterministic policy outside the model — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1).
- Comparison articles say per-user policy enforcement usually needs a separate policy layer or a commercial product on top of a gateway — [Speakeasy](https://www.speakeasy.com/blog/best-mcp-gateways-for-enterprise-2026).

### Inferences
- writ's "entitlements tied to the human principal" model is closest to Cerbos-plus-gateway or SpiceDB-plus-agentgateway setups, but packaged as one MCP-native layer. That is a plausible convenience differentiator rather than a capability no one else has.

### Gaps
- It is unconfirmed whether MCPX, Operant, Zenity or Noma support argument-value conditions joined to principal entitlements; their docs were not retrieved.

## 3. Delegation and attenuation across sub-agents; taint and data-flow tracking

### Takeaway
Delegation and attenuation for agents is still mostly at the Internet-Draft and small-project stage (Attenuating Agent Tokens, WIMSE delegation chain, Biscuit-based packages). Taint and data-flow tracking is mostly academic (CaMeL, FIDES) plus Invariant's toxic flow analysis, which is a static or predictive risk analysis rather than runtime enforcement.

### Cited Findings
- IETF draft "Attenuating Agent Tokens" (niyikiza, -00/-01 in June 2026) is JWT-based and says no existing OAuth standard defines delegation chains with token-local chain authentication, deterministic attenuation and offline verification — [IETF -00](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-00), [IETF -01](https://www.ietf.org/archive/id/draft-niyikiza-oauth-attenuating-agent-tokens-01.html).
- IETF draft "Agent Delegation Chain" (asor-wimse, -00 August 2026 to -03 October 2026) notes that OAuth Token Exchange (RFC 8693) needs an authorization-server round trip per hop and that its "act" claim is informational and cannot enforce attenuation at chain depth of two or more — [IETF -03](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-03), [IETF -01](https://www.ietf.org/archive/id/draft-asor-wimse-agent-delegation-chain-01.html).
- The same draft says Biscuit offers public-key, offline attenuation but does not natively encode delegation versus execution roles, depth limits or chain position — [IETF -03](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-03).
- A blog post notes that macaroons do not create an authenticated actor chain and that MCP security guidance forbids token passthrough — [Medium](https://medium.com/@sam.zyshan/macaroon-tokens-delegating-smaller-permissions-to-ai-agents-0849fd0c14bf).
- The "agent-identity-protocol" PyPI package uses Ed25519, Biscuit and Datalog for MCP and A2A delegation. It self-reports about 2.3 ms against about 20 ms for a two-hop token exchange — [PyPI](https://pypi.org/project/agent-identity-protocol/). A related package also exists — [agent-authority](https://pypi.org/project/agent-authority/).
- An academic survey identifies offline revocation and integration with web standards as open problems — [arXiv 2510.25819](https://arxiv.org/html/2510.25819v1).
- Keycard issues short-lived credentials scoped to one tool, API or data request, but no source describes sub-agent narrowing — [SecurityWeek](https://www.securityweek.com/keycard-emerges-from-stealth-mode-with-38-million-in-funding/).
- CaMeL (Google, arXiv:2503.18813) separates control flow from data flow and tracks capabilities. It solves 67% of AgentDojo tasks with provable security according to the abstract, while a later evaluation reports 77%. It does not defend against attacks that leave control and data flow unchanged — [arXiv](https://arxiv.org/pdf/2503.18813v1), [HF papers](https://huggingface.co/papers/2503.18813), [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1).
- FIDES (Microsoft, arXiv:2505.23643) applies information-flow control with integrity and confidentiality labels. Its details here come from secondary sources — [codex.danielvaughan.com](https://codex.danielvaughan.com/2026/07/08/out-of-band-prompt-injection-defences-camel-fides-progent-codex-cli-sandbox-approval-hooks/), [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1).
- A 2026 paper applies information-flow control to privacy leakage from agents — [arXiv 2609.14003](https://arxiv.org/pdf/2609.14003).
- Invariant's toxic flow analysis models trust and sensitivity properties of tool flows to predict attacks, shipped in mcp-scan — [Invariant blog](https://invariantlabs.ai/blog/toxic-flow-analysis).

### Inferences
- writ's Biscuit task tokens with sub-agent narrowing line up with where the IETF drafts are heading, and with gaps the drafts themselves name in Biscuit (depth and roles), which writ could fill. Its coarse taint-to-human-approval rule is a practical, weaker form of CaMeL- or FIDES-style information-flow control. No commercial product in the sources was found to enforce runtime taint.

### Gaps
- No commercial vendor was confirmed to ship runtime taint propagation or sub-agent token attenuation; this may reflect search coverage.
- The primary FIDES paper was not read.

## 4. Who offers policy replay or testing?

### Takeaway
No major vendor surfaced with policy replay against recorded traffic plus a CI gate. Several small open-source MCP proxies offer dry-run, shadow mode, simulation or hash-chained logs, which shows demand but means writ's replay feature is not unique in concept.

### Cited Findings
- HarrisonCN/mcp-gateway (v6.5.0, PR #86) has a `/admin/policy-sim/simulate` endpoint that diffs a candidate policy against past recorded calls. It also has a shadow mode that runs a second policy on live traffic and records where it diverges — [GitHub PR](https://github.com/HarrisonCN/mcp-gateway/pull/86).
- mcp-policy-gateway has dry-run that logs decisions without enforcing them. It notes that hash-chaining alone cannot detect log truncation — [GitHub](https://github.com/Spuddy10345/mcp-policy-gateway).
- mcp-gate provides allow, deny and redact rules, tamper-evident audit logs, simulation against recorded traffic, and a NIST/OWASP mapping — [GitHub](https://github.com/rsh1k/mcp-gate).
- agentguard offers spend limits, approvals for destructive actions, a kill switch, dry-run diffs (with synthesized tool results) and a hash-chained audit log — [GitHub](https://github.com/agentwares/agentguard).
- agentgate v0.9.0 has a `policy test` command and a CI mode that turns "ask" decisions into deny — [GitHub release](https://github.com/FelixMa01/agentgate/releases/tag/v0.9.0).
- aat-mcp signs each audit record with ES256 before execution — [PyPI](https://pypi.org/project/aat-mcp/).
- cMCP enforces policy inside a TEE and produces an attested audit chain — [GitHub](https://github.com/agentrust-io/cmcp).
- A curated list of agent-governance tools exists — [awesome-ai-agent-governance](https://github.com/systempromptio/awesome-ai-agent-governance).

### Inferences
- writ's distinctive angle is replay that fails CI specifically when a new policy is looser than the old one, a monotonicity or regression check. HarrisonCN's simulator reports decision diffs but was not described as a CI gate. That makes writ's feature a refinement of an existing idea, not a new category.

### Gaps
- The star counts and maturity of these small projects are unknown because GitHub access was blocked.
- It was not checked whether Cerbos (which has policy test suites), OPA or Styra offer replay of recorded MCP calls.

## 5. Open-source alternatives and GitHub traction

### Takeaway
The main open-source alternatives are agentgateway (Linux Foundation and AAIF), Docker MCP Gateway, Invariant mcp-scan and Guardrails (now Snyk), NeMo Guardrails, LlamaFirewall, Cerbos, Pomerium, the Kong core and Tyk proxies, plus many small MCP policy proxies. Star counts could not be retrieved.

### Cited Findings
- agentgateway is a Linux Foundation and AAIF project — [agentgateway blog](https://agentgateway.dev/blog/2026-06-04-agentgateway-joins-aaif/).
- Docker MCP Gateway is open source — [Tyk](https://tyk.io/learning-center/best-enterprise-mcp-gateways/).
- The Kong core is Apache 2.0, but its MCP plugins are enterprise-only — [Tyk](https://tyk.io/learning-center/best-enterprise-mcp-gateways/).
- LlamaFirewall is open source — [arXiv](https://arxiv.org/html/2505.03574v1). A third-party comparison table lists it as not MCP-native — [mcp-firewall](https://github.com/ressl/mcp-firewall).
- Cerbos is open source — [Cerbos](https://www.cerbos.dev/ecosystem/mcp).
- Small MCP policy proxies exist, including mcp-gate, agentguard, mcp-policy-gateway, agentgate and mcp-firewall — [GitHub mcp-gate](https://github.com/rsh1k/mcp-gate), [GitHub agentguard](https://github.com/agentwares/agentguard), [GitHub mcp-firewall](https://github.com/ressl/mcp-firewall).

### Inferences
- The open-source field is crowded at the small-project level and anchored by agentgateway at the foundation level. writ's Rust implementation and Apache-2.0 license match agentgateway's profile (also Rust, according to its docs ecosystem; not verified here).

### Gaps
- No GitHub stars or contributor counts were collected for any repo, because the GitHub API was blocked in this session. Re-run with GitHub access or allow github.com fetches.
- NeMo Guardrails' tool-rail features were not retrieved.

## 6. Where is the market consolidating (2025–2026 acquisitions)?

### Takeaway
In 2025 almost all independent prompt-injection and AI-firewall vendors were bought by platform security companies (Snyk, Check Point, SentinelOne, Palo Alto, Cato). In 2026 the activity moved to large rounds for agent-security platforms (Zenity, HiddenLayer), consolidation in the tool and action layer (Arcade buying Smithery), and NHI and agent-identity M&A interest.

### Cited Findings
- 2025 deals: Snyk–Invariant (June), Palo Alto–Protect AI (closed July), SentinelOne–Prompt Security (August), Check Point–Lakera (September), Cato–Aim (September) — [Forrester](https://www.forrester.com/blogs/securing-ais-ma-feeding-frenzy-is-on/), [Senthex](https://senthex.com/en/blog/why-independent-ai-firewall/).
- One analysis calls these the "largest platform security vendors... adding agent-security to an enforcement point they already own". It says that in 2026 buyers evaluate AI security "as a module inside a platform relationship" — [aioutlooks](https://aioutlooks.com/compare-ai-security-solutions/), [getcoretech](https://www.getcoretech.net/articles/ai-security-platforms-explained-2026).
- A European vendor claims that every independent AI firewall was acquired in 2025; this is a self-interested source — [Senthex](https://senthex.com/en/blog/why-independent-ai-firewall/).
- 2026 events: Zenity's $125M Series C (August), HiddenLayer's $100M Series B (September), Arcade's $60M Series A (June) and its acquisition of Smithery (August) — [Zenity](https://zenity.io/press-release/zenity-raises-125-million-to-secure-the-era-of-1-billion-ai-agents), [SecurityWeek](https://www.securityweek.com/hiddenlayer-raises-100-million-for-ai-runtime-security/), [BusinessWire](https://www.businesswire.com/news/home/20260615229631/en/Arcade-Raises-$60M-to-Become-the-Secure-Action-Layer-Behind-Every-Production-AI-Agent), [Forbes](https://www.forbes.com/sites/janakirammsv/2026/08/10/arcade-acquires-smithery-to-own-the-agent-tool-supply-chain/).
- One roundup cites $3.6B in Crunchbase funding and $96B in M&A in the agentic security context around RSAC 2026. The scope of these totals is unclear — [softwarestrategiesblog](https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/).
- One article frames the 2026 consolidation as "five exits, one holdout" (Alice/ActiveFence); the page could not be fetched — [datapace](https://datapace.ai/blog/alice-activefence-agent-security-consolidation).
- CB Insights says Astrix, Entro and Oasis have been acquired, with Token among the few independents left. It frames agent identity as the next M&A target area — [CB Insights](https://www.cbinsights.com/research/ai-agent-identity-acquisitions-targets/).

### Inferences
- Independent, vendor-neutral, open-source policy layers have become scarcer as the classifiers were absorbed into SASE, EDR and AppSec suites. That leaves room for a neutral open-source component, and also means writ competes against "free module in an existing platform contract".

### Gaps
- The acquirers and dates for Astrix, Entro and Oasis were not confirmed.
- The details of the "five exits" were not retrieved.
- No 2026 acquisitions of the remaining MCP gateway vendors were found.

## 7. Where writ is differentiated, and where it is behind

### Takeaway
writ's combination is uncommon among the sources reviewed, though most of its individual pieces exist elsewhere: deterministic argument-level policy, principal entitlements, runtime taint that escalates to a human, attenuable Biscuit task tokens, a hash-chained recorder, and replay that fails CI when a policy gets looser. It is behind on enterprise plumbing: hosted SaaS, UI, SSO and OAuth integration, HTTP and remote-MCP gateway features, a catalog, and commercial support.

### Cited Findings
- Classifier vendors are probabilistic and model-based (PromptGuard, AlignmentCheck, Prompt Shields) — [arXiv LlamaFirewall](https://arxiv.org/html/2505.03574v1), [Microsoft Learn](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter-prompt-shields).
- Gateways mostly route traffic and leave per-user authorization to the tools — [Speakeasy](https://www.speakeasy.com/blog/best-mcp-gateways-for-enterprise-2026).
- Competitors have enterprise identity integration: agentgateway works with Entra and Keycloak, Okta has XAA, and Pomerium has IdP-backed policy — [agentgateway SSO](https://agentgateway.dev/blog/2026-01-26-enterprise-mcp-sso/), [Okta](https://www.okta.com/newsroom/articles/cross-app-access-extends-mcp-to-bring-enterprise-grade-security-to-ai-agents/), [Pomerium](https://www.pomerium.com/docs/capabilities/mcp).
- Human approval exists elsewhere: HumanLayer has an SDK decorator and MCPX has approval workflows — [everydev](https://www.everydev.ai/tools/humanlayer), [Arcade comparison](https://www.arcade.dev/blog/best-mcp-gateways-enterprise/).
- Hash-chained logs and dry-run exist in small OSS projects — [agentguard](https://github.com/agentwares/agentguard), [HarrisonCN PR](https://github.com/HarrisonCN/mcp-gateway/pull/86).
- Attenuating agent tokens are an active IETF topic that names gaps in Biscuit — [IETF WIMSE draft](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-03).
- Out-of-band deterministic defenses (CaMeL, FIDES, Progent) are the research direction, with strong AgentDojo results — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1).

### Inferences
- **Areas where writ appears differentiated** (inferred; vendor-by-vendor confirmation is incomplete):
  1. Taint that escalates to human approval in a production proxy. Only research systems and Invariant's static analysis were found.
  2. Biscuit tokens that sub-agents narrow, inside the same enforcement layer as policy and audit.
  3. Replay as a "policy got looser" CI gate.
  4. Entitlement-aware argument conditions as a first-class YAML feature, rather than an external engine integration.
  5. Neutral Apache-2.0 licensing while competitors are absorbed into platforms.
- **Areas where writ is likely behind:**
  1. No SaaS, control-plane UI, dashboards or approval inbox, which MCPX, Zenity, Operant and Pomerium offer.
  2. HTTP/streamable-HTTP, multi-tenant remote gateway features and OAuth 2.1/XAA integration, where agentgateway, Kong and Pomerium are ahead.
  3. No content classifiers for PII, secrets or injection detection, which Invariant Guardrails and the platforms include.
  4. No discovery or inventory of agents and MCP servers (mcp-scan, Operant Discovery, Astrix and other NHI tools).
  5. No enterprise sales or compliance mappings (mcp-gate maps to NIST and OWASP).
- Likely integration partners, rather than competitors: identity vendors (Keycard, Okta XAA, Auth0) as entitlement and identity sources; agentgateway or Pomerium as the network edge in front of writ; and Cerbos, SpiceDB or OpenFGA as external entitlement stores.

### Gaps
- writ's own feature set was taken from the brief and not verified against the code.
- It is unconfirmed whether Zenity, Noma, Lasso, Pillar or Operant ship taint, replay or attenuation features, because their product documentation was not retrieved.
