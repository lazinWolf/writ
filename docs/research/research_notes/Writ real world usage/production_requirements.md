# Production Requirements for an AI-Agent Tool-Call Security and Policy Layer (writ)

Scope: the compliance, operational, developer-experience, human-approval and adoption requirements that "writ" (a Rust MCP proxy and daemon providing policy, entitlements, taint, approvals, signed delegation tokens, a hash-chained audit log and replay; local-only today, with stdio, a Unix socket, YAML and a CLI) must meet to be adopted in production. Research date: 2026-11-04.

Method note: this session's network blocked direct page fetches of several primary hosts (artificialintelligenceact.eu, gibsondunn.com). Findings therefore rest on search-result extracts. Where the only source is a vendor or secondary blog, the item says so. **LEGAL** marks a binding legal or contractual requirement. **BEST PRACTICE** marks an industry norm or auditor expectation.

---

## Compliance and regulation: what do the EU AI Act, NIST, ISO 42001, SOC 2 and sector rules require of an agent tool-call layer, and on what timeline?

### Takeaway
The EU AI Act's high-risk obligations, which cover automatic logging (Art. 12), log retention of at least 6 months (Arts. 19 and 26(6)) and human oversight (Art. 14), were delayed by the Digital Omnibus (Regulation (EU) 2026/1744, in force since 27 July 2026). Annex III systems now face them on 2 Dec 2027 and Annex I product-embedded AI on 2 Aug 2028. The delay gives writ a roughly 13-month window to become the "Art. 12/14 evidence layer" for agents. US frameworks (NIST, FINRA) are voluntary or supervisory expectations rather than statute, but they all point the same way: per-agent identity, scoped authority, action logs and human checkpoints. Sector rules (PCI DSS, HIPAA) set the hard numbers on log retention.

### Cited Findings

**EU AI Act timeline after the Digital Omnibus (LEGAL)**
- Negotiators reached a provisional deal on 7 May 2026. Parliament endorsed it on 16 Jun 2026, the Council adopted it on 29 Jun, it was signed on 8 Jul, and it entered into force on 27 Jul 2026 after publication in the Official Journal — [Usercentrics](https://usercentrics.com/knowledge-hub/eu-ai-act-high-risk-delay-article-50-transparency-consent/); [Sidley Data Matters](https://datamatters.sidley.com/2026/06/22/eu-lawmakers-reach-provisional-agreement-to-delay-key-eu-ai-act-obligations/)
- The amending act is Regulation (EU) 2026/1744, published in the OJ on 24 Jul 2026 — [AIActo](https://www.aiacto.eu/en/blog/digital-omnibus-ai-act-report-2027); [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-omnibus-vii-deadline-delay-20260/)
- New high-risk dates: standalone Annex III systems move to **2 Dec 2027** (from 2 Aug 2026). AI embedded in Annex I regulated products moves to **2 Aug 2028** (from 2 Aug 2027) — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-deadline-omnibus-20260/); [Hogan Lovells](https://www.hlc.com/en/publications/eu-legislators-agree-to-delay-for-highrisk-ai-rules); [VerifyWise](https://verifywise.ai/blog/eu-ai-act-omnibus-what-changed)
- The Art. 50(2) watermarking grace period for systems already on the market runs to 2 Dec 2026. National regulatory sandboxes move to 2 Aug 2027. Per one analysis, the Art. 50 disclosure-of-AI-interaction duties kept their 2 Aug 2026 date. Summaries differ on details, so check the OJ text — [Usercentrics](https://usercentrics.com/knowledge-hub/eu-ai-act-high-risk-delay-article-50-transparency-consent/); [Winston Taylor](https://www.winstontaylor.com/insights/ai-act-rules-on-high-risk-ai-delayed-as-ai-digital-omnibus-agreed); [DLA Piper](https://knowledge.dlapiper.com/dlapiperknowledge/globalemploymentlatestdevelopments/2026/The-Digital-AI-Omnibus-Proposed-deferral-of-high-risk-AI-obligations-under-the-AI-Act)
- Commentators stress the deadline is "deferred, not cancelled" — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-deadline-omnibus-20260/)

**EU AI Act Article 12, record-keeping (LEGAL for high-risk systems)**
- Art. 12 is a provider design duty: high-risk systems must technically allow automatic recording of events over their lifetime. It sits in Chapter III Section 2 alongside accuracy and cybersecurity — [Regulation-AI academy, module 5](https://www.regulation-ai.eu/en/academy/ai-act-provider/module-5/); [TrueScreen](https://truescreen.io/insights/ai-act-record-keeping-requirements/)
- Art. 19 (providers) and Art. 26(6) (deployers) require logs under the party's control to be kept for a period suited to the intended purpose, **at least six months**, unless other Union or national law says otherwise — [Pipelab](https://pipelab.org/learn/eu-ai-act-compliance/); [Regulation-AI deployer module 2](https://www.regulation-ai.eu/en/academy/ai-act-deployer/module-2/); [module 4](https://www.regulation-ai.eu/en/academy/ai-act-deployer/module-4/)
- Under SaaS, the deployer's duty extends only to logs it actually controls. Log access therefore becomes a contractual question to settle before signing — [Pipelab](https://pipelab.org/learn/eu-ai-act-compliance/)
- Commentary on applying Art. 12 to agents argues that the logs must reconstruct which tool was called, with what inputs, under what authority and with what outcome. These sources are vendor blogs (best-practice interpretation, not legal text) — [Praesidia](https://praesidia.ai/blog/eu-ai-act-article-12-logging-ai-agents); [Datapace](https://datapace.ai/blog/eu-ai-act-ai-agent-logging-requirements); [KLA Digital](https://kla.digital/blog/eu-ai-act-article-12-logging-requirements); [MeshAI](https://meshai.dev/blog/eu-ai-act-article-12-record-keeping)

**EU AI Act Article 14, human oversight (LEGAL for high-risk systems)**
- Art. 14 is covered with Arts. 12–13 as "oversight by design" in the provider academy material — [Regulation-AI module 5](https://www.regulation-ai.eu/en/academy/ai-act-provider/module-5/). (I could not fetch the article text. See Gaps for the 14(4) and 14(5) specifics.)

**NIST (voluntary; BEST PRACTICE, likely to become procurement expectations)**
- NCCoE concept paper, "Accelerating the Adoption of Software and AI Agent Identity and Authorization": released 5 Feb 2026, comments closed 2 Apr 2026. Authors: H. Booth, B. Fisher, R. Galluzzo and J. Roberts. It is a scoping document for a demonstration project, not a standard — [NCCoE PDF](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf); [CSRC](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd); [NIST news](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)
- The paper's premise: agents should be identifiable entities in enterprise identity systems, not anonymous automation on shared credentials. Its open questions include how agent credentials are issued, updated and revoked, and whether authorization should adapt in real time to the agent's context. Candidate standards: OAuth, OIDC, SCIM, SPIFFE/SPIRE. RAG-only and LLM-only systems are out of scope — [Biometric Update](https://biometricupdate.com/202603/nist-concept-paper-explores-identity-and-authorization-controls-for-ai-agents); [Biometric Update (Feb)](https://www.biometricupdate.com/202602/nccoe-seeks-input-on-project-to-apply-identity-authorization-standards-to-agentic-ai); [Hogan Lovells](https://hlc.com/en/publications/shaping-the-future-of-ai-security-nist-seeking-input-on-agent-identity-authorization)
- NIST CAISI launched an AI Agent Standards Initiative on 17 Feb 2026. It is expected to produce voluntary guidelines on identity and authorization, security and risk, and monitoring and logging, with an "AI Agent Interoperability Profile" reportedly planned for Q4 2026. This is a secondary source (CSA), not verified on nist.gov — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-initiative-complia/)
- There is no official NIST AI RMF agentic profile. The "Agentic Profile" circulating is a CSA practitioner paper. AI RMF 1.0 (Jan 2023) and AI 600-1 do not distinguish advisory systems from autonomous systems with irreversible effects — [CSA Agentic NIST AI RMF Profile](https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/)

**ISO/IEC 42001 (voluntary certification; BEST PRACTICE)**
- Annex A control A.6.2.8, "AI system recording of event logs". One quoted wording: the organization shall determine at which life-cycle phases event-log recording is enabled. Another paraphrase: logs must support auditability, incident investigation and monitoring. The normative text was not verified — [ISMS.online](https://www.isms.online/iso-42001/annex-a-controls/a-6-ai-system-life-cycle/a-6-2-8-ai-system-recording-of-event-logs/); [Cyberday](https://www.cyberday.ai/requirement/iso-42001-a-6-2-8-ai-system-recording-of-event-logs)
- One commentator notes A.6.2.8 requires that events are recorded but does not require records in a sequence to be linked. Hash-chaining therefore goes beyond the control — [AgenticRail blog](https://agenticrail-web.pages.dev/blog/iso-42001-a628-event-log/)

**SOC 2 (contractual or attestation; BEST PRACTICE)**
- SOC 2 prescribes no fixed retention period. Organizations set a policy based on risk. The industry norm is about 12 months for security logs, and several guides suggest about 13 months so the whole observation window is covered — [Konfirmity](https://www.konfirmity.com/blog/soc-2-logging-pipelines-for-soc-2); [DecryptionDigest](https://www.decryptiondigest.com/blog/security-log-retention-pci-dss-hipaa-soc2-compliance-guide); [ComplyJet](https://www.complyjet.com/blog/logging-stack-soc-2-auditor)
- Auditors expect a documented retention policy, evidence that someone reviews logs or acts on alerts (CC7.2), storage separate from the generating system, restricted write access, and a way to prove after the fact that nothing was altered. Typical implementations hash log batches into a separate store or use WORM storage (S3 Object Lock). Claims that CC7.2 "requires immutability" are not supported by the criteria text — [Safeguard](https://safeguard.sh/resources/blog/how-to-meet-soc-2-audit-logging-requirements); [ComplyJet](https://www.complyjet.com/blog/logging-stack-soc-2-auditor); [hoop.dev](https://hoop.dev/blog/immutable-audit-logs-soc-2-ensuring-security-and-compliance)

**PCI DSS v4.0.1 (contractual for card environments; effectively LEGAL)**
- Req. 10.5.1: keep audit log history for at least **12 months**, with the most recent **3 months immediately available** for analysis. Some sources wrongly cite 10.7 — [Daydream](https://learn.daydream.ai/requirements/pci-dss-10-5-1); [PCI DSS Guide](https://pcidssguide.com/what-are-the-pci-dss-log-retention-requirements/); [CyberSilo](https://cybersilo.tech/pci-dss-requirement-10)
- PCI SSC published non-mandatory guidance on securing AI in payment environments, dated 7 Oct 2026. It covers how AI is deployed, reducing misuse, fit with existing PCI standards, and use cases. Where it differs, the PCI standards take precedence — [PCI SSC press release](https://www.pcisecuritystandards.org/about_us/press_releases/pci-ssc-publishes-additional-guidance-on-securing-ai-in-payment-environments/)

**HIPAA (LEGAL for covered entities and business associates)**
- §164.312(b) requires audit controls. Sources commonly state a **six-year** retention period, but they disagree on its legal basis: Aptible ties it to §164.312(b), and others cite the documentation-retention rule — [Aptible](https://www.aptible.com/hipaa/audit-log-retention); [Netizen](https://www.netizen.net/news/post/7735/audit-log-retention-what-pci-dss-nist-hipaa-and-fedramp-expect)
- Retained does not mean hot. Logs must be retrievable for six years, not kept in the primary aggregator — [Netizen](https://www.netizen.net/news/post/7735/audit-log-retention-what-pci-dss-nist-hipaa-and-fedramp-expect)

**DORA (LEGAL for EU financial entities since 17 Jan 2025)**
- The detailed logging duties sit in Art. 12 of Delegated Regulation (EU) 2024/1774 (the RTS on the ICT risk management framework). It requires logging procedures covering access control, capacity management, change management, ICT operations and network traffic, plus **measures to detect failure of the logging systems themselves** — [SpringLex RTS Art. 12](https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-12/); [Graylog](https://graylog.org/post/centralized-log-management-for-the-digital-operational-resilience-act/)
- DORA Level-1 Art. 12 requires documented and tested backup, restoration and recovery. BaFin also highlights the redundant ICT capacity required by Art. 12(4) — [BaFin guidance](https://www.bafin.de/SharedDocs/Downloads/EN/Anlage/dl_2024_07_08_Aufsichtsmitteilung_Umsetzungshinweise_DORA_en.pdf?__blob=publicationFile&v=3); [Daydream](https://learn.daydream.ai/requirements/dora-dora-12)
- A law-firm blog argues agents under DORA need per-agent identity, tool-invocation logs and recorded human approvals for gated steps (interpretation) — [Moring](https://www.moring.ai/blogs/dora-compliance-ai-agents/)

**FINRA (US broker-dealers; supervisory expectation under existing rules)**
- FINRA's 2026 Annual Regulatory Oversight Report (Dec 2025) has an AI-agents section. It defines agents as "systems or programs that are capable of autonomously performing and completing tasks on behalf of a user". It flags these risks: autonomy (acting without human validation or approval), scope and authority (exceeding the user's intended mandate or permissions), and unintended disclosure of sensitive data. Suggested considerations include tracking agent actions and limiting system access — [FINRA release](https://finra.org/media-center/newsreleases/2025/finra-publishes-2026-regulatory-oversight-report-empower-member-firm); [Sidley](https://datamatters.sidley.com/2025/12/16/finra-issues-2026-regulatory-oversight-report/); [Mondaq](https://www.mondaq.com/unitedstates/new-technology/1759638/finras-2026-report-addresses-emerging-trends-and-current-practices-relating-to-generative-ai); [Smarsh](https://www.smarsh.com/blog/thought-leadership/finra-2026-oversight-priorities-ai-communications-fraud)
- FINRA does not mandate specific tools. It raises expectations on governance, documentation, testing and accountability — [Financial Planning](https://www.financial-planning.com/news/finra-calls-attention-to-ai-compliance-risks)

**SOX (LEGAL for US issuers via SOX 404 ICFR)**
- ITGCs (access to programs and data, program changes, operations) fall within management's SOX 404 assessment where IT supports financial processing — [Wikipedia: IT controls](https://en.wikipedia.org/wiki/Information_technology_controls). I found no authoritative guidance specific to AI agents (see Gaps).

### Inferences
Checklist with the bar for each item:
1. **Tamper-evident, complete tool-call log** (EU AI Act Art. 12; ISO 42001 A.6.2.8; SOC 2; PCI 10; HIPAA 164.312(b); DORA RTS Art. 12). Bar: every call records agent identity, delegating human, tool and arguments (with redaction), policy version and decision, approver, result and timestamps. The hash-chain must be verifiable offline, with periodic anchoring of the chain head to external WORM storage or a transparency store, because a local chain alone is not "separate from the generating system". writ's chain exceeds the ISO bar (no linking required). Its gap is external anchoring and export.
2. **Configurable retention with tiers.** Bar: minimum 6 months (AI Act), 12 months with 3 hot (PCI), 6 years retrievable (HIPAA). Ship retention policies and cold-tier export (S3 Object Lock or equivalent) plus SIEM forwarding (Splunk, Datadog, OTel or syslog).
3. **Logging-failure detection** (DORA RTS Art. 12). Bar: alert, and optionally fail closed, if the audit sink stops accepting writes.
4. **Human oversight primitives** (Art. 14; FINRA "autonomy"). Bar: approval gates, a stop or kill switch per agent and session, and override with recorded justification.
5. **Agent identity and delegated authority** (NCCoE; FINRA "scope and authority"). Bar: per-agent workload identity (SPIFFE/OIDC) and token-based delegation that maps onto OAuth token exchange. writ's signed delegation tokens should interoperate with OAuth/OIDC rather than be a proprietary format.
6. **Change control on policies** (SOX ITGC; DORA change-management logging). Bar: policy versions are signed, reviewed (two-person) and themselves logged. Replay under a new policy is strong evidence of testing before change.
7. The timeline means EU buyers will run procurement in 2027 for a 2 Dec 2027 deadline. "Art. 12/14 mapping docs" are a sales asset now.

### Gaps
- The exact text of AI Act Art. 14(4)(a)–(e) (understanding, automation-bias awareness, interpretation, disregard or override, a "stop" button) and Art. 14(5) (verification by two natural persons for Annex III 1(a) biometric ID). This is from my own background knowledge and was not verified in this session because the AI Act site was blocked. Verify on [EUR-Lex 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj).
- Whether the Omnibus changed the Art. 12, 14 or 26 text itself, as opposed to only the dates. Not confirmed.
- HIPAA: whether the six years derives from §164.316(b)(2) or §164.530(j). The sources conflict, so verify against the eCFR.
- SEC-specific guidance on AI agents (e.g. 2026 exam priorities) was not researched for lack of budget.
- SOX: no PCAOB or auditor guidance on AI agents in ITGC testing was found.
- The content of the PCI SSC AI guidance document (logging and agent specifics) was not retrieved.
- NIST AI RMF revision status and the planned Q4 2026 interoperability profile were not verified on nist.gov.

---

## Operational: latency, availability (fail-open vs fail-closed), multi-tenancy, deployment modes, secrets and scaling

### Takeaway
Embedded policy engines evaluate in microseconds (Cedar's median is 4–11 µs). OPA ranges from sub-millisecond to tens of milliseconds depending on policy and input size. An agent tool-call proxy should therefore target policy-decision overhead well under 1 ms at p99, excluding approvals. The ecosystem default for an inline authorizer is fail-closed (Envoy ext_authz `failure_mode_allow: false`), with fail-open as an explicit, observable opt-in.

### Cited Findings
- Cedar's peer-reviewed evaluation reports a median of about 4 µs (Google Drive-like scenario; 4.0 µs at 5 entities and 5.0 µs at 50) and about 11 µs (GitHub-like scenario). p99 stayed under 10 µs and 20 µs respectively and was roughly flat as input grew — [Cedar paper (Amazon Science PDF)](https://cdn.amazon.science/96/a8/1b427993481cbdf0ef2c8ca6db85/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization.pdf); [ACM](https://dl.acm.org/doi/full/10.1145/3649835); [Murat Demirbas summary](http://muratbuffalo.blogspot.com/2025/03/cedar-new-language-for-expressive-fast.html)
- The same paper reports Cedar 42.8–80.8x faster than Rego. Critics note this is the authors' own benchmark, comparing different operations — [3h4x blog](https://3h4x.github.io/tech/2026/06/23/cedar-vs-opa)
- OPA figures vary widely: under 1 ms p99 in-process in some claims, 2.5–8 ms in others, and 50–200 ms for policies that traverse large inputs such as full Kubernetes manifests. These are low-quality, conflicting sources. The consistent advice is to benchmark your own policies — [zop.dev](https://zop.dev/resources/blogs/opa-vs-cedar-when-policy-as-code-hits-500-accounts); [Hivebook](https://hivebook.wiki/wiki/opa-vs-cedar-policy-engine-comparison-for-authorization); [Inferensys](https://inferensys.com/differences/enterprise-agent-identity-and-permission-platforms/non-human-identity-management-platforms/open-policy-agent-vs-cedar)
- OPA's own Envoy performance docs separate end-to-end latency (network, app and OPA) from the OPA-Envoy plugin's evaluation time. The reference deployment does not enable decision logs, and you are told to benchmark their cost yourself — [OPA docs: Envoy performance](https://openpolicyagent.org/docs/v0.56.0/envoy-performance)
- Envoy ext_authz `failure_mode_allow` defaults to false, which is fail-closed. On authorizer failure Envoy returns 403 by default. When fail-open is enabled, requests pass on network errors or 5xx responses, and a `failure_mode_allowed` counter tracks them. OPA's sample config uses `failure_mode_allow: false` — [Netdata guide](https://www.netdata.cloud/guides/envoy/envoy-ext-authz-failure-mode-allowed/); [OPA docs](https://openpolicyagent.org/docs/v0.56.0/envoy-performance); historical bugs in fail-open behaviour: [envoy#4124](https://github.com/envoyproxy/envoy/issues/4124), [envoy#10158](https://github.com/envoyproxy/envoy/issues/10158)
- OPA decision logs support masking of sensitive fields and buffer limits, which is relevant to redacting tool arguments in audit logs — [OPA configuration docs](https://www.openpolicyagent.org/docs/configuration); [OPA PR #1466 (masking)](https://github.com/open-policy-agent/opa/pull/1466/files)
- DORA requires redundant ICT capacity (Art. 12(4)) and tested restoration, which bears directly on HA for an inline control in EU finance — [BaFin](https://www.bafin.de/SharedDocs/Downloads/EN/Anlage/dl_2024_07_08_Aufsichtsmitteilung_Umsetzungshinweise_DORA_en.pdf?__blob=publicationFile&v=3)
- Tailscale's model of open clients with a closed coordination server, and the self-hosted alternative Headscale that grew up around it, show demand for self-hostable and air-gapped control planes — [Start With Identity](https://startwithidentity.com/articles/top-7-open-source-zero-trust-tools/)

### Inferences
Checklist with the bar for each item:
1. **Latency.** Bar: policy evaluation p99 under 1 ms in-process (the Rust engine should hit tens of µs, like Cedar). Total proxy overhead per MCP call should be p99 under 5 ms, excluding upstream tool time and human approvals. Publish benchmarks with methodology, and measure audit-write cost separately (OPA's guidance). Use asynchronous, batched log shipping with a local durable buffer so the hash-chain write never becomes the bottleneck.
2. **Fail mode.** Bar: fail-closed by default and configurable per tool or tenant ("fail-open for read-only tools"), with a metric and alert whenever fail-open fires (mirroring Envoy's counter). Approval timeouts resolve to deny by default.
3. **HA.** Bar: a stateless decision path (policy bundle cached locally) so any replica can decide. Approvals, delegation-token revocation and audit chain heads need a replicated store (e.g. Postgres or Raft), plus documented backup and restore (DORA).
4. **Deployment modes.** Bar, in order of demand (inferred): (a) local or sidecar (today), (b) network gateway for remote MCP over Streamable HTTP with TLS and OAuth, (c) Kubernetes Helm chart or operator, (d) a central control plane distributing signed policy bundles and collecting audit (the OPA bundle and decision-log pattern), (e) air-gapped operation with no phone-home, (f) optional hosted SaaS control plane.
5. **Multi-tenancy.** Bar: tenant-scoped policies, keys, audit chains and RBAC on the admin API, so one tenant cannot read another's logs or approvals.
6. **Secrets.** Bar: writ should inject credentials so agents never see raw tool credentials. Integrate with Vault or OpenBao, cloud KMS and the OS keychain. Never log secrets (redaction or masking, as OPA does). Signing keys for tokens and the log should be in KMS or HSM-capable storage.
7. **Observability.** Bar: Prometheus metrics, OpenTelemetry traces with decision spans, structured JSON logs.

### Gaps
- No primary benchmarks of MCP-proxy overhead or API gateways (Envoy, Kong) were retrieved. The latency budget numbers for gateways are therefore my inference, not sourced.
- No sourced survey of buyer preference between sidecar, gateway and SaaS for agent security.
- AWS Verified Permissions or Cedar-agent latency and SLA figures were not retrieved.

---

## Developer and policy-authoring experience: policy-as-code, testing, verification, dry-run or shadow mode, simulation, bootstrapping from traffic

### Takeaway
Mature authorization ecosystems combine four things. Policies live as code in Git and are validated against a schema. They have unit tests (OPA `opa test`) and formal analysis (Cedar's SMT-based symbolic compiler, which checks equivalence, subsumption and never-errors). Rollout goes per rule through an audit or shadow mode before enforcement (Kyverno Audit vs Enforce). Policies are bootstrapped from observed activity (AWS IAM Access Analyzer generates policies from up to 90 days of CloudTrail). writ's replay feature maps directly onto "simulate a new policy against real history", which is a differentiator.

### Cited Findings
- Cedar validates policies against a schema, so references to unknown attributes, actions or entity types fail before deployment — [Manning liveBook](https://livebook.manning.com/learn/concepts/cedar-symbolic-compiler--tool/authorization-in-action); [Cedar paper](https://cdn.amazon.science/96/a8/1b427993481cbdf0ef2c8ca6db85/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization.pdf)
- Cedar's symbolic compiler (the Rust crate `cedar-policy-symcc`) compiles policies to SMT using CVC5. It supports these checks: the policy never errors, policy-set subsumption, equivalence and disjointness — [docs.rs cedar-policy-symcc](https://docs.rs/cedar-policy-symcc); [crate page](https://docs.rs/crate/cedar-policy-symcc/latest)
- The Lean formalization claims the symbolic-compiler checks are sound and complete — [cedar-spec Lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)
- Research is applying agentic, verifier-guided synthesis to Cedar policies (LLM drafts with a solver checking them) — [AutoCedar (arXiv)](https://arxiv.org/html/2607.03656v1)
- Kyverno sets the mode per rule: Enforce blocks at admission, while Audit allows the request and records it in a PolicyReport. The newer field is `validate.failureAction`, replacing the deprecated `spec.validationFailureAction`. Background scans report violations by existing resources — [Kyverno docs](https://kyverno.io/docs/policy-types/cluster-policy/validate/); [EKS Workshop](https://www.eksworkshop.com/docs/security/kyverno/reports); [Big Bang docs](https://docs-bigbang.dso.mil/latest/packages/kyverno-reporter/docs/overview/); [oneuptime](https://oneuptime.com/blog/post/2026-02-02-kyverno-policies/view)
- Real users report confusion when "Audit" policies were enforced anyway, so mode semantics must be clear and visible — [kyverno/policies discussion #716](https://github.com/kyverno/policies/discussions/716)
- OPA has no first-class "shadow mode" feature. Teams build it from decision logs. Guidance says to run new rules in shadow first to spot false blocks — [hoop.dev](https://hoop.dev/blog/how-to-configure-opa-policy-engine); examples of custom shadow setups: [GitHub juggernaut PR #322](https://github.com/umeranjum17/juggernaut/pull/322)
- AWS IAM Access Analyzer generates a least-privilege policy template from CloudTrail activity over a period of up to 90 days. It needs an enabled trail, prompts for action-level detail on some services, and its output is a starting point to review — [AWS docs: generate policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html); [AWS docs](https://docs.aws.amazon.com/en_us/IAM/latest/UserGuide/access_policies_generate-policy.html); [AWS Security Blog](https://aws.amazon.com/blogs/security/use-iam-access-analyzer-policy-generation-to-grant-fine-grained-permissions-for-your-aws-cloudformation-service-roles/)

### Inferences
Checklist with the bar for each item:
1. **Schema-validated policies.** Bar: `writ policy validate` fails CI on unknown tools or arguments, using the MCP `tools/list` schemas as the policy schema.
2. **Unit tests.** Bar: a `writ policy test` that reads fixture tool calls and expected decisions, in the style of `opa test`, with coverage output and JUnit format for CI.
3. **Static analysis.** Bar: at minimum, detect shadowed, unreachable or conflicting rules and diff two policy versions ("which calls change decision?"). Stretch goal: an SMT-backed equivalence or subsumption check, or compiling to or embedding Cedar to inherit its tooling.
4. **Modes per rule.** Bar: `enforce`, `audit` (log the would-be decision) and `off`, set per rule, with mode shown in every audit record to avoid the Kyverno confusion.
5. **Replay and simulation.** Bar: `writ replay --policy new.yaml --since 30d` outputs a decision diff (allowed→denied and denied→allowed) by tool, agent and tenant. It should be runnable in CI on a PR as a policy-change gate (the SOX/DORA change-control evidence).
6. **Bootstrap from traffic.** Bar: `writ policy generate --from-audit --since 14d` emits a least-privilege draft (tools and argument patterns actually used), following the Access Analyzer precedent: reviewable output, never auto-applied.
7. **GitOps.** Bar: policies loaded from a Git-synced directory or a signed bundle URL, with hot reload and the version hash recorded in each audit entry.

### Gaps
- No primary data was found on how many teams use policy unit tests or shadow mode (adoption statistics).
- OPA `opa test` docs and Cedar Analysis CLI docs were not fetched directly. Details above come from the crate docs and paper.

---

## Human approval UX: fatigue, SLA and timeouts, mobile, step-up auth, four-eyes rules

### Takeaway
The best-documented failure mode is approval fatigue. MFA push-bombing shows that context-free approve/deny prompts get reflexively approved. CISA recommends number matching as a stopgap and phishing-resistant MFA as the goal. For agent approvals the bar is: rare, context-rich prompts bound to the exact call and arguments; step-up authentication for high-risk actions; rate limits on approval requests; and approver-behaviour monitoring.

### Cited Findings
- CISA: threat actors defeat push-based MFA through the "MFA fatigue" technique. CISA recommends number matching where phishing-resistant MFA is not yet feasible — [CISA fact sheet: number matching](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf)
- Number matching reduces careless approvals but is not origin-bound, because real-time phishing proxies can relay the number. FIDO2 and passkeys bind approval to the legitimate origin — [Start With Identity](https://startwithidentity.com/breaches/mfa-fatigue-push-bombing/); [Hive Security](https://hivesecurity.gitlab.io/blog/mfa-fatigue-push-bombing-detection-defense/); [LoginRadius](https://www.loginradius.com/blog/identity/mfa-fatigue-attacks-prevention)
- Agent-approval guidance (vendor) says approval fatigue sets in when requests are so frequent that approving becomes a reflex. Its recommendations: bind each approval to the exact tool call and arguments; for high-risk actions, require the approver to type a specific value (amount, account digits); monitor approval rate and decision time per approver, where near-instant approval of nearly everything signals rubber-stamping; and recognize that a manipulated agent could flood approvers the way push bombing does — [AgentFort](https://agentfort.net/agent-security/human-approval)
- FINRA's 2026 report flags agents "acting without human validation or approval" as a key risk, which makes recorded human checkpoints a supervisory expectation in broker-dealers — [Sidley](https://datamatters.sidley.com/2025/12/16/finra-issues-2026-regulatory-oversight-report/)
- DORA-oriented guidance calls for recorded human approvals on gated steps — [Moring](https://www.moring.ai/blogs/dora-compliance-ai-agents/)

### Inferences
Checklist with the bar for each item:
1. **Approval-worthy events only.** Bar: approvals triggered by risk (taint plus a sensitive sink, irreversible or financial action), not by every call. Track and report the approval rate, aiming low enough that approvals stay meaningful (no sourced target found).
2. **Context-rich, call-bound prompts.** Bar: show the agent, delegating user, tool, full arguments (diff-style), taint provenance and the policy rule. Bind the approval cryptographically to a hash of the call, so it cannot be replayed onto a different call.
3. **Channels.** Bar: CLI and TTY (today), plus Slack or Teams, web UI and a mobile-friendly link. Webhooks allow integration with ITSM tools (ServiceNow or Jira) for change-style approvals.
4. **Timeouts and SLA.** Bar: a configurable timeout per rule, a default deny on timeout, escalation to a secondary approver, and the agent receiving a structured "pending" or "denied: timeout" result so it does not hang.
5. **Step-up auth.** Bar: WebAuthn or passkey re-authentication for high-risk approvals. Never a bare "Approve" push button for critical actions.
6. **Four-eyes and segregation of duties.** Bar: N-of-M approvers, with a rule that the requester or delegator cannot self-approve (SOX/SoD logic). Everything is recorded in the audit chain.
7. **Anti-flooding.** Bar: rate-limit approval requests per agent and session. A burst of approval requests should auto-suspend the agent.

### Gaps
- No primary study quantifying approval fatigue thresholds for agent or HITL approvals was found. The AgentFort source is a vendor blog.
- No sourced benchmark for approval SLAs (e.g. median human response time) in agent workflows.
- The literal text of AI Act Art. 14(5)'s two-person verification (limited to remote biometric ID) was not verified.

---

## Adoption path for open-source infra security tools: what made OPA, Falco, Teleport, Tailscale, Cilium and Vault succeed, and how open-core works

### Takeaway
Successful projects pair a permissive or neutral OSS core, often with CNCF or Linux Foundation governance (OPA graduated 2021, Falco 2024), with a commercial edition that adds enterprise features or a hosted control plane (Sysdig Secure on Falco; Teleport Enterprise over the AGPL Community Edition; Tailscale's open clients and closed coordination server). License rug-pulls trigger forks: HashiCorp's 2023 move to BSL led to OpenTofu and OpenBao. That is a strong signal for writ to keep its core under an OSI license and monetize the control plane, compliance and enterprise features.

### Cited Findings
- Sysdig open-sourced Falco in 2016. It became the first runtime-security project in the CNCF Sandbox (2018), entered Incubation in Apr 2020 and graduated in Feb 2024. Named adopters: Cisco, Shopify, Skyscanner, Vinted — [CNCF announcement](https://www.cncf.io/announcements/2024/02/29/cloud-native-computing-foundation-announces-falco-graduation/); [Security Boulevard](https://securityboulevard.com/2024/02/cncf-graduates-falco-project-to-improve-linux-security/)
- Falco is open core: Sysdig Secure is the commercial product built on it. Sysdig claims 60% of the Fortune 500 use Falco, a vendor claim that is unverified — [Sysdig](https://www.sysdig.com/opensource/falco)
- OPA graduated from the CNCF in Feb 2021 — [ARMO](https://www.armosec.io/blog/best-open-source-kubernetes-security-tools/)
- HashiCorp moved Terraform, Vault and other products from MPL-2.0 to BSL 1.1 in Aug 2023. BSL is source-available, forbids competing offerings, and converts to open source after about 4 years per release. OpenTofu (Linux Foundation) forked Terraform. OpenBao (Linux Foundation, MPL-2.0) forked Vault from its last MPL release. Sources conflict on OpenTofu's license and OpenBao's fork date — [Wikipedia: formerly open-source software](https://en.wikipedia.org/wiki/List_of_formerly_open-source_or_free_software); [WZ-IT](https://wz-it.com/en/blog/open-source-licence-change-chronicle/); [Digitalis](https://digitalis.io/post/choosing-a-secrets-storage-hashicorp-vault-vs-openbao); [bespinian](https://bespinian.io/en/blog/openbao-os-vault-alternative/)
- Tailscale's clients are open source but its coordination server is not, and Headscale exists as the self-hosted alternative. Teleport Community Edition is AGPL-3.0, while identity governance, device trust and other enterprise features are commercial — [Start With Identity](https://startwithidentity.com/articles/top-7-open-source-zero-trust-tools/)
- An IETF Internet-Draft proposes a standard audit-trail format for autonomous AI agents, mapped to SOC 2, ISO/IEC 42001 and PCI DSS v4.0.1 logging requirements. It is a draft, not adopted, but it is an interoperability target worth tracking — [IETF draft-sharif-agent-audit-trail](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/)

### Inferences
Checklist with the bar for each item:
1. **Frictionless install.** Bar: a single static Rust binary via `brew`, `cargo install`, a curl script and a container image. Five minutes from install to the first blocked tool call, with one-line wrapping of an existing MCP server config (e.g. Claude Desktop or Cursor).
2. **Docs and examples.** Bar: a policy library for common MCP servers (filesystem, GitHub, Slack, databases, payments), a playground, and compliance mapping guides (AI Act Art. 12/14, SOC 2, PCI 10, HIPAA, DORA).
3. **Governance and licensing.** Bar: keep the core under Apache-2.0 or MPL-2.0, and consider a CNCF Sandbox or LF submission for neutrality. Avoid BSL, given the OpenTofu and OpenBao precedent.
4. **Open-core split** (following the Teleport, Tailscale and Sysdig pattern). OSS: proxy, policy engine, local audit, CLI, replay. Commercial: a multi-tenant control plane, SSO/SCIM, approvals UI and mobile, long-term audit storage with external anchoring, compliance reports and evidence packs, SIEM connectors, and support with an SLA.
5. **Standards alignment as an adoption lever.** Bar: emit audit records in an exportable, documented schema (and track the IETF draft). Support OAuth/OIDC/SPIFFE identities, matching the NCCoE direction.

### Gaps
- No primary postmortems or case studies on why Cilium, Vault or Tailscale were adopted (single binary, docs and so on) were retrieved. Those claims above are inferences.
- Teleport's license history (Apache-2.0 to AGPL around v16) and Tailscale's revenue model were not verified in sources.
- No data on OSS-to-paid conversion rates for security tools.
