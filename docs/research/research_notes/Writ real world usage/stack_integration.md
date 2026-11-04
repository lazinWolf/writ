# Writ Stack Integration Map: How an Agent Tool-Call Policy Layer Plugs into Enterprise and Developer Stacks (as of 2026-11-04)

> Method note: WebFetch to modelcontextprotocol.io, aaif.io and workos.com failed because the session's network allowlist blocks them. Findings below come from search-engine result snippets and summaries, with URLs as returned. Primary spec pages were cited where search surfaced them, but their full text was not read directly. Claims from vendor blogs or aggregators are flagged as such. The report writer should treat the specific field and header names reported for the 2026-07-28 MCP spec as "reported by secondary sources" until someone checks them against modelcontextprotocol.io.

## 1. MCP transports, spec revisions, authorization, elicitation/sampling, client config, transparent proxying

### Takeaway
MCP has five dated revisions. The newest, 2026-07-28, is a stateless redesign: it drops the initialize handshake and Mcp-Session-Id, and adds required Mcp-Method/Mcp-Name routing headers and W3C trace context in `_meta`. Gateways can route and authorize from headers without reading the request body, which makes an HTTP policy proxy much cheaper to build. writ currently supports stdio only. Its priorities should be: (a) a Streamable HTTP front end that acts as an RFC 9728 protected resource and does not pass client tokens through; (b) per-request version and capability handling instead of sessions; (c) propagation of trace context and `_meta`.

### Cited Findings
**Spec versions and the 2026-07-28 revision**
- Released spec versions are 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25 and 2026-07-28. The RC was locked on May 21, 2026 and the final release was scheduled for July 28, 2026 — [MCP blog: 2026-07-28 RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/); [hidekazu-konishi timeline](https://hidekazu-konishi.com/entry/mcp_specification_version_timeline.html). Sources disagree on whether it is final: some still call it an RC, and newer ones call it released — [eSEOspace changelog](https://eseospace.com/blog/mcp-specification-changelog/); [Stacktree](https://stacktr.ee/blog/mcp-2026-spec-changes).
- In 2026-07-28 the initialization handshake is removed, and version and capability data travel with each request. A new `server/discover` call lets clients learn supported versions and capabilities. Protocol-level sessions and the `Mcp-Session-Id` header are gone from Streamable HTTP, so servers can sit behind ordinary load balancers — [MCP blog RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/); [Microsoft App Service blog](https://techcommunity.microsoft.com/blog/appsonazureblog/mcp-just-went-stateless-%E2%80%94-what-the-2026-spec-changes-about-scaling-on-app-servic/4530222); [AAIF migration post](https://aaif.io/blog/mcp-2026-07-28-whats-changing-and-how-to-migrate).
- Streamable HTTP now requires `Mcp-Method` and `Mcp-Name` headers so gateways can route without parsing the body. Servers reject requests whose headers and body disagree — [mcpservers.org blog](https://blog.mcpservers.org/posts/mcp-spec-2026-07-28); [Stacktree](https://stacktr.ee/blog/mcp-2026-spec-changes).
- List and resource responses gain cache-lifetime fields, and W3C Trace Context is carried in metadata (`_meta`) — [MCP blog RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/); [AAIF](https://aaif.io/blog/mcp-2026-07-28-whats-changing-and-how-to-migrate).
- Tool input and output schemas support full JSON Schema 2020-12. The extensions framework is formalized, MCP Apps (sandboxed iframe HTML UIs) is added, and Tasks moved from core into an official extension — [mcpservers.org blog](https://blog.mcpservers.org/posts/mcp-spec-2026-07-28).
- A formal deprecation policy was added, and three features were deprecated. One secondary source names them as Sampling, Roots and Logging — [MCP Sampling Is Deprecated (blog)](https://www.carlosaragon.online/blog/mcp-sampling-deprecated-elicitation). I have not confirmed this list against the spec.
- Another secondary source reports that 2026-07-28 moved URL-mode elicitation onto a multi-round-trip pattern and removed the earlier notification and `elicitationId` fields — [safeguard.sh](https://safeguard.sh/resources/blog/mcp-elicitation-explained-how-servers-ask-users-for-input-and-how-to-secure-it) (secondary; unverified).

**Authorization**
- In 2026-07-28, servers MUST publish OAuth Protected Resource Metadata (RFC 9728), and clients MUST use Resource Indicators (RFC 8707). Several smaller auth rules were also tightened — [MCP blog RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/); [WorkOS: 2026 spec auth](https://workos.com/blog/mcp-2026-spec-agent-authentication).
- 2025-11-25 brought async Tasks, "better OAuth" and an extensions mechanism — [WorkOS 2025-11-25 recap](https://workos.com/blog/mcp-2025-11-25-spec-update); [daily.dev](https://daily.dev/posts/one-year-of-mcp-november-2025-spec-release-cyldqjdwh).
- Enterprise-managed authorization: Okta's Cross App Access (XAA) is its product name for the IETF Identity Assertion JWT Authorization Grant (ID-JAG), and it underpins MCP's enterprise-managed authorization extension. The client gets an ID-JAG from the enterprise IdP, which applies admin policy, and the MCP server's authorization server exchanges it for an access token — [WorkOS XAA](https://workos.com/blog/id-jag-cross-app-access); [SSOJet](https://ssojet.com/blog/okta-cross-app-access-xaa-id-jag).
- Primary spec page for authorization (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization. I could not fetch it, so the exact MUST wording on token passthrough and confused deputy is not quoted here (see Gaps). Microsoft's Q&A guidance for Entra Agent ID likewise says "OAuth passthrough is not recommended" — [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5766622/example-for-on-behalf-of-flow-in-azure-ai-foundry).

**Elicitation and sampling (2025-11-25)**
- URL-mode elicitation (SEP-1036) sends users to external URLs "for out-of-band interactions that must not pass through the MCP client". It is explicitly not for authorizing the MCP client's access to the MCP server — [MCP spec: Elicitation 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation).
- Sampling with tools (SEP-1577) lets servers start sampling requests that include tool definitions, which enables server-side agent loops — [WorkOS 2025-11-25](https://workos.com/blog/mcp-2025-11-25-spec-update); [developersdigest](https://www.developersdigest.tech/blog/mcp-client-features-explained-2026).

**Client configuration and proxy insertion**
- Claude Desktop, Cursor and Windsurf use an `mcpServers` JSON block with `command`/`args` for stdio. `npx mcp-remote <url>` is a stdio shim that forwards to a remote HTTP+SSE server and supports OAuth — [mcp-remote](https://mcpservers.org/servers/geelen/mcp-remote).
- The Azure DevOps remote MCP example uses an `mcp.json` with a top-level `servers` key and `"type": "http"`, which is the VS Code-style layout — [Microsoft Learn: Azure DevOps remote MCP](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server?view=azure-devops).
- Claude Code accepts `streamable-http` as an alias for `http`. An entry with a `url` but no `type` is a configuration error, because an untyped entry is read as stdio — [Claude Code MCP docs](https://code.claude.com/docs/en/mcp).
- Transport bridges already exist: `mcp-proxy` converts between stdio and Streamable HTTP/SSE in both directions (e.g. `mcp-proxy --port=8080 -- uvx mcp-server-fetch`) — [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy). Aggregating proxies also exist — [ptbsare/mcp-proxy-server](https://github.com/ptbsare/mcp-proxy-server).
- OpenAI's platform docs on MCP servers/connectors: [OpenAI MCP guide](https://developers.openai.com/api/docs/guides/tools-connectors-mcp). Only the existence of the page was confirmed. It suggests ChatGPT/Responses API connectors consume remote (HTTP) MCP servers.

### Inferences
- For stdio clients, writ can be inserted transparently today by rewriting the `command` of each `mcpServers` entry to `writ wrap -- <orig>`. This is the same pattern `mcp-remote` uses. Remote-only clients (ChatGPT connectors, hosted agents) cannot launch local processes, so they need writ to expose Streamable HTTP with a URL the user registers in place of the upstream URL.
- An HTTP writ must act as its own OAuth protected resource: publish RFC 9728 metadata, validate tokens whose audience is writ, then get a separate upstream token (RFC 8693 exchange or ID-JAG) instead of forwarding the client token. Forwarding would violate the passthrough guidance and create a confused deputy.
- The 2026-07-28 statelessness suits writ: per-request policy decisions need no session affinity, and `Mcp-Method`/`Mcp-Name` let a fast pre-filter deny before body parsing. writ must still check that the body agrees with the headers, because the spec requires servers to reject mismatches.
- writ's Biscuit task token could ride in `_meta` (alongside traceparent) for agent-to-proxy propagation. This needs care: `_meta` comes from the client, so writ must verify the token signature rather than trust it.
- URL-mode elicitation is a standards-native channel through which writ could send a "go approve at <url>" prompt back to the user's client. That gives a protocol-level alternative to `writ sudo`, but it depends on client support and on the 2026 changes to the round-trip shape.

### Gaps
- Exact normative text on token passthrough ("MUST NOT accept tokens not issued for it") and confused-deputy mitigations (per-client consent for proxy servers using static client IDs) was not retrieved because modelcontextprotocol.io was blocked. This needs direct verification.
- Client ID Metadata Documents (CIMD) as the 2025-11-25 default registration method: I recall this from training, and it was not confirmed in this session.
- I did not verify current Cursor, VS Code or ChatGPT developer-mode config specifics, or which clients have implemented the 2026-07-28 revision.

## 2. MCP gateways and registries: can writ be a plugin, filter or sidecar?

### Takeaway
Most major gateways now expose a per-tool policy hook. Docker MCP Gateway interceptors, Envoy's MCP filter plus ext_authz, AgentCore Gateway Cedar policies/interceptors, and Kong plugins are each a plausible place for writ to sit as an external decision point. Envoy ext_authz and Docker interceptors are the most direct fits for writ's existing engine. The official MCP Registry is still in preview, and writ would mainly consume it, for allowlisting and server provenance.

### Cited Findings
- **Docker MCP Gateway**: interceptors are configurable filters between clients and MCP tools that let users "plug in generic interceptors to help secure any MCP server". They can run before a call (argument checks), after it (redaction), or both — [docker/mcp-gateway security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md); [Docker blog](https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/). The CLI accepts `--interceptor` in `when:type:path` format — [docker mcp gateway run reference](https://docs.docker.com/reference/cli/docker/mcp/gateway/run/). Interceptors can run as containers — [ajeetraina.com](https://www.ajeetraina.com/a-quick-look-at-docker-mcp-gateway-interceptors/). The security model treats configured interceptors as trusted, and registry and catalog entries as possibly untrusted — [security.md](https://github.com/docker/mcp-gateway/blob/main/docs/security.md).
- **Envoy**: Envoy has a native MCP HTTP filter that extracts MCP attributes for RBAC or ext_authz. By default it exports metadata under `envoy.filters.http.mcp`, which an external authorization service can evaluate — [Envoy MCP filter docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/mcp_filter). Envoy AI Gateway announced MCP support — [Envoy AI Gateway blog](https://aigateway.envoyproxy.io/blog/mcp-implementation/).
- **agentgateway** (Linux Foundation/Solo lineage) offers ext_authz over gRPC or HTTP and "MCP Auth" to "scope which tools each identity may invoke" — [agentgateway.dev](https://agentgateway.dev/). kgateway has an `ExtAuthPolicy` resource — [kgateway API reference](https://kgateway.dev/docs/envoy/latest/reference/api/).
- **AWS Bedrock AgentCore Gateway + Policy**: Cedar authorizes each tool call through the gateway. Attaching a policy is default-deny, each tool is its own action entity, and there are no wildcard actions (group tools by gateway target instead) — [AWS Security Blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [AgentCore policy scope](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-scope.html). A `LOG_ONLY` mode evaluates without blocking — [GatewayPolicyEngineConfiguration API](https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_GatewayPolicyEngineConfiguration.html). Tool listing uses Cedar partial evaluation to hide tools that would always be denied — [AWS Security Blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/). Policies can check tool arguments, e.g. expense amount — [Xebia](https://xebia.com/blog/cedar-policies-for-amazon-bedrock-agentcore-gateway/). Natural-language policy authoring is available — [AgentCore starter toolkit](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/policy/overview.html). One comparison dates Cedar policy GA to 3 March 2026 and mentions gateway interceptors — [vdf.ai comparison](https://vdf.ai/blog/mcp-gateway-comparison/) (secondary).
- **Azure API Management**: can expose REST APIs as MCP servers or front existing ones, and applies APIM policies to that traffic. One comparison says policies apply per server rather than per tool, and cover tools but not resources or prompts — [vdf.ai](https://vdf.ai/blog/mcp-gateway-comparison/); [TrueFoundry best gateways](https://www.truefoundry.com/blog/best-mcp-gateways) (secondary).
- **Kong AI Gateway**: MCP plugins (Enterprise) provide per-tool allow and deny lists and an audit log of attempts — [requesty comparison](https://www.requesty.ai/blog/mcp-gateway-comparison-2026-enterprise-scalability-security); [mcpmanager](https://mcpmanager.ai/blog/best-mcp-gateway-for-engineering/) (secondary). Cerbos lists Kong among its integrations — [Cerbos vs OpenFGA](https://www.cerbos.dev/blog/cerbos-vs-openfga).
- **Cloudflare MCP server portals**: admins choose which tools each portal exposes, disabled tools cannot be called, and access logging goes through Cloudflare Access — [getmaxim remote gateways](https://www.getmaxim.ai/articles/remote-mcp-server-gateways/) (secondary).
- **Official MCP Registry**: still in "preview; breaking changes or data resets may occur before GA" — [Registry ToS](https://modelcontextprotocol.io/registry/terms-of-service). The API was frozen at v0.1 on 2025-10-24 ahead of v1 — [modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry). The registry does not support private servers and is not designed for self-hosting — [Registry about](https://modelcontextprotocol.io/registry/about). A third-party source says it was still in preview in October 2026 — [dev.to](https://dev.to/zordhalo/where-to-list-your-mcp-server-from-someone-who-just-did-it-3kcj). Launch post: [MCP Registry preview](https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/).

### Inferences
- **Fastest gateway wins:**
  - Ship `writ` as an Envoy/agentgateway ext_authz gRPC server that reads `envoy.filters.http.mcp` metadata. This mirrors OPA-Envoy and reuses writ's policy plus audit.
  - Ship a Docker MCP Gateway interceptor (container or exec) that calls writd for the decision.
- **AgentCore** has its own Cedar engine. writ's role there is better as a policy compiler or emitter (YAML to Cedar) plus `writ replay` against AgentCore's LOG_ONLY decision logs, not as an inline filter.
- **Tool-list filtering** (AgentCore partial evaluation, OpenFGA list filtering) is now table stakes. writ should filter `tools/list` by policy and not only deny `tools/call`.
- **Registry integration**: writ policy could pin servers by registry name and version as a supply-chain control.

### Gaps
- IBM ContextForge (plugin framework, OPA/Cedar plugins), Google Vertex/Apigee MCP support, and Microsoft's Windows on-device MCP registry: I found no sources in this session's search budget.
- I did not confirm Kong's plugin names or Azure APIM's per-tool granularity from primary docs.

## 3. Identity: how agents get delegated user identity today

### Takeaway
Delegation converges on token exchange. Entra uses OBO (jwt-bearer with `requested_token_use=on_behalf_of`) for agent identities derived from "agent identity blueprints". Okta uses ID-JAG/XAA, which combines RFC 8693 at the IdP with RFC 7523 at the resource AS. Auth0 uses Token Vault exchange plus CIBA for asynchronous approval. AAuth and related IETF agent-auth drafts are still individual drafts. writ's Biscuit attenuation is complementary: it covers intra-task narrowing that IdPs don't express. To integrate, writ would bind task tokens to a verified upstream subject (OIDC/ID-JAG/OBO claims) and do exchange on the egress side.

### Cited Findings
- **Entra Agent ID**: OBO is supported for Foundry agents via the Agent ID platform. Agents are confidential clients, so classic `/authorize` and public-client OBO flows don't apply — [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5791173/is-delegated-authentication-via-oauth2-obo-(on-beh). An "agent identity blueprint" is the parent registration holding credentials and delegated permissions, and agent identities are its children. Copilot Studio and Foundry agents get Agent IDs automatically, and the token call uses the jwt-bearer grant with `requested_token_use=on_behalf_of`. Parts are still preview — [TrueFoundry Entra guide](https://www.truefoundry.com/docs/agent-platform/agent-governance/scenarios/microsoft-entra) (third-party). There are three flows: autonomous agent app, OBO, and the agent's own user account — [Compass Security, June 2026](https://blog.compass-security.com/2026/06/entra-agent-id-from-a-security-perspective/). Foundry performs OBO with the blueprint, and OAuth passthrough is not recommended — [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5766622/example-for-on-behalf-of-flow-in-azure-ai-foundry). Architecture blog: [Microsoft Tech Community OBO multi-agent](https://techcommunity.microsoft.com/t5/azure-architecture-blog/securing-multi-agent-ai-with-user-context-entra-id-obo-for/ba-p/4493308).
- **Okta / XAA / ID-JAG**: ID-JAG combines RFC 8693 token exchange at the IdP with an RFC 7523 JWT bearer grant at the resource AS. The draft is draft-ietf-oauth-identity-assertion-authz-grant-04 (May 2026, a WG document). Okta advises against issuing refresh tokens for an ID-JAG exchange — [SSOJet](https://ssojet.com/blog/okta-cross-app-access-xaa-id-jag); [WorkOS](https://workos.com/blog/id-jag-cross-app-access). It requires the "Okta for AI Agents" subscription — [LiteLLM ID-JAG docs](https://docs.litellm.ai/docs/mcp_id_jag.md). The resource AS must support the JWT bearer grant and trust the customer's Okta issuer — [MintMCP XAA](https://docs.mintmcp.com/docs/cross-app-access). Scalekit also implements XAA for MCP — [Scalekit](https://docs.scalekit.com/mcp/auth-methods/xaa/).
- **Auth0 for AI Agents** is GA — [Auth0 blog GA](https://auth0.com/blog/auth0-for-ai-agents-generally-available/); [docs](https://auth0.com/docs/get-started/auth0-for-ai-agents). Token Vault uses OAuth token exchange so the backend gets short-lived provider tokens while refresh tokens stay in the vault — [Auth0 Token Vault](https://auth0.com/blog/auth0-token-vault-secure-token-exchange-for-ai-agents/). Token Vault doesn't do approvals, so HITL combines it with asynchronous authorization (CIBA) — [Auth0 blog](https://auth0.com/blog/secure-ai-stop-managing-api-keys-by-hand/); [LogRocket](https://blog.logrocket.com/authorizing-ai-agents/). Auth0 FGA can gate MCP tools — [Auth0 FGA for MCP](https://auth0.com/ai/docs/mcp/get-started/secure-mcp-server-with-auth0-fga).
- **IETF agent drafts**: AAuth (Hardt), an individual draft, replaces bearer tokens with signed requests and cryptographic agent identity. Sources disagree on the revision (-10 on 6 Aug 2026 vs -11 on 2026-09-25). The earlier Rosenberg/White AAuth drafts have expired — [draft-rosenberg-oauth-aauth-01](https://datatracker.ietf.org/doc/html/draft-rosenberg-oauth-aauth-01); [draft-patwhite-aauth](https://datatracker.ietf.org/doc/draft-patwhite-aauth/); [standards status overview](https://hidekazu-konishi.com/entry/where_ai_agent_authorization_standards_stand.html). draft-klrc-aiagent-auth applies existing standards (OAuth, WIMSE/workload identity) to agents rather than inventing new protocols — [draft-klrc-aiagent-auth-00](https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-00.html). WIMSE has an interim agenda on agents — [WIMSE interim 2026](https://datatracker.ietf.org/doc/agenda-interim-2026-wimse-01-wimse-01/).
- **SPIFFE/SPIRE**: OPA, Envoy and SPIRE are already combined for ext_authz on SVID identity — [opa-envoy-spire-ext-authz](https://github.com/open-policy-agent/opa-envoy-spire-ext-authz). I found no 2026 SPIFFE-specific agent profile.

### Inferences
- writ should accept an inbound OIDC/JWT (or ID-JAG-derived access token) and map `sub`, `act` (RFC 8693 actor claim) and agent ID into Biscuit facts at `writ fork` time. The root token then carries both who the human is and which agent it is. On egress, writ (HTTP mode) should do RFC 8693/OBO itself instead of forwarding tokens.
- For workload identity in k8s, writd could authenticate callers by SPIFFE SVID (mTLS) instead of Unix-socket peer credentials.
- Biscuit offline attenuation overlaps conceptually with AAuth's signed-request and capability direction. writ could track AAuth as a possible future wire format, but nothing there is standardized yet.

### Gaps
- Primary Okta docs on "Okta for AI Agents" and Microsoft Learn Entra Agent ID pages were not read directly.
- I did not find whether Claude Desktop, Cursor or ChatGPT implement the MCP enterprise-managed authorization (ID-JAG) extension.

## 4. Policy engines: emit or consume OPA/Rego, Cedar, OpenFGA, Cerbos?

### Takeaway
Each engine already has an agent/MCP story. Cedar is native in AgentCore. OpenFGA publishes an MCP modeling guide (`tool#can_call`). Cerbos positions itself as an MCP PDP. OPA is the default ext_authz PDP for Envoy. writ's best position is as the PEP plus audit/replay layer that can delegate decisions (consume) to OPA/Cedar/Cerbos/OpenFGA and can compile its YAML into Cedar (emit) for AgentCore.

### Cited Findings
- OPA-Envoy implements the Envoy External Authorization gRPC API, is often deployed as a k8s sidecar, and typically answers `data.envoy.authz.allow` — [OPA Envoy docs](https://openpolicyagent.org/docs/latest/envoy-introduction); [OPA v0.22 Envoy](https://www.openpolicyagent.org/docs/v0.22.0/envoy-authorization/). Styra Enterprise OPA has the same pattern — [Styra](https://docs.styra.com/enterprise-opa/tutorials/integrating-envoy).
- Cedar in AgentCore: default deny, one action per tool, argument-level conditions, partial evaluation for tool listing — [AWS Security Blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [policy scope](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-scope.html).
- OpenFGA models each tool as a `tool` type with a `can_call` relation, checked per request with the calling user as subject. Listing is filtered so clients see only tools they can invoke — [OpenFGA MCP server authorization](https://openfga.dev/docs/use-cases/mcp-server-authorization); [OpenFGA agents/MCP modeling](https://openfga.dev/docs/modeling/agents/mcp-authorization.md). Auth0 FGA is the managed equivalent — [Auth0 FGA MCP](https://auth0.com/ai/docs/mcp/get-started/secure-mcp-server-with-auth0-fga).
- Cerbos acts as a PDP an MCP server queries per tool use, can enable or disable tools at connection time, and works at a gateway, in the server, or via agent hooks — [Cerbos MCP authorization](https://www.cerbos.dev/blog/mcp-authorization); [Cerbos MCP features](https://www.cerbos.dev/features-benefits-and-use-cases/dynamic-authorization-for-MCP-servers); [Cerbos vs OpenFGA](https://www.cerbos.dev/blog/cerbos-vs-openfga).

### Inferences
- writ's "mock file-based entitlement source" maps naturally onto OpenFGA `Check`/`ListObjects`. That would be the first real entitlement backend to replace the mock.
- Emitting Cedar lets writ users carry policies into AgentCore. Consuming OPA/Cerbos lets writ fit into orgs that have standardized on them. writ's differentiators (Biscuit attenuation, approvals, hash-chained audit, replay) sit outside any of these engines.
- `writ replay` can serve as a pre-deploy test harness for any delegated engine, since it re-runs historical calls through the candidate PDP.

### Gaps
- I found no official OPA MCP guide; only a non-authoritative blog compares OPA and Cerbos for MCP — [Zenn](https://zenn.dev/naokky/articles/202509-cerbos-opa-mcp-ultra-fine-grained-rbac-abac).

## 5. Observability and audit: OTel GenAI/MCP semconv, SIEM ingestion, tamper evidence

### Takeaway
OTel defines MCP spans (`{mcp.method.name} {target}`, with `gen_ai.operation.name=execute_tool` and `gen_ai.tool.name`), but they are still in Development status. With 2026-07-28 carrying W3C trace context in `_meta`, writ should emit spans that are children of the client's trace and export over OTLP. SIEMs (Splunk, Datadog, Elastic) take OTLP or structured JSON. writ's hash chain is ahead of most vendors, which claim "tamper-evident" without saying how it works.

### Cited Findings
- MCP span name is `{mcp.method.name} {target}` (e.g. `tools/call get_invoice`). `mcp.method.name` is required, `gen_ai.operation.name=execute_tool` is recommended, and `gen_ai.tool.name`, `mcp.session.id`, `mcp.protocol.version` and `jsonrpc.request.id` are also used. Use MCP conventions instead of generic RPC ones. Status was Development as of May 2026 — [Greptime on OTel GenAI semconv](https://greptime.com/blogs/2026-05-09-opentelemetry-genai-semantic-conventions); [mcpplaygroundonline](https://mcpplaygroundonline.com/blog/mcp-observability-opentelemetry); [docker-agent telemetry/mcp Go pkg](https://pkg.go.dev/github.com/docker/docker-agent/pkg/telemetry/mcp).
- The MCP Python SDK emits these `tools/call` spans — [MCP Python SDK OpenTelemetry](https://py.sdk.modelcontextprotocol.io/run/opentelemetry/index.md).
- Note: `mcp.session.id` is recommended in semconv, but 2026-07-28 removed protocol sessions — [MCP blog RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/). The semconv may lag the spec.
- ToolHive emits structured audit events with an `mcp_tool_call` type and `target.method`/`target.name` fields, and integrates with Fluentd, Filebeat and Splunk — [ToolHive k8s audit logging](https://docs.stacklok.com/toolhive/guides-k8s/logging); [ToolHive vMCP audit](https://docs.stacklok.com/toolhive/guides-vmcp/audit-logging).
- Datadog: logging is up to MCP server providers, so watch for abnormal tool usage and authN/authZ failures. Datadog publishes MCP SIEM detection rules — [Datadog MCP detection rules](https://www.datadoghq.com/blog/mcp-detection-rules/).
- TrueFoundry claims a "tamper-evident JSON log per tool call" exported via OTel to Grafana, Datadog, Splunk or any OTLP endpoint, with no mechanism described — [TrueFoundry governance](https://www.truefoundry.com/blog/enterprise-mcp-governance-control-audit-secure-mcp-server-access).
- Pre-dispatch rejections (rate limit, permission, unknown tool, bad args, confirmation) often leave no trace in some implementations. This is a gap to avoid — [Vendure MCP tool call log](https://docs.vendure.io/current/framework/reference/core-plugins/mcp-plugin/mcp-tool-call-log).
- Compliance mapping: NIST SP 800-53 AU-2 and CIS v8 Control 8, and audit must not be bypassable or suppressible — [nhimg glossary](https://nhimg.org/glossary/mcp-audit-logging/).

### Inferences
- writ should emit (1) OTel spans following the MCP semconv, with policy decision attributes (rule id, decision, approval id) as custom `writ.*` attributes, and (2) its JSONL audit log with periodic chain-head anchoring (e.g. to an external WORM store or signed checkpoint). The hash chain proves internal integrity but not that the tail wasn't truncated.
- Logging denials and pending approvals, not just executed calls, is a differentiator given the Vendure finding.

### Gaps
- I found no sources on OCSF mapping, Microsoft Sentinel ingestion, or Elastic-specific MCP integration within budget.

## 6. Approvals: Slack/Teams, PagerDuty, ServiceNow, HITL products

### Takeaway
The market standard is async approval with Slack buttons keyed to a specific tool-call ID, with timeout-as-deny (HumanLayer, Trigger.dev, call-a-human-mcp). IdP-native async approval (Auth0 CIBA) and framework-native pauses (OpenAI Agents SDK `needs_approval`/`require_approval`) are the other patterns. `writ sudo` should become a pluggable approval backend (CLI, Slack, CIBA, webhook) keyed by call ID, with idempotent decisions.

### Cited Findings
- HumanLayer: an SDK/API with a `@require_approval()` decorator that routes to Slack, email and others. The tool runs only on Approve, and deny or timeout fails gracefully. Slack approvals may still be beta — [everydev HumanLayer](https://www.everydev.ai/tools/humanlayer); [typevar HumanLayer](https://typevar.dev/articles/humanlayer/humanlayer); [bestaiagents](https://bestaiagents.ai/agent/humanlayer).
- Trigger.dev: Slack buttons carry the tool-call ID, so a click resolves exactly that call, and a second click on a call already decided is ignored — [Trigger.dev HITL](https://trigger.dev/human-in-the-loop-ai-agents).
- call-a-human-mcp: the MCP tool call blocks until a Slack or macOS-dialog response or timeout — [GitHub](https://github.com/nishantmodak/call-a-human-mcp).
- withHuman: reviewers decide in a web or mobile app, and Slack replies don't decide — [withHuman](https://withhuman.ai/comparisons/humanlayer-alternatives).
- Permit.io best-practices write-up on HITL approval flows — [Permit.io](https://www.permit.io/blog/human-in-the-loop-for-ai-agents-best-practices-frameworks-use-cases-and-demo).
- Auth0 CIBA: the agent waits for user approval on a separate device — [Auth0 for AI Agents docs](https://auth0.com/docs/get-started/auth0-for-ai-agents); [LogRocket](https://blog.logrocket.com/authorizing-ai-agents/). Email and Guardian push are supported — [dev.to Assistant0](https://dev.to/async_dime/assistant0-secure-ai-personal-assistant-l11).
- OpenAI Agents SDK: the runner checks `needs_approval`/`require_approval` per tool call. Hosted MCP has `on_approval_request` — [OpenAI Agents SDK HITL](https://openai.github.io/openai-agents-python/human_in_the_loop/); [OpenAI guardrails & approvals guide](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals).

### Inferences
- writ's approval request should be a durable record (call ID, args hash, policy rule, requester's Biscuit chain). That record is delivered to adapters and resolved once, with the decision appended to the hash-chained audit. A Slack adapter is the first must-have. Teams, PagerDuty (for on-call escalation) and ServiceNow (for change-ticket-backed approvals) are enterprise follow-ons.
- The approval could be minted as a short-lived attenuated Biscuit (approval-as-capability), which fits writ's model better than a boolean flag.

### Gaps
- I found no sources on PagerDuty or ServiceNow change-approval integration for agent tool calls, or on Microsoft Teams adaptive-card approvals for agents.
- LangGraph `interrupt()`/HumanInTheLoopMiddleware specifics were not retrieved.

## 7. Deployment: Kubernetes sidecar/operator, Helm, Envoy ext_authz, CI/GitHub Actions

### Takeaway
The established k8s pattern is a PDP sidecar behind Envoy ext_authz (OPA-Envoy), now made MCP-aware by Envoy's MCP filter. ToolHive shows an MCP-specific k8s operator with audit logging. writ should ship (1) an ext_authz gRPC mode, (2) a Helm chart and sidecar image, and (3) a GitHub Action that runs `writ replay` as a policy gate.

### Cited Findings
- OPA-Envoy is commonly a k8s sidecar implementing the ext_authz gRPC API — [OPA Envoy intro](https://openpolicyagent.org/docs/latest/envoy-introduction). Generic ext_authz setup: [OneUptime ext_authz guide](https://oneuptime.com/blog/post/2026-02-09-envoy-ext-authz-filter/view).
- Envoy's MCP filter plus ext_authz enables per-MCP-attribute decisions — [Envoy MCP filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/mcp_filter).
- Gateway API has HTTP auth work in GEP-1494 — [GEP-1494](https://gateway-api.sigs.k8s.io/geps/gep-1494/). kgateway has `ExtAuthPolicy` — [kgateway API](https://kgateway.dev/docs/envoy/latest/reference/api/).
- ToolHive runs MCP servers on k8s with structured audit logging — [ToolHive k8s logging](https://docs.stacklok.com/toolhive/guides-k8s/logging).
- The 2026-07-28 stateless transport lets MCP servers scale behind ordinary load balancers — [Microsoft App Service blog](https://techcommunity.microsoft.com/blog/appsonazureblog/mcp-just-went-stateless-%E2%80%94-what-the-2026-spec-changes-about-scaling-on-app-servic/4530222).

### Inferences
- A writ sidecar per agent pod could serve the Unix socket (as today) to the agent container through a shared volume, with no network exposure. That is a low-effort first k8s story. The ext_authz mode covers shared gateways.
- In CI, coding agents (e.g. Claude Code in GitHub Actions) read MCP config from the repo, so `writ wrap` can be injected via config. A `writ replay` Action fails PRs that change policy in ways that flip historical decisions.

### Gaps
- I did not retrieve Claude Code GitHub Actions or Copilot coding agent MCP configuration and permission docs.
- I found no existing Helm or operator for MCP policy sidecars other than ToolHive and agentgateway.

## 8. Framework hooks: LangGraph, OpenAI Agents SDK, Claude Agent SDK, Google ADK, CrewAI; calling `writ fork` on sub-agent spawn

### Takeaway
Every major framework has a pre-tool interception point. Claude Agent SDK PreToolUse returns allow/deny/ask/defer plus updatedInput. OpenAI Agents SDK has `needs_approval`, `require_approval` on MCP servers, and tool guardrails. Google ADK has `before_tool_callback`, LangGraph has `interrupt`, and CrewAI has tool hooks; I could not verify those last three this session. A writ adapter would call writd for decisions from these hooks and call `writ fork` from the sub-agent or handoff creation path, passing the attenuated token into the child's environment or MCP `_meta`.

### Cited Findings
- Claude Agent SDK PreToolUse output can set `permissionDecision` to allow, deny, ask or defer, with a reason and `updatedInput` — [Claude Agent SDK hooks](https://code.claude.com/docs/en/agent-sdk/hooks); [platform docs hooks](https://platform.claude.com/docs/en/agent-sdk/hooks); [Hooks reference](https://code.claude.com/docs/en/hooks).
- Evaluation order: PreToolUse hook, then deny rules, allow rules, ask rules, permission mode, `canUseTool`, PostToolUse. A hook returning allow does not skip deny and ask rules — [Agent SDK permissions](https://code.claude.com/docs/fr/agent-sdk/permissions.md); [docs.claude.com permissions](https://docs.claude.com/fr/api/agent-sdk/permissions).
- `continueOnBlock: true` returns the block reason to Claude as a tool error so it can adapt — [Hooks reference](https://code.claude.com/docs/en/hooks). An older issue says `updatedInput` required `permissionDecision: "allow"` — [claude-agent-sdk-python #381](https://github.com/anthropics/claude-agent-sdk-python/issues/381).
- OpenAI Agents SDK: `require_approval` on `MCPServerStdio`, `MCPServerSse` and `MCPServerStreamableHttp`. A local MCP approval callable does not receive call arguments or call ID, unlike `FunctionTool.needs_approval` — [OpenAI Agents SDK MCP](https://openai.github.io/openai-agents-python/mcp/); [HITL](https://openai.github.io/openai-agents-python/human_in_the_loop/). MCP servers reportedly accept tool guardrails from openai-agents 0.22.3 — [temporalio/ai-integrations PR #401](https://github.com/temporalio/ai-integrations/pull/401) (secondary). JS SDK tools guide: [openai-agents-js tools](https://openai.github.io/openai-agents-js/guides/tools/).

### Inferences
- **Claude Agent SDK adapter**: a PreToolUse hook (matching `mcp__*` and built-in tools) calls writd over the Unix socket and maps writ allow/deny/approve to allow/deny/ask/defer. "defer" or "ask" can route to `writ sudo`. Sub-agent spawn arrives as a tool call (the Task/Agent tool), so the same PreToolUse hook can call `writ fork` with the sub-agent's declared scope and inject the child token. Because hook allow does not override deny rules, writ can only narrow permissions, never widen them.
- **OpenAI Agents SDK**: the MCP `require_approval` callable lacks args, so writ cannot make argument-level decisions through it. Prefer wrapping the MCP server with `writ wrap` (transport level) or using tool guardrails. Handoffs are the natural `writ fork` point.
- **LangGraph**: a writ "ask" decision maps naturally onto `interrupt()` and resume, and subgraph invocation is the fork point. This is not verified this session.

### Gaps
- I could not retrieve primary docs for LangGraph `interrupt`/HumanInTheLoopMiddleware, Google ADK `before_tool_callback`, or CrewAI tool hooks within budget.
- I did not confirm whether the Claude Agent SDK exposes a dedicated SubagentStart hook usable for `writ fork`. The inference above relies on intercepting the subagent tool call instead.
