# AgentTrap

**Comprehensive Rogue AI Agent Honeypot & Deception Fabric**
Implementation Specification v0.5 | September 2026

Primary stack: Go + Vue 3 + strict TypeScript + Bun-only package management

> **Design goal:** a protocol-agnostic synthetic enterprise that safely reveals unauthorized autonomous behavior across tools, identities, agents, data, cloud, browsers, and infrastructure.

---

## 1. Product Definition

AgentTrap is a defensive deception and observation platform for autonomous software and AI agents. It presents a coherent synthetic enterprise containing believable applications, identities, data, tools, infrastructure, documents, memory, agents, credentials, and administrative workflows. Every sensitive-looking asset is synthetic, every interaction is observable, and no route to production is required.

The product is deliberately broader than an MCP honeypot. MCP, A2A, HTTP, browser automation, cloud APIs, databases, SSH, Git, email, messaging, RAG, memory, OAuth/OIDC, Kubernetes and other protocols are adapters that expose views into one shared synthetic world.

### Primary security questions

- Who is acting: human, scanner, automation framework, delegated agent, compromised agent, or unknown autonomous actor?
- What authority did the actor possess, request, inherit, or attempt to expand?
- What sequence of actions was performed across protocols and systems?
- Did the actor interact with assets that exist only as security canaries?
- Did information, credentials, memory, or authority propagate to another agent or destination?
- Did behavior remain consistent with the originating task, principal, scope and delegation chain?

## 2. Architectural Principles

| Principle | Requirement |
|---|---|
| One synthetic reality | All adapters query and mutate the same world graph. Git, AWS, Slack, Kubernetes and MCP must agree about the same entities. |
| Behavior over isolated requests | Detection is based on temporal action sequences, delegation and data lineage, not a single HTTP request. |
| Canary-first evidence | High-confidence signals come from interaction with nonexistent authority, identities, secrets, agents, memories or resources. |
| Containment by construction | Synthetic credentials must have no production authority. Outbound traffic is brokered, sinkholed or simulated. |
| Protocol fidelity | Adapters should behave sufficiently like real systems to survive automated and agent-driven reconnaissance. |
| Statefulness | Mutations persist in the synthetic world so later reads are consistent. |
| Replayability | World seed, snapshots, scenario versions and event streams allow incident reconstruction. |
| Simple deployment first | Single-node and single-binary operation precedes distributed control-plane sophistication. |

## 3. High-Level Architecture

```
External / Internal Agent
          |
  +-------v----------------------+
  | Protocol / Interaction Edge  |
  | MCP A2A HTTP Browser SSH DB  |
  +---------------+--------------+
                  |
          +-------v--------+
          | Adapter Layer  |
          +-------+--------+
                  | semantic operations
          +-------v--------+
          | Synthetic World|
          | Graph + State  |
          +---+---------+--+
              |         |
       +------v--+   +--v---------+
       |Deception|   |Identity /  |
       | Engine  |   |Delegation  |
       +----+----+   +------+-----+
            |               |
            +-------+-------+
                    | events
          +---------v----------+
          | Behavior / Risk    |
          | Correlation Engine |
          +---------+----------+
                    |
      +-------------v-------------+
      | Postgres / ClickHouse /   |
      | OTel / object archive     |
      +-------------+-------------+
                    |
          +---------v----------+
          | Vue Admin Console  |
          +--------------------+
```

## 4. Synthetic Enterprise World Model

The world engine is the most important subsystem and should be implemented before protocol adapters. Protocol code never invents its own unrelated fake records; it requests entities, relationships and mutations from the world engine.

| Category | Core entities |
|---|---|
| Identity | Organization, BusinessUnit, User, Group, Role, ServiceAccount, OAuthClient, WorkloadIdentity |
| Agents | Agent, AgentInstance, AgentCard, Skill, Tool, Delegation, Task, Principal |
| Applications | Application, Service, API, Endpoint, Job, Deployment, Pipeline |
| Infrastructure | Host, VM, Container, Cluster, Namespace, CloudAccount, Network, DNSRecord |
| Data | Database, Schema, Table, Bucket, Object, File, Document, VectorCollection |
| Collaboration | Email, ChatMessage, Channel, Ticket, WikiPage, Repository, PullRequest |
| Security | Credential, Secret, Scope, Policy, Certificate, Canary, AuditEvent |
| AI context | Memory, Conversation, PromptResource, RAGDocument, ModelEndpoint |

```
USER --OWNS--> AGENT --DELEGATES_TO--> AGENT
AGENT --ACTS_FOR--> PRINCIPAL
ROLE --CAN_ACCESS--> DATABASE
REPOSITORY --DEPLOYS--> SERVICE --RUNS_IN--> CLUSTER
SERVICE --USES--> SECRET
DOCUMENT --REFERENCES--> SERVICE
MEMORY --MENTIONS--> CREDENTIAL
```

### World requirements

- Deterministic generation from a seed.
- Synthetic historical depth: old tickets, commits, rotations, employee turnover, deployments and deprecated systems.
- Temporal state and versioned snapshots.
- Cross-system referential consistency.
- Safe synthetic data generation only; never seed from production secrets or customer records.
- Branching scenario paths rather than scripted linear sequences.

## 5. Deception Model

AgentTrap should expose multiple kinds of canaries. The strongest canaries represent authority or information that no legitimate workflow should need.

| Primitive | Examples |
|---|---|
| HoneyCredential | AWS-key-shaped value, OAuth token, database password, kube token, SSH key |
| HoneyIdentity | deprecated admin account, backup service identity, cross-tenant principal |
| HoneyTool | `emergency_assume_role`, `restore_secret`, `export_archive` |
| HoneyScope | `organization.superadmin`, `finance.breakglass`, `offline_admin` |
| HoneyAgent | legacy finance agent, retired deployment agent, archived support agent |
| HoneyMemory | old operational memory pointing toward a decoy asset |
| HoneyDocument | runbook, incident report, architecture diagram, deployment note |
| HoneyEndpoint | internal admin API, legacy vault endpoint, upload sink |
| HoneyRelationship | service-account -> backup-admin, repository -> hidden pipeline |
| HoneyResource | bucket, database, namespace, queue, vector collection |

### Behavioral Canary Chains

```
Chat message
   -> internal runbook
      -> repository
         -> Terraform state
            -> decoy IAM role
               -> decoy bucket
                  -> canary credential
                     -> controlled egress sink
```

A scanner may touch one node. A reasoning system may follow the semantic references across several interfaces. The chain, not a single access, becomes the high-value detection signal.

## 6. Protocol and Service Coverage

| Priority | Adapter family | Initial scope |
|---|---|---|
| P0 | HTTP / REST / OpenAPI | Routing, auth, JSON APIs, admin and internal endpoints, realistic errors and pagination |
| P0 | MCP | Tools, resources, prompts, tasks, authorization, multiple protocol personas |
| P0 | A2A | Agent Cards, task/message interaction, skills, auth metadata, delegation traps |
| P0 | OAuth / OIDC | Authorization code + PKCE, client credentials, device flow, token exchange, introspection, scopes |
| P0 | Browser | Synthetic intranet/admin apps with stateful navigation, forms, downloads, uploads and session telemetry |
| P1 | SSH / filesystem | Interactive shell facade, realistic files, env, logs, common CLI commands |
| P1 | Git | Repos, history, issues/PR metadata, historical secret canaries |
| P1 | PostgreSQL / MySQL | Wire-compatible subset, schemas, roles, realistic synthetic records |
| P1 | AWS subset | STS, IAM, S3, Secrets Manager, SSM, EC2, EKS/ECS, CloudTrail/CloudWatch surface |
| P1 | Kubernetes | Namespaces, pods, deployments, services, secrets, service accounts, RBAC, logs |
| P2 | Messaging / email / tickets | Slack-like, SMTP/IMAP/API, Jira/ServiceNow-like workflows |
| P2 | RAG / vector / memory | Search, retrieval, vector queries, memory CRUD, cross-agent propagation |
| P2 | Directory | LDAP/SCIM-like user/group/service-account enumeration |
| P3 | Azure / GCP | Cloud identity, compute, storage, secret and logging subsets |

## 7. Adapter Framework

Go adapters translate protocol-specific requests into semantic world operations and then encode protocol-specific responses. Business logic belongs in the world/deception layers, not inside adapters.

```go
type Adapter interface {
    Name() string
    Protocols() []Protocol
    Start(context.Context) error
    Handle(context.Context, Interaction) (Result, error)
    Capabilities() []Capability
}

type World interface {
    Get(context.Context, EntityID) (*Entity, error)
    Query(context.Context, Query) ([]Entity, error)
    Relations(context.Context, EntityID, RelationType) ([]Relation, error)
    Mutate(context.Context, Mutation) error
}
```

Built-in adapters should compile into the primary binary. Avoid native Go `.so` plugins. Third-party adapters can later use gRPC subprocesses; lightweight policy/transform extensions can use WASM.

## 8. Identity, Authorization and Delegation

- Model human principal, agent identity, workload identity, service account and delegated identity separately.
- Preserve the complete delegation chain and scope at each hop.
- Record requested, granted, denied, exchanged and replayed scopes/tokens.
- Create decoy roles/scopes/identities that are semantically plausible but unnecessary to legitimate tasks.
- Support synthetic OAuth Resource Indicators and token exchange flows.
- Use SPIFFE/SPIRE optionally for AgentTrap internal service identity, not as a requirement for MVP.

```
Human Principal
    -> Agent A [orders.read]
        -> Agent B [delegated: orders.read]
            -> Tool
                -> Resource

Alert conditions:
  delegation scope expands
  principal disappears
  cross-tenant resource requested
  canary scope requested
  decoy identity assumed
```

## 9. Browser and Computer-Use Surface

Browser interaction is first-class because many agents never speak MCP/A2A directly. AgentTrap should host internally consistent synthetic web applications such as wiki, cloud console, Git, ticketing, monitoring, finance and identity administration.

- Capture navigation graph, DOM target selection, forms, downloads/uploads, JS execution, viewport/screenshot cadence and session timing.
- Use generated synthetic application state from the world graph.
- Preserve realistic authentication, role visibility, pagination, errors and state mutation.
- Never expose real external administrative systems from browser personas.

## 10. Cloud and Infrastructure Emulation

### AWS initial subset

- STS get-caller-identity and assume-role-like synthetic flows
- IAM users/roles/policies metadata
- S3 listing/object operations
- Secrets Manager and SSM metadata/value traps
- EC2 metadata and inventory
- EKS/ECS discovery
- CloudTrail/CloudWatch-like logs that reference the same world identities

### Infrastructure adapters

- Kubernetes API subset with RBAC-consistent visibility
- Docker/OCI metadata facade
- DNS authoritative zones for the synthetic enterprise
- SSH shell facade and synthetic filesystem
- PostgreSQL/MySQL with generated schemas and records

## 11. Agent Memory, RAG and Model Endpoints

- Expose `memory.search/list/read/write/delete/share` with user and agent ownership semantics.
- Plant canary memories and observe cross-session or cross-agent propagation.
- Expose synthetic RAG search/retrieval with document lineage.
- Optionally provide OpenAI-compatible model/embedding endpoints for model discovery and credential-reuse telemetry.
- Taint synthetic information internally so downstream movement can be correlated even when literal values are transformed.

## 12. Detection and Risk Model

Start with deterministic rules and explicit canary evidence. Behavioral scoring comes second. LLM analysis may summarize incidents or propose hypotheses, but should not be the primary blocking mechanism.

| Dimension | Examples |
|---|---|
| Deception interaction | ghost tool, decoy identity, canary credential, honey memory, synthetic admin endpoint |
| Authorization | scope escalation, repeated denied scope, audience switching, unauthorized role assumption |
| Discovery | sensitive enumeration, relationship traversal, credential-oriented search |
| Lateral movement | cross-service traversal, identity reuse, protocol switching |
| Delegation | unexpected depth, authority expansion, decoy agent invocation |
| Exfiltration | canary in upload/email/chat/webhook, archive creation, unusual aggregation |
| Persistence | new identity, scheduled job, token retention, config mutation |
| Task deviation | actions inconsistent with declared task or originating principal |

```
risk = weighted(
  deception, authorization, discovery,
  lateralMovement, delegation,
  exfiltration, persistence, taskDeviation
)
```

Store severity and confidence separately.

## 13. Agent and Automation Fingerprinting

- **Transport:** IP/ASN, TLS fingerprint, HTTP settings, connection reuse, timing.
- **Protocol:** MCP/A2A version, headers, serialization behavior, capability declarations, error handling.
- **Behavior:** tool order, retries, concurrency, pagination, denial response, stateful follow-up.
- **Semantic:** which descriptions attract the actor, how references are followed, discovery depth and task persistence.
- **Cross-protocol session correlation** using identity, credentials, source network, canary IDs, temporal proximity and behavioral fingerprints.

Framework labels (e.g., agent SDKs or browser automation stacks) must be probabilistic and never inferred from one header or one request.

## 14. Anti-Fingerprinting and Realism

- Stateful mutations must persist across protocols.
- Timestamps, pagination, identifiers, error codes, historical records and latency distributions must remain internally consistent.
- Generate normal assets as well as traps; not every interesting resource should be a canary.
- Use multiple personas and protocol versions to avoid a single static fingerprint.
- Run an internal test suite that looks for signs the environment is synthetic.
- Measure a persona realism score across protocol, semantic, temporal, network, state and identity consistency.

## 15. Containment and Safety

| Control | Requirement |
|---|---|
| Network isolation | No production peering or routes. Separate honeypot network from control plane. |
| Credentials | All credentials synthetic and invalid outside AgentTrap. |
| Egress | Central broker defaults to deny; allowed actions are sinkholed or simulated. |
| Execution | High-interaction shell/browser/code workloads run in gVisor or Firecracker-class isolation. |
| Filesystem | Rootless, read-only base image where feasible, ephemeral writable state. |
| Resource controls | CPU/memory/time quotas and per-session limits. |
| Control plane | Never reachable through the attacker-facing network. |
| Internal services | PostgreSQL, ClickHouse, NATS, the hub ingest API and the admin console listen only on private or loopback interfaces. Only spoke facade/adapter ports are public. |
| Kill switch | Quarantine, drain and destroy operations per sensor/world. |

## 16. Event, Storage and Observability Architecture

```
Spoke adapter
   -> normalized Interaction event
      -> spoke disk queue
         -> hub ingest (HTTPS + mTLS; NATS JetStream leaf nodes later)
            -> Correlator / Risk Engine
            -> PostgreSQL (world/config/incidents)
            -> ClickHouse (high-volume telemetry)
            -> Object storage (optional payloads/PCAP/artifacts)
            -> OpenTelemetry export
```

- PostgreSQL is authoritative for world state, entities, relationships, policies, scenarios and incidents.
- ClickHouse stores high-volume event analytics only when scale requires it; MVP may start with PostgreSQL alone.
- v1 ships events from spoke to hub as batched HTTPS over mTLS, with a durable disk queue on the spoke. Inside the hub, in-process channels plus PostgreSQL are sufficient.
- NATS JetStream is the preferred event bus once multiple regional spokes exist, because leaf nodes provide store-and-forward from edge to hub and it is lightweight, Go-native and operationally simpler than Kafka. See §30.
- OpenTelemetry spans correlate principals, agents, sessions, tools, resources and cross-protocol activity.
- Raw payload retention is optional, encrypted and short-lived; structured features should be the default.

## 17. Admin Console

The admin console is a Vue SPA backed entirely by Go APIs. It is not part of the deception surface and should be isolated from attacker-facing networks.

| Area | Choice |
|---|---|
| Framework | Vue 3, latest stable release line |
| Language | TypeScript, strict mode plus `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` |
| Package manager/runtime tooling | Bun only; `bun.lock` committed; npm/pnpm/yarn lockfiles rejected |
| Build | Vite |
| Routing | Vue Router |
| State | Pinia for UI state; TanStack Query for server state |
| Graph visualization | Cytoscape.js |
| Charts | Apache ECharts |
| API contract | OpenAPI generated from Go backend; generated TypeScript client/types |
| Realtime | SSE or WebSocket for live sessions/incidents |

### Strict TypeScript baseline

```json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "useUnknownInCatchVariables": true,
    "noImplicitOverride": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "moduleResolution": "Bundler"
  }
}
```

## 18. Admin UX Requirements

- **Live Sessions:** active identities, protocols, current action, risk trajectory and canary interactions.
- **Behavior Graph:** principal -> agent -> delegation -> tool -> resource -> destination.
- **Incident Timeline:** ordered, correlated actions across protocols.
- **Canary Lineage:** where a canary originated, who accessed it, how it transformed and where it moved.
- **World Explorer:** browse synthetic users, services, cloud resources, documents, agents and relationships.
- **Personas/Scenarios:** declarative configuration, validation and preview.
- **Sensors:** health, exposed protocols, persona, load, quarantine/drain controls.
- **Replay:** rebuild a world snapshot and replay an incident event sequence.

## 19. Go Repository Structure

```
agenttrap/
  cmd/
    agenttrap/        # single binary: `hub` and `spoke` roles
    worldgen/
    replay/
  internal/
    world/
    graph/
    events/
    identity/
    deception/
    canary/
    behavior/
    fingerprint/
    policy/
    telemetry/
    hub/              # ingest API, spoke registry, world-pack distribution
    spoke/            # disk queue, hub client, world-pack loader
    pki/              # private CA, enrollment, cert renewal
  adapters/
    http/ mcp/ a2a/ oauth/ browser/ ssh/ git/
    aws/ kubernetes/ postgres/ mysql/ redis/
    smtp/ imap/ ldap/ s3/ rag/ memory/ llm/
  personas/
  scenarios/
  api/
  web/
  deploy/
```

## 20. Scenario Definition

```yaml
id: lateral-cloud-access
entry:
  source: chat
paths:
  - artifact: deployment_runbook
  - artifact: repository
  - artifact: terraform_state
  - artifact: iam_role
  - artifact: legacy_bucket
signals:
  terraform_state_read: 10
  iam_role_assumed: 25
  canary_bucket_read: 40
```

Scenario definitions should describe optional paths and scoring hints, not force an actor down a scripted sequence. The actor must retain freedom to navigate the synthetic world.

## 21. Control-Plane API

```
/api/v1/worlds
/api/v1/personas
/api/v1/scenarios
/api/v1/sensors
/api/v1/entities
/api/v1/agents
/api/v1/sessions
/api/v1/interactions
/api/v1/canaries
/api/v1/incidents
/api/v1/replays
/api/v1/policies
/api/v1/intelligence
/api/openapi.json
```

Every state-changing administrative action must pass authorization, validation and an immutable audit event before mutating the world or sensor configuration.

## 22. Deployment Modes

| Mode | Description |
|---|---|
| Local single-node (v1) | Hub and one spoke as separate containers on one host, same binary in two roles; spoke reaches hub over mTLS on an internal network; PostgreSQL private to the hub. See §30. |
| Internet honeynet | Regional spokes expose selected protocols; central hub remains isolated. See §30. |
| Enterprise internal deception | Decoy tools, identities, agents, resources and memories coexist with real agent environments but never depend on production credentials. |
| Distributed research | Multiple sensors/regions share persona definitions and central analytics while maintaining isolated runtime state. |

```bash
agenttrap pki init --dir ./pki
agenttrap hub   --db "$DSN" --pki-dir ./pki --bootstrap-spoke local-1 --bootstrap-out ./local-1.json
agenttrap spoke --bundle ./local-1.json --listen :8080
agenttrap admin get /admin/incidents        # run inside the hub container
```

## 23. Minimal CI/CD

CI/CD should remain intentionally small until deployment complexity justifies more. No GitOps platform, release orchestration system, service mesh or multi-environment pipeline is required for the initial product.

| Area | Minimum |
|---|---|
| Go | gofmt check, go vet, `go test ./...`, `go build ./cmd/...` |
| Vue/TS | `bun install --frozen-lockfile`, typecheck, lint, test, build |
| Dependency policy | Bun only in `web/`. Reject `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml`. |
| Container | Build one sensor/control-plane image and optionally one web image. |
| Security | Basic dependency/vulnerability scan and secret scan; keep tooling replaceable. |
| Release | Tag -> build binaries/images -> publish. Add signing/SBOM later when distribution requires it. |

```
Backend gate:
  gofmt -> go vet -> go test -> go build

Frontend gate:
  bun install --frozen-lockfile
  bun run typecheck
  bun run lint
  bun run test
  bun run build
```

## 24. Implementation Phases

| Phase | Deliverable |
|---|---|
| 0 - Core | Entity/relationship model, world store, deterministic generator, event schema, canary engine, scenario engine, risk primitives. |
| 1 - Agent edge | HTTP, MCP, A2A, OAuth/OIDC, browser facade; Vue admin with live sessions and graph. |
| 2 - Developer surface | SSH/filesystem, Git, PostgreSQL, Redis, synthetic source/history. |
| 3 - Cloud | AWS subset, S3, Secrets Manager-like surface, Kubernetes, metadata service, controlled egress. |
| 4 - Enterprise | Email, chat, tickets, documents, directory/SCIM-like APIs. |
| 5 - AI-native | Memory, RAG, vector stores, model endpoints, delegation and information lineage. |
| 6 - Research | Adaptive deception, framework fingerprinting, behavioral clustering, campaign correlation, facade test suite. |

Status (2026-09-27): phase 1 complete for the DemoGPU persona (HTTP, MCP, A2A 0.3, OAuth 2.1/OIDC
with dynamic registration, PKCE, client credentials, device flow, token exchange and introspection, browser facade,
Vue admin); phase 2 complete (SSH/filesystem, Redis, PostgreSQL decoys with synthetic content);
phase 3 complete: an AWS subset (STS, IAM, S3, Secrets Manager, SSM, EC2, EKS/ECS discovery, CloudTrail,
CloudWatch Logs) at `aws.` reached via a planted SDK endpoint, the EC2 instance metadata service
(IMDS v1/v2) on the SSH node, a Kubernetes API subset at `k8s.` (discovery, namespaces, pods,
deployments, secrets, configmaps, service accounts, GPU nodes, SelfSubjectAccessReview) reached via a
planted kubeconfig, and a controlled egress broker (default deny, collectors simulated, canaries in
outbound payloads flagged as exfiltration) — the cloud and infrastructure credentials all correlate with
the SSH, Postgres and vLLM surfaces; phase 5 complete for the AI-native surfaces: agent memory over MCP
(memory_search/list/read/write/share/delete) with per-principal ownership and
canary memories, and a retrieval knowledge base + vector store
(kb_collections/kb_search/kb_get/kb_similar) with canary documents and a taint
id per document for information lineage; both reuse the shared credential slots
and feed detection of credential-hunting searches, cross-principal reads, reads
of secret-bearing content, memory poisoning and propagation (model and
embedding endpoints were already in place from phase 1); phase 6 started: adaptive deception (authorization- and depth-gated surface, lure variants),
probabilistic framework fingerprinting, behavioral clustering, campaign correlation and the facade
test suite with the §29.10 consistency score.

## 25. Recommended First Production Milestone

- Go world engine and adapter framework.
- PostgreSQL as initial authoritative store.
- HTTP + MCP + A2A + OAuth/OIDC + browser adapters.
- SSH/filesystem + Git + PostgreSQL adapter.
- AWS subset sufficient for identity/S3/secrets discovery.
- Behavioral canary chains and cross-protocol session correlation.
- Deterministic risk rules and confidence scoring.
- OpenTelemetry export.
- Vue 3 strict-TypeScript admin console with Bun-only tooling.
- Single-node Docker Compose deployment: hub, one spoke, Pingap edge and PostgreSQL, with spoke→hub mTLS (§30).

ClickHouse, NATS, SPIFFE/SPIRE, Firecracker pools, advanced ML clustering, multi-region spokes and sophisticated release automation should be deferred until telemetry volume or operational needs justify them.

## 26. Non-Goals

- Autonomous counter-attacking or hacking back.
- Routing arbitrary attacker traffic to third parties.
- Using real production credentials as bait.
- Replacing IAM, EDR, SIEM or endpoint security controls.
- Inferring malicious intent from private model reasoning.
- Building perfect full clones of every SaaS/cloud product; implement the smallest high-fidelity surface needed for believable agent interaction.

## 27. Success Metrics

| Metric | Meaning |
|---|---|
| Canary interaction rate | How often suspicious actors discover and use decoy artifacts. |
| Deception depth | Number of semantically connected synthetic steps traversed. |
| Cross-protocol correlation accuracy | Ability to reconstruct one actor/session across HTTP, OAuth, MCP, DB, cloud, etc. |
| False positive rate | Legitimate test/workflows incorrectly classified. |
| Scanner suppression rate | Commodity scanning removed from analyst attention. |
| Attribution confidence | Confidence linking actions to the same agent/principal/framework. |
| Honeypot suspicion rate | How often the test suite or an observed agent identifies the environment as synthetic. |
| Replay fidelity | Ability to reproduce a session from world snapshot and event history. |

## 28. Locked Technical Decisions

| Concern | Decision |
|---|---|
| Primary language | Go |
| Admin framework | Vue 3 |
| Frontend typing | Strict TypeScript; generated OpenAPI client/types |
| Frontend package manager | Bun only |
| Frontend build | Vite |
| World/config store | PostgreSQL |
| High-volume analytics | ClickHouse when needed |
| Eventing | v1: HTTPS + mTLS batch ingest with spoke disk queue; NATS JetStream leaf nodes when multiple spokes exist |
| Topology | Hub and spoke; spokes dial out to hub only; v1 runs both on one node |
| Spoke-hub auth | mTLS with a private CA, short-lived per-spoke certificates |
| Spoke edge proxy | Pingap (Pingora-based) for TLS termination and routing |
| Observability | OpenTelemetry |
| Graph UI | Cytoscape.js |
| Charts | Apache ECharts |
| Policy | CEL initially |
| Third-party extension | gRPC processes and/or WASM; no native Go `.so` plugin dependency |
| CI/CD | Minimal quality gates only; no heavy delivery platform initially |

## 29. Facade / Persona Infrastructure

Public-facing identity is part of the deception model, not cosmetic branding. A sensor deployment must present a coherent, fictional organization whose public footprint and internal synthetic world agree over time. Nothing in the domain, website, certificates, documentation, or service naming should advertise that the environment is a honeypot, research lab, security product, sandbox, or agent trap.

### 29.1 Design Goals

- Use fictional companies, fictional employees, fictional customers, and synthetic data only.
- Make the organization operationally ordinary rather than conspicuously attractive or security-themed.
- Maintain consistency between public website, DNS, TLS, developer documentation, email conventions, status history, source repositories, SaaS artifacts, and the internal world graph.
- Avoid clues such as "agent", "trap", "honey", "security", "research", "lab", "sandbox", "decoy", "test", "mcp", or "a2a" in public-facing names unless naturally justified by the fictional business.
- Keep canaries sparse. The environment should contain substantially more mundane legitimate-looking objects than trap objects.

### 29.2 Domain and Naming Strategy

Each world persona should generate a neutral business identity and a realistic service namespace. Example pattern:

```
www.<company-domain>
api.<company-domain>
auth.<company-domain>
developers.<company-domain>
status.<company-domain>
mail.<company-domain>
assets.<company-domain>
portal.<company-domain>
```

Hostnames must map to entities in the canonical world graph. Stale or legacy records may exist for realism, but they must also have coherent historical explanations.

### 29.3 Public Website

The facade site should be intentionally ordinary and credible. Recommended public pages:

- Home
- About
- Products / Services
- Careers
- Contact
- Privacy
- Terms
- Status
- Developer Documentation

Public product names, locations, technology references, and company history must be reflected inside the synthetic enterprise. If the website advertises a product, internal repositories, services, channels, cloud tags, tickets, and databases should reference the same product vocabulary.

### 29.4 DNS and TLS Realism

- Use coherent DNS records and service naming rather than a flat collection of bait hostnames.
- TLS SANs should match plausible services and avoid large, obviously synthetic certificate bursts.
- Certificate issuance should evolve over time for long-lived personas.
- DNS, certificates, service availability, and world history should be versioned so replayed sessions see the correct historical state.

### 29.5 Email, Directory, and Identity Consistency

Public mailboxes such as support, sales, careers, privacy, and security should follow the same domain and mail posture as synthetic employees. Employee naming conventions must match directory, chat, ticket, Git, and email identities. No public or internal identity may correspond to a real person without explicit authorization.

### 29.6 Status and Operational History

A believable organization should have temporal depth. Generate and correlate:

- historical status incidents
- scheduled maintenance
- Git releases and commits
- ticket history
- employee turnover
- service migrations
- credential rotations
- deprecated endpoints
- documentation changes

A public status incident should have matching internal evidence such as tickets, logs, deployment records, or chat discussion when those systems are exposed.

### 29.7 Developer and Repository Facade

Developer documentation may expose normal APIs, SDKs, webhook documentation, rate limits, authentication flows, and OpenAPI descriptions. Public repositories can include SDKs, examples, CLIs, and infrastructure examples. Commit dates, contributors, tags, release history, and internal references must be temporally coherent. Sensitive canaries should generally be discovered through deeper navigation, not advertised directly on public pages.

### 29.8 Canary Density and Placement

Canaries must be sparse and contextually plausible. A target ratio should favor normal objects by at least an order of magnitude. For example, a world might contain 100 normal assets, 5 legitimately interesting assets, and 1-2 true canaries. The objective is to observe abnormal exploration, not to lure every visitor toward an obvious bait path.

### 29.9 Multiple Persona Families

Internet deployments should rotate among multiple organization archetypes to reduce platform fingerprinting. Examples include SaaS, logistics, retail software, manufacturing, healthcare analytics, and fintech. Each persona family should vary its cloud provider, technology stack, naming conventions, directory structure, public content style, and exposure surface while sharing the same AgentTrap behavioral telemetry model.

### 29.10 Facade Consistency Score

Before a persona is deployed publicly, AgentTrap should compute a consistency score. Suggested dimensions:

| Dimension | Weight |
|---|---|
| domain/DNS consistency | 10 |
| TLS/certificate consistency | 10 |
| public/internal naming consistency | 15 |
| identity and email consistency | 10 |
| Git/release history consistency | 10 |
| status/incident history consistency | 10 |
| API/documentation consistency | 10 |
| temporal consistency | 10 |
| service behavior/error realism | 10 |
| canary sparsity and placement | 5 |

Recommended deployment gate: score >= 85/100 for an Internet-facing persona.

### 29.11 Persona Infrastructure Module

Recommended module layout:

```
persona-infra/
  domain/
  dns/
  tls/
  website/
  docs/
  status/
  email/
  git/
  directory/
  history/
  consistency/
```

### 29.12 Safety Boundary

- Do not impersonate an existing real company or person.
- Do not use real customer data, real production credentials, or real privileged tokens.
- Do not allow the facade to relay attacks, spam, phishing, or arbitrary traffic to third parties.
- All outbound interactions must pass through the controlled egress broker and remain subject to containment policy.
- Public deception should measure behavior without creating an unauthorized path into unrelated systems.

### 29.13 Architectural Rule

The facade is a projection of the same canonical world model used by MCP, A2A, cloud, Git, databases, browser applications, messaging, identity, RAG, and memory adapters. Public and internal surfaces must never invent independent realities.

### 29.14 v1 Persona: DemoGPU

The first spoke presents **DemoGPU** (`demogpu.example`), a fictional GPU cloud and LLM inference gateway. The business type is chosen because it holds exactly what a rogue agent wants: provider API keys, compute, credits and tokens. It also naturally justifies agent, model and MCP vocabulary on public surfaces.

| Surface | Purpose |
|---|---|
| `www.demogpu.example` | Marketing site, pricing, waitlist |
| `docs.demogpu.example` | Quickstart containing a "sample" key (canary) |
| `api.demogpu.example` | OpenAI-compatible `/v1/models`, `/v1/chat/completions`, `/v1/embeddings` (§11) |
| `console.demogpu.example` | Login, usage, "Provider keys" page |
| `mcp.demogpu.example` | MCP server: `list_keys`, `create_token`, `get_usage` |
| `status.demogpu.example` | Status page with coherent incident history |
| `/.well-known/agent.json`, `/llms.txt` | A2A card and agent-facing discovery hints |

v1 canary chain:

```
docs sample key -> API call with sample key -> console / MCP key listing
  -> planted "provider" key -> reuse of that key anywhere
```

Each step is a signal; reuse of the planted provider key is definitive.

Domain hygiene: WHOIS privacy enabled; registrar, DNS, hosting and mail accounts separate from any AgentTrap-related account; SPF/DKIM/DMARC configured; no shared analytics IDs, verification records or redirects linking to the operator. The product or operator name never appears on any DemoGPU surface.

## 30. Sensor Topology: Hub and Spoke

AgentTrap runs as one central **hub** (control plane) and one or more **spokes** (sensor nodes). Spokes are the only attacker-facing components. The hub collects events, correlates across spokes and distributes world packs and configuration.

```
            +--------------------- HUB (private only) --------------------+
            |  ingest API · PostgreSQL · correlation · console · packs     |
            +---------^-------------------^-------------------^-----------+
                      |  mTLS, outbound   |  from spokes only |
               +------+-----+      +------+-----+      +------+-----+
               | Spoke US   |      | Spoke EU   |      | Spoke APAC |
               | persona A  |      | persona B  |      | persona C  |
               +------^-----+      +------^-----+      +------^-----+
                      +------- public: facade, API, MCP, A2A -------+
```

### 30.1 Roles

- One Go binary, two roles: `agenttrap hub` and `agenttrap spoke`. Code is shared; each role runs in its own process or container.
- **Spoke:** runs the edge proxy, facade and adapters against a local copy of its world pack; records events to a durable disk queue; forwards them to the hub. Keeps serving if the hub is unavailable.
- **Hub:** authoritative PostgreSQL, ingest API, correlation and risk engine, admin console API, world-pack and config registry, spoke registry and kill switch.

### 30.2 Network Rules

- Spokes dial out to the hub. The hub never initiates connections to spokes and exposes no public listener.
- Hub, PostgreSQL and console listen only on private, VPN or loopback interfaces. Console access is via SSH tunnel or VPN.
- Spokes expose only facade and adapter ports.
- Spoke credentials are write-only for events and read-only for that spoke's own world pack and config. A compromised spoke cannot read other spokes' data or hub state.

### 30.3 mTLS

- Private CA dedicated to spoke-hub traffic. Offline root, online intermediate on the hub. Never reused for facade TLS.
- Each spoke has its own identity (`spoke:<id>` in the certificate SAN); the hub authorizes by that identity, not by network location.
- Short-lived certificates (24-72h) with automatic renewal; revocation is done by refusing renewal and blocking the identity.
- Private keys are generated on the spoke and never leave it; only CSRs are sent.
- New spokes enroll with a one-time, short-lived token created on the hub; after that they renew with their current certificate.
- Spokes pin the hub CA and do not trust the system store for hub connections.
- Admin console authentication uses a separate CA or login mechanism; spoke certificates are never accepted there.
- mTLS is in addition to network isolation, not a replacement for it.

### 30.4 Spoke Edge Proxy

- Each spoke fronts its public surfaces with **Pingap** (a reverse proxy built on Cloudflare's Pingora). It terminates public TLS (ACME / Let's Encrypt in the persona's name), routes hostnames to Go adapters, and passes the client address to adapters via PROXY protocol or a forwarded header that the adapters trust only from the proxy.
- The Pingap admin interface is bound to loopback or disabled in production.
- Response headers, error pages, TLS settings and HTTP/2 behavior must match the persona's claimed stack and be stripped of proxy-identifying defaults (§14).
- Client TLS fingerprints (JA4) are a fingerprinting signal (§13). Pingap 0.14 has no JA3/JA4 support, so a separate **JA4 sensor** computes them:
  - It runs as its own container sharing Pingap's network namespace, reads packets through an `AF_PACKET` socket with only `CAP_NET_RAW` (all other capabilities dropped, read-only filesystem), and never modifies traffic.
  - It reassembles ClientHellos split across TCP segments and fingerprints only the first ClientHello per connection.
  - It reports each fingerprint with the client `ip:port` to an internal spoke endpoint that accepts only the proxy's address.
  - Pingap forwards the client port as `X-Real-Port`, so the spoke attaches the JA4 to every HTTP request on that connection and also records a `tls_hello` event.
  - The implementation is our own, written from the JA4 specification (BSD-3-Clause; FoxIO disclaims patents on JA4). JA4+ methods and FoxIO-licensed data (ja4db, sample captures, mapping files) are not used. A fingerprint-to-client table is built from observed traffic.
- Using Pingora directly (custom Rust) is deferred unless Pingap cannot meet these requirements.

### 30.5 Events and World Packs

- Events are batched to the hub over HTTPS with mTLS, acknowledged per batch and deleted from the disk queue only after acknowledgement. Batches are idempotent.
- World packs and configuration are signed by the hub and verified by the spoke before loading.
- Canary values are unique per spoke, so any leaked value identifies where it was collected. Reuse of one spoke's canary at another spoke is a cross-spoke correlation signal.
- Personal data (for example source IPs) is pseudonymized on the spoke with a keyed hash where required by the spoke's jurisdiction, or the hub is hosted in a compatible jurisdiction.

### 30.6 v1: Single Node

v1 runs the full topology on one host with Docker Compose:

```
one host
|- pingap     public: 80/443 (and any facade adapter ports)
|- spoke      internal network only; mTLS client to hub
|- hub        internal network only; no published ports
|- postgres   reachable only from hub
`- console    bound to 127.0.0.1; reached via SSH tunnel
```

- Spoke and hub communicate over an internal Docker network (`internal: true`) using the same mTLS path as a remote spoke.
- Hub, spoke and PostgreSQL are attached only to internal networks: no published ports and no internet egress. Only Pingap joins a non-internal network.
- The admin API listens on loopback inside the hub container; operators use `docker compose exec hub agenttrap admin ...`. The Vue console is deferred to a later version.
- On first start the hub creates the CA (`--auto-pki`, single-node only) and a bootstrap spoke, writing its one-time enrollment bundle to a volume shared with the spoke.
- Moving a spoke to another host or region requires only enrollment and configuration, not code changes.

### 30.7 Later Versions

- Regional spokes (US, EU, APAC), each with a different persona, hosting provider, ASN and technology stack to prevent linking spokes by fingerprint (§29.9).
- WireGuard or private interconnect between spokes and hub.
- NATS JetStream leaf nodes for edge store-and-forward.
- Cross-spoke campaign correlation in the console.


---

## 31. Honeypot Modules

Added October 2026. Modules are persona-independent traps, each answering one kind of attack observed in real traffic. They complement the persona (which attracts agents) by answering the mass scanning and exploitation that reaches every public address.

### 31.1 Contract

- A module implements `Name`, `Claim` and `Serve` (`modules/module.go`). `Claim` reads only the request line and headers and returns `Pass`, `Vhost` (serve a hostname no persona surface answers, such as a bare IP) or `Attack` (a recognized attack, on any web surface). The strongest claim wins; ties go to registration order (`modules/builtin`).
- Modules never touch API-shaped persona surfaces (`api`, `vllm`, `mcp`, `aws`, `k8s`) and never answer ordinary persona pages.
- A module returns a `Hit` (attack name, CVEs, stage `probe`/`exploit`, signals, small detail); the facade records a `request` event tagged with the module and, for probes and exploits, an `exploit` event.
- A module may hand out persona canaries through `Request.Canary(slot, fallback)`. Those exposures carry `detail.module`; uses of such keys carry `detail.exposed_by`.
- Modules never execute payloads, read the host filesystem or make outbound connections. Bodies are read up to a per-module cap and drained up to 64 MiB.

### 31.2 Scoring rules

Keys harvested from module files are scanner work, not agent behavior: they are excluded from the canary chain, incidents and the funnel, and an address that uses one is classified as a scanner ("used a key harvested from a planted file"). Exploit attempts make an address a scanner unless agent evidence outweighs them; probes are listed among its reasons. The hub overview reports exploit counts per module, and the digest lists them.

### 31.3 Built-in modules (v1)

| Module | Attacks | Response |
|---|---|---|
| `traversal` | Apache cgi-bin traversal/RCE (CVE-2021-41773/42013), Vite `/@fs/` bypass (CVE-2025-30208/31125/31486), Tomcat `..;/`, generic `../` | Decoy system files; canned command output; commands and download URLs recorded |
| `webshell` | Searches for webshells planted by others | Shell login; passwords, commands and uploads recorded |
| `aiplatforms` | Langflow (CVE-2025-3248, CVE-2026-33017), Flowise (CVE-2025-59528, CVE-2026-46442), Feast (CVE-2026-23536), exposed Ollama, LiteLLM config | Platform-shaped answers; code, prompts and pulls recorded; config carries canaries |
| `secretfiles` | `.env`, `.git`, `.aws`, compose/CI files, `wp-config.php` backups | Believable files with per-exposure canaries |
| `php2shell` | PHP2Shell (CVE-2026-109618/109619) | Default virtual host as nginx + PHP-FPM 8.4.26; memory-exhaustion fatal error for exploit-shaped requests |

### 31.4 Choosing new modules

New modules come from observed demand: the most-requested unanswered paths, exploit families and JA4 fingerprints in the event store (`scripts/prod-diagnose.sh` summarizes them). A module is worth adding when many distinct addresses ask for something the decoy does not answer, or when a new vulnerability is being exploited in the wild.

---

*End of specification*
