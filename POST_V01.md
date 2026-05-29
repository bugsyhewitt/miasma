# miasma — Post-v0.1 Roadmap

Ranked backlog of improvements for miasma after v0.1. Items are sorted by
**value tier** (high → medium → low), then by approximate implementation
effort within each tier. Each plugin entry includes the CVE, why it belongs
here, what a benign probe looks like, and its confidence level.

---

## Tier 1 — Ship next (high value, clear benign probe)

These are immediately actionable: the vulnerability is widely deployed, the
benign probe is a version-check or unauthenticated endpoint hit with no
side effects, and bug-bounty programs regularly pay on them.

### 1.1 Spring Boot Actuator exposure (misconfiguration) — ✅ IMPLEMENTED

**Status:** Implemented as plugin `miasma_actuator_001` (Phase 2, Rotation 2).
Benign probe walking `/actuator/health` → `/actuator` → `/actuator/env`, with a
header-only `/actuator/heapdump` check (no body download). HIGH when
`/actuator/env` leaks secret-bearing keys (`password`/`secret`/`key`/`token`/
`credential`); MEDIUM on partial exposure.

**ID:** MIASMA-ACTUATOR-001  
**Vuln class:** Exposed sensitive management endpoints  
**CVSS:** N/A (misconfiguration, not a discrete CVE) — but see CVE-2025-22235
for the matcher bug and CVE-2025-41243 for the Spring Cloud Gateway RCE vector

**Why it matters:**  
Spring Boot applications that expose `/actuator/*` without authentication leak
environment variables, credentials, heap dumps, thread traces, and full runtime
configuration. In one documented real-world breach (Volkswagen) a heap dump
exposed plaintext AWS keys giving access to terabytes of vehicle data. CISA
and multiple security advisories in 2025 flagged this as a top-priority finding.

**Benign probe:**  
- HTTP GET `/actuator` → if 200, endpoint is live
- HTTP GET `/actuator/env` → reveals environment variables including secrets
- HTTP GET `/actuator/heapdump` → confirms heap dump available (do NOT download;
  just check the Content-Type header and response size)
- HTTP GET `/actuator/health` → low-risk baseline (always check this first)

Confidence: **high** if `/actuator/env` returns 200 with JSON containing keys
like `password`, `secret`, `key`, or `token`.

**Ports:** 80, 443, 8080, 8443, 8090, 9090

---

### 1.2 Redis unauthenticated access

**ID:** MIASMA-REDIS-001  
**Related CVEs:** CVE-2025-49844 ("RediShell", CVSS 10.0), CVE-2025-21605
(DoS via unauthenticated client, CVSS 7.5)

**Why it matters:**  
Approximately 60,000 internet-exposed Redis instances have no authentication
configured (Wiz research, October 2025). CVE-2025-49844 is a critical Lua
use-after-free enabling RCE on authenticated+unauthenticated instances —
making unauthenticated Redis exposure a two-step chain to RCE. Bug bounty
programs rate unauthenticated Redis access as P1/critical.

**Benign probe:**  
Open a TCP connection to port 6379. Send `PING\r\n`. A `+PONG` response with
no authentication challenge confirms unauthenticated access. Follow with
`INFO server` to extract the Redis version (confirms CVE-2025-49844 scope for
versions ≤ 8.2.1). No data modification, no keys read.

Confidence: **high**

**Ports:** 6379, 6380, 16379

---

### 1.3 Elasticsearch unauthenticated access

**ID:** MIASMA-ELASTIC-001  
**Vuln class:** Misconfiguration — no auth on HTTP API  

**Why it matters:**  
Unauthenticated Elasticsearch clusters are a perennial bug-bounty finding.
The HTTP REST API on port 9200 exposes index names, document counts, cluster
topology, and node metadata with no authentication. Even locked-down clusters
often leak metadata. Default credential pairs like `elastic:changeme` persist
widely.

**Benign probe:**  
- HTTP GET `http://<host>:9200/` → "You Know, for Search" banner without auth
  challenge confirms open access
- HTTP GET `http://<host>:9200/_cat/indices?v` → lists all index names (no
  data read, just schema) — confirms access depth
- Try `elastic:changeme` and `admin:elasticadmin` via HTTP Basic if a 401 is
  returned

Confidence: **high** on open access; **medium** on default-cred match

**Ports:** 9200, 9201, 9300

---

### 1.4 Jenkins CVE-2024-23897 — unauthenticated arbitrary file read

**ID:** CVE-2024-23897  
**CVSS:** 9.8 (Critical)  
**Affected:** Jenkins ≤ 2.441, LTS ≤ 2.426.2

**Why it matters:**  
The Jenkins CLI command parser substitutes `@<filepath>` with the file's
contents. An unauthenticated attacker can read the first few lines of any
file on the controller filesystem, including `/etc/passwd`,
`/var/jenkins_home/secrets/initialAdminPassword`, and credential XML files.
Authenticated users can read full files. Heavily exploited in the wild;
Nuclei template available. Patched in Jenkins 2.442+ / LTS 2.426.3+.

**Benign probe:**  
Send a CLI `who-am-i` command with an `@/etc/passwd` argument via the Jenkins
CLI endpoint (`/cli`). The response leaks the first few lines of
`/etc/passwd`. No modification, no authentication required. Version check
via `/login` page title or `X-Jenkins` header provides pre-flight targeting.

Confidence: **high** (version fingerprint + CLI response confirms)

**Ports:** 80, 443, 8080, 8090

---

### 1.5 Apache Tomcat CVE-2025-55752 — path traversal via Rewrite Valve

**ID:** CVE-2025-55752  
**CVSS:** High  
**Affected:** Apache Tomcat with Rewrite Valve configured

**Why it matters:**  
A path traversal in Tomcat's RewriteValve allows reading of files inside
`/WEB-INF/` (web.xml, classes, credentials) and `/META-INF/` that are
normally blocked by Tomcat's security constraints. These directories commonly
contain database passwords, JDBC credentials, and application secrets.
Complements the existing CVE-2009-3548 (Tomcat default creds) plugin well.

**Benign probe:**  
HTTP GET request to `/<app>/WEB-INF/web.xml` through crafted rewrite-exploiting
path. If the server returns XML content rather than a 403/404, the traversal is
confirmed. Version fingerprint via Server header and `/manager/text/serverinfo`
(if accessible).

Confidence: **medium** (requires Rewrite Valve to be configured)

**Ports:** 8080, 8443, 80, 443

---

## Tier 2 — High value, slightly more complex probe

### 2.1 Fortinet FortiWeb CVE-2025-64446 — auth bypass via path traversal — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2025_64446` (Phase 2, Rotation 9). Benign,
read-only probe: fingerprints FortiWeb via `/` and `/login` (Server/Set-Cookie/
body markers), establishes the direct `/api/v2.0/cmdb/system/status` endpoint as
a refusing control (`401`/`403`), then reads the same privileged status JSON
through a small ordered set of traversal-crafted paths. HIGH when the traversal
returns `200` with status markers (`serial`/`version`/`build`) while the direct
path refused; MEDIUM when FortiWeb fingerprints but the bypass is not cleanly
confirmed (no markers, or the direct path did not refuse). No privileged action
is ever performed.

**ID:** CVE-2025-64446  
**CVSS:** Critical (added to CISA KEV November 2025)  
**Affected:** Fortinet FortiWeb (WAF appliance)

**Why it matters:**  
Active exploitation observed from October 2025. The FortiWeb API path traversal
bypasses authentication by prefixing a valid API path (`/api/v2.0/cmdb/...`)
and traversing to underlying CGI. Full admin access without credentials.
FortiWeb is widely deployed in enterprise environments and frequently appears
in bug bounty scope.

**Benign probe:**  
HTTP GET with traversal-crafted path to the API endpoint. A successful response
(200 with JSON admin data) vs. 403 indicates vulnerability. Check for FortiWeb
fingerprints in `Server` header or `/api/v2.0/cmdb/system/status` endpoint
before attempting.

Confidence: **high** on fingerprinted FortiWeb hosts

**Ports:** 80, 443, 8443

---

### 2.2 Spring Cloud Gateway CVE-2025-41243 — unauthenticated SpEL/env injection — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2025_41243` (Phase 2, Rotation 12).
Benign, read-only exposure probe: `GET /actuator/gateway/routes` (the mutable
route table) and, as a fallback, `GET /actuator/gateway` (the gateway actuator
base). HIGH when the routes path returns `200` with a JSON *array* (the route
table — the mutate-able SpEL-injection surface is confirmed exposed); MEDIUM when
the route table is not cleanly served but the gateway base returns `200` JSON. No
route modification, no SpEL injection, no POSTs are ever performed. An SPA
`index.html` (non-JSON) or a JSON object at the routes path is not flagged.
Redirects are not followed. Evidence records only the route count and route
*ids* (operator labels, not secrets). Default ports: 8080, 8443, 80, 443.

**ID:** CVE-2025-41243  
**CVSS:** High (unauthenticated RCE via actuator endpoint)

**Why it matters:**  
When Spring Cloud Gateway has `management.endpoints.web.exposure.include=gateway`
set and actuator endpoints are unsecured, an unauthenticated attacker can
modify routes via the actuator API — injecting SpEL expressions that exfiltrate
environment variables, credentials, and API keys. Widely seen in enterprise
Java deployments.

**Benign probe:**  
HTTP GET `/actuator/gateway/routes` → if accessible without auth, confirms
the gateway actuator is exposed. Do NOT attempt route modification.
Check for Spring Cloud Gateway fingerprints (`x-application-context` header
or error page signatures).

Confidence: **medium** (exposure confirmation without exploitation)

**Ports:** 8080, 8443, 80, 443

---

### 2.3 Commvault Command Center CVE-2025-34028 — unauthenticated SSRF/pre-auth RCE — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2025_34028` (Phase 2, Rotation 15).
Benign, read-only, **version-fingerprint-only** probe: fingerprints Commvault
Command Center via the login console (`/commandcenter/`, `/webconsole/`,
`/commandcenter/login`, `/`) using body/`Server`/`cv_*`-cookie markers, then reads
the advertised build string and flags the affected `11.38` Innovation Release line
(dotted `11.38`/`11.38.x` or an `SP38` tag). HIGH when Commvault fingerprints AND
an affected `11.38` version is present; MEDIUM when Command Center fingerprints but
no version string could be read (hardened/stripped login page). A non-Commvault
host and a Commvault host on a known-safe release (e.g. `11.36`) are never flagged.
The vulnerable `/deployWebpackage.do` endpoint is **never** contacted — triggering
it is active SSRF/RCE and out of scope; this is a fingerprint flag for
human-driven confirmation. Default ports: 443, 80, 8443.

**ID:** CVE-2025-34028  
**CVSS:** Critical  
**Affected:** Commvault Command Center Innovation Release 11.38

**Why it matters:**  
Commvault is widely used enterprise backup software. Pre-auth RCE via
`/deployWebpackage.do` endpoint. Highly targeted in ransomware campaigns
because backup appliances are crown jewels for adversaries. Frequently
in-scope on enterprise bug bounty programs.

**Benign probe:**  
HTTP GET `/webconsole/commandcenter/default.aspx` or equivalent login page to
fingerprint Commvault. Check the version string in the login page HTML.
A version match for 11.38 is sufficient to flag for human review — do NOT
attempt the deploy endpoint.

Confidence: **medium** (version fingerprint only; no active probe of
vulnerable endpoint)

**Ports:** 443, 80, 8443

---

### 2.4 Traccar CVE-2025-61666 — unauthenticated local file inclusion (Windows) — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2025_61666` (Phase 2, Rotation 13). Benign,
read-only probe: fingerprints Traccar via the unauthenticated `/api/server` JSON
(Traccar-specific keys like `deviceReadonly`/`mapUrl`/`bingKey`) and the root page,
establishes the direct `/conf/traccar.xml` path as a refusing control (`404`/`403`),
then reads the same config through a small ordered set of override-servlet
traversal shapes (forward-slash, Windows backslash, and double-encoded). HIGH when
the traversal returns `200` with Traccar properties-XML markers (`<entry key=…>`)
while the direct path refused; MEDIUM when Traccar fingerprints but the LFI is not
cleanly confirmed. A non-Traccar host and an SPA `index.html` are never flagged.
The leaked secret **values** are never persisted — evidence records only the config
*key names* plus a `secret_keys_present` flag (mirroring the `.env`/`.git`
redaction convention). Default ports: 8082, 80, 443.

**ID:** CVE-2025-61666  
**Affected:** Traccar 6.1–6.8.1 on Windows  
**Vuln class:** LFI via override servlet

**Why it matters:**  
Traccar GPS tracking is widely deployed by logistics companies and small fleets.
Default install exposes the `DefaultOverrideServlet` without authentication.
On Windows, path normalization failures allow reading arbitrary files including
`conf/traccar.xml` which contains database credentials and server secrets.
Bug bounty programs for logistics/fleet management companies frequently have
Traccar in scope.

**Benign probe:**  
HTTP GET to the override endpoint with a benign traversal to `conf/traccar.xml`
or equivalent. Presence of XML configuration data in the response confirms LFI.
Fingerprint Traccar via `/api/server` endpoint first (returns server info
without auth on unpatched versions).

Confidence: **high** on Windows Traccar hosts ≤ 6.8.1

**Ports:** 8082, 80, 443

---

## Tier 3 — Good additions after Tier 1 & 2 are done

### 3.1 Exposed `.git` directory — ✅ IMPLEMENTED

**Status:** Implemented as plugin `miasma_git_001` (Phase 2, Rotation 10).
Benign, read-only probe: `GET /.git/HEAD` (flags only a genuine Git symbolic
ref or detached-HEAD SHA — an SPA `index.html` returned for every path is NOT
flagged), then `GET /.git/config` to detect credential-bearing remote URLs
(`://user:pass@`), with the password **redacted** in evidence. HIGH when
`/.git/HEAD` confirms the exposed directory. Redirects are not followed (the
dotfile must be served directly). Default ports: 80, 443, 8080, 8443.

**ID:** MIASMA-GIT-001  
**Vuln class:** Information disclosure (misconfiguration)

**Why it matters:**  
An accessible `.git/` directory on a web server exposes full source code,
commit history, credentials stored in config files, and environment files
committed by mistake. Consistently a P1/P2 finding in bug bounty programs.
Not a CVE — a widely recognised misconfiguration.

**Benign probe:**  
HTTP GET `/.git/HEAD` → response containing `ref: refs/heads/` confirms
exposed .git. Follow with `/.git/config` to check for remote URLs with
embedded credentials.

Confidence: **high**

---

### 3.2 Exposed `.env` file — ✅ IMPLEMENTED

**Status:** Implemented as plugin `miasma_env_001` (Phase 2, Rotation 11).
Benign, read-only probe: `GET /.env` (then the `/.env.production`, `/.env.local`,
`/.env.dev` variants) and flags only a body that parses as dotenv content
(`KEY=value` assignment lines) — an SPA `index.html` returned for every path is
NOT flagged. HIGH when a secret-bearing key (`SECRET`/`PASSWORD`/`TOKEN`/
`API_KEY`/`ACCESS_KEY`/`DATABASE_URL`/`DSN`/…) is present; MEDIUM when the served
file is config-only. The leaked secret **values** are never persisted — evidence
records only the exposed key *names*. Redirects are not followed. Default ports:
80, 443, 8080, 8443.

**ID:** MIASMA-ENV-001  
**Vuln class:** Information disclosure (misconfiguration)

**Why it matters:**  
`.env` files containing `DATABASE_URL`, `AWS_SECRET_ACCESS_KEY`, API keys,
and JWT secrets are among the most common bug bounty finds. Frequently
exposed by misconfigured Laravel, Node.js, and Django deployments.

**Benign probe:**  
HTTP GET `/.env` → 200 response containing `KEY=value` pairs confirms
exposure. Check for Laravel-specific paths (`/.env.production`,
`/.env.local`) too.

Confidence: **high**

---

### 3.3 CVE-2025-32975 — Quest KACE SMA authentication bypass — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2025_32975` (Phase 2, Rotation 16).
Benign, read-only, **version-fingerprint-only** probe: fingerprints Quest KACE
SMA via the login console (`/userui/login.php`, `/userui/`, `/adminui/login.php`,
`/`) using body / `X-KACE-*` header / `kboxid`-cookie markers, then reads the
advertised dotted `MAJOR.MINOR.PATCH` build (from an `X-KACE-Version` header or
the login HTML) and flags any build below the fixed `14.1` line (the March 2025
patch). HIGH when KACE fingerprints AND an affected (`<14.1`) version is present;
MEDIUM when KACE fingerprints but no version string could be read (hardened /
stripped login page). A non-KACE host and a KACE host on a fixed release (`14.1`+)
are never flagged. The authentication bypass is **never** attempted — performing
it is active exploitation and out of scope; this is a fingerprint flag for
human-driven confirmation. Default ports: 443, 80.

**ID:** CVE-2025-32975  
**CVSS:** 10.0  
**Affected:** Quest KACE SMA (Systems Management Appliance) — all versions
before the March 2025 patch

**Why it matters:**  
CISA KEV; active exploitation confirmed from March 2026. KACE SMA is deployed
in enterprise IT management. Authentication bypass allows full admin account
takeover. Niche enough that automated scanners often miss it, making it a
strong manual bug-bounty finding.

**Benign probe:**  
Fingerprint KACE SMA via login page (`/ui/login`) title/logo. Check
`X-KACE-Version` response header or login page HTML for version strings.
Flag if version predates the patch. Do NOT attempt the auth bypass itself.

Confidence: **medium** (version fingerprint only)

**Ports:** 443, 80

---

### 3.4 Kubernetes API server — unauthenticated access — ✅ IMPLEMENTED

**Status:** Implemented as plugin `miasma_k8s_001` (Phase 2, Rotation 17).
Benign, read-only, **enumeration-only** probe: `GET /version` fingerprints the
Kubernetes API server (JSON object with `gitVersion`/`major`/`minor`) and
confirms anonymous read in one request; only after that fingerprint is
`GET /api/v1/namespaces` consulted. HIGH when `/version` fingerprints Kubernetes
AND `/api/v1/namespaces` returns a `NamespaceList` (anonymous access reaches live
resources) — evidence records only the namespace **count**, never the names or
any resource contents. MEDIUM when `/version` answers anonymously (build-version
leak) but namespace enumeration is refused (`401`/`403`). A host that refuses
`/version`, a non-Kubernetes JSON/HTML `200`, or a bare namespace `200` without
the `/version` fingerprint is never flagged. No credentials, bearer tokens, or
service-account JWTs are ever sent; no Secret contents are read and no resource
is mutated. Default ports: 6443, 8443, 443.

**ID:** MIASMA-K8S-001  
**Vuln class:** Misconfiguration — anonymous auth enabled

**Why it matters:**  
Kubernetes API servers with anonymous authentication enabled (`--anonymous-auth=true`,
which was the default in older versions) allow unauthenticated enumeration of
cluster resources. Frequently in scope for cloud-native bug bounty programs.

**Benign probe:**  
HTTP GET `https://<host>:6443/version` → returns cluster version without auth
if anonymous access is enabled. HTTP GET `https://<host>:6443/api/v1/namespaces`
→ if 200 (not 403), anonymous access to namespace list is confirmed.

Confidence: **high** on version endpoint; **medium** on namespace listing

**Ports:** 6443, 8443, 443

---

### 3.5 Langflow CVE-2025-3248 — unauthenticated RCE — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2025_3248` (Phase 2, Rotation 18).
Benign, read-only, **version-fingerprint-only** probe: fingerprints Langflow via
the unauthenticated version endpoint (`/api/v1/version`, with `/health` and `/`
as fallbacks) using a `langflow` body/header marker, reads the advertised build,
and flags any version strictly below the fixed `1.3.0` line. HIGH when Langflow
fingerprints AND an affected (`< 1.3.0`) version is present; MEDIUM when Langflow
fingerprints but no version string could be read (hardened/stripped deployment).
A non-Langflow host (a bare `{"version": ...}` JSON without a `langflow` marker is
not a fingerprint) and a Langflow host on a fixed release (`1.3.0`+) are never
flagged. The vulnerable `/api/v1/validate/code` endpoint is **never** contacted
and the probe never POSTs — triggering the endpoint is active RCE and out of
scope; this is a fingerprint flag for human-driven confirmation. Default ports:
7860, 80, 443, 8080, 8443.

**ID:** CVE-2025-3248
**CVSS:** 9.8 (Critical)
**Affected:** Langflow before 1.3.0

**Why it matters:**
Langflow is a widely deployed low-code framework for building LLM/agent
workflows. Before 1.3.0, `/api/v1/validate/code` compiles and executes
attacker-supplied Python via `exec` with no authentication — a direct pre-auth
RCE. CISA added it to the KEV catalog in May 2025 after in-the-wild exploitation
(botnet/crypto-miner recruitment). Langflow hosts commonly store downstream
LLM-provider and internal API keys, making them high-value targets and a
recurring item on AI/ML bug-bounty scope.

**Benign probe:**
HTTP GET `/api/v1/version` → returns the build version without auth on Langflow
hosts. Compare against the fixed 1.3.0 line and flag affected builds. Do NOT
POST to `/api/v1/validate/code` — that is the active RCE trigger.

Confidence: **high** on fingerprinted Langflow hosts below 1.3.0; **medium** on
version-unreadable Langflow hosts

**Ports:** 7860, 80, 443, 8080, 8443

---

### 3.6 Ivanti Connect Secure CVE-2025-0282 — pre-auth RCE — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2025_0282` (Phase 2, Rotation 19).
Benign, read-only, **version-fingerprint-only** probe: fingerprints Ivanti
Connect Secure via the unauthenticated GINA client version file
(`/dana-na/nc/nc_gina_ver.txt`, with the `/dana-na/auth/url_default/welcome.cgi`
login page, `/dana-na/`, and `/` as fallbacks) using `/dana-na/`-family /
Pulse-Secure / `welcome.cgi` body+header markers, reads the advertised Ivanti
`MAJOR.MINORRn.m` build, and flags any version strictly below the fixed
`22.7R2.5` line. HIGH when Ivanti fingerprints AND an affected (`< 22.7R2.5`)
version is present; MEDIUM when Ivanti fingerprints but no version string could be
read (hardened/stripped appliance). A non-Ivanti host (a bare version-looking
token without an Ivanti marker is not a fingerprint) and an Ivanti appliance on a
fixed release (`22.7R2.5`+) are never flagged. The memory-corruption overflow is
**never** triggered — doing so crashes/compromises the appliance and is out of
scope; this is a fingerprint flag for human-driven confirmation. Default ports:
443, 80, 8443.

**ID:** CVE-2025-0282  
**CVSS:** 9.0 (Critical)  
**Affected:** Ivanti Connect Secure / Policy Secure / Neurons for ZTA before 22.7R2.5

**Why it matters:**  
CISA KEV (January 2025); active in-the-wild exploitation by a China-nexus actor
deploying the SPAWN malware family (Mandiant/Google). Ivanti SSL VPN appliances
sit at the network edge and are perennial enterprise targets and recurring
bug-bounty / red-team scope. An unauthenticated stack overflow yields pre-auth
RCE on the appliance.

**Benign probe:**  
HTTP GET `/dana-na/nc/nc_gina_ver.txt` (the unauthenticated GINA version file) to
fingerprint Ivanti and read the build, with the welcome/login page and root page
as fallbacks. Compare against the fixed 22.7R2.5 line and flag affected builds.
Do NOT send an overflow payload — that is the active, destructive RCE trigger.

Confidence: **high** on fingerprinted Ivanti hosts below 22.7R2.5; **medium** on
version-unreadable Ivanti hosts

**Ports:** 443, 80, 8443

---

### 3.7 Ivanti EPMM CVE-2026-1340 / CVE-2026-1281 — unauthenticated RCE — ✅ IMPLEMENTED

**Status:** Implemented as plugin `cve_2026_1340` (Phase 2, Rotation 20). Added
via a fresh gap analysis after the entire Tier 1/2/3 roadmap above was found
already shipped — sourced from the 2026 CISA KEV catalog. Benign, read-only,
**RCE-never-triggered** probe: fingerprints Ivanti EPMM (MobileIron Core) via the
`/mifs/admin` "Ivanti User Portal: Sign In" login surface, then checks whether the
two vulnerable feature endpoints `/mifs/c/appstore/fob/` and
`/mifs/c/aftstore/fob/` are *routed* (non-`404`) using payload-free GETs — no Bash
command is ever smuggled, so the RCE is never triggered. HIGH when EPMM
fingerprints AND a vulnerable endpoint is reachable OR a readable build is in the
affected `< 12.8.0.0` window; MEDIUM when EPMM fingerprints with neither signal
(hardened/stripped, or patched via the emergency RPM that leaves the version
unchanged). A non-EPMM host and a patched (`>= 12.8.0.0`) host with no reachable
endpoint are never flagged. Distinct from the Ivanti Connect Secure plugin
(`cve_2025_0282`): EPMM is the MobileIron MDM control plane under `/mifs/`, not
the `/dana-na/` SSL-VPN portal. Default ports: 443, 80, 8443.

**ID:** CVE-2026-1340 (sibling CVE-2026-1281)
**CVSS:** 9.8 (Critical)
**Affected:** Ivanti EPMM before 12.8.0.0 (12.5.x / 12.6.x / 12.7.x branches)

**Why it matters:**
Both were exploited in the wild as zero-days (patched 2026-01-29); CVE-2026-1281
is on CISA's KEV catalog and a public PoC is available. EPMM is the enterprise
MDM control plane, so a compromised appliance is a fleet-wide foothold; >2,000
instances were internet-exposed at disclosure.

Confidence: **high** on EPMM hosts with a reachable feature endpoint or an
affected readable build; **medium** on version/endpoint-unreadable EPMM hosts

**Ports:** 443, 80, 8443

---

## Infrastructure improvements (non-plugin)

These are framework-level improvements that increase miasma's utility and
should be scheduled alongside plugin work.

### I.1 Service-type targeting (skip probes that don't match fingerprint)

Currently plugins probe all open ports. A service-type gate — "only run
HTTP-class plugins against ports where nmap reports `http` or `ssl/http`" —
would cut false-probe noise and reduce scan time significantly.

**Effort:** Medium (touches `runner.py` + `core.py` + all plugins)

---

### I.2 Plugin metadata: `port_hint` and `service_hint` fields — ✅ IMPLEMENTED

**Status:** Implemented (Phase 2). Standardised optional `port_hint: list[int]`
and `service_hint: list[str]` metadata fields. The runner's `is_applicable`
filter skips a plugin only when recon found open ports, the plugin declares a
hint, and no open port/service matches — so irrelevant plugins (e.g. the Redis
plugin against an SSH-only host) are skipped without ever risking a dropped
finding. `default_ports` is kept as a backwards-compatible alias for
`port_hint`. All shipped CVE/misconfig plugins now declare both hints.

Add optional `port_hint: list[int]` and `service_hint: list[str]` to plugin
metadata so the runner can skip obviously irrelevant plugins (e.g., Redis
plugin when no port 6379/6380 is open). The Tomcat plugin already does this
manually; standardise it.

**Effort:** Small (metadata convention + runner filter)

---

### I.3 `--output-file` flag for JSON findings — ✅ IMPLEMENTED

**Status:** Implemented (Phase 2). `--output-file <path>` writes the JSON report
to a file instead of stdout; `-` forces stdout (the default). Enables piping
into downstream tooling (e.g., `unearth` → miasma → `covenant`).

Add `--output-file <path>` to the CLI so findings can be written to a file
directly, enabling piping into downstream tooling (e.g., `unearth` → miasma
→ `covenant`). Currently only stdout is supported.

**Effort:** Small (CLI + cli.py)

---

### I.4 Concurrent plugin execution — ✅ IMPLEMENTED

**Status:** Implemented (Phase 2, Rotation 14). `run_plugins(..., concurrency=N)`
runs up to N I/O-bound plugin probes in parallel through a
`ThreadPoolExecutor`, surfaced via the `--concurrency N` CLI flag (default `1`,
sequential — original behaviour preserved exactly). Plugins are resolved and
filtered through `is_applicable` *before* any worker slot is used, so an
inapplicable plugin never occupies a thread. Findings are collected via
`pool.map`, which preserves input order — so the JSON report is byte-for-byte
deterministic regardless of N (concurrency changes only the timing, never the
output). Per-plugin error isolation is preserved: a raising plugin still
becomes a single `"error"`-confidence Finding without aborting the run.
`--concurrency < 1` is rejected at both the CLI and runner layers.

Run plugins concurrently (via `asyncio` or `ThreadPoolExecutor`) to reduce
total scan time when multiple plugins are specified. I/O-bound probes
(HTTP, TCP) are the bottleneck; concurrency provides a large speedup.

**Effort:** Medium (runner.py refactor; plugins must be thread-safe)

---

## Ranking summary

| Rank | Item | Type | Effort |
|---|---|---|---|
| 1 | Spring Boot Actuator exposure | Plugin | Small |
| 2 | Redis unauthenticated access | Plugin | Small |
| 3 | Elasticsearch unauthenticated access | Plugin | Small |
| 4 | Jenkins CVE-2024-23897 file read | Plugin | Small-Medium |
| 5 | `--output-file` CLI flag ✅ | Infrastructure | Small |
| 6 | Plugin `port_hint`/`service_hint` ✅ | Infrastructure | Small |
| 7 | Apache Tomcat CVE-2025-55752 | Plugin | Medium |
| 8 | Fortinet FortiWeb CVE-2025-64446 ✅ | Plugin | Medium |
| 9 | Exposed `.git` directory ✅ | Plugin | Small |
| 10 | Exposed `.env` file ✅ | Plugin | Small |
| 11 | Spring Cloud Gateway CVE-2025-41243 ✅ | Plugin | Medium |
| 12 | Traccar CVE-2025-61666 ✅ | Plugin | Medium |
| 13 | Service-type targeting | Infrastructure | Medium |
| 14 | Concurrent plugin execution ✅ | Infrastructure | Medium |
| 15 | Commvault CVE-2025-34028 ✅ | Plugin | Medium |
| 16 | Quest KACE CVE-2025-32975 ✅ | Plugin | Small |
| 17 | Kubernetes API unauthenticated ✅ | Plugin | Small |
| 18 | Langflow CVE-2025-3248 RCE ✅ | Plugin | Small |
| 19 | Ivanti Connect Secure CVE-2025-0282 RCE ✅ | Plugin | Small |
| 20 | Ivanti EPMM CVE-2026-1340 unauthenticated RCE ✅ | Plugin | Small |
| 21 | Docker daemon unauthenticated TCP API ✅ | Plugin | Small |
| 24 | Grafana unauthenticated / default-credential access ✅ | Plugin | Small |

---

*Research lap completed 2026-05-26. Sources: CISA KEV catalog, Wiz Research,
Rapid7, Qualys, Sysdig, ProjectDiscovery Nuclei Templates, NVD, HeroDevs,
SentinelOne Vulnerability Database, SecurityWeek.*

---

## Rotation 21 fresh-gap addition

### 21. Docker Daemon Unauthenticated TCP API — MIASMA-DOCKER-001

**Rank: fresh gap (R21, 2026-05-29)** — All POST_V01 plugin items §1.1–§3.7 were
already shipped. Docker daemon unauthenticated TCP API was the highest-value
unimplemented gap: port 2375 HTTP with no authentication gives any client full
container control and a documented path to root on the host.

**What:** `dockerd -H tcp://0.0.0.0:2375` with no TLS and no auth lets any
network client call the Docker Engine HTTP API. `GET /version` fingerprints
the daemon; `GET /containers/json` enumerates running containers. A privileged
container with a host-path bind mount achieves root on the host filesystem.

**Probe:** Read-only GETs only — `GET /version` then `GET /containers/json`.
No container created, started, or stopped. Evidence records only the version
string and container count.

**Severity:**
- HIGH: `/containers/json` returns 200 with a JSON array (container enumeration)
- MEDIUM: `/version` fingerprints Docker but container list is refused

**STATUS: ✅ IMPLEMENTED (R21, 2026-05-29).** Plugin `miasma_docker_001.py`,
12 tests in `tests/test_docker.py`. Ports: 2375 (HTTP), 2376 (HTTPS).
Total tests: 287 → 299 (+12).

---

## Rotation 24 fresh-gap addition

### 24. Grafana Unauthenticated / Default-Credential Access — MIASMA-GRAFANA-001

**Rank: fresh gap (R24, 2026-05-29)** — The dispatched options were Grafana or
Redis unauthenticated access. Redis (§1.2, `miasma_redis_001.py`) was already
shipped, so the other option — Grafana — was implemented. Grafana is among the
most internet-exposed dashboards, and two recurring misconfigurations make it a
P1/critical finding: the factory `admin:admin` credential is rarely rotated, and
`[auth.anonymous] enabled = true` exposes dashboards and org metadata to anyone.

**What:** Default-credential access grants full Grafana administration,
including data-source credential disclosure for every configured database / cloud
connection. Anonymous access exposes internal dashboards, asset inventories, and
dashboard-embedded queries without authentication.

**Probe:** Read-only fingerprint + two minimal checks. `GET /api/health`
fingerprints Grafana (version/database keys); `POST /login` with the single
factory `admin:admin` pair confirms default creds (200); `GET /api/org` with no
auth confirms anonymous access. No dashboard read, no data source touched, no
config changed; exactly one credential pair attempted (not a brute force).

**Severity:**
- CRITICAL: default `admin:admin` login accepted
- HIGH: anonymous `/api/org` returns org metadata

**STATUS: ✅ IMPLEMENTED (R24, 2026-05-29).** Plugin `miasma_grafana_001.py`,
14 tests in `tests/test_grafana.py`. Ports: 3000, 80, 443 (HTTPS), 8080.
Total tests: 323 → 337 (+14).

## Rotation 25 fresh-gap addition

### 25. Apache Solr Unauthenticated Admin API Access — MIASMA-SOLR-001

**Rank: fresh gap (R25, 2026-05-29).** Apache Solr ships with no authentication
enabled by default; the Admin API is reachable by any client that can reach the
HTTP port, leaking the indexed dataset, schema, JVM/OS fingerprint, and every
configured core, and gating the CVE-2019-17558 / CVE-2017-12629 RCE chains.

**Probe:** Read-only. `GET /solr/admin/info/system?wt=json` fingerprints Solr and
captures the version banner; `GET /solr/admin/cores?wt=json` with no credentials
enumerates cores. No document read, no core created, no RCE handler invoked.

**Severity:**
- HIGH: `/solr/admin/cores` enumerates cores without authentication
- MEDIUM: system-info answers but core-listing is auth-gated

**STATUS: ✅ IMPLEMENTED (R25, 2026-05-29).** Plugin `miasma_solr_001.py`,
13 tests in `tests/test_solr.py`. Ports: 8983, 8984, 80, 443 (HTTPS), 8080.

## Rotation 26 fresh-gap addition

### 26. Prometheus Unauthenticated HTTP API Access — MIASMA-PROMETHEUS-001

**Rank: fresh gap (R26, 2026-05-29)** — The dispatched options were Elasticsearch
or Prometheus unauthenticated access. Elasticsearch (§1.3,
`miasma_elastic_001.py`) was already shipped, so the other option — Prometheus —
was implemented. Prometheus ships with no authentication, authorization, or TLS
on its HTTP API by default; the upstream project states explicitly that securing
the endpoint is the operator's responsibility.

**What:** The most valuable leak is the scrape-target inventory — Prometheus has
already discovered every monitored service, so `/api/v1/targets` is a live,
authoritative map of the internal estate (better than a port scan). The running
config (`/api/v1/status/config`) can additionally disclose scrape-time
credentials (basic-auth passwords, bearer tokens) embedded in scrape_configs.

**Probe:** Read-only fingerprint + two minimal status reads.
`GET /api/v1/status/buildinfo` fingerprints Prometheus (version/revision/
goVersion keys); `GET /api/v1/targets` confirms the inventory is readable and
counts active targets; `GET /api/v1/status/config` is scanned in-memory (never
stored) for credential markers to escalate severity. No query is run, no rule is
mutated, and no admin endpoint (`/-/reload`, TSDB admin API) is touched.

**Severity:**
- HIGH: config readable with credential markers, OR `/api/v1/targets` enumerates
  one or more active scrape targets without authentication
- MEDIUM: status API answers without authentication but no targets and no
  credentials observed

**STATUS: ✅ IMPLEMENTED (R26, 2026-05-29).** Plugin `miasma_prometheus_001.py`,
16 tests in `tests/test_prometheus.py`. Ports: 9090, 80, 443 (HTTPS), 8080, 9091.
Total tests: 350 → 366 (+16).
