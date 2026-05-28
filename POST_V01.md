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

### 2.1 Fortinet FortiWeb CVE-2025-64446 — auth bypass via path traversal

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

### 2.2 Spring Cloud Gateway CVE-2025-41243 — unauthenticated SpEL/env injection

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

### 2.3 Commvault Command Center CVE-2025-34028 — unauthenticated SSRF/pre-auth RCE

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

### 2.4 Traccar CVE-2025-61666 — unauthenticated local file inclusion (Windows)

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

### 3.1 Exposed `.git` directory

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

### 3.2 Exposed `.env` file

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

### 3.3 CVE-2025-32975 — Quest KACE SMA authentication bypass

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

### 3.4 Kubernetes API server — unauthenticated access

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

### I.4 Concurrent plugin execution

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
| 8 | Fortinet FortiWeb CVE-2025-64446 | Plugin | Medium |
| 9 | Exposed `.git` directory | Plugin | Small |
| 10 | Exposed `.env` file | Plugin | Small |
| 11 | Spring Cloud Gateway CVE-2025-41243 | Plugin | Medium |
| 12 | Traccar CVE-2025-61666 | Plugin | Medium |
| 13 | Service-type targeting | Infrastructure | Medium |
| 14 | Concurrent plugin execution | Infrastructure | Medium |
| 15 | Commvault CVE-2025-34028 | Plugin | Medium |
| 16 | Quest KACE CVE-2025-32975 | Plugin | Small |
| 17 | Kubernetes API unauthenticated | Plugin | Small |

---

*Research lap completed 2026-05-26. Sources: CISA KEV catalog, Wiz Research,
Rapid7, Qualys, Sysdig, ProjectDiscovery Nuclei Templates, NVD, HeroDevs,
SentinelOne Vulnerability Database, SecurityWeek.*
