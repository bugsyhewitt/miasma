# miasma

A lightweight, plugin-driven verifier of high-confidence vulnerabilities for
**bug-bounty recon-to-verification handoff**.

`miasma` is not another network scanner — `nmap`, `masscan`, OpenVAS, and
Nessus already own that space. Instead, `miasma`:

- takes a single host (e.g. output from a recon tool like `unearth`),
- fingerprints it with the system `nmap`,
- runs **benign verification probes** for the specific CVEs you care about,
- emits per-host JSON findings with vuln ID, confidence, and reproduction
  evidence.

Each probe is a small, auditable Python file. Linux-native — no JVM, no Docker.

## System dependencies

`miasma`'s recon phase shells out to `nmap` via the shared
[`nmap-wrapper`](https://github.com/bugsyhewitt/nmap-wrapper) library (installed
automatically as a dependency). **`nmap` itself is not pip-installable** —
install it with your system package manager first:

```bash
# Debian / Ubuntu
sudo apt install nmap

# Arch
sudo pacman -S nmap

# Fedora
sudo dnf install nmap

# macOS (Homebrew)
brew install nmap
```

Verify it's on your `PATH`:

```bash
nmap --version
```

> Note: the test suite mocks the `nmap` layer, so tests pass even without
> `nmap` installed. You only need `nmap` to run a real recon scan.

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/miasma
cd miasma
pip install -e .
```

## Usage

Fingerprint a host and run the bundled test plugin (always reports a finding —
useful for verifying your install end to end):

```bash
miasma --target 127.0.0.1 --port-range 1-1000 --plugins test_always_finds
```

Run the real Tomcat default-credentials check (CVE-2009-3548):

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2009_3548
```

Run several plugins at once (comma-separated) and see available plugins:

```bash
miasma --target 10.0.0.5 --plugins test_always_finds,cve_2009_3548
miasma --list-plugins
```

Write the JSON report to a file (for piping into downstream tooling) instead of
stdout with `--output-file`. Use `-` to force stdout (the default):

```bash
miasma --target 10.0.0.5 --plugins cve_2009_3548 --output-file findings.json
```

When you request several plugins, run their probes in parallel with
`--concurrency`. Each probe is an I/O-bound network round-trip that mostly
waits, so concurrency cuts wall time roughly in proportion to how many plugins
overlap. The default is `1` (sequential). Findings are always emitted in the
**requested plugin order** regardless of how many threads run, so the JSON
report is byte-for-byte deterministic — concurrency changes only the timing:

```bash
miasma --target 10.0.0.5 \
  --plugins miasma_redis_001,miasma_elastic_001,cve_2024_23897,miasma_actuator_001 \
  --concurrency 4
```

Output is JSON:

```json
{
  "target": "127.0.0.1",
  "port_range": "1-1000",
  "open_ports": [22, 8080],
  "plugins": ["test_always_finds"],
  "findings": [
    {
      "vuln_id": "MIASMA-TEST-0001",
      "host": "127.0.0.1",
      "confidence": "high",
      "evidence": { "note": "test plugin always reports a finding", "open_ports": [22, 8080] },
      "description": "Verification plugin that unconditionally reports a finding."
    }
  ]
}
```

### CLI options

| Option | Description |
|---|---|
| `--target` | Host to scan and probe (IP or hostname). |
| `--plugins` | Comma-separated plugin names (file stems under `miasma/plugins`). |
| `--port-range` | nmap port spec for the recon phase (default `1-1000`). |
| `--concurrency` | Run up to N plugin probes in parallel (default `1`, sequential). Findings stay in requested order regardless of N. |
| `--format` | Output format (`json`, default). |
| `--output-file` | Write the JSON report to this path instead of stdout (`-` = stdout). |
| `--list-plugins` | List available plugins and exit. |

## Writing a plugin

A plugin is **one Python file** in `miasma/plugins/<cve-id>.py` exposing a
module-level `metadata: dict` and a `probe(target: Target) -> Finding | None`
function. Return a `Finding` if the target is vulnerable, or `None` if not.

```python
# miasma/plugins/cve_2024_12345.py
from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2024-12345",
    "name": "Example service auth bypass",
    "description": "Reports a finding when /admin returns 200 without auth.",
    "confidence": "high",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
    # Optional targeting hints — see "Targeting hints" below.
    "port_hint": [8080, 8443],
    "service_hint": ["http", "https"],
}


def probe(target: Target) -> Finding | None:
    import httpx

    for port in target.open_ports():
        url = f"http://{target.host}:{port}/admin"
        try:
            resp = httpx.get(url, timeout=5.0)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence=metadata["confidence"],
                evidence={"url": url, "status_code": resp.status_code},
                description=metadata["description"],
            )
    return None
```

Drop the file in `miasma/plugins/`, then run it:

```bash
miasma --target 10.0.0.5 --plugins cve_2024_12345
```

> Plugin filenames use underscores (`cve_2024_12345.py`) because the runner
> discovers plugins via Python's import system, and module names can't contain
> hyphens. The canonical CVE id lives in `metadata["vuln_id"]`.

Keep probes **benign**: read-only verification, no exploitation, no state
change. The goal is high-confidence "this is real" evidence for a human to
confirm — not a weaponized exploit.

### Targeting hints (`port_hint` / `service_hint`)

Two optional metadata fields let the runner **skip plugins that obviously
can't match** a target, cutting wasted network round-trips:

| Field | Type | Meaning |
|---|---|---|
| `port_hint` | `list[int]` | Ports this plugin cares about (e.g. `[6379, 6380]` for Redis). |
| `service_hint` | `list[str]` | nmap service-name substrings this plugin cares about (e.g. `["redis"]`, `["http", "https"]`). |

A plugin is **skipped** for a target only when *all* of these hold, so a real
finding is never silently dropped:

1. recon found at least one open port (if recon found nothing, the plugin
   always runs and falls back to its own default-port ordering), **and**
2. the plugin declares at least one of `port_hint` / `service_hint`, **and**
3. none of the open ports match a declared `port_hint`, **and**
4. none of the open ports' nmap service names contain a declared
   `service_hint` (case-insensitive substring match).

A plugin that declares neither hint always runs (it opts out of filtering —
this is how `test_always_finds` behaves). `port_hint` is the canonical field;
`default_ports` is accepted as a backwards-compatible alias for plugins that
predate the convention.

This means a Redis plugin won't probe an SSH-only host, but a Redis instance
listening on a non-standard port still gets caught as long as nmap fingerprints
its service name as `redis`.

## Bundled plugins

| Plugin | Vuln ID | Purpose |
|---|---|---|
| `test_always_finds` | `MIASMA-TEST-0001` | Canonical test plugin — always returns a finding. |
| `cve_2009_3548` | `CVE-2009-3548` | Apache Tomcat default/weak manager credentials. |
| `miasma_actuator_001` | `MIASMA-ACTUATOR-001` | Exposed Spring Boot Actuator management endpoints (env/secret leak, heap dump). |
| `miasma_redis_001` | `MIASMA-REDIS-001` | Redis reachable without authentication (PING/INFO handshake). |
| `cve_2024_23897` | `CVE-2024-23897` | Jenkins CLI unauthenticated arbitrary file read (args4j `@file` expansion). |
| `cve_2025_55752` | `CVE-2025-55752` | Apache Tomcat Rewrite Valve path traversal into `/WEB-INF/` (web.xml disclosure). |
| `cve_2025_64446` | `CVE-2025-64446` | Fortinet FortiWeb authentication bypass via API path traversal (CISA KEV). |
| `miasma_git_001` | `MIASMA-GIT-001` | Exposed `.git/` directory (source code, commit history, committed secrets). |
| `miasma_env_001` | `MIASMA-ENV-001` | Exposed `.env` file (database URLs, cloud keys, API keys, app secrets). |
| `cve_2025_41243` | `CVE-2025-41243` | Spring Cloud Gateway exposed actuator (`/actuator/gateway/routes`) — mutable route table enables SpEL/env injection. |
| `cve_2025_61666` | `CVE-2025-61666` | Traccar (Windows) unauthenticated LFI via the override servlet — reads `conf/traccar.xml` (DB credentials). |
| `cve_2025_34028` | `CVE-2025-34028` | Commvault Command Center pre-auth SSRF→RCE — version-fingerprint of the affected 11.38 Innovation Release (CISA KEV). |
| `cve_2025_32975` | `CVE-2025-32975` | Quest KACE SMA unauthenticated authentication bypass — version-fingerprint of builds below the fixed 14.1 line (CISA KEV, CVSS 10.0). |
| `miasma_k8s_001` | `MIASMA-K8S-001` | Kubernetes API server reachable without authentication (anonymous-auth) — `/version` build leak plus anonymous `/api/v1/namespaces` enumeration. |
| `cve_2025_3248` | `CVE-2025-3248` | Langflow unauthenticated RCE via `/api/v1/validate/code` — version-fingerprint of builds below the fixed 1.3.0 line (CISA KEV, CVSS 9.8). |
| `cve_2025_0282` | `CVE-2025-0282` | Ivanti Connect Secure pre-auth stack-overflow RCE — version-fingerprint of appliances below the fixed 22.7R2.5 line (CISA KEV, CVSS 9.0). |
| `cve_2026_1340` | `CVE-2026-1340` | Ivanti EPMM (MobileIron Core) unauthenticated RCE — fingerprints EPMM and checks reachability of the vulnerable `/mifs/c/{app,aft}store/fob/` feature endpoints with payload-free GETs (CISA KEV, CVSS 9.8). |

### MIASMA-ACTUATOR-001 — Spring Boot Actuator exposure

Probes for unauthenticated Spring Boot `/actuator/*` management endpoints,
which can leak environment variables, credentials, configuration, and a
downloadable heap dump. The probe is benign and read-only:

1. `GET /actuator/health` — lowest-risk baseline; confirms a Spring Boot app.
2. `GET /actuator` — confirms the management base is reachable.
3. `GET /actuator/env` — the sensitive endpoint (environment variables).
4. `GET /actuator/heapdump` — **header-only** check; the body is never
   downloaded, only `Content-Type` / `Content-Length` are inspected.

Severity:

- **high** — `/actuator/env` returns `200` with JSON keys that look like
  secrets (`password`, `secret`, `key`, `token`, `credential`).
- **medium** — the management surface is reachable but no recognised secrets
  are exposed (env reachable without secrets, or `/actuator` reachable while
  `/actuator/env` is blocked) — partial exposure still worth reporting.

Default management ports: `80, 443, 8080, 8443, 8090, 9090`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins miasma_actuator_001
```

### MIASMA-REDIS-001 — Redis unauthenticated access

Probes for a Redis instance reachable without authentication. Unauthenticated
Redis grants full read/write access to every key and also gates the
CVE-2025-49844 ("RediShell", CVSS 10.0) Lua use-after-free RCE chain on affected
builds. The probe speaks the Redis inline protocol over a raw TCP socket and is
benign and read-only:

1. Connect to a candidate port and send `PING\r\n`.
   - `+PONG` (no auth challenge) → unauthenticated access confirmed.
   - `-NOAUTH` / `-ERR ... AUTH ...` → authentication is enforced; not vulnerable.
2. On confirmed access, send `INFO server\r\n` and parse only the
   `redis_version` line for evidence.

No keys are read, no data is written, no config is touched.

Severity:

- **high** — `PING` returns `+PONG` with no authentication challenge.

When the reported `redis_version` is `<= 8.2.1`, the finding flags
`cve_2025_49844_in_scope` and notes CVE-2025-49844 in the description.

Default ports (port hints): `6379, 6380, 16379`.

```bash
miasma --target 10.0.0.7 --port-range 1-20000 --plugins miasma_redis_001
```

### CVE-2024-23897 — Jenkins unauthenticated arbitrary file read

Probes for the Jenkins CLI arbitrary file read (CVSS 9.8, affecting Jenkins
`<= 2.441` / LTS `<= 2.426.2`). The Jenkins CLI command parser expands any
argument of the form `@<path>` into that file's contents (an args4j feature),
and the `/cli` endpoint is reachable without authentication — so an attacker can
read arbitrary files off the controller (`/etc/passwd`,
`secrets/initialAdminPassword`, credential XML). The probe is benign: it targets
only the world-readable `/etc/passwd` and reports the leaked lines as evidence —
no file is written and no secret-bearing path is read.

1. `GET /login` — fingerprint Jenkins and read the `X-Jenkins` version header.
2. Drive the CLI download/upload duplex protocol against `/cli?remoting=false`
   with the args4j-framed command `who-am-i @/etc/passwd`. The resulting CLI
   error echoes the file's first lines back.

Severity:

- **high** — the CLI leaked `/etc/passwd` content (`root:` marker present in the
  reply); the file read is confirmed.
- **medium** — the reported version is within the vulnerable range
  (weekly `<= 2.441` / LTS `<= 2.426.2`) but the CLI file-read could not be
  confirmed on this probe (hardened, filtered, or endpoint changed) — worth a
  manual check.

Default ports (port hints): `8080, 80, 443, 8090`.

```bash
miasma --target 10.0.0.9 --port-range 1-10000 --plugins cve_2024_23897
```

### CVE-2025-55752 — Apache Tomcat Rewrite Valve path traversal

Probes for the Tomcat path traversal that becomes reachable when the Rewrite
Valve (`rewrite.config`) is configured. A crafted, rewrite-decoded path slips
past Tomcat's security constraints and reaches the normally-protected
`/WEB-INF/` directory, whose `web.xml` deployment descriptor routinely carries
JDBC/database credentials, JNDI resources, and application secrets. The probe is
benign and read-only — it only *attempts to read* the inert `WEB-INF/web.xml`
descriptor; nothing is written and no state changes.

1. `GET /` — fingerprint Tomcat via the `Server` header (`Apache-Coyote`/`Tomcat`).
2. `GET <traversal>/WEB-INF/web.xml` — a small ordered set of well-known
   traversal shapes. A normal request returns `403`/`404`; a `200` whose body
   contains the `<web-app` descriptor marker confirms the traversal read.

Severity:

- **high** — the protected `WEB-INF/web.xml` was returned (`200` with a
  `<web-app` marker); the path-traversal read is confirmed.
- **medium** — the host fingerprints as Tomcat and a normally-protected path
  returned a non-`403`/`404` status, but the descriptor read was not confirmed
  on this probe (hardened, partially exposed, or behind a different layout) —
  worth a manual check.

A non-Tomcat host is never flagged, even if it answers oddly, to avoid false
positives. Default ports (port hints): `8080, 8443, 80, 443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_55752
```

### CVE-2025-64446 — Fortinet FortiWeb authentication bypass

Probes for the FortiWeb (Fortinet WAF appliance) authentication bypass added to
the CISA KEV catalog in November 2025 (active exploitation observed from October
2025). A request prefixed with a *valid* API path (`/api/v2.0/cmdb/…`) and then
traversed back down to a privileged CGI handler is authorised against the
harmless prefix the router sees first, but the dot-segments silently re-target it
at an administrative endpoint — yielding unauthenticated admin access. The probe
is benign and read-only — it only *reads* the inert `system/status` endpoint and
performs no privileged action (no user creation, no config write):

1. `GET /` and `GET /login` — fingerprint FortiWeb via the `Server`/`Set-Cookie`
   headers and the login page markers.
2. `GET /api/v2.0/cmdb/system/status` — the *direct* authenticated endpoint,
   which a sane appliance refuses (`401`/`403`) without a session. This is the
   control.
3. `GET <traversal>/system/status` — the same status data reached through a
   traversal-crafted path. A `200` carrying status JSON (`serial`/`version`/
   `build` markers) while the direct path refused confirms the bypass.

Severity:

- **high** — FortiWeb fingerprinted, the traversal path returned privileged
  status data (`200` + status markers), and the direct path refused (`401`/
  `403`). The auth bypass is confirmed read-only.
- **medium** — the host fingerprints as FortiWeb but the bypass was not cleanly
  confirmed (traversal answered `200` without status markers, or the direct path
  did not refuse) — worth a manual check.

A non-FortiWeb host is never flagged, even if it answers oddly, to avoid false
positives. Default ports (port hints): `443, 80, 8443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_64446
```

### MIASMA-GIT-001 — Exposed `.git` directory

Probes for a web server that serves its `.git/` directory. When `.git/` is
reachable, an attacker can reconstruct the entire repository offline — full
source code, complete commit history, and any secrets (API keys, database
credentials, `.env` files) that were ever committed, even if later removed.
Consistently a P1/P2 bug-bounty finding; it's a misconfiguration (usually a
`git clone` into the web root), not a discrete CVE. The probe is benign and
read-only — it fetches two small, inert metadata files and never dumps objects
or reconstructs history:

1. `GET /.git/HEAD` — a genuine `.git/HEAD` is a one-line symbolic ref
   (`ref: refs/heads/<branch>`) or a raw 40-hex SHA for a detached HEAD. A
   server that returns its SPA `index.html` for every path is **not** flagged.
2. `GET /.git/config` — if the remote URL embeds credentials
   (`://user:pass@host`), that is flagged; the password is **redacted**
   (`://user:***@`) so the report never persists the leaked secret verbatim.

Severity:

- **high** — `/.git/HEAD` returns `200` with a valid Git ref; the exposed `.git`
  directory is confirmed. If `/.git/config` also leaks a credential-bearing
  remote URL, the finding evidence flags it (redacted).

Redirects are not followed: an exposed `.git/HEAD` is served as a static file,
so a redirect to a login page or SPA route means the dotfile is not directly
served and is not flagged. Default ports (port hints): `80, 443, 8080, 8443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins miasma_git_001
```

### MIASMA-ENV-001 — Exposed `.env` file

Probes for a web server that serves its application `.env` file. A served `.env`
leaks the application's most concentrated bundle of secrets — `DATABASE_URL`,
`AWS_SECRET_ACCESS_KEY`, API keys, JWT/app signing secrets, SMTP credentials —
and is among the most common high-impact bug-bounty findings, routinely caused
by misconfigured Laravel, Node.js, and Django deployments that serve the project
root statically. It's a misconfiguration, not a discrete CVE. The probe is benign
and read-only — it fetches a small, inert file at a handful of well-known dotenv
locations and never writes anything:

1. `GET /.env` — the canonical location.
2. `GET /.env.production`, `GET /.env.local`, `GET /.env.dev` — Laravel/Node
   environment-specific variants, checked when `/.env` is absent.

A `200` whose body parses as dotenv content (`KEY=value` assignment lines)
confirms exposure. A server that returns its SPA `index.html` for every path is
**not** flagged (HTML has no `KEY=` lines).

Severity:

- **high** — the served file parses as dotenv content **and** at least one key
  name looks secret-bearing (`SECRET`/`PASSWORD`/`TOKEN`/`API_KEY`/`ACCESS_KEY`/
  `DATABASE_URL`/`DSN`/…). A live `.env` with real secrets is confirmed.
- **medium** — the served file parses as dotenv content but exposes only config
  keys (no recognised secret-bearing key) — still an information-disclosure
  misconfiguration worth a manual look.

The leaked secret *values* are never persisted: evidence records only the
exposed key *names*, so the report flags the exposure without storing the
secrets verbatim. Redirects are not followed (the dotfile must be served
directly). Default ports (port hints): `80, 443, 8080, 8443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins miasma_env_001
```

### CVE-2025-41243 — Spring Cloud Gateway exposed actuator

Probes for a Spring Cloud Gateway whose actuator `gateway` endpoints are exposed
without authentication. Spring Cloud Gateway exposes `/actuator/gateway/*` to let
operators inspect and **mutate** the routing table at runtime. When those
endpoints are unauthenticated, an attacker can POST a new route carrying a Spring
Expression Language (SpEL) payload in a filter; on the next request through that
route the SpEL is evaluated, exfiltrating environment variables, credentials, and
API keys (or achieving RCE). The probe is benign and read-only — it **never**
POSTs, modifies a route, or injects an expression. It only confirms the surface
is reachable without auth:

1. `GET /actuator/gateway/routes` — the route table (a JSON array). A `200`
   serving an array confirms the mutable route surface is exposed.
2. `GET /actuator/gateway` — the gateway actuator base (fallback). A `200` JSON
   object listing gateway sub-endpoints is partial confirmation.

A server that returns its SPA `index.html` for every path is **not** flagged
(HTML doesn't parse as JSON), and a JSON *object* at the routes path is not
treated as a route table.

Severity:

- **high** — `/actuator/gateway/routes` returns `200` with a JSON array (the
  route table). The mutate-able route surface is confirmed exposed.
- **medium** — the route table is not cleanly served but the gateway actuator
  base `/actuator/gateway` returns `200` JSON (surface present, route table not
  confirmed).

Evidence records only the route count and route *ids* (operator-chosen labels,
not secrets) so a human can confirm the table is real without us touching it.
Redirects are not followed (a redirect to a login page means the surface is not
unauthenticated). Default ports (port hints): `8080, 8443, 80, 443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_41243
```

### CVE-2025-61666 — Traccar unauthenticated LFI (Windows)

Probes for the Traccar (open-source GPS fleet tracking) local file inclusion on
Windows. Traccar's default install exposes a `DefaultOverrideServlet` without
authentication; on Windows a path-normalisation failure lets an encoded traversal
escape the override root and read arbitrary files. The crown jewel is
`conf/traccar.xml` — the main config — which holds the database JDBC URL and
credentials. Affected: Traccar 6.1 – 6.8.1 on Windows. The probe is benign and
read-only — it only *reads* the inert config file, writing nothing:

1. `GET /api/server` — Traccar's unauthenticated server-info JSON. A clean 200
   carrying Traccar-specific keys (`deviceReadonly`, `mapUrl`, `bingKey`, …) is
   the primary fingerprint; the root page body is a secondary check.
2. `GET /conf/traccar.xml` — the LFI target requested **directly**. On a sane
   install this is not web-servable (`404`/`403`); that refusal is the control.
3. `GET <override-traversal>` — the same `conf/traccar.xml` reached through the
   override-servlet traversal. A `200` whose body is the Traccar properties-XML
   config while the direct path refused confirms the LFI.

A non-Traccar host is **never** flagged, even if it answers oddly, to avoid false
positives. An SPA `index.html` returned for the traversal path is not the config
(no properties-XML markers) and is not flagged. Redirects are not followed.

Severity:

- **high** — Traccar fingerprinted, the override traversal returned the
  `conf/traccar.xml` config (`200` + properties-XML markers) that the direct path
  refused (`404`/`403`). The LFI read is confirmed.
- **medium** — the host fingerprints as Traccar but the LFI was not cleanly
  confirmed (patched, non-Windows, filtered, or the direct path did not refuse) —
  a candidate worth a manual check.

The leaked secret **values** are never persisted — evidence records only the
config *key names* present (e.g. `database.password`) plus a `secret_keys_present`
flag, mirroring the redaction convention of the `.env` and `.git` plugins. Default
ports (port hints): `8082, 80, 443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_61666
```

### CVE-2025-34028 — Commvault Command Center pre-auth SSRF / RCE

Fingerprints Commvault Command Center — the web console for the widely deployed
Commvault enterprise backup suite — and flags the affected **11.38 Innovation
Release** line, which exposes `/deployWebpackage.do` without authentication and
chains to server-side request forgery and pre-auth remote code execution. Backup
appliances are crown-jewel ransomware targets, so the CVE is on CISA's KEV
catalog.

This probe is **version-fingerprint only** and never touches the vulnerable
endpoint — triggering `/deployWebpackage.do` is an active exploitation step and is
deliberately out of scope. The flow is benign and read-only:

1. `GET /commandcenter/` (then `/webconsole/`, `/commandcenter/login`, `/`) —
   fingerprint Command Center via the login-page body, the `Server` header, and
   `cv_*` login cookies. The first path that fingerprints wins for that port.
2. Read the advertised build string — Command Center exposes its release as a
   dotted `11.38` / `11.38.x` or an `SP38` service-pack tag on the login page. The
   `11.38` line is the affected window.

A non-Commvault host is **never** flagged, even if it coincidentally mentions a
`11.38`-ish string. A Commvault host on a known-safe release (e.g. `11.36`) is a
clean negative, not a candidate. Redirects are not followed.

Severity:

- **high** — Commvault Command Center fingerprinted **and** an affected `11.38`
  Innovation Release version string is present. The pre-auth SSRF→RCE surface is
  exposed; flag for an operator-driven active check (which miasma does not run).
- **medium** — Command Center fingerprinted but **no** version string could be
  read (hardened login page or stripped banner) — worth a manual version check.

The vulnerable `/deployWebpackage.do` endpoint is **never** contacted and no
credentials are submitted; evidence records only the fingerprint path, `Server`
header, and the version string read from the public login page. Default ports
(port hints): `443, 80, 8443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_34028
```

### CVE-2025-32975 — Quest KACE SMA authentication bypass

Fingerprints Quest KACE SMA (Systems Management Appliance) — an enterprise IT
endpoint-management appliance that pushes software and patches to managed hosts —
and flags builds below the fixed **14.1** line (the March 2025 patch). Those
versions carry an authentication bypass (CVSS 10.0) that hands an attacker a full
administrator session without credentials, making a hijacked console a fleet-wide
foothold. The CVE is on CISA's KEV catalog with confirmed in-the-wild
exploitation.

This probe is **version-fingerprint only** and never attempts the bypass —
performing it is an active exploitation step and is deliberately out of scope. The
flow is benign and read-only:

1. `GET /userui/login.php` (then `/userui/`, `/adminui/login.php`, `/`) —
   fingerprint KACE via the login-page body, the `X-KACE-*` headers, and the
   `kboxid` login cookie. The first path that fingerprints wins for that port.
2. Read the advertised build — KACE exposes a dotted `MAJOR.MINOR.PATCH` string
   in an `X-KACE-Version` header or on the login page. Anything below `14.1` is
   the affected window; `14.1` and above is fixed.

A non-KACE host is **never** flagged, even if it coincidentally mentions a
`14.0`-ish string. A KACE host on a fixed release (`14.1`+) is a clean negative,
not a candidate. Redirects are not followed.

Severity:

- **high** — KACE SMA fingerprinted **and** an affected version (below `14.1`) is
  present. The unauthenticated admin-takeover surface is exposed; flag for an
  operator-driven active check (which miasma does not run).
- **medium** — KACE SMA fingerprinted but **no** version string could be read
  (hardened login page or stripped banner) — worth a manual version check.

The authentication bypass is **never** attempted and no credentials are
submitted; evidence records only the fingerprint path, `Server` header, and the
version string read from the public login page. Default ports (port hints):
`443, 80`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_32975
```

### MIASMA-K8S-001 — Kubernetes API server unauthenticated access

Detects a Kubernetes API server with **anonymous authentication** enabled
(`--anonymous-auth=true` — the default on older clusters, still common on
self-managed installs). The API server is the control-plane front door, so
anonymous read access is a direct path toward cluster compromise and a recurring
P1/P2 cloud-native bug-bounty finding. The probe is **enumeration only** — it
never sends credentials or tokens, never reads Secret contents, and never
mutates a resource. The flow is benign and read-only:

1. `GET /version` — the API server's build endpoint. On an anonymous-enabled
   cluster this returns a JSON object carrying `gitVersion`/`major`/`minor`,
   which is both the canonical Kubernetes fingerprint **and** confirms anonymous
   read in one request. A non-JSON or non-Kubernetes `200` is **never** treated
   as a fingerprint.
2. `GET /api/v1/namespaces` — consulted only after `/version` fingerprints
   Kubernetes. A `200` carrying a `NamespaceList` means anonymous access reaches
   live cluster resources; a `401`/`403` is the secure refusal.

Severity:

- **high** — the host fingerprints as a Kubernetes API server **and**
  `/api/v1/namespaces` returns a `NamespaceList`. Anonymous access reaches live
  resources. Evidence records only the namespace **count** — never their names,
  secrets, or any resource contents.
- **medium** — `/version` answers anonymously (a build-version information leak)
  but namespace enumeration is refused (`401`/`403`) — worth a manual deeper
  check.

A host that refuses `/version` anonymously, a non-Kubernetes JSON/HTML `200`, or
a bare namespace `200` without the `/version` fingerprint is **never** flagged.
Redirects are not followed and no `Authorization` header is ever sent. Default
ports (port hints): `6443, 8443, 443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins miasma_k8s_001
```

### CVE-2025-3248 — Langflow unauthenticated remote code execution

Detects a [Langflow](https://github.com/langflow-ai/langflow) deployment on a
build affected by **CVE-2025-3248** (CVSS 9.8, CISA KEV May 2025). Before 1.3.0,
Langflow's `/api/v1/validate/code` endpoint compiles and executes
attacker-supplied Python via `exec` **without authentication** — a pre-auth RCE
on a framework that commonly holds downstream LLM-provider and internal API keys.
The probe is **version-fingerprint only** — it never POSTs and **never** contacts
the vulnerable `/api/v1/validate/code` endpoint (triggering it is active RCE and
out of scope). The flow is benign and read-only:

1. `GET /api/v1/version` — Langflow's unauthenticated version endpoint, which is
   both the Langflow fingerprint (a `langflow` marker in the body/headers) **and**
   the affected-version source in one request. `/health` and `/` are tried as
   fallbacks to fingerprint Langflow when the version endpoint is stripped.
2. The advertised build is compared to the fixed `1.3.0` line; any build strictly
   below `1.3.0` is the affected window.

Severity:

- **high** — the host fingerprints as Langflow **and** an affected `< 1.3.0`
  version is present. The pre-auth RCE surface is exposed; flagged for an
  operator-driven active check.
- **medium** — Langflow fingerprints but no version string could be read
  (hardened/stripped deployment) — worth a manual version check.

A non-Langflow host (a bare `{"version": ...}` JSON without a `langflow` marker is
never treated as a fingerprint) and a Langflow host on a fixed release (`1.3.0`+)
are **never** flagged. Redirects are not followed and no `Authorization` header is
ever sent. Default ports (port hints): `7860, 80, 443, 8080, 8443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_3248
```

### CVE-2025-0282 — Ivanti Connect Secure pre-auth stack-overflow RCE

Detects an [Ivanti Connect Secure](https://www.ivanti.com/) (formerly Pulse
Connect Secure) / Policy Secure / Neurons for ZTA gateway on a build affected by
**CVE-2025-0282** (CVSS 9.0, CISA KEV January 2025). Before `22.7R2.5` the web
component contains an **unauthenticated** stack-based buffer overflow allowing
pre-auth remote code execution; it was exploited in the wild by a China-nexus
actor deploying the SPAWN malware family. The probe is **version-fingerprint
only** — the vulnerability is a memory-corruption overflow, so actually
triggering it would crash or compromise the appliance and is out of scope. No
overflow payload is ever sent; the flow is benign and read-only:

1. `GET /dana-na/nc/nc_gina_ver.txt` — Ivanti's unauthenticated GINA client
   version file, which is both an Ivanti fingerprint **and** the affected-version
   source in one request. `/dana-na/auth/url_default/welcome.cgi`, `/dana-na/`,
   and `/` are tried as fallbacks to fingerprint Ivanti when the version file is
   stripped.
2. The advertised build (Ivanti's `MAJOR.MINORRn.m` form, e.g. `22.7R2.4`) is
   compared to the fixed `22.7R2.5` line; any build strictly below it is the
   affected window.

Severity:

- **high** — the host fingerprints as Ivanti Connect Secure **and** an affected
  `< 22.7R2.5` version is present. The pre-auth RCE surface is exposed; flagged
  for an operator-driven active check.
- **medium** — Ivanti fingerprints but no version string could be read
  (hardened/stripped appliance) — worth a manual version check.

A non-Ivanti host (a bare version-looking token without an Ivanti marker is never
treated as a fingerprint) and an Ivanti appliance on a fixed release
(`22.7R2.5`+) are **never** flagged. Redirects are not followed and no
`Authorization` header is ever sent. Default ports (port hints): `443, 80, 8443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2025_0282
```

### CVE-2026-1340 — Ivanti EPMM unauthenticated remote code execution

Detects an [Ivanti Endpoint Manager Mobile](https://www.ivanti.com/) (EPMM,
formerly MobileIron Core) deployment exposed to **CVE-2026-1340** (CVSS 9.8,
with sibling **CVE-2026-1281**, on CISA's KEV catalog). EPMM's "In-House
Application Distribution" (`/mifs/c/appstore/fob/`) and "Android File Transfer
Configuration" (`/mifs/c/aftstore/fob/`) feature endpoints accept an
unauthenticated HTTP request that smuggles a Bash command into the request and
executes it as an OS command on the appliance — a pre-auth RCE. Ivanti shipped
emergency patches on 2026-01-29; both bugs were exploited in the wild as
zero-days. The permanent fix lands in EPMM 12.8.0.0; the 12.5.x / 12.6.x /
12.7.x (and earlier) branches are affected unless the emergency RPM is applied.
EPMM is the enterprise MDM control plane (it manages enrolled mobile fleets), so
a compromised appliance is a fleet-wide foothold — and there were >2,000
internet-exposed instances at disclosure.

This probe is **benign and never triggers the RCE**. The vulnerability fires
only when a Bash *command* is smuggled into the request; this probe sends **no
command, no payload, no injection** — only plain unauthenticated GETs of public
paths. Unlike the version-fingerprint-only plugins, EPMM does not serve its build
version to unauthenticated HTTP on a sane appliance, so the primary signal is the
**reachability of the vulnerable feature endpoints**:

1. `GET /mifs/admin` (then `/mifs/`, `/mifs/c/windows/admin`, `/`) — fingerprint
   EPMM via the "Ivanti User Portal: Sign In" / MobileIron login markup, the
   `Server` header, and the EPMM session cookies. A non-EPMM host is **never**
   flagged.
2. `GET /mifs/c/appstore/fob/` and `GET /mifs/c/aftstore/fob/` — the two
   vulnerable feature endpoints, requested with **no command payload**. Ivanti's
   own detection guidance treats a `404` as "the path is not serving"; a routed
   (non-`404`) response on a fingerprinted EPMM host confirms the vulnerable
   feature surface is present and exposed. No command is ever sent, so the RCE is
   never triggered.
3. The EPMM build string is read opportunistically if it leaks on the public
   surface; an affected `< 12.8.0.0` build reinforces / upgrades the finding.

Severity:

- **high** — the host fingerprints as EPMM **and** (a vulnerable feature endpoint
  is routed/reachable **or** a readable build is in the affected `< 12.8.0.0`
  window). The unauthenticated RCE surface is exposed; flag for an
  operator-driven active check (which miasma skips).
- **medium** — EPMM fingerprints but neither a vulnerable endpoint is confirmed
  reachable nor a build string could be read (hardened/stripped, or patched via
  the emergency RPM which leaves the advertised version unchanged) — worth a
  manual check, since it might still be the affected line.

A non-EPMM host is **never** flagged, even if a `/mifs/c/...fob/` path
coincidentally answers `200`, because the EPMM fingerprint gates the whole probe.
An EPMM host on a patched (`>= 12.8.0.0`) build with no reachable endpoint is a
clean negative. Redirects are not followed and no `Authorization` header is ever
sent. Default ports (port hints): `443, 80, 8443`.

```bash
miasma --target 10.0.0.5 --port-range 1-10000 --plugins cve_2026_1340
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite mocks `nmap` at the shared `nmap-wrapper` seam
(`nmap_wrapper.scanner._new_scanner`), so it's green on systems without `nmap`
installed.

## License

MIT — see [LICENSE](LICENSE).
