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
