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

## Bundled plugins

| Plugin | Vuln ID | Purpose |
|---|---|---|
| `test_always_finds` | `MIASMA-TEST-0001` | Canonical test plugin — always returns a finding. |
| `cve_2009_3548` | `CVE-2009-3548` | Apache Tomcat default/weak manager credentials. |
| `miasma_actuator_001` | `MIASMA-ACTUATOR-001` | Exposed Spring Boot Actuator management endpoints (env/secret leak, heap dump). |
| `miasma_redis_001` | `MIASMA-REDIS-001` | Redis reachable without authentication (PING/INFO handshake). |

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
