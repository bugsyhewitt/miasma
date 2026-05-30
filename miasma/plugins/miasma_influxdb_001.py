"""MIASMA-INFLUXDB-001 — InfluxDB unauthenticated HTTP API exposure.

InfluxDB is the dominant open-source time-series database for metrics, IoT
telemetry, application-performance-monitoring backends, and SRE dashboards.
Two recurring misconfigurations turn an internet- or broadly-internal-
reachable InfluxDB into a P1/critical finding:

    1. **InfluxDB 1.x — auth disabled (the shipped default).** The 1.x
       configuration file ships with ``[http] auth-enabled = false``; until
       an operator flips that flag and creates an admin user, every HTTP API
       endpoint answers any peer that can reach the default port 8086. An
       unauthenticated peer can read every measurement in every database
       (``SHOW DATABASES`` → ``SELECT * FROM <m>``), write or delete
       arbitrary points, ``DROP DATABASE``, and on builds before the
       2019 hardening can read the OS via the ``CREATE SUBSCRIPTION`` UDP
       sink. The probe confirms via the documented unauthenticated query
       endpoint: ``GET /query?q=SHOW DATABASES`` returns a 200 with a
       ``results[0].series[0].values`` array — the cluster-wide database
       inventory.

    2. **InfluxDB 2.x — uninitialised "setup mode".** A freshly installed
       2.x server with no admin token configured exposes ``/api/v2/setup``
       in "allowed" state. ``GET /api/v2/setup`` returns
       ``{"allowed": true}`` while the appliance is waiting for its first
       admin to be created. Any peer that POSTs to ``/api/v2/setup`` first
       wins the admin token, the initial org, the initial bucket — full
       takeover. The probe NEVER POSTs; it only reads ``GET /api/v2/setup``
       and reports the exposed setup window for a human to claim before an
       attacker does. (A 2.x server with auth already configured returns
       ``{"allowed": false}``, which is the secure state and is not flagged.)

This probe is BENIGN and read-only. No measurement is read, no point is
written, no database is created or dropped, no admin is created. The probe
runs the minimal GET requests a human would run by hand to confirm the
exposure and then stops:

    1. ``GET /health`` — fingerprints InfluxDB 2.x. A genuine reply is a
       JSON object carrying ``name == "influxdb"`` (case-insensitive) and a
       parseable ``version`` string. This identifies a 2.x server but does
       not on its own confirm exposure; the setup-allowed check follows.
    2. ``GET /ping`` — fingerprints InfluxDB 1.x. The 1.x server answers
       with the ``X-Influxdb-Version`` response header (and on newer 1.x
       builds the ``X-Influxdb-Build`` header). A non-empty
       ``X-Influxdb-Version`` value is a InfluxDB-specific marker that no
       other product ships.
    3. ``GET /api/v2/setup`` — for fingerprinted 2.x servers, confirms
       whether the appliance is sitting in unconfigured setup mode.
       ``allowed: true`` → HIGH (any peer can claim the admin token).
    4. ``GET /query?q=SHOW DATABASES`` — for fingerprinted 1.x servers,
       confirms whether the HTTP API answers privileged metadata queries
       without authentication. A 200 with a ``results[0].series[0].values``
       array → HIGH (the database inventory is readable, which gates full
       read/write/delete of every measurement in every database).

A non-InfluxDB host (a coincidental JSON 200 on ``/health`` without the
``name == "influxdb"`` marker, or a 200 on ``/ping`` without the
``X-Influxdb-Version`` header) is NEVER flagged. A 1.x server that answers
``/ping`` but refuses ``/query`` with a 401 / 403 (auth enabled) is a clean
negative. A 2.x server whose ``/api/v2/setup`` returns ``{"allowed":
false}`` (already initialised) is a clean negative. Redirects are not
followed.

Evidence records only the host, port, InfluxDB major version (1.x / 2.x),
the version string, and either the database **count** (1.x) or the
``setup_allowed`` boolean (2.x). Database names, measurement names, point
values, and tokens are NEVER read or stored.

Severity matrix:
    * HIGH — InfluxDB 1.x fingerprints AND ``/query?q=SHOW DATABASES``
             returns the database inventory without authentication, OR
             InfluxDB 2.x fingerprints AND ``/api/v2/setup`` returns
             ``allowed: true`` (the admin-token claim window is open to
             any peer).
    * none  — Not InfluxDB, InfluxDB 1.x with auth enforced (``/query``
              refused), or InfluxDB 2.x already initialised
              (``allowed: false``).

Candidate ports: ``8086`` (the documented default for both 1.x and 2.x),
``8087`` (a conventional secondary-instance port), ``80`` and ``443`` (the
common reverse-proxy fronts; ``443`` is contacted over HTTPS, everything
else over plain HTTP).

[Worker decision: filename is miasma_influxdb_001.py (underscores) because
the runner discovers plugins via importlib and module names cannot contain
hyphens; canonical id MIASMA-INFLUXDB-001 lives in metadata["vuln_id"],
matching the existing miasma_*_001.py convention. MIASMA-MONGODB-001 (the
primary spec target) was already shipped (#28 in the bundled-plugins
table), so this rotation pivots to the spec's explicitly-named secondary
target MIASMA-INFLUXDB-001 per the spec's "verify against the actual
codebase before implementing" clause. InfluxDB completes the time-series
/ metrics-stack family alongside the existing miasma_prometheus_001
(Prometheus is the scrape engine; InfluxDB is the long-term storage tier
that operators routinely point Prometheus at via remote_write). Both 1.x
auth-disabled and 2.x setup-allowed paths are covered in one plugin
because both share the same /ping + /health fingerprint surface and both
collapse to a single HIGH finding for an operator — splitting them would
duplicate the fingerprint work without clarifying the report.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-INFLUXDB-001",
    "name": "InfluxDB Unauthenticated HTTP API Exposure",
    "description": (
        "InfluxDB reachable without authentication on its HTTP API. "
        "InfluxDB 1.x ships with [http] auth-enabled = false by default, so "
        "an unauthenticated peer can read every database (SHOW DATABASES), "
        "every measurement, and write or delete arbitrary points. "
        "InfluxDB 2.x exposes /api/v2/setup in 'allowed' state while the "
        "appliance is uninitialised — any peer that POSTs first wins the "
        "admin token, the initial org, and the initial bucket. Both "
        "misconfigurations are routinely the highest-impact finding on a "
        "time-series / observability estate."
    ),
    "confidence": "high",
    "references": [
        "https://docs.influxdata.com/influxdb/v1/administration/authentication_and_authorization/",
        "https://docs.influxdata.com/influxdb/v2/install/?t=Linux#set-up-influxdb-v2",
        "https://docs.influxdata.com/influxdb/v2/api/#operation/PostSetup",
        "https://docs.influxdata.com/influxdb/v1/tools/api/#ping-http-endpoint",
        "https://owasp.org/www-community/Broken_Access_Control",
    ],
    "port_hint": [8086, 8087, 80, 443],
    "service_hint": ["influxdb", "influx", "http", "https"],
    "default_ports": [8086, 8087, 80, 443],
}

_TIMEOUT = 5.0

# Canonical TLS ports for the reverse-proxy front; everything else plain HTTP.
_HTTPS_PORTS = (443,)

# The InfluxDB 1.x /ping response header that no other product ships.
_INFLUXDB_VERSION_HEADER = "x-influxdb-version"
_INFLUXDB_BUILD_HEADER = "x-influxdb-build"

# Top-level marker in the InfluxDB 2.x /health JSON body. The 2.x server
# answers /health with {"name": "influxdb", "message": "...", "status":
# "pass", "version": "2.7.5", ...}; the "name" field is the unique marker.
_INFLUXDB_2X_NAME_MARKER = "influxdb"


def _candidate_ports(target: Target) -> list[int]:
    open_ports = target.open_ports()
    if open_ports:
        influx_like = [
            port
            for port in open_ports
            if "influx" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return influx_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


def _get(url: str) -> httpx.Response | None:
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _parse_2x_health(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the parsed /health body if it identifies as InfluxDB 2.x.

    Genuine InfluxDB 2.x /health has:
      * status_code == 200
      * a JSON object body
      * a ``name`` field containing "influxdb" (case-insensitive)
      * a parseable ``version`` string
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    name_field = body.get("name")
    if not isinstance(name_field, str):
        return None
    if _INFLUXDB_2X_NAME_MARKER not in name_field.lower():
        return None
    version_field = body.get("version")
    if not isinstance(version_field, str) or not version_field:
        return None
    return body


def _parse_1x_ping(resp: httpx.Response) -> dict[str, str] | None:
    """Return version metadata if /ping identifies as InfluxDB 1.x.

    The 1.x /ping endpoint answers ``204 No Content`` (or ``200`` with
    ``?verbose=true``) and always carries an ``X-Influxdb-Version`` header
    whose value is the semver build string. That header is InfluxDB-specific
    and no other product ships it. A reply without the header is not InfluxDB.
    """
    # /ping is documented as 204 (default) or 200 (verbose). Anything else
    # is either an error response or a non-InfluxDB service.
    if resp.status_code not in (200, 204):
        return None
    version = resp.headers.get(_INFLUXDB_VERSION_HEADER)
    if not isinstance(version, str) or not version:
        return None
    out: dict[str, str] = {"version": version}
    build = resp.headers.get(_INFLUXDB_BUILD_HEADER)
    if isinstance(build, str) and build:
        out["build"] = build
    return out


def _parse_setup_allowed(resp: httpx.Response) -> bool | None:
    """Return the ``allowed`` boolean from /api/v2/setup, or None if not parseable.

    The 2.x setup endpoint answers ``{"allowed": true}`` while the appliance
    is uninitialised and ``{"allowed": false}`` after the initial admin has
    been created. Anything else (non-200, non-JSON, missing key) returns None
    and is treated as "could not confirm exposure" rather than a positive.
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    allowed = body.get("allowed")
    if not isinstance(allowed, bool):
        return None
    return allowed


def _count_databases(resp: httpx.Response) -> int | None:
    """Return the database count from /query?q=SHOW DATABASES, or None.

    The 1.x query endpoint answers ``{"results": [{"series": [{"name":
    "databases", "columns": ["name"], "values": [["_internal"], ...]}]}]}``
    on success. A 200 carrying that shape confirms unauthenticated metadata
    access — even a single-row reply (the always-present ``_internal``
    database) is a positive. A 401 / 403 / non-JSON / shape mismatch is None
    and not flagged.
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    results = body.get("results")
    if not isinstance(results, list) or not results:
        return None
    first = results[0]
    if not isinstance(first, dict):
        return None
    series = first.get("series")
    if not isinstance(series, list) or not series:
        return None
    first_series = series[0]
    if not isinstance(first_series, dict):
        return None
    values = first_series.get("values")
    if not isinstance(values, list):
        return None
    return len(values)


def _probe_port(target: Target, port: int) -> Finding | None:
    base = f"{_scheme(port)}://{target.host}:{port}"

    # --- Try InfluxDB 2.x first via /health. ---
    health_resp = _get(f"{base}/health")
    if health_resp is not None:
        health_body = _parse_2x_health(health_resp)
        if health_body is not None:
            setup_resp = _get(f"{base}/api/v2/setup")
            if setup_resp is not None:
                allowed = _parse_setup_allowed(setup_resp)
                if allowed is True:
                    evidence: dict[str, Any] = {
                        "host": target.host,
                        "port": port,
                        "influxdb_major": "2.x",
                        "influxdb_version": health_body.get("version"),
                        "setup_allowed": True,
                    }
                    commit = health_body.get("commit")
                    if isinstance(commit, str) and commit:
                        evidence["commit"] = commit
                    return Finding(
                        vuln_id=metadata["vuln_id"],
                        host=target.host,
                        confidence="high",
                        evidence=evidence,
                        description=(
                            metadata["description"]
                            + " /api/v2/setup answers 200 with "
                            "{\"allowed\": true} — the appliance is in "
                            "uninitialised setup mode and any peer that "
                            "POSTs to /api/v2/setup first wins the admin "
                            "token, the initial org, and the initial bucket."
                        ),
                    )
            # InfluxDB 2.x fingerprinted but setup is not 'allowed' — the
            # appliance is already initialised. Clean negative on this port;
            # do not fall through to the 1.x query path on the same server.
            return None

    # --- Fall back to InfluxDB 1.x via /ping + /query. ---
    ping_resp = _get(f"{base}/ping")
    if ping_resp is None:
        return None
    ping_meta = _parse_1x_ping(ping_resp)
    if ping_meta is None:
        return None

    query_resp = _get(f"{base}/query?q=SHOW%20DATABASES")
    if query_resp is None:
        return None
    db_count = _count_databases(query_resp)
    if db_count is None:
        # 1.x fingerprinted but /query refused — auth is enforced. Not flagged.
        return None

    evidence = {
        "host": target.host,
        "port": port,
        "influxdb_major": "1.x",
        "influxdb_version": ping_meta["version"],
        "database_count": db_count,
    }
    if "build" in ping_meta:
        evidence["build"] = ping_meta["build"]
    return Finding(
        vuln_id=metadata["vuln_id"],
        host=target.host,
        confidence="high",
        evidence=evidence,
        description=(
            metadata["description"]
            + " /query?q=SHOW DATABASES answers 200 with the database "
            "inventory and no authentication challenge — every database, "
            "every measurement, and full write/delete of every point is "
            "reachable without credentials."
        ),
    )


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        finding = _probe_port(target, port)
        if finding is not None:
            return finding
    return None
