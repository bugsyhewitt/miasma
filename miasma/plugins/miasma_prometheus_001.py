"""MIASMA-PROMETHEUS-001 — Prometheus unauthenticated HTTP API access.

Prometheus ships with **no authentication, no authorization, and no TLS** on its
HTTP API. The upstream project explicitly states that securing the endpoint is
the operator's responsibility (reverse proxy, network policy), so an instance
reachable on its default port 9090 exposes the full read API to any client that
can reach it. That API is a goldmine for an attacker mapping an internal estate:

    * /api/v1/targets   — every scrape target, i.e. the host:port of every
                          monitored service. This is a live, authoritative
                          inventory of the internal network — far better than a
                          port scan because Prometheus already did the discovery.
    * /api/v1/status/config — the running configuration, including scrape
                          configs, relabeling rules, alertmanager endpoints, and
                          (on misconfigured deployments) bearer tokens / basic-
                          auth passwords embedded in scrape_configs.
    * /api/v1/status/buildinfo — version banner, used to scope known CVEs.

Bug-bounty programs routinely rate an internet-exposed, unauthenticated
Prometheus as P2/MEDIUM for the inventory leak alone, escalating to P1/HIGH when
the config endpoint discloses credentials.

This probe is BENIGN and read-only. It runs the three minimal GET requests a
human would run by hand to confirm the finding:

    1. GET /api/v1/status/buildinfo — fingerprints Prometheus; a genuine reply
       is ``{"status":"success","data":{"version": ...}}`` carrying the
       ``version``/``revision``/``goVersion`` keys unique to the Prometheus API.
    2. GET /api/v1/targets — confirms the scrape-target inventory is readable
       without authentication and captures the active-target count.
    3. GET /api/v1/status/config — confirms the running config is readable; the
       raw YAML is scanned (not stored) for credential markers to raise severity.

No query is run, no rule is mutated, no admin endpoint (/-/reload, the TSDB admin
API) is touched. Only the read status endpoints are contacted — exactly the
handshake used to confirm the finding by hand.

Severity matrix:
    * HIGH   — buildinfo confirms Prometheus AND /status/config is readable and
               its body contains credential markers (password/bearer_token).
    * HIGH   — /api/v1/targets enumerates one or more active scrape targets
               without authentication (internal inventory leak).
    * MEDIUM — buildinfo confirms Prometheus and at least one status endpoint is
               readable, but no targets and no credentials were observed
               (still an unauthenticated API surface worth reporting).
    * none   — Prometheus not fingerprinted, or the API is authenticated.

Candidate ports: 9090 (primary), 80, 443, 8080, 9091 (pushgateway/proxy fronts).

[Worker decision: plugin filename is miasma_prometheus_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-PROMETHEUS-001 lives in
metadata["vuln_id"], matching the existing miasma_solr_001.py /
miasma_grafana_001.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-PROMETHEUS-001",
    "name": "Prometheus Unauthenticated HTTP API Access",
    "description": (
        "Prometheus HTTP API reachable without authentication, exposing the "
        "full scrape-target inventory (every monitored host:port), the running "
        "configuration, and the version banner. Prometheus ships with no auth, "
        "authz, or TLS by default; the /api/v1/targets inventory is an "
        "authoritative map of the internal estate, and /api/v1/status/config "
        "can leak scrape-config credentials."
    ),
    "confidence": "high",
    "references": [
        "https://prometheus.io/docs/operating/security/",
        "https://prometheus.io/docs/prometheus/latest/querying/api/",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [9090, 80, 443, 8080, 9091],
    "service_hint": ["prometheus", "http", "https"],
    "default_ports": [9090, 80, 443, 8080, 9091],
}

# Keys present in a genuine /api/v1/status/buildinfo data object. The Prometheus
# API answers this endpoint with a small object carrying these keys on every
# build that exposes it (Prometheus 2.14+).
_BUILDINFO_KEYS = ("version", "revision", "goVersion")

# Markers that, if present in the raw /status/config YAML, indicate the running
# configuration is leaking scrape-time credentials — escalates the finding.
_CREDENTIAL_MARKERS = ("password", "bearer_token", "credentials")

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Prometheus-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        prom_like = [
            port
            for port in open_ports
            if "prometheus" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return prom_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS only for the canonical TLS port; everything else plain HTTP."""
    return "https" if port == 443 else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign unauthenticated GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common on
    internal Prometheus deployments fronted by a reverse proxy.
    """
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _buildinfo(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the buildinfo ``data`` object if genuinely Prometheus, else None."""
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict) or body.get("status") != "success":
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    if all(key in data for key in _BUILDINFO_KEYS):
        return data
    return None


def _parse_version(data: dict[str, Any]) -> str | None:
    """Pull the Prometheus version from a buildinfo data object (None if absent)."""
    value = data.get("version")
    if isinstance(value, str) and value:
        return value
    return None


def _count_active_targets(base: str) -> int | None:
    """GET /api/v1/targets and return the active-target count.

    Returns ``None`` when the request fails or the endpoint is authenticated;
    an int (possibly 0) when the endpoint answered with a parseable target list.
    """
    resp = _get(f"{base}/api/v1/targets")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict) or body.get("status") != "success":
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    active = data.get("activeTargets")
    if not isinstance(active, list):
        return None
    return len(active)


def _config_leaks_credentials(base: str) -> bool | None:
    """GET /api/v1/status/config and report whether it leaks credentials.

    Returns ``None`` when the config endpoint is unreachable/authenticated,
    ``True`` when the running config's YAML contains a credential marker, and
    ``False`` when the config is readable but no markers were found. The raw
    YAML is scanned in-memory only — it is never stored in the finding.
    """
    resp = _get(f"{base}/api/v1/status/config")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict) or body.get("status") != "success":
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    yaml_text = data.get("yaml")
    if not isinstance(yaml_text, str):
        return None
    lowered = yaml_text.lower()
    return any(marker in lowered for marker in _CREDENTIAL_MARKERS)


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        buildinfo_resp = _get(f"{base}/api/v1/status/buildinfo")
        if buildinfo_resp is None:
            continue

        data = _buildinfo(buildinfo_resp)
        if data is None:
            # Not Prometheus on this port (or buildinfo auth-gated) — try next.
            continue

        version = _parse_version(data)

        # Two supplementary unauthenticated reads, both benign.
        target_count = _count_active_targets(base)
        config_creds = _config_leaks_credentials(base)

        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "version": version,
            "api_unauthenticated": True,
        }

        # --- Path A: config leaks credentials => HIGH ---
        if config_creds is True:
            evidence["config_readable"] = True
            evidence["config_leaks_credentials"] = True
            if target_count is not None:
                evidence["targets_exposed"] = True
                evidence["active_target_count"] = target_count
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence=evidence,
                description=(
                    metadata["description"]
                    + " The /api/v1/status/config endpoint returned the running "
                    "configuration without authentication, and the config "
                    "contains scrape-time credential markers "
                    "(password/bearer_token)."
                ),
            )

        # --- Path B: scrape-target inventory readable => HIGH ---
        if target_count is not None:
            evidence["targets_exposed"] = True
            evidence["active_target_count"] = target_count
            if config_creds is False:
                evidence["config_readable"] = True
                evidence["config_leaks_credentials"] = False
            if target_count > 0:
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence=evidence,
                    description=(
                        metadata["description"]
                        + " The /api/v1/targets endpoint enumerated "
                        f"{target_count} active scrape target(s) without "
                        "authentication — the internal service inventory is "
                        "exposed."
                    ),
                )
            # targets endpoint readable but empty — still unauthenticated.
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="medium",
                evidence=evidence,
                description=(
                    metadata["description"]
                    + " The status API answered without authentication; the "
                    "scrape-target list was readable but empty."
                ),
            )

        # --- Path C: only buildinfo (and maybe config w/o creds) readable ---
        if config_creds is False:
            evidence["config_readable"] = True
            evidence["config_leaks_credentials"] = False
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence=evidence,
            description=(
                metadata["description"]
                + " The /api/v1/status/buildinfo endpoint answered without "
                "authentication (version and build metadata exposed); the "
                "scrape-target inventory was not reachable on this port."
            ),
        )

    return None
