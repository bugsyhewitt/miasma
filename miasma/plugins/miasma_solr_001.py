"""MIASMA-SOLR-001 — Apache Solr unauthenticated Admin API access.

Apache Solr ships with **no authentication enabled by default**. Out of the box
the Admin API — including the system-info, core-listing, config, and (on many
builds) the SQL/stream/replication handlers — is reachable by any client that
can reach the HTTP port. An exposed Solr instance leaks the indexed dataset, the
schema, the JVM/OS fingerprint, and every configured core, and it is the entry
point for a documented RCE chain:

    * CVE-2019-17558 — the VelocityResponseWriter ``params.resource.loader``
      template injection -> RCE, reachable on any core with config-API access.
    * CVE-2017-12629 — RemoteStreaming / XXE on the config and replication
      handlers.

Unauthenticated Admin API access is exactly the precondition both chains assume,
so the version banner is captured to scope affected builds. Bug bounty programs
rate an internet-exposed, unauthenticated Solr Admin API as P1/critical.

This probe is BENIGN and read-only. It runs the two minimal requests a human
would run by hand to confirm the finding:

    1. GET /solr/admin/info/system?wt=json  — fingerprints Solr; the JSON body
       carries the ``lucene``/``solr_home``/``jvm`` keys unique to Solr and the
       ``lucene.solr-spec-version`` (or ``solr-spec-version``) version banner.
    2. GET /solr/admin/cores?wt=json        — with no credentials. A 200 whose
       ``status`` object enumerates one or more cores confirms full Admin API
       access (HIGH). When system-info answered but core-listing is auth-gated,
       the reachable Admin surface is still reported (MEDIUM).

No document is read, no core is created, no config is written, no template is
rendered — exactly the system/cores handshake used to confirm the finding by
hand. The RCE handlers are NEVER invoked; the version is only fingerprinted.

Severity matrix:
    * HIGH   — /solr/admin/cores enumerates cores without authentication.
    * MEDIUM — /solr/admin/info/system answers but core-listing is auth-gated
               (partial Admin-API exposure still worth reporting).
    * none   — Solr not fingerprinted, or the Admin API is authenticated.

Candidate ports: 8983 (primary), 8984, 80, 443, 8080 (reverse-proxy fronts).

[Worker decision: plugin filename is miasma_solr_001.py (underscores) because
the runner discovers plugins via importlib and module names cannot contain
hyphens. The canonical id MIASMA-SOLR-001 lives in metadata["vuln_id"],
matching the existing miasma_grafana_001.py / miasma_redis_001.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-SOLR-001",
    "name": "Apache Solr Unauthenticated Admin API Access",
    "description": (
        "Apache Solr Admin API reachable without authentication, exposing the "
        "indexed data, schema, JVM/OS fingerprint, and every configured core. "
        "Solr ships with auth disabled by default; the exposed Admin API also "
        "gates the CVE-2019-17558 (VelocityResponseWriter template injection) "
        "and CVE-2017-12629 (RemoteStreaming/XXE) RCE chains."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-17558",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-12629",
        "https://solr.apache.org/guide/solr/latest/deployment-guide/securing-solr.html",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [8983, 8984, 80, 443, 8080],
    "service_hint": ["solr", "http", "https"],
    "default_ports": [8983, 8984, 80, 443, 8080],
}

# Keys present in a genuine Solr /admin/info/system JSON body. Solr answers this
# endpoint with a small object carrying these top-level keys on every build.
_SYSTEM_KEYS = ("lucene", "jvm")

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Solr-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        solr_like = [
            port
            for port in open_ports
            if "solr" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return solr_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS only for the canonical TLS port; everything else plain HTTP."""
    return "https" if port == 443 else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign unauthenticated GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common on
    internal Solr deployments fronted by a reverse proxy.
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


def _system_info(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the parsed /admin/info/system body if genuinely Solr, else None."""
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    if all(key in body for key in _SYSTEM_KEYS):
        return body
    return None


def _parse_version(system: dict[str, Any]) -> str | None:
    """Pull the Solr spec version from a /admin/info/system body (None if absent).

    Newer Solr nests the banner under ``lucene.solr-spec-version``; some builds
    expose ``lucene.lucene-spec-version`` or a top-level ``solr-spec-version``.
    """
    lucene = system.get("lucene")
    if isinstance(lucene, dict):
        for key in ("solr-spec-version", "solr-impl-version"):
            value = lucene.get(key)
            if isinstance(value, str) and value:
                return value
    top = system.get("solr-spec-version")
    if isinstance(top, str) and top:
        return top
    return None


def _enumerate_cores(base: str) -> list[str] | None:
    """GET /admin/cores with no auth. Return the core names if enumeration works.

    Returns ``None`` when the request fails or the Admin API is authenticated;
    an empty list when the endpoint answered but reported no cores (still proves
    unauthenticated Admin access, so callers treat ``[]`` as a positive).
    """
    resp = _get(f"{base}/solr/admin/cores?wt=json")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    status = body.get("status")
    if not isinstance(status, dict):
        return None
    return list(status.keys())


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        system_resp = _get(f"{base}/solr/admin/info/system?wt=json")
        if system_resp is None:
            continue

        system = _system_info(system_resp)
        if system is None:
            # Not Solr on this port (or system-info auth-gated) — try the next.
            continue

        version = _parse_version(system)

        # --- Path A: full Admin API access (core enumeration) ---
        cores = _enumerate_cores(base)
        if cores is not None:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "host": target.host,
                    "port": port,
                    "version": version,
                    "admin_api_unauthenticated": True,
                    "cores": cores,
                    "core_count": len(cores),
                },
                description=(
                    metadata["description"]
                    + " The /solr/admin/cores endpoint enumerated cores without "
                    "authentication — the Admin API is fully reachable."
                ),
            )

        # --- Path B: system-info reachable but core-listing auth-gated ---
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence={
                "host": target.host,
                "port": port,
                "version": version,
                "admin_api_unauthenticated": True,
                "system_info_reachable": True,
            },
            description=(
                metadata["description"]
                + " The /solr/admin/info/system endpoint answered without "
                "authentication (JVM/OS fingerprint and version exposed); "
                "core enumeration was not reachable on this port."
            ),
        )

    return None
