"""MIASMA-ELASTIC-001 — Elasticsearch unauthenticated access probe.

Elasticsearch clusters exposing port 9200 with no authentication reveal cluster
topology, index names, document counts, shard assignments, and node metadata via
the built-in HTTP REST API. Bug-bounty programs routinely rate unauthenticated
Elasticsearch as P1/HIGH. Clusters that respond to the root endpoint confirm
their identity with the phrase "You Know, for Search" in the JSON body.

A more severe variant exists when default credentials have not been changed
(``elastic:changeme`` or ``admin:elasticadmin``). Default credentials are rated
P0/CRITICAL because they allow full cluster administration: index creation/
deletion, settings mutation, snapshot export, and user enumeration on secured
deployments.

This probe is BENIGN and read-only. It makes three classes of HTTP requests:

    1. GET /                  — cluster info check ("You Know, for Search")
    2. GET /_cat/indices?v    — index listing (confirms data exposure depth)
    3. GET / (with Basic Auth) — default-credential check; only attempted when
                                 the unauthenticated root returns a 401.

No data is modified. No documents are read. No configuration is changed. The
default-credential attempt sends one or two HTTP headers; it is the minimal
interaction a human would perform to confirm the finding.

Severity matrix:
    * CRITICAL — 401 on unauthenticated GET / AND default credentials accepted.
    * HIGH     — unauthenticated GET / returns cluster info ("You Know, for
                 Search"), OR /_cat/indices?v returns an index listing.
    * none     — authenticated with non-default creds, or port unreachable.

Candidate ports: 9200 (primary), 9201 (secondary HTTP), 9300 (transport —
probed last; httpx raises on the binary handshake which is silently swallowed).

[Worker decision: plugin filename is miasma_elastic_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-ELASTIC-001 lives in
metadata["vuln_id"], matching the existing miasma_actuator_001.py /
miasma_redis_001.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-ELASTIC-001",
    "name": "Elasticsearch Unauthenticated Access",
    "description": (
        "Elasticsearch cluster reachable without authentication, exposing "
        "cluster topology, index names, document counts, and node metadata "
        "via the HTTP REST API on port 9200."
    ),
    "confidence": "high",
    "references": [
        "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
        "https://discuss.elastic.co/t/security-default-configuration/303977",
        "https://hackerone.com/reports/",
    ],
    # Ports the probe will try, in order. 9300 is the binary transport port;
    # httpx will fail with a connection error which is silently swallowed.
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [9200, 9201, 9300],
    "service_hint": ["elasticsearch", "http"],
    "default_ports": [9200, 9201, 9300],
}

# Marker string present in every Elasticsearch cluster-info response.
_ES_SIGNATURE = "You Know, for Search"

# Default credential pairs to try when auth is enforced (port returns 401).
# Ordered by prevalence — elastic:changeme is the factory default for v8+.
_DEFAULT_CREDS = [
    ("elastic", "changeme"),
    ("admin", "elasticadmin"),
]

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open ES-ish ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        es_like = [
            port
            for port in open_ports
            if "elastic" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return es_like or open_ports
    return list(metadata["default_ports"])


def _get(url: str, auth: tuple[str, str] | None = None) -> httpx.Response | None:
    """Benign GET; returns None on any transport error.

    ``auth`` is an optional ``(username, password)`` pair for HTTP Basic Auth.
    TLS verification is disabled because self-signed certificates are common on
    internal Elasticsearch deployments.
    """
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
            auth=auth,
        )
    except httpx.HTTPError:
        return None


def _is_open_access(resp: httpx.Response) -> bool:
    """True if the response body contains the ES cluster-info signature."""
    if resp.status_code != 200:
        return False
    try:
        body = resp.text
    except Exception:
        return False
    return _ES_SIGNATURE in body


def _probe_indices(base: str) -> str | None:
    """GET /_cat/indices?v and return the response text, or None on failure."""
    resp = _get(f"{base}/_cat/indices?v")
    if resp is None or resp.status_code != 200:
        return None
    try:
        return resp.text
    except Exception:
        return None


def _probe_default_creds(base: str) -> str | None:
    """Try each default-credential pair. Return the matching username or None."""
    for username, password in _DEFAULT_CREDS:
        resp = _get(base, auth=(username, password))
        if resp is not None and resp.status_code == 200 and _is_open_access(resp):
            return username
    return None


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"http://{target.host}:{port}"

        root_resp = _get(base)
        if root_resp is None:
            continue

        # --- Path A: unauthenticated cluster info (open access) ---
        if _is_open_access(root_resp):
            evidence: dict[str, Any] = {
                "host": target.host,
                "port": port,
                "open_access": True,
            }

            # Supplementary: check whether the index listing is also exposed.
            indices_text = _probe_indices(base)
            if indices_text is not None:
                evidence["indices_exposed"] = True
                # Capture a brief preview (first 500 chars) for the report.
                evidence["indices_preview"] = indices_text[:500]

            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence=evidence,
                description=metadata["description"],
            )

        # --- Path B: authentication required — try default credentials ---
        if root_resp.status_code == 401:
            matched_user = _probe_default_creds(base)
            if matched_user is not None:
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="critical",
                    evidence={
                        "host": target.host,
                        "port": port,
                        "default_creds": True,
                        "matched_user": matched_user,
                    },
                    description=(
                        metadata["description"]
                        + f" Default credentials accepted (user: {matched_user!r}). "
                        "Full administrative access may be possible."
                    ),
                )
            # 401 but no default creds matched — not vulnerable on this port.
            continue

        # Any other status (e.g. non-ES service) — skip this port.

    return None
