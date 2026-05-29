"""MIASMA-GRAFANA-001 — Grafana unauthenticated / default-credential access.

Grafana is one of the most common dashboards exposed to the internet, and two
recurring misconfigurations turn that exposure into a P1/critical finding:

    1. Default credentials — a fresh Grafana ships with ``admin:admin``. Many
       deployments never rotate it. Logging in with the factory password grants
       full administrative control: data-source credential disclosure (every
       configured database / cloud connection), org/user management, and (via
       the SQL/plugin data sources) frequently a path to the host.

    2. Anonymous access — ``[auth.anonymous] enabled = true`` lets any
       unauthenticated client read dashboards and enumerate the org. Operators
       turn this on for "public" dashboards without realising it also exposes
       internal metrics, asset inventories, and dashboard-embedded queries.

This probe is BENIGN and read-only. It fingerprints Grafana first, then runs
the two minimal checks a human would run by hand to confirm the finding:

    1. GET /api/health        — fingerprints Grafana; the JSON body carries the
                                ``version``/``database`` keys unique to Grafana.
    2. GET /api/org           — with no credentials. A 200 + an org ``id``/``name``
                                means anonymous access is enabled (HIGH).
    3. POST /login            — body ``{"user":"admin","password":"admin"}``.
                                A 200 (Grafana answers the failed login with 401)
                                confirms the default credential (CRITICAL). The
                                request only attempts the single factory pair.

No dashboard is read, no data source is touched, no configuration is changed —
exactly the health/org/login handshake used to confirm the finding manually.

Severity matrix:
    * CRITICAL — default admin:admin login accepted.
    * HIGH     — anonymous /api/org returns org metadata (anonymous access on).
    * none     — Grafana fingerprinted but auth enforced, or not Grafana.

Candidate ports: 3000 (primary), 80, 443, 8080 (common reverse-proxy fronts).

[Worker decision: plugin filename is miasma_grafana_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-GRAFANA-001 lives in
metadata["vuln_id"], matching the existing miasma_elastic_001.py /
miasma_redis_001.py / miasma_docker_001.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-GRAFANA-001",
    "name": "Grafana Unauthenticated / Default-Credential Access",
    "description": (
        "Grafana instance reachable with the factory admin:admin credential "
        "or with anonymous access enabled, exposing dashboards, data-source "
        "credentials, and org/user administration via the HTTP API."
    ),
    "confidence": "high",
    "references": [
        "https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/",
        "https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/anonymous-auth/",
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [3000, 80, 443, 8080],
    "service_hint": ["grafana", "http", "https"],
    "default_ports": [3000, 80, 443, 8080],
}

# Keys present in a genuine Grafana /api/health JSON body. Grafana answers
# /api/health unauthenticated on every build, returning a small object such as
# {"commit":"...","database":"ok","version":"10.4.0"}.
_HEALTH_KEYS = ("database", "version")

# The single factory credential pair Grafana ships with. We only ever try the
# one documented default — this is a misconfiguration check, not a brute force.
_DEFAULT_USER = "admin"
_DEFAULT_PASS = "admin"

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Grafana-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        grafana_like = [
            port
            for port in open_ports
            if "grafana" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return grafana_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS only for the canonical TLS port; everything else plain HTTP."""
    return "https" if port == 443 else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign unauthenticated GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common on
    internal Grafana deployments behind a reverse proxy.
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


def _post(url: str, json: dict[str, Any]) -> httpx.Response | None:
    """Benign POST (single default-credential login attempt); None on error."""
    try:
        return httpx.post(
            url,
            json=json,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _is_grafana(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the parsed /api/health body if it is genuinely Grafana, else None."""
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    if all(key in body for key in _HEALTH_KEYS):
        return body
    return None


def _anonymous_org(base: str) -> dict[str, Any] | None:
    """GET /api/org with no auth. Return the org body if anonymous access is on."""
    resp = _get(f"{base}/api/org")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if isinstance(body, dict) and ("id" in body or "name" in body):
        return body
    return None


def _default_creds_accepted(base: str) -> bool:
    """POST admin:admin to /login. Grafana returns 200 on success, 401 on fail."""
    resp = _post(
        f"{base}/login",
        {"user": _DEFAULT_USER, "password": _DEFAULT_PASS},
    )
    return resp is not None and resp.status_code == 200


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        health_resp = _get(f"{base}/api/health")
        if health_resp is None:
            continue

        health = _is_grafana(health_resp)
        if health is None:
            # Not Grafana on this port (or auth-gated health) — try the next.
            continue

        version = health.get("version")

        # --- Path A: default credentials (most severe) ---
        if _default_creds_accepted(base):
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="critical",
                evidence={
                    "host": target.host,
                    "port": port,
                    "version": version,
                    "default_creds": True,
                    "matched_user": _DEFAULT_USER,
                },
                description=(
                    metadata["description"]
                    + " Default credentials (admin:admin) accepted — full "
                    "administrative access, including data-source credential "
                    "disclosure, is possible."
                ),
            )

        # --- Path B: anonymous access enabled ---
        org = _anonymous_org(base)
        if org is not None:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "host": target.host,
                    "port": port,
                    "version": version,
                    "anonymous_access": True,
                    "org_name": org.get("name"),
                },
                description=(
                    metadata["description"]
                    + " Anonymous access is enabled — dashboards and org "
                    "metadata are readable without authentication."
                ),
            )

        # Grafana fingerprinted but auth enforced on this port — not vulnerable.

    return None
