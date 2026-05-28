"""CVE-2025-41243 — Spring Cloud Gateway exposed actuator (SpEL/env injection).

Spring Cloud Gateway exposes a management actuator surface under
``/actuator/gateway/*`` that lets an operator inspect and *mutate* the gateway's
routing table at runtime. When ``management.endpoints.web.exposure.include``
includes ``gateway`` and those actuator endpoints are left unauthenticated, an
attacker can POST a new route whose filters carry a Spring Expression Language
(SpEL) payload. On the next request through that route the SpEL is evaluated —
exfiltrating environment variables, credentials, and API keys, or achieving RCE.
This is the same exposed-actuator vector noted alongside the Spring Boot Actuator
misconfiguration plugin (CVE-2025-41243).

This probe is BENIGN and read-only. It confirms only that the gateway actuator
is *reachable without authentication* — it never POSTs, never modifies a route,
and never injects an expression:

    GET /actuator/gateway/routes  — the route table (a JSON array). If this is
                                    served 200 without an auth challenge, the
                                    mutation surface is exposed.
    GET /actuator/gateway         — the gateway actuator base (fallback). A 200
                                    JSON object listing gateway sub-endpoints is
                                    partial confirmation the surface is live.

Severity matrix:
    * HIGH   — /actuator/gateway/routes returns 200 with a JSON *array* (the
               route table). The mutate-able route surface is confirmed exposed:
               an attacker could add a SpEL-bearing route. The route table is
               the single endpoint a human would hit to confirm by hand.
    * MEDIUM — /actuator/gateway/routes is not cleanly exposed but the gateway
               actuator base /actuator/gateway returns 200 with a JSON body
               listing gateway sub-endpoints (the surface is present but the
               route table itself was not confirmed served as an array).
    * none   — neither endpoint returns gateway-shaped JSON (404/401/403, a
               redirect, or a 200 body that is HTML — an SPA that returns
               index.html for every path must not be flagged).

No route IDs or filter contents are exploited; evidence records only the count
of routes observed and the route *ids* (which are operator-chosen labels, not
secrets) so a human can confirm the table is real without us touching it.

[Worker decision: plugin filename is cve_2025_41243.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens —
matching the existing cve_2024_23897.py / cve_2025_64446.py convention. The
canonical id CVE-2025-41243 lives in metadata["vuln_id"].]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-41243",
    "name": "Spring Cloud Gateway exposed actuator",
    "description": (
        "Spring Cloud Gateway exposes its actuator gateway endpoints "
        "(/actuator/gateway/routes) without authentication. The route table is "
        "mutable at runtime, allowing an unauthenticated attacker to inject a "
        "Spring Expression Language (SpEL) payload via a new route filter and "
        "exfiltrate environment variables, credentials, and API keys."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-41243",
        "https://docs.spring.io/spring-cloud-gateway/reference/spring-cloud-gateway/actuator-api.html",
        "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",
    ],
    # Management ports we'll consider; also the fallback when recon found none.
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [8080, 8443, 80, 443],
    "service_hint": ["http", "https"],
    "default_ports": [8080, 8443, 80, 443],
}

# The route table (HIGH) is checked first; the gateway base (MEDIUM) is fallback.
_ROUTES_PATH = "/actuator/gateway/routes"
_GATEWAY_PATH = "/actuator/gateway"

# TLS ports where we should speak https.
_TLS_PORTS = (443, 8443)

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open web-ish ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        web_like = [
            port
            for port in open_ports
            if "http" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return web_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """https for the TLS-typical ports, http otherwise."""
    return "https" if port in _TLS_PORTS else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign GET; returns None on any transport error.

    TLS verification is disabled and redirects are not followed: the actuator
    endpoint is served directly, so a redirect (e.g. to a login page) means the
    surface is *not* unauthenticated and must not flag.
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


def _json_or_none(resp: httpx.Response) -> Any | None:
    """Parse the body as JSON; None if it isn't JSON (e.g. an SPA index.html)."""
    try:
        return resp.json()
    except (ValueError, httpx.HTTPError):
        return None


def _route_ids(routes: list[Any]) -> list[str]:
    """Extract operator-chosen route ids from the route table, if present.

    The Spring Cloud Gateway route table is a JSON array of route objects, each
    typically carrying a ``route_id`` (or ``id``). These are labels, not secrets,
    and let a human confirm the table is real without us mutating anything.
    """
    ids: list[str] = []
    for entry in routes:
        if not isinstance(entry, dict):
            continue
        rid = entry.get("route_id") or entry.get("id")
        if rid is not None:
            ids.append(str(rid))
    return ids


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. HIGH: the mutate-able route table served as a JSON array.
        routes_resp = _get(f"{base}{_ROUTES_PATH}")
        if routes_resp is not None and routes_resp.status_code == 200:
            body = _json_or_none(routes_resp)
            # A genuine route table is a JSON *array*. An SPA index.html parses
            # as None (not JSON); a JSON object is the gateway base, not routes.
            if isinstance(body, list):
                route_ids = _route_ids(body)
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence={
                        "host": target.host,
                        "port": port,
                        "url": f"{base}{_ROUTES_PATH}",
                        "path": _ROUTES_PATH,
                        "route_count": len(body),
                        # Route ids are operator labels, not secrets.
                        "route_ids": route_ids,
                    },
                    description=metadata["description"],
                )

        # 2. MEDIUM: the gateway actuator base reachable (surface present, route
        #    table not cleanly confirmed). The base returns a JSON object.
        gateway_resp = _get(f"{base}{_GATEWAY_PATH}")
        if gateway_resp is not None and gateway_resp.status_code == 200:
            body = _json_or_none(gateway_resp)
            if isinstance(body, dict):
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="medium",
                    evidence={
                        "host": target.host,
                        "port": port,
                        "url": f"{base}{_GATEWAY_PATH}",
                        "path": _GATEWAY_PATH,
                        "note": (
                            "Gateway actuator base reachable; route table not "
                            "confirmed as a served array (partial exposure)."
                        ),
                    },
                    description=metadata["description"],
                )

    return None
