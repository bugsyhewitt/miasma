"""CVE-2025-34028 — Commvault Command Center unauthenticated SSRF / pre-auth RCE.

Commvault Command Center (the web console for the widely deployed Commvault
enterprise backup suite) exposes a ``/deployWebpackage.do`` endpoint that, on the
Innovation Release 11.38 line before the April 2025 fix, can be reached without
authentication and chained into server-side request forgery and ultimately
pre-auth remote code execution. Backup appliances are crown-jewel targets for
ransomware crews — a compromised Command Center hands an adversary the keys to
every backup it manages — so the CVE was added to CISA's KEV catalog and is a
recurring item on enterprise bug-bounty scope.

This probe is BENIGN, read-only, and VERSION-FINGERPRINT ONLY. It never touches
the vulnerable ``/deployWebpackage.do`` endpoint and performs no SSRF: triggering
the deploy path is an active exploitation step and out of scope for miasma. We
instead fingerprint the Command Center login console and read its advertised
service-pack / version string, flagging only when the host is identifiably
Commvault Command Center AND its version falls in the affected 11.38 Innovation
Release window. A human then confirms and decides on the active check.

Flow:

    1. GET /commandcenter/         — Command Center's web console. Also tried:
       GET /webconsole/             the legacy webconsole path and the root page.
       GET /
                                    Any one is enough to fingerprint Commvault via
                                    body/title/cookie markers.
    2. Read the version string      — Command Center advertises its build as an
                                     ``11.38.x`` / ``SP38`` style string in the
                                     login page HTML (and sometimes a header). The
                                     11.38 Innovation Release line is the affected
                                     window for CVE-2025-34028.

Severity:
    * HIGH   — the host fingerprints as Commvault Command Center AND an affected
               11.38 Innovation Release version string is present. The pre-auth
               SSRF→RCE surface is exposed; flag for an operator-driven active
               check (which miasma deliberately does not perform).
    * MEDIUM — the host fingerprints as Commvault Command Center but no version
               string could be read (hardened login page, stripped banner). The
               appliance is worth a manual version check — it MIGHT be the
               affected line.
    * none   — not a Commvault Command Center host, or a version string was read
               and it is outside the affected 11.38 window.

No credentials are submitted and the vulnerable deploy endpoint is never
contacted. Evidence records the fingerprint markers and the version string read
from the public login page only.

[Worker decision: plugin filename is cve_2025_34028.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2024_23897.py / cve_2025_55752.py / cve_2025_61666.py convention.]

[Worker decision: this probe is version-fingerprint-only — the POST_V01.md entry
explicitly says "do NOT attempt the deploy endpoint" because /deployWebpackage.do
is an active SSRF/RCE trigger, not a benign read. So unlike the traversal plugins
(Tomcat/Traccar/FortiWeb) there is no "control vs. bypass" comparison: a HIGH is
gated on Commvault fingerprint + affected-version match, not on a privileged read.]
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-34028",
    "name": "Commvault Command Center unauthenticated SSRF / pre-auth RCE",
    "description": (
        "Commvault Command Center Innovation Release 11.38 (before the April 2025 "
        "fix) exposes /deployWebpackage.do without authentication, enabling "
        "server-side request forgery that chains to pre-auth remote code "
        "execution. Backup appliances are high-value ransomware targets; the CVE "
        "is on CISA's KEV catalog. This probe fingerprints the Command Center "
        "version only and never touches the vulnerable endpoint."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-34028",
    ],
    # Command Center is an HTTPS web console; 443 is the norm, 80/8443 follow.
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [443, 80, 8443],
    "service_hint": ["http", "https"],
    "default_ports": [443, 80, 8443],
}

# Fingerprint paths. Any one returning a Commvault marker identifies the host.
# All are unauthenticated GETs against the public web console / login surface;
# none is the vulnerable /deployWebpackage.do endpoint (deliberately untouched).
_FINGERPRINT_PATHS = (
    "/commandcenter/",
    "/webconsole/",
    "/commandcenter/login",
    "/",
)

# Substrings (case-insensitive) that mark a Commvault Command Center host across
# the login page body, the Server header, and Set-Cookie.
_COMMVAULT_MARKERS = (
    "commvault",
    "command center",
    "commandcenter",
    "webconsole",
    "cv_loginlocale",  # a Command Center login cookie name
)

# The affected line is the 11.38 Innovation Release. Command Center advertises its
# build in a few interchangeable forms — a dotted ``11.38`` / ``11.38.x`` or an
# ``SP38`` service-pack tag. We match both shapes; the major must be 11 and the
# service pack must be 38 to be the affected Innovation Release window.
_VERSION_DOTTED_RE = re.compile(r"\b11\.38(?:\.\d+)?\b")
_VERSION_SP_RE = re.compile(r"\bSP\s*38\b", re.IGNORECASE)

# A looser extractor used purely to RECORD whatever version-ish string the page
# advertises, so the MEDIUM/HIGH evidence is human-auditable. Never used to flag.
_ANY_VERSION_RE = re.compile(r"\b(?:11\.\d{1,2}(?:\.\d+)?|SP\s*\d{1,2})\b", re.IGNORECASE)

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

    TLS verification is disabled (appliances ship self-signed certs) and redirects
    are not followed: the login console is served directly, and a redirect to an
    SSO provider means we should not assume a local Commvault surface.
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


def _is_commvault(resp: httpx.Response | None) -> bool:
    """True when the response fingerprints a Commvault Command Center host.

    We look across the page body, the Server header, and the Set-Cookie header
    (Command Center sets ``cv_*`` cookies on the login page).
    """
    if resp is None:
        return False
    haystack = " ".join(
        (
            _server_header(resp),
            resp.headers.get("set-cookie", ""),
            _body(resp),
        )
    ).lower()
    return any(marker in haystack for marker in _COMMVAULT_MARKERS)


def _affected_version(text: str) -> bool:
    """True when the text advertises an affected 11.38 Innovation Release build."""
    return bool(_VERSION_DOTTED_RE.search(text) or _VERSION_SP_RE.search(text))


def _version_string(resp: httpx.Response | None) -> str | None:
    """Record whatever version-ish token the page advertises (for evidence only).

    Prefers an affected-window match; otherwise returns the first version-ish
    token found, or None. This is purely for human auditing — flagging is decided
    by :func:`_affected_version`, never by this loose extractor.
    """
    if resp is None:
        return None
    haystack = " ".join((_server_header(resp), _body(resp)))
    affected = _VERSION_DOTTED_RE.search(haystack) or _VERSION_SP_RE.search(haystack)
    if affected is not None:
        return affected.group(0)
    loose = _ANY_VERSION_RE.search(haystack)
    return loose.group(0) if loose is not None else None


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this a Commvault Command Center host at all? Try the
        #    console paths in order; the first that fingerprints wins for this port.
        fingerprint_resp: httpx.Response | None = None
        fingerprint_path: str | None = None
        for path in _FINGERPRINT_PATHS:
            resp = _get(f"{base}{path}")
            if _is_commvault(resp):
                fingerprint_resp = resp
                fingerprint_path = path
                break

        if fingerprint_resp is None:
            # Not a Commvault host on this port — never flag, even on odd bodies.
            continue

        server = _server_header(fingerprint_resp)
        version = _version_string(fingerprint_resp)
        # Re-read the affected check on the same combined haystack the extractor
        # used, so HIGH and the recorded version string stay consistent.
        haystack = " ".join((server, _body(fingerprint_resp)))

        if _affected_version(haystack):
            # Commvault Command Center on the affected 11.38 Innovation Release
            # line. The pre-auth SSRF→RCE surface is exposed; flag for an
            # operator-driven active check (which miasma deliberately skips).
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "base_url": base,
                    "fingerprint_path": fingerprint_path,
                    "server_header": server,
                    "version_detected": version,
                    "affected_release": "11.38 Innovation Release",
                    "note": (
                        "Commvault Command Center fingerprinted on the affected "
                        "11.38 Innovation Release line. The vulnerable "
                        "/deployWebpackage.do endpoint was NOT contacted — this is "
                        "a version-fingerprint flag for human-driven confirmation."
                    ),
                },
                description=metadata["description"],
            )

        # A version string WAS read but it is outside the affected 11.38 window —
        # this host is not vulnerable to CVE-2025-34028. Do not flag it (not even
        # MEDIUM): a known-safe version is a clean negative, not a candidate.
        if version is not None:
            continue

        # Commvault fingerprinted but NO version string could be read at all
        # (hardened login page, stripped banner). Remember the first such host as
        # a MEDIUM candidate worth a manual version check; a confirmed HIGH on a
        # later port still wins.
        if medium_evidence is None:
            medium_evidence = {
                "base_url": base,
                "fingerprint_path": fingerprint_path,
                "server_header": server,
                "version_detected": version,
                "note": (
                    "Commvault Command Center fingerprinted but no affected "
                    "11.38 version string was read (hardened login page or "
                    "stripped banner). Manual version check recommended; the "
                    "deploy endpoint was NOT contacted."
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
