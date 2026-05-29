"""CVE-2025-32975 — Quest KACE SMA unauthenticated authentication bypass.

Quest KACE SMA (Systems Management Appliance) is an enterprise IT endpoint
management appliance. Before the March 2025 fix, all versions are affected by an
authentication bypass (CVSS 10.0) that hands an attacker a full administrator
session without credentials. KACE SMA is deployed deep inside enterprise IT —
it pushes software and patches to managed endpoints — so a hijacked SMA console
is a fleet-wide foothold. CVE-2025-32975 is on CISA's KEV catalog with confirmed
in-the-wild exploitation, and the appliance is niche enough that automated
scanners frequently miss it, making it a strong manual bug-bounty finding.

This probe is BENIGN, read-only, and VERSION-FINGERPRINT ONLY. It never attempts
the authentication bypass: performing the bypass is an active exploitation step
and out of scope for miasma (the POST_V01 entry says explicitly "do NOT attempt
the auth bypass itself"). Instead we fingerprint the KACE SMA login console and
read its advertised version, flagging only when the host is identifiably KACE SMA
AND its version predates the March 2025 fix (build 14.0.x before patch, i.e. any
release below 14.1). A human then confirms and decides on the active check.

Flow:

    1. GET /userui/login.php   — the KACE SMA admin login console. Also tried:
       GET /userui/                the user portal landing, and the root page.
       GET /
                                 Any one is enough to fingerprint KACE via the
                                 page body, the ``X-KACE-*`` headers, or the
                                 ``kboxid``/``kace`` cookies.
    2. Read the version string  — KACE advertises its build either in an
                                 ``X-KACE-Version`` (or ``X-DELL-KACE-*``) response
                                 header or in the login page HTML (``Version
                                 14.0.x``). The affected window is everything
                                 BELOW 14.1 (the March 2025 fixed line).

Severity:
    * HIGH   — the host fingerprints as KACE SMA AND an affected version (below
               14.1) is present. The unauthenticated admin-takeover surface is
               exposed; flag for an operator-driven active check (which miasma
               deliberately does not perform).
    * MEDIUM — the host fingerprints as KACE SMA but no version string could be
               read (hardened/stripped login page). The appliance is worth a
               manual version check — it MIGHT be the affected line.
    * none   — not a KACE SMA host, or a version string was read and it is at or
               above the fixed 14.1 line (a clean negative, not a candidate).

No credentials are submitted and the authentication bypass is never attempted.
Evidence records the fingerprint markers and the version string read from the
public login page only.

[Worker decision: plugin filename is cve_2025_32975.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2025_34028.py / cve_2024_23897.py convention.]

[Worker decision: this probe is version-fingerprint-only — mirroring the Commvault
CVE-2025-34028 plugin. The POST_V01.md entry explicitly says "Do NOT attempt the
auth bypass itself", so there is no "control vs. bypass" comparison: a HIGH is
gated on KACE fingerprint + affected-version match, not on a privileged read.]

[Worker decision: the affected window is "below 14.1". The fix shipped in the
14.1 line (March 2025); KACE SMA versions are MAJOR.MINOR.PATCH (e.g. 14.0.290).
We treat any KACE build whose (major, minor) sorts strictly below (14, 1) as
affected, and (14, 1) or higher as fixed. A KACE host whose version cannot be
parsed to (major, minor) is treated as "no version read" → MEDIUM, never a clean
negative — we must not silently clear an appliance we couldn't actually version.]
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-32975",
    "name": "Quest KACE SMA unauthenticated authentication bypass",
    "description": (
        "Quest KACE SMA (Systems Management Appliance) versions before the "
        "March 2025 fix (below the 14.1 line) contain an authentication bypass "
        "(CVSS 10.0) granting full administrator access without credentials. "
        "KACE SMA pushes software and patches to managed endpoints, so a hijacked "
        "console is a fleet-wide foothold; the CVE is on CISA's KEV catalog. This "
        "probe fingerprints the KACE version only and never attempts the bypass."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-32975",
    ],
    # KACE SMA is an HTTPS web console; 443 is the norm, 80 follows.
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [443, 80],
    "service_hint": ["http", "https"],
    "default_ports": [443, 80],
}

# Fingerprint paths. Any one returning a KACE marker identifies the host. All are
# unauthenticated GETs against the public login / portal surface; none attempts
# the authentication bypass (deliberately untouched).
_FINGERPRINT_PATHS = (
    "/userui/login.php",
    "/userui/",
    "/adminui/login.php",
    "/",
)

# Substrings (case-insensitive) that mark a KACE SMA host across the login page
# body, the response headers, and Set-Cookie.
_KACE_MARKERS = (
    "kace sma",
    "kace systems management",
    "kace",
    "kbox",  # legacy KBOX branding and the kboxid session cookie prefix
    "x-kace",
    "x-dell-kace",
)

# KACE advertises its build as a dotted MAJOR.MINOR.PATCH string, e.g.
# "Version 14.0.290" in the login HTML or an X-KACE-Version header. We capture
# major and minor to compare against the fixed (14, 1) line.
_VERSION_RE = re.compile(r"\b(\d{1,2})\.(\d{1,2})(?:\.\d+)?\b")

# Headers that may carry the KACE build directly.
_VERSION_HEADERS = ("x-kace-version", "x-dell-kace-version", "x-kace-appliance")

# The fix shipped in the 14.1 line; anything strictly below (14, 1) is affected.
_FIXED_MAJOR_MINOR = (14, 1)

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
    external SSO provider means we should not assume a local KACE surface.
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


def _header_blob(resp: httpx.Response | None) -> str:
    """Join header names+values into one searchable string (for fingerprinting).

    KACE-specific markers can live in header *names* (e.g. ``X-KACE-Version``)
    even when the value itself is generic, so we fold both into the haystack.
    """
    if resp is None:
        return ""
    return " ".join(f"{name}: {value}" for name, value in resp.headers.items())


def _is_kace(resp: httpx.Response | None) -> bool:
    """True when the response fingerprints a KACE SMA host.

    We look across the page body, the response headers (names included), and the
    Set-Cookie header (KACE sets a ``kboxid`` session cookie on the login page).
    """
    if resp is None:
        return False
    haystack = " ".join(
        (
            _header_blob(resp),
            resp.headers.get("set-cookie", ""),
            _body(resp),
        )
    ).lower()
    return any(marker in haystack for marker in _KACE_MARKERS)


def _parse_major_minor(text: str) -> tuple[int, int] | None:
    """Extract the first dotted MAJOR.MINOR from ``text`` as an int tuple."""
    match = _VERSION_RE.search(text)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


def _version_haystack(resp: httpx.Response | None) -> str:
    """The combined text we read the KACE version from (headers + body).

    Dedicated version headers are listed first so a header-advertised build wins
    over an incidental number in the page body.
    """
    if resp is None:
        return ""
    header_versions = " ".join(
        resp.headers.get(name, "") for name in _VERSION_HEADERS
    )
    return " ".join((header_versions, _server_header(resp), _body(resp)))


def _is_affected(major_minor: tuple[int, int]) -> bool:
    """True when a parsed (major, minor) is strictly below the fixed 14.1 line."""
    return major_minor < _FIXED_MAJOR_MINOR


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this a KACE SMA host at all? Try the console paths in
        #    order; the first that fingerprints wins for this port.
        fingerprint_resp: httpx.Response | None = None
        fingerprint_path: str | None = None
        for path in _FINGERPRINT_PATHS:
            resp = _get(f"{base}{path}")
            if _is_kace(resp):
                fingerprint_resp = resp
                fingerprint_path = path
                break

        if fingerprint_resp is None:
            # Not a KACE host on this port — never flag, even on odd bodies.
            continue

        server = _server_header(fingerprint_resp)
        haystack = _version_haystack(fingerprint_resp)
        major_minor = _parse_major_minor(haystack)
        version = (
            f"{major_minor[0]}.{major_minor[1]}" if major_minor is not None else None
        )

        if major_minor is not None and _is_affected(major_minor):
            # KACE SMA below the fixed 14.1 line. The unauthenticated
            # admin-takeover surface is exposed; flag for an operator-driven
            # active check (which miasma deliberately skips).
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "base_url": base,
                    "fingerprint_path": fingerprint_path,
                    "server_header": server,
                    "version_detected": version,
                    "fixed_release": "14.1 (March 2025)",
                    "note": (
                        "Quest KACE SMA fingerprinted on an affected version "
                        "(below the fixed 14.1 line). The authentication bypass "
                        "was NOT attempted — this is a version-fingerprint flag "
                        "for human-driven confirmation."
                    ),
                },
                description=metadata["description"],
            )

        # A parseable version WAS read and it is at/above the fixed 14.1 line —
        # this host is not vulnerable to CVE-2025-32975. Do not flag it (not even
        # MEDIUM): a known-fixed version is a clean negative, not a candidate.
        if major_minor is not None:
            continue

        # KACE fingerprinted but NO version string could be read at all (hardened
        # login page, stripped banner). Remember the first such host as a MEDIUM
        # candidate worth a manual version check; a confirmed HIGH on a later port
        # still wins.
        if medium_evidence is None:
            medium_evidence = {
                "base_url": base,
                "fingerprint_path": fingerprint_path,
                "server_header": server,
                "version_detected": None,
                "note": (
                    "Quest KACE SMA fingerprinted but no version string was read "
                    "(hardened login page or stripped banner). Manual version "
                    "check recommended; the authentication bypass was NOT "
                    "attempted."
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
