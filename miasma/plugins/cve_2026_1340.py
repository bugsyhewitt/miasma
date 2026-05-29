"""CVE-2026-1340 — Ivanti Endpoint Manager Mobile (EPMM) unauthenticated RCE.

Ivanti Endpoint Manager Mobile (EPMM, formerly MobileIron Core) contains a
code-injection vulnerability in two unauthenticated feature endpoints — the
"In-House Application Distribution" handler (``/mifs/c/appstore/fob/``) and the
"Android File Transfer Configuration" handler (``/mifs/c/aftstore/fob/``). An
UNAUTHENTICATED attacker can smuggle a Bash command into an HTTP request to
either endpoint and have it executed as an OS command on the appliance — a
pre-auth remote code execution (CVSS 9.8). Ivanti shipped emergency patches on
2026-01-29 (sibling CVE-2026-1281); both were exploited in the wild as
zero-days and CVE-2026-1281 is on CISA's KEV catalog. The permanent fix lands
in EPMM 12.8.0.0; the 12.5.x / 12.6.x / 12.7.x (and earlier) branches are
affected unless the emergency RPM is applied. EPMM is the enterprise MDM
control plane (it manages enrolled mobile fleets), so a compromised appliance
is a fleet-wide foothold and EPMM is a recurring enterprise edge / bug-bounty
target — there were >2,000 internet-exposed instances at disclosure.

This probe is BENIGN, read-only, and DOES NOT TRIGGER THE RCE. The vulnerability
fires only when a Bash *command* is smuggled into the request; this probe sends
NO command, NO payload, NO injection — only plain unauthenticated GETs of public
paths. It distinguishes EPMM from non-EPMM via the Ivanti User Portal login
surface, then confirms whether the *vulnerable feature endpoints are reachable
and routed* on this appliance (the exposure signal) without ever exercising
them. It also reads the EPMM build string opportunistically: a sane EPMM does
NOT serve its version unauthenticated, so a readable affected build is a strong
upgrade of the finding, but the absence of one does not weaken the
endpoint-exposure signal.

Flow:

    1. GET /mifs/admin (then /mifs/, /mifs/c/windows/admin, /)  — fingerprint
       EPMM via the "Ivanti User Portal: Sign In" / MobileIron login markup,
       the Server header, and the EPMM session cookies. The first path that
       fingerprints wins for this port. A non-EPMM host is NEVER flagged.
    2. GET /mifs/c/appstore/fob/ and /mifs/c/aftstore/fob/  — the two vulnerable
       feature endpoints, requested with NO command payload. Ivanti's own
       detection guidance notes legitimate use returns 200 and a 404 means the
       path is not serving — so a *routed* (non-404) response on a fingerprinted
       EPMM host confirms the vulnerable feature surface is present and exposed.
       We never include a Bash command, so the RCE is never triggered.
    3. Opportunistically read the EPMM build string if it leaks on the public
       surface; flag the affected ``< 12.8.0.0`` window when a version is read.

Severity:

    * HIGH   — the host fingerprints as EPMM AND (a vulnerable feature endpoint
               is routed/reachable, OR a readable build string is in the
               affected ``< 12.8.0.0`` window). The unauthenticated RCE surface
               is exposed; flag for an operator-driven active check (which
               miasma skips — no command is ever sent).
    * MEDIUM — the host fingerprints as EPMM but neither the vulnerable feature
               endpoints are confirmed reachable nor a build string could be
               read (hardened/stripped/patched-via-RPM appliance). Worth a
               manual check — it MIGHT still be the affected line, since the
               emergency RPM does not change the advertised version.
    * none   — not an EPMM host, or EPMM fingerprinted with a readable build at
               or above the fixed 12.8.0.0 line AND no vulnerable endpoint was
               reachable (a clean negative).

No credentials are submitted and no Bash command / injection payload is ever
constructed — every request is a plain GET of a public path. Evidence records
the fingerprint marker, the endpoints reached and their routing status, and the
version string only if it leaked on the public surface.

[Worker decision (R20): the necromancer POST_V01.md roadmap is fully shipped —
every Tier 1/2/3 plugin and every infrastructure item already exists in the
codebase (verified by reading miasma/plugins/ and tests/). A fresh gap analysis
against the 2026 CISA KEV catalog surfaced Ivanti EPMM CVE-2026-1281 /
CVE-2026-1340 (CVSS 9.8, KEV, zero-day RCE, public PoC, >2k exposed hosts) as
the highest-value uncovered finding. It is a DISTINCT product from the existing
Ivanti Connect Secure plugin (cve_2025_0282.py): EPMM is the MobileIron MDM
control plane served under /mifs/, not the /dana-na/ SSL-VPN portal — so this
is a new plugin, not a tweak to the existing one.]

[Worker decision: filename is cve_2026_1340.py (underscores) because the runner
discovers plugins via importlib and module names cannot contain hyphens. The
canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2025_0282.py convention.]

[Worker decision: unlike the version-fingerprint-only Connect Secure / Langflow
/ KACE plugins, EPMM does NOT serve its build version to unauthenticated HTTP on
a sane appliance (platform-version-info.txt is not web-readable), so a
version-only probe would almost always be a weak MEDIUM. Instead the HIGH signal
is the *reachability of the two vulnerable feature endpoints* on a fingerprinted
EPMM host — a benign, payload-free GET that never smuggles a command and so
never triggers the RCE. A readable affected build, when it leaks, upgrades to /
reinforces HIGH; a readable patched build (>= 12.8.0.0) with no reachable
endpoint is a clean negative. This mirrors the FortiWeb/Traccar "is the
vulnerable surface present?" pattern while keeping the probe strictly benign.]
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2026-1340",
    "name": "Ivanti EPMM unauthenticated remote code execution",
    "description": (
        "Ivanti Endpoint Manager Mobile (EPMM, formerly MobileIron Core) before "
        "12.8.0.0 exposes the In-House Application Distribution "
        "(/mifs/c/appstore/fob/) and Android File Transfer Configuration "
        "(/mifs/c/aftstore/fob/) endpoints to unauthenticated code injection — a "
        "pre-auth remote code execution (CVSS 9.8, with sibling CVE-2026-1281). "
        "Both were exploited as zero-days; CVE-2026-1281 is on CISA's KEV "
        "catalog. EPMM is the enterprise MDM control plane, so a compromised "
        "appliance is a fleet-wide foothold. This probe fingerprints EPMM and "
        "checks whether the vulnerable feature endpoints are reachable using "
        "payload-free GETs only — it never smuggles a command and never triggers "
        "the RCE."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1340",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1281",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ],
    # EPMM presents its web surface on 443 by default; plain 80 usually
    # redirects to it, and 8443 is a common alternate. port_hint is the
    # canonical field the runner reads to skip irrelevant plugins; default_ports
    # is the in-probe fallback alias.
    "port_hint": [443, 80, 8443],
    "service_hint": ["http", "https"],
    "default_ports": [443, 80, 8443],
}

# The EPMM admin/login surface fingerprints the appliance. /mifs/admin is the
# administrative login; /mifs/ is the web-app root; /mifs/c/windows/admin and /
# are tried as fallbacks. The first path that fingerprints wins for a port.
_FINGERPRINT_PATHS = (
    "/mifs/admin",
    "/mifs/",
    "/mifs/c/windows/admin",
    "/",
)

# The two vulnerable feature endpoints (CVE-2026-1340 / CVE-2026-1281). We GET
# them with NO command payload to test reachability/routing only — Ivanti's own
# detection guidance notes legitimate use returns 200 and a 404 means the path
# is not serving. The RCE requires a smuggled Bash command, which we NEVER send.
_VULNERABLE_ENDPOINTS = (
    "/mifs/c/appstore/fob/",
    "/mifs/c/aftstore/fob/",
)

# Case-insensitive substrings that mark an EPMM / MobileIron Core host across the
# body, the Server header, and Set-Cookie. "ivanti user portal" is the canonical
# login title; "/mifs/" and "mifs" are the defining EPMM web path; "mobileiron"
# is the legacy branding; "mics"/"jsessionid"-on-/mifs are session cookies.
_EPMM_MARKERS = (
    "ivanti user portal",
    "/mifs/",
    "mifs/admin",
    "mobileiron",
    "endpoint manager mobile",
)

# The permanent fix lands in EPMM 12.8.0.0; any build strictly below that is the
# affected window (the 12.5.x / 12.6.x / 12.7.x and earlier branches).
_FIXED_VERSION = (12, 8, 0, 0)
_FIXED_VERSION_STR = "12.8.0.0"

# EPMM build form: a dotted MAJOR.MINOR.PATCH[.BUILD] string, e.g. "12.7.0.1" or
# "11.10.0.2". Captured for recording + the affected-window decision. We require
# at least three dotted components so a bare two-part token (e.g. an unrelated
# "1.2") is not mistaken for an EPMM build.
_VERSION_RE = re.compile(r"\b(\d{1,2})\.(\d{1,2})\.(\d{1,3})(?:\.(\d{1,4}))?\b")

# A routed (non-404) HTTP status on a vulnerable feature endpoint means the path
# is serving on this appliance — the exposure signal. A 404 means the feature is
# not routed here (patched/disabled), which is NOT an exposure signal.
_NOT_ROUTED_STATUS = 404

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

    TLS verification is disabled (EPMM appliances commonly serve self-signed or
    internal-CA certs) and redirects are not followed: the login surface and
    feature endpoints are served directly, and a redirect away means we should
    not assume a local EPMM surface. No Authorization header or token is ever
    sent, and no Bash command / injection payload is ever constructed — every
    request is a plain GET of a public path.
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


def _is_epmm(resp: httpx.Response | None) -> bool:
    """True when the response fingerprints an Ivanti EPMM / MobileIron host.

    We look across the page/body, the Server header, and Set-Cookie for an EPMM
    marker. A bare version-looking token from an unrelated host is NOT an EPMM
    fingerprint.
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
    return any(marker in haystack for marker in _EPMM_MARKERS)


def _version_string(resp: httpx.Response | None) -> str | None:
    """Read the advertised EPMM build string from a response, if it leaked.

    Scans the body and Server header for the dotted EPMM build token. EPMM does
    NOT serve its version unauthenticated on a sane appliance, so this is best
    effort — purely for recording + the affected-window decision. Returns None
    when no EPMM-form version token is present.
    """
    if resp is None:
        return None
    haystack = " ".join((_server_header(resp), _body(resp)))
    match = _VERSION_RE.search(haystack)
    return match.group(0) if match is not None else None


def _parse_version(version: str) -> tuple[int, int, int, int] | None:
    """Parse an EPMM build into a comparable (major, minor, patch, build)."""
    match = _VERSION_RE.search(version)
    if match is None:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3))
    build = int(match.group(4)) if match.group(4) is not None else 0
    return (major, minor, patch, build)


def _is_affected(version: str) -> bool:
    """True when the build is strictly below the fixed 12.8.0.0 line."""
    parsed = _parse_version(version)
    if parsed is None:
        return False
    return parsed < _FIXED_VERSION


def _reachable_endpoints(base: str) -> list[dict[str, Any]]:
    """Return routing status for the vulnerable feature endpoints.

    Each entry records the endpoint path and the observed status. An endpoint is
    "routed" (the exposure signal) when it answers with anything other than 404
    — Ivanti's detection guidance treats 404 as "the path is not serving". We
    send NO command payload, so the RCE is never triggered; this only tests
    whether the vulnerable feature surface is present on the appliance.
    """
    results: list[dict[str, Any]] = []
    for endpoint in _VULNERABLE_ENDPOINTS:
        resp = _get(f"{base}{endpoint}")
        if resp is None:
            continue
        results.append(
            {
                "endpoint": endpoint,
                "status_code": resp.status_code,
                "routed": resp.status_code != _NOT_ROUTED_STATUS,
            }
        )
    return results


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this an EPMM host at all? Try the admin/login
        #    surface, then the fallbacks. The first path that fingerprints wins
        #    for this port.
        fingerprint_resp: httpx.Response | None = None
        fingerprint_path: str | None = None
        for path in _FINGERPRINT_PATHS:
            resp = _get(f"{base}{path}")
            if _is_epmm(resp):
                fingerprint_resp = resp
                fingerprint_path = path
                break

        if fingerprint_resp is None:
            # Not an EPMM host on this port — never flag, even on odd bodies.
            continue

        server = _server_header(fingerprint_resp)
        version = _version_string(fingerprint_resp)

        # 2. Confirm whether the vulnerable feature endpoints are reachable —
        #    payload-free GETs only; the RCE is never triggered.
        endpoints = _reachable_endpoints(base)
        routed = [e for e in endpoints if e["routed"]]

        version_affected = version is not None and _is_affected(version)
        version_patched = version is not None and not version_affected

        # HIGH when the unauthenticated RCE surface is exposed: a vulnerable
        # feature endpoint is reachable OR a readable build is in the affected
        # window. (A patched build with no reachable endpoint is a clean
        # negative and falls through to the `continue` below.)
        if routed or version_affected:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "base_url": base,
                    "fingerprint_path": fingerprint_path,
                    "server_header": server,
                    "version_detected": version,
                    "fixed_version": _FIXED_VERSION_STR,
                    "vulnerable_endpoints": endpoints,
                    "routed_endpoints": [e["endpoint"] for e in routed],
                    "note": (
                        "Ivanti EPMM fingerprinted with the unauthenticated RCE "
                        "surface exposed (a vulnerable feature endpoint is routed "
                        "and/or an affected pre-12.8.0.0 build is advertised). No "
                        "command payload was ever sent — this is a benign "
                        "exposure flag for human-driven confirmation, the RCE was "
                        "NOT triggered."
                    ),
                },
                description=metadata["description"],
            )

        # EPMM fingerprinted, a build string WAS read and it is at or above the
        # fixed 12.8.0.0 line, and no vulnerable endpoint was reachable — a clean
        # negative. Do not flag (not even MEDIUM).
        if version_patched:
            continue

        # EPMM fingerprinted but neither a vulnerable endpoint was confirmed
        # reachable nor a build string could be read (hardened / stripped, or
        # patched via the emergency RPM which does not change the advertised
        # version). Remember the first such host as a MEDIUM candidate worth a
        # manual check; a confirmed HIGH on a later port wins.
        if medium_evidence is None:
            medium_evidence = {
                "base_url": base,
                "fingerprint_path": fingerprint_path,
                "server_header": server,
                "version_detected": version,
                "fixed_version": _FIXED_VERSION_STR,
                "vulnerable_endpoints": endpoints,
                "routed_endpoints": [],
                "note": (
                    "Ivanti EPMM fingerprinted but the vulnerable feature "
                    "endpoints were not confirmed reachable and no version "
                    "string was read (hardened/stripped, or patched via the "
                    "emergency RPM which leaves the version unchanged). Manual "
                    "check recommended; no command payload was sent."
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
