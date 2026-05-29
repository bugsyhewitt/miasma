"""CVE-2025-0282 — Ivanti Connect Secure / Policy Secure pre-auth RCE.

Ivanti Connect Secure (formerly Pulse Connect Secure), Policy Secure, and the
Neurons for ZTA gateways contain a stack-based buffer overflow in the web
component that an UNAUTHENTICATED attacker can trigger for remote code
execution. CISA added CVE-2025-0282 to the KEV catalog in January 2025 after
in-the-wild exploitation (Mandiant/Google attributed the activity to a
China-nexus espionage actor deploying the SPAWN malware family). The CVE is
CVSS 9.0 (Critical) and Ivanti VPN appliances are perennial enterprise edge
targets and frequently in bug-bounty / red-team scope.

This probe is BENIGN, read-only, and VERSION-FINGERPRINT ONLY. The
vulnerability is a memory-corruption overflow — actually triggering it would
crash or compromise the appliance, which is destructive and squarely out of
scope for miasma. Instead the probe reads Ivanti's unauthenticated public
surface: the appliance fingerprints itself through the `/dana-na/` web-login
plumbing, and the build number is published WITHOUT authentication in the GINA
client version file `/dana-na/nc/nc_gina_ver.txt` (an XML/text file the Pulse
client downloads before login) and in the welcome/login page markup. We
fingerprint the host as Ivanti Connect Secure and flag only when the advertised
build falls in the affected `< 22.7R2.5` window. A human then confirms and
decides on any active check.

Flow:

    1. GET /dana-na/nc/nc_gina_ver.txt  — the unauthenticated GINA client
       (then /dana-na/auth/url_default/    version file. On Ivanti appliances it
        welcome.cgi, then /)               returns XML/text carrying the build
                                           string AND is an Ivanti-specific
                                           fingerprint in one request. The
                                           welcome.cgi login page and the root
                                           page are tried as fallbacks to
                                           fingerprint Ivanti when the version
                                           file is stripped.
    2. Compare the version  — the fix for the 22.7 line landed in 22.7R2.5; any
                              build strictly below that is the affected window.

Severity:

    * HIGH   — the host fingerprints as Ivanti Connect Secure AND an affected
               (`< 22.7R2.5`) version string is present. The pre-auth RCE
               surface is exposed; flag for an operator-driven active check
               (which miasma skips).
    * MEDIUM — the host fingerprints as Ivanti Connect Secure but no version
               string could be read (hardened/stripped appliance). Worth a
               manual version check — it MIGHT be the affected line.
    * none   — not an Ivanti host, or a version string was read and it is at or
               above the fixed 22.7R2.5 line (a clean negative).

No credentials are submitted and no overflow payload is ever sent — every
request is a plain unauthenticated GET of a public path. Evidence records the
fingerprint marker, the endpoint reached, and the version string read from the
public surface only.

[Worker decision: plugin filename is cve_2025_0282.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2025_3248.py / cve_2024_23897.py convention.]

[Worker decision: this probe is version-fingerprint-only — CVE-2025-0282 is a
memory-corruption overflow and triggering it crashes/compromises the appliance,
so (like the Commvault, KACE and Langflow plugins) there is no benign
"control vs. bypass" active check. A HIGH is gated on an Ivanti fingerprint plus
an affected-version (< 22.7R2.5) match, never on sending a payload. An Ivanti
host on a fixed release (>= 22.7R2.5) is a clean negative and is never flagged,
not even MEDIUM.]

[Worker decision: Ivanti versions use the `MAJOR.MINORRn[Rm]` form
(e.g. 22.7R2.5). We parse the leading dotted `MAJOR.MINOR` plus the `Rn.m`
release/patch suffix into a comparable tuple. A bare dotted version with no `R`
suffix and no Ivanti marker is NOT a fingerprint — we never flag a non-Ivanti
host that happens to expose a version-looking token.]
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-0282",
    "name": "Ivanti Connect Secure pre-auth stack-overflow RCE",
    "description": (
        "Ivanti Connect Secure / Policy Secure / Neurons for ZTA before "
        "22.7R2.5 contain an unauthenticated stack-based buffer overflow in the "
        "web component allowing pre-auth remote code execution (CVSS 9.0). CISA "
        "added it to the KEV catalog in January 2025 after in-the-wild "
        "exploitation by a China-nexus actor deploying the SPAWN malware "
        "family. This probe reads the appliance's unauthenticated public "
        "version surface only and never sends an overflow payload."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-0282",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ],
    # Ivanti Connect Secure presents the SSL VPN web portal on 443 by default;
    # plain 80 usually redirects to it. port_hint is the canonical field the
    # runner reads to skip irrelevant plugins; default_ports is the in-probe
    # fallback alias.
    "port_hint": [443, 80, 8443],
    "service_hint": ["http", "https"],
    "default_ports": [443, 80, 8443],
}

# The unauthenticated GINA client version file is both an Ivanti fingerprint and
# the affected-version source. The welcome/login page and the root page are
# fallbacks that can still fingerprint Ivanti when the version file is stripped.
_VERSION_PATH = "/dana-na/nc/nc_gina_ver.txt"
_FINGERPRINT_PATHS = (
    _VERSION_PATH,
    "/dana-na/auth/url_default/welcome.cgi",
    "/dana-na/",
    "/",
)

# Case-insensitive substrings that mark an Ivanti Connect Secure host across the
# body, the Server header, and Set-Cookie. "/dana-na/" is the defining ICS
# web-login path; "dsstartpage"/"welcome to ivanti"/"pulse" appear in the login
# markup and the legacy Pulse Connect Secure branding; "dsid" is the ICS session
# cookie.
_IVANTI_MARKERS = (
    "/dana-na/",
    "dana-na",
    "ivanti connect secure",
    "pulse connect secure",
    "pulse secure",
    "dsstartpage",
    "welcome.cgi",
)

# The fix for the 22.7 line landed in 22.7R2.5; any build strictly below that is
# the affected window. Represented as the comparable tuple used below.
_FIXED_VERSION = (22, 7, 2, 5)
_FIXED_VERSION_STR = "22.7R2.5"

# Ivanti version form: MAJOR.MINOR R<rel>[.<patch>]  e.g. "22.7R2.5", "9.1R18".
# We capture the dotted MAJOR.MINOR and the R-release plus optional patch.
_IVANTI_VERSION_RE = re.compile(
    r"\b(\d{1,2})\.(\d{1,2})R(\d{1,3})(?:\.(\d{1,3}))?\b",
    re.IGNORECASE,
)

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

    TLS verification is disabled (Ivanti appliances commonly serve self-signed
    or internal-CA certs) and redirects are not followed: the version file and
    login page are served directly, and a redirect away means we should not
    assume a local Ivanti surface. No Authorization header or token is ever
    sent, and no overflow payload is ever constructed — every request is a plain
    GET of a public path.
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


def _is_ivanti(resp: httpx.Response | None) -> bool:
    """True when the response fingerprints an Ivanti Connect Secure host.

    We look across the page/body, the Server header, and Set-Cookie for an
    Ivanti marker. A bare version-looking token from an unrelated host is NOT an
    Ivanti fingerprint.
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
    return any(marker in haystack for marker in _IVANTI_MARKERS)


def _version_string(resp: httpx.Response | None) -> str | None:
    """Read the advertised Ivanti build string from a response.

    Scans the body and Server header for the Ivanti `MAJOR.MINORRn[.m]` token.
    Purely for recording + the affected-window decision. Returns None when no
    Ivanti-form version token is present.
    """
    if resp is None:
        return None
    haystack = " ".join((_server_header(resp), _body(resp)))
    match = _IVANTI_VERSION_RE.search(haystack)
    return match.group(0) if match is not None else None


def _parse_version(version: str) -> tuple[int, int, int, int] | None:
    """Parse an Ivanti version into a comparable (major, minor, rel, patch)."""
    match = _IVANTI_VERSION_RE.search(version)
    if match is None:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    rel = int(match.group(3))
    patch = int(match.group(4)) if match.group(4) is not None else 0
    return (major, minor, rel, patch)


def _is_affected(version: str) -> bool:
    """True when the version is strictly below the fixed 22.7R2.5 line."""
    parsed = _parse_version(version)
    if parsed is None:
        return False
    return parsed < _FIXED_VERSION


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this an Ivanti Connect Secure host at all? Try the
        #    version file first (it is also the affected-version source), then
        #    the login/root fallbacks. The first path that fingerprints wins for
        #    this port.
        fingerprint_resp: httpx.Response | None = None
        fingerprint_path: str | None = None
        for path in _FINGERPRINT_PATHS:
            resp = _get(f"{base}{path}")
            if _is_ivanti(resp):
                fingerprint_resp = resp
                fingerprint_path = path
                break

        if fingerprint_resp is None:
            # Not an Ivanti host on this port — never flag, even on odd bodies.
            continue

        server = _server_header(fingerprint_resp)
        version = _version_string(fingerprint_resp)
        # If we fingerprinted via the login/root page, the version file may carry
        # the build even though the fingerprint page did not. Read it explicitly
        # when we don't already have a version.
        if version is None and fingerprint_path != _VERSION_PATH:
            version_resp = _get(f"{base}{_VERSION_PATH}")
            if _is_ivanti(version_resp):
                version = _version_string(version_resp)

        if version is not None and _is_affected(version):
            # Ivanti on the affected < 22.7R2.5 line. The pre-auth RCE surface is
            # exposed; flag for an operator-driven active check (which miasma
            # deliberately skips — no overflow payload is ever sent).
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
                    "note": (
                        "Ivanti Connect Secure fingerprinted on an affected "
                        "pre-22.7R2.5 build. No overflow payload was sent — this "
                        "is a version-fingerprint flag for human-driven "
                        "confirmation, the memory-corruption RCE was NOT "
                        "triggered."
                    ),
                },
                description=metadata["description"],
            )

        # A version string WAS read but it is at or above the fixed 22.7R2.5 line
        # — this appliance is patched. A known-safe version is a clean negative,
        # not a candidate; do not flag it (not even MEDIUM).
        if version is not None:
            continue

        # Ivanti fingerprinted but NO version string could be read (hardened /
        # stripped appliance). Remember the first such host as a MEDIUM candidate
        # worth a manual version check; a confirmed HIGH on a later port wins.
        if medium_evidence is None:
            medium_evidence = {
                "base_url": base,
                "fingerprint_path": fingerprint_path,
                "server_header": server,
                "version_detected": version,
                "fixed_version": _FIXED_VERSION_STR,
                "note": (
                    "Ivanti Connect Secure fingerprinted but no version string "
                    "was read (hardened or stripped appliance). Manual version "
                    "check recommended; no overflow payload was sent."
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
