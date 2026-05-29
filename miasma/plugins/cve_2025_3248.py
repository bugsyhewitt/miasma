"""CVE-2025-3248 — Langflow unauthenticated remote code execution.

Langflow (the popular low-code framework for building LLM/agent workflows)
exposes a ``/api/v1/validate/code`` endpoint that, before the 1.3.0 fix,
compiles and executes attacker-supplied Python via ``exec`` without any
authentication. An unauthenticated request to that endpoint yields direct
remote code execution on the Langflow host — a pre-auth RCE on a framework
that frequently holds API keys for downstream LLM providers and internal
services. CISA added CVE-2025-3248 to the KEV catalog in May 2025 after
in-the-wild exploitation (botnet recruitment, crypto-miners), and it is a
recurring critical (CVSS 9.8) item on AI/ML bug-bounty scope.

This probe is BENIGN, read-only, and VERSION-FINGERPRINT ONLY. It NEVER
touches the vulnerable ``/api/v1/validate/code`` endpoint and sends no code:
POSTing to that path is the active RCE trigger and is out of scope for miasma.
We instead read Langflow's unauthenticated public version endpoint, fingerprint
the host as Langflow, and flag only when the advertised build falls in the
affected ``< 1.3.0`` window. A human then confirms and decides on the active
check.

Flow:

    1. GET /api/v1/version    — Langflow's unauthenticated version endpoint.
       (then /health, /)        On an affected build this returns a JSON object
                                with a ``version`` string and usually a
                                ``package``/``main`` marker naming Langflow. It
                                is the canonical Langflow fingerprint AND the
                                affected-version source in one request. /health
                                and the root page are tried as fallbacks to
                                fingerprint Langflow when /api/v1/version is
                                stripped.
    2. Compare the version     — the fix landed in 1.3.0; any build strictly
                                below 1.3.0 is the affected window.

Severity:

    * HIGH   — the host fingerprints as Langflow AND an affected ``< 1.3.0``
               version string is present. The pre-auth RCE surface is exposed;
               flag for an operator-driven active check (which miasma skips).
    * MEDIUM — the host fingerprints as Langflow but no version string could be
               read (hardened/stripped deployment). The host is worth a manual
               version check — it MIGHT be the affected line.
    * none   — not a Langflow host, or a version string was read and it is at or
               above the fixed 1.3.0 line (a clean negative).

No credentials are submitted and the vulnerable ``/api/v1/validate/code``
endpoint is never contacted. Evidence records the fingerprint marker, the
endpoint reached, and the version string read from the public endpoint only.

[Worker decision: plugin filename is cve_2025_3248.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical CVE id lives in metadata["vuln_id"], matching the existing
cve_2024_23897.py / cve_2025_34028.py convention.]

[Worker decision: this probe is version-fingerprint-only — POSTing the
/api/v1/validate/code endpoint is the active RCE trigger, so (like the Commvault
and KACE plugins) there is no "control vs. bypass" comparison. A HIGH is gated on
a Langflow fingerprint + an affected-version (< 1.3.0) match, never on executing
code. A Langflow host on a fixed release (>= 1.3.0) is a clean negative and is
never flagged, not even MEDIUM.]

[Worker decision: the fingerprint requires a Langflow-specific marker (the
version endpoint's package/main field naming Langflow, or a langflow token in
the body/headers) — a bare JSON ``{"version": ...}`` 200 from an unrelated API is
NOT a Langflow fingerprint, so we never flag a non-Langflow host that happens to
expose a version field.]
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2025-3248",
    "name": "Langflow unauthenticated remote code execution",
    "description": (
        "Langflow before 1.3.0 exposes /api/v1/validate/code without "
        "authentication, compiling and executing attacker-supplied Python via "
        "exec — an unauthenticated pre-auth remote code execution. Langflow "
        "deployments commonly hold downstream LLM-provider and internal API "
        "keys, so the CVE was added to CISA's KEV catalog (May 2025) after "
        "in-the-wild exploitation. This probe reads the unauthenticated version "
        "endpoint only and never touches the vulnerable code endpoint."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-3248",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ],
    # Langflow's dev server listens on 7860 by default; containerised/proxied
    # deployments commonly front it on 80/443/8080/8443. port_hint is the
    # canonical field the runner reads to skip irrelevant plugins; default_ports
    # is the in-probe fallback alias.
    "port_hint": [7860, 80, 443, 8080, 8443],
    "service_hint": ["http", "https"],
    "default_ports": [7860, 80, 443, 8080, 8443],
}

# The unauthenticated version endpoint is both the fingerprint and the affected
# -version source. /health and the root page are fallbacks that can still
# fingerprint Langflow when the version endpoint is stripped.
_VERSION_PATH = "/api/v1/version"
_FINGERPRINT_PATHS = (
    _VERSION_PATH,
    "/health",
    "/",
)

# The vulnerable endpoint — declared ONLY so we can assert in tests / review that
# the probe never contacts it. It is never requested.
_VULNERABLE_PATH = "/api/v1/validate/code"

# Case-insensitive substrings that mark a Langflow host across the JSON body, the
# Server header, and Set-Cookie. "langflow" is the package name surfaced by the
# version endpoint (``package``/``main``) and the UI title.
_LANGFLOW_MARKERS = (
    "langflow",
)

# The fix landed in 1.3.0; any build strictly below 1.3.0 is the affected window.
_FIXED_VERSION = (1, 3, 0)

# Extract a dotted semantic version (1, 2, or 3 numeric components, optional
# pre-release/build suffix we ignore for comparison). Used to RECORD and to
# decide the affected window.
_VERSION_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})(?:\.(\d{1,4}))?\b")

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

    TLS verification is disabled (self-hosted Langflow often serves self-signed
    certs) and redirects are not followed: the version endpoint is served
    directly, and a redirect to an SSO/login provider means we should not assume
    a local Langflow surface. No Authorization header or token is ever sent.
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


def _json_body(resp: httpx.Response | None) -> dict[str, Any] | None:
    """Parse a response body as a JSON object, or None if it isn't one."""
    if resp is None:
        return None
    try:
        data = json.loads(resp.text)
    except (json.JSONDecodeError, UnicodeDecodeError, httpx.HTTPError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _is_langflow(resp: httpx.Response | None) -> bool:
    """True when the response fingerprints a Langflow host.

    We look across the page/JSON body, the Server header, and Set-Cookie for a
    ``langflow`` marker. A bare ``{"version": ...}`` from an unrelated API is NOT
    a Langflow fingerprint.
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
    return any(marker in haystack for marker in _LANGFLOW_MARKERS)


def _version_string(resp: httpx.Response | None) -> str | None:
    """Read the advertised version string from a Langflow response.

    Prefers the JSON ``version`` field from /api/v1/version; falls back to the
    first dotted version token anywhere in the body/Server header. Purely for
    recording + the affected-window decision. Returns None when no version-ish
    token is present.
    """
    if resp is None:
        return None
    body = _json_body(resp)
    if body is not None:
        version = body.get("version")
        if isinstance(version, str) and _VERSION_RE.search(version):
            return version
    haystack = " ".join((_server_header(resp), _body(resp)))
    match = _VERSION_RE.search(haystack)
    return match.group(0) if match is not None else None


def _parse_version(version: str) -> tuple[int, int, int] | None:
    """Parse a dotted version string into a (major, minor, patch) tuple."""
    match = _VERSION_RE.search(version)
    if match is None:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def _is_affected(version: str) -> bool:
    """True when the version is strictly below the fixed 1.3.0 line."""
    parsed = _parse_version(version)
    if parsed is None:
        return False
    return parsed < _FIXED_VERSION


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint: is this a Langflow host at all? Try the version endpoint
        #    first (it is also the affected-version source), then the fallbacks.
        #    The first path that fingerprints wins for this port.
        fingerprint_resp: httpx.Response | None = None
        fingerprint_path: str | None = None
        for path in _FINGERPRINT_PATHS:
            resp = _get(f"{base}{path}")
            if _is_langflow(resp):
                fingerprint_resp = resp
                fingerprint_path = path
                break

        if fingerprint_resp is None:
            # Not a Langflow host on this port — never flag, even on odd bodies.
            continue

        server = _server_header(fingerprint_resp)
        version = _version_string(fingerprint_resp)
        # If we fingerprinted via /health or /, the version endpoint may carry the
        # build even though the fingerprint page did not. Read it explicitly when
        # we don't already have a version.
        if version is None and fingerprint_path != _VERSION_PATH:
            version_resp = _get(f"{base}{_VERSION_PATH}")
            if _is_langflow(version_resp):
                version = _version_string(version_resp)

        if version is not None and _is_affected(version):
            # Langflow on the affected < 1.3.0 line. The pre-auth RCE surface is
            # exposed; flag for an operator-driven active check (which miasma
            # deliberately skips — /api/v1/validate/code is never contacted).
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "base_url": base,
                    "fingerprint_path": fingerprint_path,
                    "server_header": server,
                    "version_detected": version,
                    "fixed_version": "1.3.0",
                    "note": (
                        "Langflow fingerprinted on an affected pre-1.3.0 build. "
                        "The vulnerable /api/v1/validate/code endpoint was NOT "
                        "contacted — this is a version-fingerprint flag for "
                        "human-driven confirmation, no code was executed."
                    ),
                },
                description=metadata["description"],
            )

        # A version string WAS read but it is at or above the fixed 1.3.0 line —
        # this host is patched. A known-safe version is a clean negative, not a
        # candidate; do not flag it (not even MEDIUM).
        if version is not None:
            continue

        # Langflow fingerprinted but NO version string could be read (hardened /
        # stripped deployment). Remember the first such host as a MEDIUM candidate
        # worth a manual version check; a confirmed HIGH on a later port wins.
        if medium_evidence is None:
            medium_evidence = {
                "base_url": base,
                "fingerprint_path": fingerprint_path,
                "server_header": server,
                "version_detected": version,
                "fixed_version": "1.3.0",
                "note": (
                    "Langflow fingerprinted but no version string was read "
                    "(hardened or stripped deployment). Manual version check "
                    "recommended; the vulnerable code endpoint was NOT contacted."
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
