"""MIASMA-GIT-001 — Exposed ``.git`` directory probe.

A web server that serves its working tree's ``.git/`` directory leaks the full
source code, complete commit history, and any secrets that were ever committed
(API keys, database credentials, ``.env`` files). With ``.git/`` reachable an
attacker can reconstruct the repository offline (``git-dumper`` and friends) and
mine every historical revision. Bug-bounty programs consistently rate an exposed
``.git`` directory as P1/P2.

This is not a discrete CVE — it is a widely recognised misconfiguration, most
often caused by ``git clone``-ing a repo into the web root and serving the whole
directory (Apache/nginx default static handlers happily serve dotfiles).

This probe is BENIGN and read-only. It fetches two small, inert metadata files
that exist in every Git repository:

    1. GET /.git/HEAD     — a one-line symbolic ref ("ref: refs/heads/<branch>").
    2. GET /.git/config   — the repo config; remote URLs occasionally embed
                            credentials ("https://user:pass@host/repo.git").

No repository is dumped, no objects are downloaded, no history is reconstructed.
``/.git/HEAD`` and ``/.git/config`` are the minimal two requests a human would
make to confirm the finding by hand.

Severity matrix:
    * HIGH   — /.git/HEAD returns 200 with a "ref: refs/heads/" symbolic ref
               (an exposed .git directory is confirmed). If /.git/config also
               returns a config whose remote URL embeds credentials
               (``://user:pass@``) the description is upgraded to call that out.
    * none   — /.git/HEAD is absent / non-200, or its body is not a Git ref
               (some servers return their SPA index.html for every path; that
               must not be flagged).

Candidate ports: the common web ports (80, 443, 8080, 8443). When recon has
found open ports the runner's applicability filter narrows this for us; the
probe itself still falls back to the default list when run standalone.

[Worker decision: plugin filename is miasma_git_001.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical id MIASMA-GIT-001 lives in metadata["vuln_id"], matching the
existing miasma_actuator_001.py / miasma_redis_001.py / miasma_elastic_001.py
convention.]
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-GIT-001",
    "name": "Exposed .git Directory",
    "description": (
        "The web server exposes its .git/ directory, leaking full source code, "
        "commit history, and any credentials ever committed. The repository can "
        "be reconstructed offline from the served Git objects."
    ),
    "confidence": "high",
    "references": [
        "https://owasp.org/www-community/attacks/Forced_browsing",
        "https://blog.detectify.com/2016/01/12/finding-and-exploiting-git-directories/",
        "https://github.com/arthaud/git-dumper",
    ],
    # Common HTTP(S) web ports. port_hint is the canonical field the runner reads
    # to skip irrelevant plugins; default_ports is kept as the in-probe fallback.
    "port_hint": [80, 443, 8080, 8443],
    "service_hint": ["http", "https"],
    "default_ports": [80, 443, 8080, 8443],
}

# A valid .git/HEAD is a one-line symbolic ref. Detached-HEAD repos store a raw
# 40-hex SHA instead; accept either so we don't miss a real exposure.
_HEAD_REF_RE = re.compile(r"^ref:\s+refs/")
_HEAD_SHA_RE = re.compile(r"^[0-9a-f]{40}\b")

# A remote URL with embedded credentials, e.g. https://user:pass@host/repo.git
_CRED_IN_URL_RE = re.compile(r"://[^/\s:@]+:[^/\s@]+@")

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
    return "https" if port in (443, 8443) else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign GET; returns None on any transport error.

    TLS verification is disabled and redirects are not followed: an exposed
    .git/HEAD is served as a static file, so a redirect (e.g. to a login page or
    an SPA route) means the dotfile is *not* directly served and must not flag.
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


def _is_git_head(resp: httpx.Response | None) -> bool:
    """True only when the body looks like a genuine .git/HEAD file.

    Guards against servers that return their SPA index.html (HTTP 200) for every
    path: such a body is HTML, not a Git ref, and must not be flagged.
    """
    if resp is None or resp.status_code != 200:
        return False
    try:
        body = resp.text
    except Exception:
        return False
    first_line = body.strip().splitlines()[0] if body.strip() else ""
    return bool(_HEAD_REF_RE.match(first_line) or _HEAD_SHA_RE.match(first_line))


def _config_with_creds(base: str) -> str | None:
    """GET /.git/config; return the matched credential-bearing URL or None.

    Only the credentials marker is returned (not the raw secret) so the finding
    evidence flags exposure without persisting the leaked password verbatim.
    """
    resp = _get(f"{base}/.git/config")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.text
    except Exception:
        return None
    match = _CRED_IN_URL_RE.search(body)
    if match is None:
        return None
    # Redact the password portion: keep "://user:***@" so a human knows a
    # credential is present without the report itself storing the secret.
    redacted = re.sub(r"(://[^/\s:@]+:)[^/\s@]+(@)", r"\1***\2", match.group(0))
    return redacted


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        head_resp = _get(f"{base}/.git/HEAD")
        if not _is_git_head(head_resp):
            continue

        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "url": f"{base}/.git/HEAD",
            "head_exposed": True,
        }
        description = metadata["description"]

        # Supplementary: does /.git/config leak credentials in a remote URL?
        cred_url = _config_with_creds(base)
        if cred_url is not None:
            evidence["config_exposed"] = True
            evidence["credential_in_remote_url"] = cred_url
            description += (
                " The .git/config remote URL embeds credentials "
                f"({cred_url})."
            )

        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="high",
            evidence=evidence,
            description=description,
        )

    return None
