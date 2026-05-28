"""MIASMA-ENV-001 — Exposed ``.env`` file probe.

A web server that serves its application ``.env`` file leaks the application's
most concentrated bundle of secrets: ``DATABASE_URL``, ``AWS_SECRET_ACCESS_KEY``,
API keys, JWT/app signing secrets, SMTP credentials, and more. It is among the
most common high-impact bug-bounty findings, routinely caused by misconfigured
Laravel, Node.js, and Django deployments that serve the project root statically
(the dotfile is happily handed out by default static handlers).

This is not a discrete CVE — it is a widely recognised misconfiguration.

This probe is BENIGN and read-only. It fetches a small, inert file at a handful
of well-known dotenv locations:

    GET /.env              — the canonical location.
    GET /.env.production   — Laravel/Node environment-specific variants.
    GET /.env.local
    GET /.env.dev

No file is written, no state changes, and nothing beyond the dotenv file itself
is requested. ``/.env`` is the single request a human would make to confirm the
finding by hand.

Severity matrix:
    * HIGH   — a candidate path returns 200 with a body that parses as dotenv
               content (one or more ``KEY=value`` assignment lines) AND at least
               one of those keys looks secret-bearing (``SECRET``/``KEY``/
               ``PASSWORD``/``TOKEN``/``CREDENTIAL``/``API``/``PRIVATE``/``DSN``/
               ``DATABASE_URL``). A live ``.env`` with real secrets is confirmed.
    * MEDIUM — a candidate path returns 200 with parseable dotenv content but no
               recognised secret-bearing key (config-only ``.env``: still an
               information-disclosure misconfiguration worth a manual look).
    * none   — no candidate path returns dotenv-shaped content (404/403, or a
               200 body that is HTML / not ``KEY=value`` lines — an SPA that
               returns index.html for every path must not be flagged).

The leaked secret *values* are never persisted: evidence records only the set of
exposed key *names* (and a redacted ``KEY=***`` preview), so the report flags the
exposure without storing the secrets verbatim.

Candidate ports: the common web ports (80, 443, 8080, 8443). When recon has
found open ports the runner's applicability filter narrows this for us; the probe
itself still falls back to the default list when run standalone.

[Worker decision: plugin filename is miasma_env_001.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical id MIASMA-ENV-001 lives in metadata["vuln_id"], matching the
existing miasma_git_001.py / miasma_actuator_001.py convention.]
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-ENV-001",
    "name": "Exposed .env File",
    "description": (
        "The web server exposes an application .env file, leaking environment "
        "secrets such as database URLs, cloud access keys, API keys, and app "
        "signing secrets. The file is the application's most concentrated "
        "bundle of credentials."
    ),
    "confidence": "high",
    "references": [
        "https://owasp.org/www-community/attacks/Forced_browsing",
        "https://cwe.mitre.org/data/definitions/538.html",
        "https://laravel.com/docs/configuration#environment-configuration",
    ],
    # Common HTTP(S) web ports. port_hint is the canonical field the runner reads
    # to skip irrelevant plugins; default_ports is kept as the in-probe fallback.
    "port_hint": [80, 443, 8080, 8443],
    "service_hint": ["http", "https"],
    "default_ports": [80, 443, 8080, 8443],
}

# Well-known dotenv locations, probed in order. The bare /.env is overwhelmingly
# the common case; the variants catch Laravel/Node environment-specific files.
_CANDIDATE_PATHS = ("/.env", "/.env.production", "/.env.local", "/.env.dev")

# A dotenv assignment line: KEY=value. Keys are letters, digits, and underscores
# (optionally prefixed with "export "). We deliberately do NOT require a value to
# be present (KEY= is valid dotenv), but we do require the KEY= shape.
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")

# Key-name substrings that mark a value as secret-bearing. Case-insensitive.
_SECRET_KEY_MARKERS = (
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "CREDENTIAL",
    "PRIVATE",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "DATABASE_URL",
    "DB_PASSWORD",
    "DSN",
    "AUTH",
)

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
    .env is served as a static file, so a redirect (e.g. to a login page or an
    SPA route) means the dotfile is *not* directly served and must not flag.
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


def _parse_env_keys(body: str) -> list[str]:
    """Return the KEY names found in a dotenv-shaped body, in order.

    A genuine .env is a series of ``KEY=value`` lines (with optional comments and
    blank lines). A server that returns its SPA index.html for every path yields
    HTML with no ``KEY=`` lines, so this returns an empty list and we don't flag.
    """
    keys: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE_RE.match(line)
        if match:
            keys.append(match.group(1))
    return keys


def _is_secret_key(key: str) -> bool:
    """True when a key name contains a recognised secret-bearing marker."""
    upper = key.upper()
    return any(marker in upper for marker in _SECRET_KEY_MARKERS)


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        for path in _CANDIDATE_PATHS:
            url = f"{base}{path}"
            resp = _get(url)
            if resp is None or resp.status_code != 200:
                continue

            try:
                body = resp.text
            except Exception:
                continue

            keys = _parse_env_keys(body)
            if not keys:
                # Not dotenv-shaped (HTML / SPA index / empty) — never flag.
                continue

            secret_keys = [k for k in keys if _is_secret_key(k)]
            confidence = "high" if secret_keys else "medium"

            evidence: dict[str, Any] = {
                "host": target.host,
                "port": port,
                "url": url,
                "path": path,
                # Only key *names* are persisted — never the secret values.
                "exposed_keys": keys,
                "secret_keys": secret_keys,
                "key_count": len(keys),
            }
            description = metadata["description"]
            if secret_keys:
                description += (
                    " Secret-bearing keys are present in the served file: "
                    f"{', '.join(secret_keys)} (values redacted)."
                )
            else:
                description += (
                    " The served file is config-only (no recognised "
                    "secret-bearing keys), but exposing it is still an "
                    "information-disclosure misconfiguration."
                )

            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence=confidence,
                evidence=evidence,
                description=description,
            )

    return None
