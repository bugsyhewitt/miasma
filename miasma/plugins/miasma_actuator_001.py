"""MIASMA-ACTUATOR-001 — Spring Boot Actuator exposure (misconfiguration).

Spring Boot applications that expose ``/actuator/*`` without authentication
leak environment variables, credentials, heap dumps, thread traces, and full
runtime configuration. A documented real-world breach (Volkswagen) exposed
plaintext AWS keys via an unauthenticated heap dump. CISA and multiple 2025
advisories flag this as a top-priority finding. There is no single CVE — it is
a misconfiguration class — but see CVE-2025-22235 (matcher bug) and
CVE-2025-41243 (Spring Cloud Gateway RCE vector).

This probe is BENIGN and read-only. It walks the lowest-risk endpoints first:

    1. GET /actuator/health   — confirms a Spring Boot app is alive (baseline)
    2. GET /actuator          — confirms the management base is reachable
    3. GET /actuator/env      — the sensitive endpoint (env vars, secrets)
    4. GET /actuator/heapdump — HEADER-ONLY check; the body is never downloaded

Severity:
    * HIGH   — /actuator/env returns 200 with JSON containing keys that look
               like secrets (password / secret / key / token / credential).
    * MEDIUM — the management surface is reachable (env returns 200 but with no
               recognised secrets, OR /actuator is reachable but /actuator/env
               is blocked 401/403) — partial exposure still worth reporting.
    * none   — nothing under /actuator responds 200.

No exploitation, no state change, no body download of the heap dump — only the
``Content-Type`` and ``Content-Length`` headers are inspected so a human can
confirm a downloadable dump exists.

[Worker decision: plugin filename is miasma_actuator_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-ACTUATOR-001 lives in
metadata["vuln_id"], matching the existing cve_2009_3548.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-ACTUATOR-001",
    "name": "Spring Boot Actuator exposure",
    "description": (
        "Unauthenticated Spring Boot Actuator management endpoints exposed, "
        "leaking environment variables, configuration, and potentially "
        "credentials or a downloadable heap dump."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-22235",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-41243",
        "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",
    ],
    # Management ports we'll consider; also the fallback when recon found none.
    "default_ports": [80, 443, 8080, 8443, 8090, 9090],
}

# Substrings that mark an env property key as secret-bearing (case-insensitive).
_SECRET_MARKERS = ("password", "secret", "key", "token", "credential")

# TLS ports where we should speak https.
_TLS_PORTS = (443, 8443)

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open management ports; else the defaults."""
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


def _find_secret_keys(env_json: Any) -> list[str]:
    """Extract property keys that look like secrets from /actuator/env JSON.

    Spring Boot's env endpoint shape:
        {"propertySources": [{"name": ..., "properties": {"<key>": {...}}}]}
    We tolerate malformed/partial bodies and simply return [] if we can't parse.
    """
    keys: list[str] = []
    if not isinstance(env_json, dict):
        return keys
    for source in env_json.get("propertySources", []):
        if not isinstance(source, dict):
            continue
        props = source.get("properties", {})
        if not isinstance(props, dict):
            continue
        for key in props:
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_MARKERS):
                keys.append(key)
    return keys


def _check_heapdump(base: str) -> dict[str, Any] | None:
    """Header-only check for a downloadable heap dump. Never reads the body."""
    resp = _get(f"{base}/actuator/heapdump")
    if resp is None or resp.status_code != 200:
        return None
    return {
        "available": True,
        "content_type": resp.headers.get("content-type", ""),
        "content_length": resp.headers.get("content-length", ""),
    }


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Lowest-risk baseline: is a Spring Boot app even here?
        health = _get(f"{base}/actuator/health")
        if health is None or health.status_code != 200:
            continue

        # 2. Is the management base reachable?
        actuator = _get(f"{base}/actuator")
        actuator_status = actuator.status_code if actuator is not None else None

        # 3. The sensitive endpoint.
        env = _get(f"{base}/actuator/env")
        env_status = env.status_code if env is not None else None

        if env_status == 200:
            secret_keys: list[str] = []
            try:
                secret_keys = _find_secret_keys(env.json())
            except (ValueError, httpx.HTTPError):
                secret_keys = []

            heapdump = _check_heapdump(base)
            evidence: dict[str, Any] = {
                "base_url": base,
                "health_status": 200,
                "actuator_status": actuator_status,
                "env_status": 200,
                "secret_keys": secret_keys,
            }
            if heapdump is not None:
                evidence["heapdump"] = heapdump

            # env reachable + recognised secrets => HIGH; otherwise MEDIUM.
            confidence = "high" if secret_keys else "medium"
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence=confidence,
                evidence=evidence,
                description=metadata["description"],
            )

        # 4. Partial exposure: /actuator reachable but env blocked/absent.
        if actuator_status == 200:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="medium",
                evidence={
                    "base_url": base,
                    "health_status": 200,
                    "actuator_status": 200,
                    "env_status": env_status,
                    "secret_keys": [],
                    "note": (
                        "Management base reachable; /actuator/env not exposed "
                        "(partial exposure)."
                    ),
                },
                description=metadata["description"],
            )

    return None
