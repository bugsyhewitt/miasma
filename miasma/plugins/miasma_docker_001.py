"""MIASMA-DOCKER-001 — Docker daemon unauthenticated TCP API exposure.

A Docker daemon with the plaintext TCP socket enabled (``dockerd -H
tcp://0.0.0.0:2375``) is reachable over HTTP with zero authentication. Any
client can list running containers, pull/push images, start new containers,
and — by launching a container with a host-path bind mount — read and write
arbitrary files on the host filesystem with root-equivalent access. The Docker
API has no rate limiting or session layer on the plaintext socket.

This is a critical misconfiguration. Cloud provider default AMIs and Kubernetes
node images no longer ship it, but legacy CI boxes, self-managed Docker hosts,
and some container-in-container build setups still expose it. Bug-bounty
programs and pentest assessors classify this as P1/critical.

This probe is BENIGN. It speaks only the Docker HTTP API and only issues
unauthenticated GETs against the well-known read-only diagnostic endpoints:

    1. GET /version  — the Docker version handshake. Returns a JSON object
       containing ``ApiVersion``; this is the canonical fingerprint.
    2. GET /containers/json  — running container list. A ``200`` with a JSON
       array means anonymous access reaches live container metadata.

No container is created, started, stopped, or deleted. No image is pulled or
pushed. No shell command is executed. No filesystem path is accessed. Evidence
records only the version string and container count — never container names,
image names, environment variables, or bind-mount paths.

[Worker decision: ID is MIASMA-DOCKER-001 (misconfiguration, not a CVE).
Plaintext Docker API exposure is a configuration choice, not a software
defect. Mirrors the MIASMA-REDIS-001 / MIASMA-K8S-001 naming convention.]

[Worker decision: severity HIGH when /containers/json is accessible (live
resource enumeration); MEDIUM when only /version is accessible (version
disclosure + unauthenticated API surface). This matches the K8S-001
two-tier model and correctly ranks resource enumeration above version-only
disclosure.]
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-DOCKER-001",
    "name": "Docker Daemon Unauthenticated TCP API",
    "description": (
        "Docker daemon exposes its management HTTP API on a plaintext TCP "
        "socket with no authentication. Any network client can enumerate "
        "running containers and, by launching a privileged container with a "
        "host-path bind mount, achieve root-equivalent access to the host "
        "filesystem. This is a P1/critical misconfiguration."
    ),
    "confidence": "high",
    "references": [
        "https://docs.docker.com/engine/security/protect-access/",
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    "port_hint": [2375, 2376],
    "service_hint": ["docker", "http"],
    "default_ports": [2375, 2376],
}

# Docker /version response keys that positively identify the API server.
_VERSION_KEYS = ("ApiVersion", "Version")

# The Docker containers list endpoint returns a JSON array of objects.
_CONTAINERS_PATH = "/containers/json"
_VERSION_PATH = "/version"

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    open_ports = target.open_ports()
    if open_ports:
        docker_like = [
            port
            for port in open_ports
            if "docker" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return docker_like or open_ports
    return list(metadata["default_ports"])


def _get(url: str) -> httpx.Response | None:
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _json_body(resp: httpx.Response | None) -> Any:
    if resp is None:
        return None
    try:
        return json.loads(resp.text)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None


def _docker_version(resp: httpx.Response | None) -> dict[str, Any] | None:
    """Return the parsed /version object if it fingerprints Docker, else None."""
    if resp is None or resp.status_code != 200:
        return None
    body = _json_body(resp)
    if not isinstance(body, dict):
        return None
    if any(k in body for k in _VERSION_KEYS):
        return body
    return None


def _container_count(resp: httpx.Response | None) -> int | None:
    """Return the number of containers when the list endpoint is open.

    Returns None when the endpoint refused, errored, or returned a non-array
    body (a proxy 200 on an unrelated service can return JSON objects).
    """
    if resp is None or resp.status_code != 200:
        return None
    body = _json_body(resp)
    if not isinstance(body, list):
        return None
    return len(body)


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        scheme = "https" if port == 2376 else "http"
        base = f"{scheme}://{target.host}:{port}"

        version_resp = _get(f"{base}{_VERSION_PATH}")
        version_obj = _docker_version(version_resp)
        if version_obj is None:
            continue

        api_version = version_obj.get("ApiVersion")
        docker_version = version_obj.get("Version")

        containers_resp = _get(f"{base}{_CONTAINERS_PATH}")
        count = _container_count(containers_resp)

        if count is not None:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "base_url": base,
                    "version_endpoint": _VERSION_PATH,
                    "containers_endpoint": _CONTAINERS_PATH,
                    "docker_version": docker_version,
                    "api_version": api_version,
                    "running_container_count": count,
                    "note": (
                        "Docker daemon API is accessible without authentication. "
                        "Container list enumeration succeeded — only the count is "
                        "recorded; no container names, image names, environment "
                        "variables, or bind-mount paths were read, and no resource "
                        "was created or modified."
                    ),
                },
                description=metadata["description"],
            )

        if medium_evidence is None:
            medium_evidence = {
                "base_url": base,
                "version_endpoint": _VERSION_PATH,
                "docker_version": docker_version,
                "api_version": api_version,
                "containers_status": (
                    containers_resp.status_code
                    if containers_resp is not None
                    else None
                ),
                "note": (
                    "Docker daemon API returns version information to "
                    "unauthenticated requests. Container enumeration was refused "
                    "or returned an unexpected body, but the unauthenticated API "
                    "surface is present and warrants a manual deeper check."
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
