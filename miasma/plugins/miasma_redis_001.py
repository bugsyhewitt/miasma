"""MIASMA-REDIS-001 — Redis unauthenticated access (misconfiguration).

A Redis instance reachable without authentication lets any client read, write,
and delete every key, dump the dataset, and — depending on the build — abuse
``CONFIG``/``MODULE`` and the Lua engine. Wiz research (October 2025) counted
roughly 60,000 internet-exposed Redis instances with no auth configured. Bug
bounty programs rate unauthenticated Redis as P1/critical.

The exposure also gates a documented RCE chain: CVE-2025-49844 ("RediShell",
CVSS 10.0) is a Lua use-after-free reachable on instances up to and including
8.2.1. Unauthenticated access turns that into a one-step path to RCE, so the
version banner is captured to flag in-scope builds.

This probe is BENIGN and read-only. It speaks the Redis inline protocol over a
raw TCP socket:

    1. connect to a candidate port (6379, then 6380, 16379)
    2. send ``PING\\r\\n``
       * ``+PONG``        => no auth challenge => unauthenticated access (HIGH)
       * ``-NOAUTH`` /     => authentication is required => not vulnerable
         ``-ERR ... auth``
    3. on confirmed access, send ``INFO server\\r\\n`` and parse only the
       ``redis_version`` line for evidence and CVE-2025-49844 scoping

No keys are read, no data is written, no config is touched — exactly the inline
``PING``/``INFO`` handshake a human would run by hand to confirm the finding.

[Worker decision: plugin filename is miasma_redis_001.py (underscores) because
the runner discovers plugins via importlib and module names cannot contain
hyphens. The canonical id MIASMA-REDIS-001 lives in metadata["vuln_id"],
matching the existing miasma_actuator_001.py / cve_2009_3548.py convention.]
"""

from __future__ import annotations

import socket
from typing import Any

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-REDIS-001",
    "name": "Redis Unauthenticated Access",
    "description": (
        "Redis reachable without authentication, exposing full read/write "
        "access to all keys and the server configuration. Unauthenticated "
        "access also gates the CVE-2025-49844 Lua use-after-free RCE chain on "
        "affected builds."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-49844",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-21605",
        "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
    ],
    # Ports the probe will try, in order. Also the fallback when recon found
    # nothing. Exposed as port_hint per the improvement spec.
    "port_hint": [6379, 6380, 16379],
    "default_ports": [6379, 6380, 16379],
}

# Highest Redis version still in scope for CVE-2025-49844 (RediShell).
_REDISHELL_MAX_VERSION = (8, 2, 1)

_TIMEOUT = 5.0

# Read a single inline reply. Redis PING/INFO replies are small; cap the read so
# a hostile or non-Redis service can't make us buffer unbounded data.
_RECV_BYTES = 65536


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open Redis-ish ports; else the port hints."""
    open_ports = target.open_ports()
    if open_ports:
        redis_like = [
            port
            for port in open_ports
            if "redis" in target.service(port).get("name", "").lower()
            or port in metadata["port_hint"]
        ]
        return redis_like or open_ports
    return list(metadata["port_hint"])


def _exchange(host: str, port: int, request: bytes) -> str | None:
    """Open a TCP connection, send ``request``, return the decoded reply.

    Returns ``None`` on any socket error so one dead port never aborts the run.
    The connection is always closed; nothing is written beyond ``request``.
    """
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            sock.settimeout(_TIMEOUT)
            sock.sendall(request)
            data = sock.recv(_RECV_BYTES)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _parse_version(info_reply: str) -> str | None:
    """Pull ``redis_version`` from an ``INFO server`` reply (None if absent)."""
    for line in info_reply.splitlines():
        if line.startswith("redis_version:"):
            return line.split(":", 1)[1].strip()
    return None


def _version_tuple(version: str) -> tuple[int, ...] | None:
    """Parse ``8.2.1`` (or ``7.4.0-rc1``) into a comparable int tuple."""
    head = version.split("-", 1)[0]
    parts = head.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _is_redishell_vulnerable(version: str) -> bool:
    """True if ``version`` is <= 8.2.1 (in scope for CVE-2025-49844)."""
    parsed = _version_tuple(version)
    if parsed is None:
        return False
    # Pad to 3 components for a stable comparison (8.2 -> 8.2.0).
    padded = parsed + (0,) * (3 - len(parsed)) if len(parsed) < 3 else parsed
    return padded[:3] <= _REDISHELL_MAX_VERSION


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        ping_reply = _exchange(target.host, port, b"PING\r\n")
        if ping_reply is None:
            continue

        # A bare +PONG with no auth challenge => unauthenticated access.
        # -NOAUTH / -ERR ... authentication required => auth is enforced.
        if not ping_reply.startswith("+PONG"):
            continue

        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "ping_reply": ping_reply.strip(),
        }

        description = metadata["description"]

        info_reply = _exchange(target.host, port, b"INFO server\r\n")
        if info_reply is not None:
            version = _parse_version(info_reply)
            if version is not None:
                evidence["redis_version"] = version
                if _is_redishell_vulnerable(version):
                    evidence["cve_2025_49844_in_scope"] = True
                    description = (
                        description
                        + f" Reported version {version} is <= 8.2.1, within "
                        "scope of CVE-2025-49844 (RediShell, Lua use-after-free "
                        "-> RCE chain)."
                    )

        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="high",
            evidence=evidence,
            description=description,
        )

    return None
