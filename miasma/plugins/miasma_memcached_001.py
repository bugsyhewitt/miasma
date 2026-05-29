"""MIASMA-MEMCACHED-001 — Memcached unrestricted access.

Memcached is the ubiquitous in-memory key/value cache that fronts session
stores, query caches, rate-limit counters, and feature-flag tables for an
enormous fraction of web applications. By default it listens on TCP 11211 with
**no authentication, no authorisation, and no transport encryption**. SASL is
available but off by default and rarely enabled in production deployments; the
ASCII text protocol is the default conversation, so any network client that
reaches the port can read every cached key, exfiltrate every cached value
(routinely session cookies, JWT payloads, password-reset tokens, and rendered
HTML containing user PII), and — though we never do — flush the cache or
overwrite values to poison the application's view of state.

An internet- or broadly-internal-reachable Memcached is rated P1/HIGH on
bug-bounty programs: the contents of an application cache typically include
authenticated session data that is, by itself, enough for full account
takeover. Memcached has also been a long-running UDP amplification reflector
(CVE-2018-1000115; the famous 1.7 Tbps GitHub attack), so any internet-exposed
instance is a participation risk even if the data is empty.

This probe is BENIGN and read-only. It speaks the documented ASCII text
protocol over a raw TCP socket — exactly the ``echo stats | nc host 11211``
handshake a human runs by hand to confirm the finding — and never issues any
state-changing command (``set``, ``add``, ``replace``, ``delete``, ``incr``,
``decr``, ``flush_all``, and ``cache_memlimit`` are never sent; ``get`` is
never sent against any user key):

    1. send ``version\\r\\n`` -> a healthy Memcached replies with a single
       ``VERSION <semver>\\r\\n`` line. This is the fingerprint: only
       Memcached answers ``version`` with exactly this banner. Anything else
       => not Memcached (or SASL-required servers reply ``CLIENT_ERROR`` or
       ``ERROR`` first).
    2. send ``stats\\r\\n`` -> the server stats block. Parses ONLY the
       ``version``, ``pid``, ``uptime``, ``curr_items``, ``total_items``,
       ``bytes`` (current bytes stored), ``curr_connections``, and
       ``auth_cmds`` / ``auth_errors`` lines for evidence. The presence of any
       cached items (``curr_items > 0``) is the upgrade signal: the cache
       actively holds application data that is now readable by an
       unauthenticated peer.

No ``stats items``, ``stats slabs``, ``stats cachedump``, or ``get`` is ever
sent — those would read individual keys / values. The probe only confirms the
admin-text-protocol surface answers without authentication and reports the
high-level inventory counters.

Severity matrix:
    * HIGH   — ``version`` fingerprints Memcached AND ``stats`` answers
               unauthenticated AND the cache currently holds one or more
               items (``curr_items > 0``). The cache is live and an
               unauthenticated peer can read every value.
    * MEDIUM — ``version`` fingerprints Memcached AND ``stats`` answers
               unauthenticated, but the cache is empty (``curr_items == 0``).
               The admin surface is still exposed (and the server is still a
               UDP-amplification reflector if 11211/udp is also up), but no
               live application data is present right now.
    * MEDIUM — ``version`` fingerprints Memcached but ``stats`` is refused
               (SASL-only, or stats command disabled). Still a confirmed
               unauthenticated text-protocol surface worth reporting.
    * none   — no ``VERSION`` reply on any candidate port (not Memcached, or
               SASL is enforced at connect time).

[Worker decision: plugin filename is miasma_memcached_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-MEMCACHED-001 lives in
metadata["vuln_id"], matching the existing miasma_redis_001.py /
miasma_zookeeper_001.py convention. Memcached was named directly in the
round's improvement spec as a candidate next service-exposure plugin; it is
the natural sibling of the Redis/ZooKeeper unauthenticated-datastore family
and closes a recurring P1 bug-bounty gap (live application session data in
the cache, plus UDP amplification reflector posture).]
"""

from __future__ import annotations

import socket
from typing import Any

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-MEMCACHED-001",
    "name": "Memcached Unrestricted Access",
    "description": (
        "Memcached reachable on its TCP client port without authentication, "
        "exposing the ASCII text-protocol admin surface. Memcached ships with "
        "no auth, no authz, and no TLS by default; SASL is available but rarely "
        "enabled. Any client that reaches the port can read every cached key "
        "and value — routinely application session data, JWTs, password-reset "
        "tokens, and rendered HTML containing user PII — and the same port "
        "(11211/udp) has been a long-running UDP amplification reflector "
        "(CVE-2018-1000115)."
    ),
    "confidence": "high",
    "references": [
        "https://github.com/memcached/memcached/blob/master/doc/protocol.txt",
        "https://github.com/memcached/memcached/wiki/ConfiguringServer#authentication",
        "https://nvd.nist.gov/vuln/detail/CVE-2018-1000115",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [11211, 11210, 11212],
    "service_hint": ["memcache", "memcached"],
    "default_ports": [11211, 11210, 11212],
}

# A healthy Memcached answers ``version\r\n`` with exactly one line beginning
# with this token. It is the fingerprint that distinguishes Memcached from any
# other service that happens to be on 11211.
_VERSION_PREFIX = "VERSION "

_TIMEOUT = 5.0

# stats replies are small (a few KB at most on a fully populated server). Cap
# the read so a hostile or non-Memcached service cannot make us buffer unbounded
# data. The reply is terminated by ``END\r\n`` but we accept whatever the kernel
# hands us in one recv — text-protocol stats fits comfortably in one TCP segment
# for any realistic server.
_RECV_BYTES = 65536

# stats keys we extract into evidence. Memcached's stats reply is a sequence of
# ``STAT <key> <value>\r\n`` lines terminated by ``END\r\n``. We only read the
# inventory / fingerprint counters — never an individual cache key.
_STATS_KEYS_NUMERIC = (
    "pid",
    "uptime",
    "curr_items",
    "total_items",
    "bytes",
    "curr_connections",
    "auth_cmds",
    "auth_errors",
)
_STATS_KEYS_STRING = ("version",)


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Memcached-ish open ports; else the port hints."""
    open_ports = target.open_ports()
    if open_ports:
        memcached_like = [
            port
            for port in open_ports
            if "memcache" in target.service(port).get("name", "").lower()
            or port in metadata["port_hint"]
        ]
        return memcached_like or open_ports
    return list(metadata["port_hint"])


def _exchange(host: str, port: int, command: bytes) -> str | None:
    """Open a TCP connection, send one ASCII command, return the decoded reply.

    Each command gets its own short-lived connection (mirroring ``nc``). Returns
    ``None`` on any socket error so one dead port never aborts the run. Only the
    benign commands ``version`` and ``stats`` are ever sent; no ``get``, ``set``,
    or other mutating command is issued.
    """
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            sock.settimeout(_TIMEOUT)
            sock.sendall(command)
            data = sock.recv(_RECV_BYTES)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _is_memcached_version_banner(reply: str | None) -> bool:
    """True when a ``version`` reply is Memcached's ``VERSION <semver>`` line.

    Memcached answers ``version\\r\\n`` with exactly one ``VERSION <semver>\\r\\n``
    line. We require the prefix to be present at the start of the (stripped)
    reply so a chatty banner like an SSH server's ``SSH-2.0-OpenSSH_9.6`` or a
    Redis ``-ERR unknown command 'version'`` cannot be confused for Memcached.
    """
    if reply is None:
        return False
    return reply.lstrip().startswith(_VERSION_PREFIX)


def _parse_version_banner(reply: str) -> str | None:
    """Extract the ``<semver>`` token from a Memcached ``VERSION ...`` reply."""
    head = reply.lstrip().splitlines()[0] if reply.strip() else ""
    if not head.startswith(_VERSION_PREFIX):
        return None
    version = head[len(_VERSION_PREFIX) :].strip()
    return version or None


def _parse_stats(reply: str) -> dict[str, Any]:
    """Pull the documented counter keys from a Memcached ``stats`` reply.

    A genuine ``stats`` reply is a sequence of ``STAT <key> <value>\\r\\n``
    lines terminated by a single ``END\\r\\n`` line, e.g.::

        STAT pid 1
        STAT uptime 12345
        STAT version 1.6.21
        STAT curr_items 4096
        STAT bytes 1048576
        ...
        END

    Numeric counters are coerced to ``int``; the textual ``version`` is left as
    a string. Any unknown keys are ignored. Missing keys do not raise. Returns
    an empty dict when the reply is not a stats block at all (e.g.
    ``CLIENT_ERROR`` from a SASL-only server).
    """
    parsed: dict[str, Any] = {}
    for line in reply.splitlines():
        if not line.startswith("STAT "):
            continue
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        _, key, value = parts
        if key in _STATS_KEYS_NUMERIC:
            try:
                parsed[key] = int(value)
            except ValueError:
                continue
        elif key in _STATS_KEYS_STRING:
            parsed[key] = value
    return parsed


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        # 1. Fingerprint via the documented ``version`` command. Only Memcached
        #    answers with the ``VERSION <semver>`` banner.
        version_reply = _exchange(target.host, port, b"version\r\n")
        if not _is_memcached_version_banner(version_reply):
            continue
        banner_version = _parse_version_banner(version_reply or "")

        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "version_banner": True,
        }
        if banner_version:
            evidence["version"] = banner_version
        description = metadata["description"]

        # 2. stats — confirms the admin text-protocol surface answers
        #    unauthenticated and exposes the inventory counters. May be refused
        #    on SASL-only servers (those typically refuse the initial ``version``
        #    too, but a defensive admin may have stripped just ``stats``).
        stats_reply = _exchange(target.host, port, b"stats\r\n")
        stats = _parse_stats(stats_reply) if stats_reply is not None else {}

        if stats:
            evidence["stats_unauthenticated"] = True
            # Prefer the stats-reported version (authoritative) over the banner.
            if "version" in stats:
                evidence["version"] = stats["version"]
            for key in _STATS_KEYS_NUMERIC:
                if key in stats:
                    evidence[key] = stats[key]

            curr_items = stats.get("curr_items")
            if isinstance(curr_items, int) and curr_items > 0:
                # Live cache with application data => HIGH.
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence=evidence,
                    description=(
                        description
                        + " The stats command answered without authentication "
                        "and the cache currently holds one or more items — "
                        "an unauthenticated peer can read every cached value."
                    ),
                )

            # Admin surface answers but the cache is empty right now. Still a
            # confirmed unauth Memcached (and a potential amplification
            # reflector on 11211/udp), but no live data is present.
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="medium",
                evidence=evidence,
                description=(
                    description
                    + " The stats command answered without authentication; "
                    "the cache is currently empty so no application data is "
                    "exposed right now, but the admin text-protocol surface "
                    "is reachable."
                ),
            )

        # version answered but stats is refused — still a confirmed
        # unauthenticated text-protocol surface, but only the banner is
        # reachable on this port.
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence=evidence,
            description=(
                description
                + " The version banner answered without authentication; the "
                "stats command was refused/blocked on this port (only the "
                "version banner is reachable)."
            ),
        )

    return None
