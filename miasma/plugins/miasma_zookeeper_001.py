"""MIASMA-ZOOKEEPER-001 — Apache ZooKeeper unauthenticated admin/read access.

Apache ZooKeeper is the distributed coordination service that backs Kafka,
HBase, SolrCloud, Hadoop/YARN, Druid, NiFi, ClickHouse Keeper deployments, and
countless service-discovery and distributed-lock systems. By default it listens
on TCP 2181 with **no transport authentication**: ZooKeeper's SASL/ACL system
guards individual znodes, but the connection itself is anonymous and the
"four-letter-word" (4lw) admin commands answer any client that can reach the
port. An operator who relies on znode ACLs for security still leaks the entire
server fingerprint, JVM environment, and live client/session inventory to any
unauthenticated peer — and, on the common default-ACL clusters, the znode tree
itself (Kafka topic metadata, broker registrations, config, and frequently
credentials stored as znode data) is world-readable.

An internet- or broadly-internal-reachable ZooKeeper on 2181 is rated P1/HIGH on
bug-bounty programs: the 4lw surface alone discloses the exact version (for
matching known ZooKeeper CVEs), the data directory and Java classpath, system
properties (which routinely carry credentials and tokens passed as ``-D`` flags),
and a full list of every connected client with its session id and the operations
it has issued.

This probe is BENIGN and read-only. It speaks the 4lw protocol over a raw TCP
socket — exactly the ``echo ruok | nc host 2181`` handshake a human runs by hand
to confirm the finding — and never opens a ZooKeeper client session, reads a
znode, or issues any state-changing 4lw command (``kill``, ``stmk``, ``crst``,
``srst`` are never sent):

    1. send ``ruok``  -> a healthy ZooKeeper replies ``imok`` and nothing else.
       This is the fingerprint: only ZooKeeper answers ``ruok`` with exactly
       ``imok``. Anything else => not ZooKeeper (or 4lw whitelisting blocks it).
    2. send ``srvr``  -> the server summary. Parses ONLY the ``Version:`` line
       for evidence and CVE-scoping, and the ``Mode:`` line (leader / follower /
       standalone) to record the cluster role. Confirms the admin surface
       answers unauthenticated.
    3. send ``envi``  -> the environment dump. Scanned IN MEMORY only for the
       presence of credential-bearing system properties (``*.password``,
       ``*.secret``, ``*.token``, ``javax.net.ssl.keyStorePassword`` ...). Only a
       boolean "a credential-looking property name was present" is recorded —
       the property VALUES are never stored in the finding.

Severity matrix:
    * HIGH   — ``ruok`` => ``imok`` AND ``srvr`` answers unauthenticated (the
               full admin surface — version, data dir, latency, client count —
               is exposed). Also HIGH when ``envi`` reveals a credential-bearing
               system-property name.
    * MEDIUM — ``ruok`` => ``imok`` but ``srvr`` is whitelisted/blocked (only the
               liveness word answers; still a confirmed unauthenticated 4lw
               surface worth reporting).
    * none   — no ``imok`` reply on any candidate port (not ZooKeeper, or the 4lw
               whitelist is locked down to nothing).

[Worker decision: plugin filename is miasma_zookeeper_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-ZOOKEEPER-001 lives in
metadata["vuln_id"], matching the existing miasma_redis_001.py /
miasma_etcd_001.py convention. ZooKeeper was named directly in the round's
improvement spec; it is the natural sibling of the Redis/etcd/Consul
unauthenticated-datastore family and closes the last major coordination-service
exposure gap (etcd and Consul already covered).]
"""

from __future__ import annotations

import socket
from typing import Any

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-ZOOKEEPER-001",
    "name": "Apache ZooKeeper Unauthenticated Access",
    "description": (
        "Apache ZooKeeper reachable on its client port without transport "
        "authentication, exposing the four-letter-word (4lw) admin surface. "
        "ZooKeeper listens on TCP 2181 with no connection-level auth by default; "
        "its SASL/ACL system only guards individual znodes, so an exposed port "
        "leaks the exact server version, the data directory, the JVM "
        "environment (system properties routinely carry credentials), and the "
        "live client/session inventory to any unauthenticated peer. On the "
        "common default-ACL clusters the znode tree itself (Kafka/HBase/Solr "
        "metadata and stored secrets) is world-readable."
    ),
    "confidence": "high",
    "references": [
        "https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_zkCommands",
        "https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_4lw",
        "https://nvd.nist.gov/vuln/detail/CVE-2018-8012",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-44981",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [2181, 2182, 2183, 2281],
    "service_hint": ["zookeeper", "zookeeper-client"],
    "default_ports": [2181, 2182, 2183, 2281],
}

# A healthy ZooKeeper answers the ``ruok`` four-letter word with exactly this and
# nothing else. It is the fingerprint that distinguishes ZooKeeper from any other
# service that happens to be on 2181.
_RUOK_OK = "imok"

_TIMEOUT = 5.0

# 4lw replies (srvr/envi) are small. Cap the read so a hostile or non-ZooKeeper
# service cannot make us buffer unbounded data.
_RECV_BYTES = 65536

# System-property name fragments that, if present as a key in the ``envi`` dump,
# indicate a credential is being passed to the JVM (typically via a ``-D`` flag).
# Matched case-insensitively against the property NAME only; values are never
# stored in the finding.
_CREDENTIAL_PROPERTY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "keystorepass",
    "truststorepass",
    "private",
    "apikey",
    "api.key",
)


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered ZooKeeper-ish open ports; else the port hints."""
    open_ports = target.open_ports()
    if open_ports:
        zk_like = [
            port
            for port in open_ports
            if "zookeeper" in target.service(port).get("name", "").lower()
            or port in metadata["port_hint"]
        ]
        return zk_like or open_ports
    return list(metadata["port_hint"])


def _exchange(host: str, port: int, command: bytes) -> str | None:
    """Open a TCP connection, send one 4lw ``command``, return the decoded reply.

    ZooKeeper closes the connection after answering a single four-letter word, so
    each command gets its own short-lived connection (mirroring ``nc``). Returns
    ``None`` on any socket error so one dead port never aborts the run. Nothing is
    written beyond the four-letter command; no client session is ever opened.
    """
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            sock.settimeout(_TIMEOUT)
            sock.sendall(command)
            data = sock.recv(_RECV_BYTES)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _is_imok(reply: str | None) -> bool:
    """True when a ``ruok`` reply is exactly ZooKeeper's ``imok`` liveness word."""
    return reply is not None and reply.strip() == _RUOK_OK


def _parse_srvr(reply: str) -> dict[str, str]:
    """Pull the ``Version`` and ``Mode`` fields from an ``srvr`` reply.

    A genuine ``srvr`` reply is a small block of ``Key: value`` lines, e.g.::

        Zookeeper version: 3.8.4-... built on ...
        Latency min/avg/max: 0/0/0
        ...
        Mode: standalone
        Node count: 5

    Returns a dict with any of the keys ``version`` / ``mode`` that were found.
    The version line's label is ``Zookeeper version`` (one word), so it is keyed
    by the leading ``version`` token after the colon-split.
    """
    parsed: dict[str, str] = {}
    for line in reply.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip().lower()
        value = value.strip()
        if not value:
            continue
        if label.endswith("version") and "version" not in parsed:
            parsed["version"] = value
        elif label == "mode" and "mode" not in parsed:
            parsed["mode"] = value
    return parsed


def _envi_leaks_credentials(reply: str) -> bool:
    """Scan an ``envi`` dump's PROPERTY NAMES for credential-bearing markers.

    The ``envi`` reply is a block of ``key=value`` system-property lines. Only the
    property NAME (left of ``=``) is examined, case-insensitively, against the
    credential markers. Values are never read into the finding, so no secret is
    ever stored. Returns ``True`` when any property name matches a marker.
    """
    for line in reply.splitlines():
        if "=" not in line:
            continue
        name = line.split("=", 1)[0].strip().lower()
        if any(marker in name for marker in _CREDENTIAL_PROPERTY_MARKERS):
            return True
    return False


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        # 1. Fingerprint via ruok => imok. Only ZooKeeper answers this exactly.
        if not _is_imok(_exchange(target.host, port, b"ruok")):
            continue

        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "ruok_reply": _RUOK_OK,
        }
        description = metadata["description"]

        # 2. srvr — confirms the admin surface answers unauthenticated and leaks
        #    the version / mode. May be whitelisted out even when ruok answers.
        srvr_reply = _exchange(target.host, port, b"srvr")
        srvr = _parse_srvr(srvr_reply) if srvr_reply is not None else {}

        if srvr:
            evidence["admin_4lw_unauthenticated"] = True
            if "version" in srvr:
                evidence["version"] = srvr["version"]
            if "mode" in srvr:
                evidence["mode"] = srvr["mode"]

            # 3. envi — scan property NAMES only for credential markers.
            envi_reply = _exchange(target.host, port, b"envi")
            if envi_reply is not None and _envi_leaks_credentials(envi_reply):
                evidence["env_properties_leak_credentials"] = True
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence=evidence,
                    description=(
                        description
                        + " The envi 4lw dump exposed a credential-bearing JVM "
                        "system-property name (password/secret/token/...) without "
                        "authentication."
                    ),
                )

            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence=evidence,
                description=(
                    description
                    + " The srvr 4lw command answered without authentication, "
                    "exposing the server version, mode, and runtime summary."
                ),
            )

        # ruok answered but srvr is whitelisted/blocked — still a confirmed
        # unauthenticated 4lw surface, but only the liveness word is reachable.
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence=evidence,
            description=(
                description
                + " The ruok liveness command answered imok without "
                "authentication; the srvr summary was whitelisted/blocked on this "
                "port (only the liveness word is reachable)."
            ),
        )

    return None
