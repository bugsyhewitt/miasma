"""MIASMA-CASSANDRA-001 — Apache Cassandra unauthenticated native-protocol access.

Apache Cassandra is the dominant wide-column distributed datastore that backs
session stores, time-series telemetry, IoT ingest pipelines, fraud-detection
feature stores, and the metadata layers of countless SaaS products. By default
the binary native protocol listens on TCP ``9042`` with ``authenticator:
AllowAllAuthenticator`` and ``authorizer: AllowAllAuthorizer`` — meaning **no
authentication, no authorisation, and (without explicit configuration) no
transport encryption**. Any client that can reach 9042 can open a CQL session,
read every keyspace and table, SELECT every row, and write or DROP at will.

The Cassandra documentation and every production hardening guide
(DataStax, Apache, CIS) explicitly call out the default ``AllowAllAuthenticator``
as an internet-exposure footgun, and historical shodan-style scans repeatedly
find tens of thousands of internet-reachable nodes still on the defaults. An
internet- or broadly-internal-reachable Cassandra on 9042 is rated P1/HIGH on
bug-bounty programs: the contents of a Cassandra cluster typically include
authenticated session data, PII, and application secrets that, by themselves,
enable full account-takeover or data-breach claims.

This probe is BENIGN and read-only. It speaks the documented Cassandra native
binary protocol over a raw TCP socket — exactly the two-frame handshake a CQL
driver runs at session open — and never executes any CQL query, never opens a
keyspace, and never sends any credential:

    1. send an ``OPTIONS`` frame (opcode ``0x05``, empty body). A healthy
       Cassandra answers with a ``SUPPORTED`` frame (opcode ``0x06``) carrying
       a string multimap with at least ``CQL_VERSION`` (and usually
       ``COMPRESSION`` and ``PROTOCOL_VERSIONS``) entries. Only Cassandra (and
       its protocol-compatible siblings — ScyllaDB, DataStax Enterprise) answer
       this exchange with a SUPPORTED frame. Anything else => not Cassandra.
       The ``OPTIONS`` frame is the documented capability-discovery message a
       driver sends BEFORE STARTUP; it has no state-changing semantics.
    2. send a ``STARTUP`` frame (opcode ``0x01``, body = string map
       ``{"CQL_VERSION": "3.0.0"}``). The server's reply distinguishes
       authenticator posture:
         * ``READY`` (opcode ``0x02``, empty body) => the cluster accepts the
           session with no credentials. Full CQL access for any reachable peer.
         * ``AUTHENTICATE`` (opcode ``0x03``, body = [string] authenticator
           class name) => the cluster requires SASL credentials. Cassandra is
           confirmed exposed at the wire level, but the authenticator is set.
           No credential is ever sent — the probe disconnects.
         * ``ERROR`` (opcode ``0x00``) or anything else => Cassandra is still
           fingerprinted from the SUPPORTED reply, but the STARTUP response is
           unexpected (typically a protocol-version mismatch on a non-standard
           build). Record the fingerprint without claiming a posture.

No ``QUERY`` (opcode ``0x07``), ``PREPARE`` (opcode ``0x09``), ``EXECUTE``
(opcode ``0x0A``), ``BATCH`` (opcode ``0x0D``), or ``AUTH_RESPONSE`` (opcode
``0x0F``) is ever sent — those would execute CQL or attempt a credential.
Evidence records only the host, port, the negotiated CQL_VERSION and
COMPRESSION values from the SUPPORTED frame, the protocol version observed in
the response header, and (when AUTHENTICATE is returned) the authenticator
class name the server advertises. No row, no keyspace name, no table name, no
credential is ever read or stored.

Severity matrix:
    * HIGH   — ``OPTIONS`` fingerprints Cassandra AND ``STARTUP`` is answered
               with ``READY``: a CQL session opens with no credentials and
               every keyspace is reachable for SELECT / INSERT / DROP.
    * MEDIUM — ``OPTIONS`` fingerprints Cassandra AND ``STARTUP`` is answered
               with ``AUTHENTICATE``: the binary native protocol is reachable
               on this port and the cluster identity is leaked, but the
               authenticator is configured (no credential is ever attempted).
    * MEDIUM — ``OPTIONS`` fingerprints Cassandra but the ``STARTUP`` reply is
               an ERROR / unexpected opcode (protocol-version mismatch, or a
               non-standard build). The wire surface is confirmed reachable.
    * none   — no ``SUPPORTED`` frame on any candidate port (not Cassandra,
               or the port is firewalled at the application layer).

[Worker decision: plugin filename is miasma_cassandra_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-CASSANDRA-001 lives in
metadata["vuln_id"], matching the existing miasma_redis_001.py /
miasma_zookeeper_001.py / miasma_memcached_001.py convention. Cassandra was
the long-queued candidate from R30 / R31; with Memcached (R30) and RabbitMQ
(R31) shipped, Cassandra is the remaining major unauthenticated-datastore
gap. The handshake uses native protocol v4 (the universally-supported
version since Cassandra 2.2 / 2014); v5 / v3 fallback is intentionally not
attempted to keep the probe to a single round-trip pair, matching the
project's other "one fingerprint + one capability check" plugins. Only
opcodes that a CQL driver sends BEFORE the first user query are ever
written; no QUERY / PREPARE / EXECUTE / BATCH / AUTH_RESPONSE is constructed
in this file at all.]
"""

from __future__ import annotations

import socket
import struct
from typing import Any

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-CASSANDRA-001",
    "name": "Apache Cassandra Unauthenticated Native-Protocol Access",
    "description": (
        "Apache Cassandra reachable on its binary native-protocol port without "
        "authentication. Cassandra ships with authenticator: AllowAllAuthenticator "
        "and authorizer: AllowAllAuthorizer by default; any client that reaches "
        "TCP 9042 can open a CQL session, read every keyspace and table, and "
        "write or DROP at will. The probe runs the documented two-frame "
        "OPTIONS / STARTUP handshake that every CQL driver runs at session "
        "open — a READY response confirms unauthenticated access; an "
        "AUTHENTICATE response confirms the wire surface is reachable but the "
        "authenticator is set (no credential is ever sent)."
    ),
    "confidence": "high",
    "references": [
        "https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec",
        "https://cassandra.apache.org/doc/latest/cassandra/managing/operating/security.html",
        "https://docs.datastax.com/en/security/6.8/security/secAuthenticationTOC.html",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias. 9042 is
    # the documented native-protocol port; 9142 is the documented client_encryption
    # port (TLS-wrapped); 9043 is the conventional secondary instance port.
    "port_hint": [9042, 9043, 9142],
    "service_hint": ["cassandra", "apani1", "cassandra-cql"],
    "default_ports": [9042, 9043, 9142],
}

_TIMEOUT = 5.0

# Frame size cap. SUPPORTED / READY / AUTHENTICATE bodies are tiny (a few hundred
# bytes at most — a string multimap of CQL versions and a compression list). Cap
# the read so a hostile or non-Cassandra service cannot make us buffer unbounded
# data. The header is 9 bytes, so 65k is comfortably more than any legitimate
# session-open frame.
_RECV_BYTES = 65536

# Native protocol v4 — universally supported since Cassandra 2.2 (2014). The
# request direction byte is 0x04; the response direction byte is 0x84 (top bit
# set marks a response). v5 / v3 fallback is intentionally not attempted: a
# server that does not support v4 will reply with an ERROR frame whose body
# carries the supported version range, and that ERROR is still a positive
# Cassandra fingerprint when combined with the SUPPORTED reply to OPTIONS.
_PROTO_VERSION_REQ = 0x04
_PROTO_VERSION_RESP_MASK = 0x80  # top bit set => response

# Opcodes (native_protocol_v4.spec section 2.4).
_OPCODE_ERROR = 0x00
_OPCODE_STARTUP = 0x01
_OPCODE_READY = 0x02
_OPCODE_AUTHENTICATE = 0x03
_OPCODE_OPTIONS = 0x05
_OPCODE_SUPPORTED = 0x06

# Header struct: !BBhBI = direction-byte, flags-byte, stream-id (signed 16-bit
# big-endian), opcode, body length (unsigned 32-bit big-endian). v4 widened the
# stream id to 16 bits; we use stream 0 for every request.
_HEADER_FMT = "!BBhBI"
_HEADER_LEN = 9


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Cassandra-ish open ports; else the port hints."""
    open_ports = target.open_ports()
    if open_ports:
        cassandra_like = [
            port
            for port in open_ports
            if "cassandra" in target.service(port).get("name", "").lower()
            or port in metadata["port_hint"]
        ]
        return cassandra_like or open_ports
    return list(metadata["port_hint"])


def _build_frame(opcode: int, body: bytes = b"") -> bytes:
    """Build a native-protocol v4 request frame.

    Header is 9 bytes: direction (0x04), flags (0x00 — no compression, no
    tracing, no warning, no custom payload), stream id (0), opcode, body length.
    """
    return struct.pack(_HEADER_FMT, _PROTO_VERSION_REQ, 0, 0, opcode, len(body)) + body


def _encode_string(value: str) -> bytes:
    """Encode a Cassandra ``[string]`` — unsigned 16-bit length + UTF-8 bytes."""
    raw = value.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


def _encode_string_map(entries: dict[str, str]) -> bytes:
    """Encode a Cassandra ``[string map]`` — 16-bit count + n*(string,string)."""
    body = struct.pack("!H", len(entries))
    for key, value in entries.items():
        body += _encode_string(key) + _encode_string(value)
    return body


def _build_startup_frame(cql_version: str = "3.0.0") -> bytes:
    """Build a STARTUP request body = {"CQL_VERSION": cql_version}.

    Only CQL_VERSION is sent. COMPRESSION is intentionally omitted — every
    server supports an uncompressed session and adding LZ4 / Snappy would mean
    bundling a compression library or implementing the byte format ourselves
    for no fingerprinting benefit. NO_COMPACT and THROW_ON_OVERLOAD options are
    also omitted as they only affect query semantics this probe never triggers.
    """
    return _build_frame(_OPCODE_STARTUP, _encode_string_map({"CQL_VERSION": cql_version}))


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly ``n`` bytes, returning None on short read or socket error."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(sock: socket.socket) -> tuple[int, int, bytes] | None:
    """Read one Cassandra native-protocol response frame.

    Returns ``(direction_byte, opcode, body)``, or None on socket error /
    truncation / oversized frame. The direction byte is returned raw so the
    caller can confirm the response-direction top bit is set (a positive
    Cassandra fingerprint signal — only a Cassandra-protocol server flips
    that bit on a v4 frame).
    """
    header = _recv_exact(sock, _HEADER_LEN)
    if header is None or len(header) != _HEADER_LEN:
        return None
    direction, _flags, _stream, opcode, length = struct.unpack(_HEADER_FMT, header)
    if length > _RECV_BYTES:
        # Reject suspiciously large frames — a real SUPPORTED / READY /
        # AUTHENTICATE body fits in well under a kilobyte.
        return None
    if length == 0:
        return direction, opcode, b""
    body = _recv_exact(sock, length)
    if body is None or len(body) != length:
        return None
    return direction, opcode, body


def _is_response_direction(direction: int) -> bool:
    """True when the direction byte has the response top-bit set (0x84 for v4)."""
    return bool(direction & _PROTO_VERSION_RESP_MASK)


def _parse_string(body: bytes, offset: int) -> tuple[str | None, int]:
    """Decode a Cassandra ``[string]`` at ``offset``. Returns (value, new_offset).

    On any length / decode error returns (None, original_offset) so the caller
    can short-circuit gracefully — a malformed reply is treated as "fingerprint
    only" rather than raising.
    """
    if offset + 2 > len(body):
        return None, offset
    (length,) = struct.unpack_from("!H", body, offset)
    start = offset + 2
    end = start + length
    if end > len(body):
        return None, offset
    try:
        return body[start:end].decode("utf-8"), end
    except UnicodeDecodeError:
        return None, offset


def _parse_string_multimap(body: bytes) -> dict[str, list[str]]:
    """Decode a Cassandra ``[string multimap]`` (the SUPPORTED frame body).

    Layout: u16 entry_count, then entry_count * (string key, string-list value).
    A string-list is u16 count + n * string. Returns an empty dict on any error
    so a malformed reply degrades to "fingerprinted but no detail" rather than
    raising.
    """
    parsed: dict[str, list[str]] = {}
    if len(body) < 2:
        return parsed
    try:
        (entry_count,) = struct.unpack_from("!H", body, 0)
    except struct.error:
        return parsed
    offset = 2
    for _ in range(entry_count):
        key, offset = _parse_string(body, offset)
        if key is None:
            return parsed
        if offset + 2 > len(body):
            return parsed
        (value_count,) = struct.unpack_from("!H", body, offset)
        offset += 2
        values: list[str] = []
        for _v in range(value_count):
            value, offset = _parse_string(body, offset)
            if value is None:
                return parsed
            values.append(value)
        parsed[key] = values
    return parsed


def _parse_authenticate_body(body: bytes) -> str | None:
    """Decode an AUTHENTICATE frame body = [string] authenticator class name."""
    value, _ = _parse_string(body, 0)
    return value


def _options_exchange(sock: socket.socket) -> tuple[int, bytes] | None:
    """Send OPTIONS, read the response. Returns (opcode, body) or None on error.

    A genuine Cassandra answers OPTIONS with opcode 0x06 (SUPPORTED). Any other
    opcode (or no response, or a request-direction reply) is treated as "not
    Cassandra" and the caller short-circuits the port.
    """
    try:
        sock.sendall(_build_frame(_OPCODE_OPTIONS))
    except OSError:
        return None
    frame = _read_frame(sock)
    if frame is None:
        return None
    direction, opcode, body = frame
    if not _is_response_direction(direction):
        return None
    return opcode, body


def _startup_exchange(sock: socket.socket) -> tuple[int, bytes] | None:
    """Send STARTUP, read the response. Returns (opcode, body) or None on error."""
    try:
        sock.sendall(_build_startup_frame())
    except OSError:
        return None
    frame = _read_frame(sock)
    if frame is None:
        return None
    direction, opcode, body = frame
    if not _is_response_direction(direction):
        return None
    return opcode, body


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        try:
            with socket.create_connection(
                (target.host, port), timeout=_TIMEOUT
            ) as sock:
                sock.settimeout(_TIMEOUT)

                # 1. Fingerprint via OPTIONS => SUPPORTED. Only Cassandra (and
                #    its protocol-compatible siblings) answer with opcode 0x06.
                options_result = _options_exchange(sock)
                if options_result is None:
                    continue
                opt_opcode, opt_body = options_result
                if opt_opcode != _OPCODE_SUPPORTED:
                    continue

                supported = _parse_string_multimap(opt_body)
                evidence: dict[str, Any] = {
                    "host": target.host,
                    "port": port,
                    "protocol_version": _PROTO_VERSION_REQ,
                    "supported_frame": True,
                }
                cql_versions = supported.get("CQL_VERSION")
                if cql_versions:
                    evidence["cql_versions"] = cql_versions
                compression = supported.get("COMPRESSION")
                if compression:
                    evidence["compression"] = compression
                protocol_versions = supported.get("PROTOCOL_VERSIONS")
                if protocol_versions:
                    evidence["protocol_versions"] = protocol_versions

                description = metadata["description"]

                # 2. STARTUP — distinguishes READY (no auth) from AUTHENTICATE
                #    (auth enforced). No credential is ever sent in either
                #    branch; AUTHENTICATE just records the advertised class.
                startup_result = _startup_exchange(sock)
                if startup_result is None:
                    # SUPPORTED came back but STARTUP got no response or a
                    # malformed one. Still a confirmed Cassandra wire surface.
                    return Finding(
                        vuln_id=metadata["vuln_id"],
                        host=target.host,
                        confidence="medium",
                        evidence=evidence,
                        description=(
                            description
                            + " The OPTIONS frame answered with a SUPPORTED "
                            "frame (Cassandra fingerprint confirmed) but the "
                            "STARTUP frame got no readable response — the "
                            "binary native-protocol surface is reachable but "
                            "the authenticator posture could not be determined."
                        ),
                    )

                startup_opcode, startup_body = startup_result

                if startup_opcode == _OPCODE_READY:
                    # READY with empty body => unauthenticated CQL session.
                    evidence["startup_response"] = "READY"
                    evidence["unauthenticated_session"] = True
                    return Finding(
                        vuln_id=metadata["vuln_id"],
                        host=target.host,
                        confidence="high",
                        evidence=evidence,
                        description=(
                            description
                            + " The STARTUP frame was answered with a READY "
                            "frame — a CQL session opens with no credentials. "
                            "Every keyspace and table is reachable for SELECT, "
                            "INSERT, UPDATE, and DROP by any peer that can "
                            "reach this port."
                        ),
                    )

                if startup_opcode == _OPCODE_AUTHENTICATE:
                    evidence["startup_response"] = "AUTHENTICATE"
                    authenticator = _parse_authenticate_body(startup_body)
                    if authenticator:
                        evidence["authenticator"] = authenticator
                    return Finding(
                        vuln_id=metadata["vuln_id"],
                        host=target.host,
                        confidence="medium",
                        evidence=evidence,
                        description=(
                            description
                            + " The STARTUP frame was answered with an "
                            "AUTHENTICATE frame — the binary native-protocol "
                            "surface is reachable and the cluster identity is "
                            "leaked, but the authenticator is configured. No "
                            "credential was attempted."
                        ),
                    )

                # ERROR or any other opcode — Cassandra is still fingerprinted
                # from the SUPPORTED reply, but the STARTUP response is unusual
                # (typically a protocol-version mismatch on a non-standard
                # build). Record the fingerprint without claiming a posture.
                evidence["startup_response_opcode"] = startup_opcode
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="medium",
                    evidence=evidence,
                    description=(
                        description
                        + " The OPTIONS frame answered with a SUPPORTED frame "
                        "(Cassandra fingerprint confirmed) but the STARTUP "
                        "frame returned an unexpected opcode — the wire "
                        "surface is reachable but the authenticator posture "
                        "could not be determined from this response."
                    ),
                )
        except OSError:
            continue

    return None
