"""MIASMA-MONGODB-001 — MongoDB unauthenticated access (misconfiguration).

A MongoDB instance reachable without authentication lets any network client
read, write, and delete every document in every database, enumerate the full
list of databases and collections, dump credentials stored in application
collections, and — depending on build and configuration — abuse server-side
JavaScript. Historically, tens of thousands of internet-exposed MongoDB
instances ran with ``--noauth`` (the pre-3.6 default bound to all interfaces),
and the "Mongo Lock"/ransom sweeps of 2017 and the recurring exposure scans
since then keep this a live, high-impact misconfiguration. Bug-bounty programs
and pentest assessors rate unauthenticated MongoDB as P1/critical.

This probe is BENIGN and read-only. It speaks the MongoDB wire protocol over a
raw TCP socket using the legacy ``OP_QUERY`` opcode (opcode 2004), which every
MongoDB server still answers, against the ``admin.$cmd`` virtual collection:

    1. connect to a candidate port (27017, then 27018, 27019)
    2. send an ``OP_QUERY`` running the ``{buildInfo: 1}`` admin command.
       buildInfo is reachable pre-auth on every build and identifies the server
       (it is the canonical fingerprint and yields the version banner).
       * an ``OP_REPLY`` whose document has ``ok: 1.0`` and a ``version`` field
         => this is a MongoDB server and it answered an admin command without
         any authentication handshake.
    3. on a confirmed server, send a second ``OP_QUERY`` running
       ``{listDatabases: 1}``.
       * ``ok: 1.0`` with a ``databases`` array => unauthenticated access reaches
         privileged cluster-wide metadata (HIGH). Only the database *count* is
         recorded — never database names, collection names, or any document.
       * an auth error (``ok: 0.0`` / ``code`` 13 "Unauthorized" / "requires
         authentication") => the server enforces auth on privileged commands
         even though buildInfo answered; not unauthenticated for the purposes of
         this finding (no finding emitted).

No document is read, written, or deleted. No collection is listed. No
server-side JavaScript is evaluated. Evidence records only the version string
and the database count — never database names, collection names, or document
contents.

[Worker decision: ID is MIASMA-MONGODB-001 (misconfiguration, not a CVE).
Unauthenticated MongoDB is a configuration choice, not a software defect.
Mirrors the MIASMA-REDIS-001 / MIASMA-DOCKER-001 / MIASMA-K8S-001 naming
convention.]

[Worker decision: severity HIGH only when listDatabases succeeds (privileged
cluster-wide enumeration). buildInfo answering alone is NOT treated as a finding
— buildInfo is reachable pre-auth on a correctly secured server too, so emitting
on buildInfo alone would false-positive on every hardened MongoDB. Requiring
listDatabases to succeed unauthenticated is the precise signal for the
misconfiguration we report, matching the project's bias toward verified, low
false-positive findings.]

[Worker decision: the wire protocol is implemented inline with the stdlib
``struct`` module rather than adding a pymongo dependency. The probe issues
exactly two read-only admin commands; a full driver would pull in connection
pooling, SCRAM auth, topology monitoring, and BSON codecs we do not need, and
the project keeps its dependency surface minimal (httpx + python-nmap only).]
"""

from __future__ import annotations

import socket
import struct
from typing import Any

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-MONGODB-001",
    "name": "MongoDB Unauthenticated Access",
    "description": (
        "MongoDB reachable without authentication, exposing full read/write "
        "access to every database and collection. An unauthenticated client "
        "can enumerate databases cluster-wide, dump documents (including "
        "credentials stored by applications), and delete or ransom data. This "
        "is a P1/critical misconfiguration."
    ),
    "confidence": "high",
    "references": [
        "https://www.mongodb.com/docs/manual/administration/security-checklist/",
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    # Ports the probe will try, in order. Also the fallback when recon found
    # nothing.
    "port_hint": [27017, 27018, 27019],
    "service_hint": ["mongodb", "mongod", "mongo"],
    "default_ports": [27017, 27018, 27019],
}

_TIMEOUT = 5.0

# OP_QUERY opcode (the legacy query message every MongoDB build still answers).
_OP_QUERY = 2004
# OP_REPLY opcode (the response to OP_QUERY).
_OP_REPLY = 1

# Cap the reply read so a hostile or non-Mongo service can't make us buffer
# unbounded data. buildInfo / listDatabases (count-only) replies are small.
_MAX_REPLY = 1 << 20  # 1 MiB

# MongoDB error code for "Unauthorized" (auth required on a privileged command).
_UNAUTHORIZED_CODE = 13


# --- Minimal BSON encode/decode (only the subset the two commands need) ------


def _bson_int32(name: str, value: int) -> bytes:
    return b"\x10" + name.encode("utf-8") + b"\x00" + struct.pack("<i", value)


def _bson_document(fields: bytes) -> bytes:
    """Wrap encoded element bytes into a length-prefixed BSON document."""
    body = fields + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _command_query(command: str) -> bytes:
    """A single-element BSON command document, e.g. ``{buildInfo: 1}``."""
    return _bson_document(_bson_int32(command, 1))


def _cstring(buf: bytes, offset: int) -> tuple[str, int]:
    """Read a NUL-terminated C string from ``buf`` starting at ``offset``."""
    end = buf.index(b"\x00", offset)
    return buf[offset:end].decode("utf-8", errors="replace"), end + 1


def _bson_to_dict(buf: bytes) -> dict[str, Any]:
    """Decode a BSON document into a dict.

    Implements only the element types MongoDB returns for the buildInfo and
    listDatabases command replies that this probe inspects: double (0x01),
    string (0x02), embedded document (0x03), array (0x04), boolean (0x08),
    int32 (0x10), int64 (0x12). Unknown types abort the decode (return what was
    parsed so far) rather than guessing a length and desyncing the stream.
    """
    out: dict[str, Any] = {}
    if len(buf) < 5:
        return out
    (doc_len,) = struct.unpack_from("<i", buf, 0)
    pos = 4
    end = min(doc_len, len(buf))
    while pos < end:
        type_byte = buf[pos]
        pos += 1
        if type_byte == 0x00:  # end-of-document marker
            break
        try:
            key, pos = _cstring(buf, pos)
        except ValueError:
            break
        if type_byte == 0x01:  # double
            (val,) = struct.unpack_from("<d", buf, pos)
            pos += 8
            out[key] = val
        elif type_byte == 0x02:  # UTF-8 string
            (slen,) = struct.unpack_from("<i", buf, pos)
            pos += 4
            out[key] = buf[pos : pos + slen - 1].decode("utf-8", errors="replace")
            pos += slen
        elif type_byte in (0x03, 0x04):  # embedded document / array
            (sub_len,) = struct.unpack_from("<i", buf, pos)
            sub = _bson_to_dict(buf[pos : pos + sub_len])
            if type_byte == 0x04:
                # Arrays are documents keyed "0","1",...; expose as a list.
                out[key] = list(sub.values())
            else:
                out[key] = sub
            pos += sub_len
        elif type_byte == 0x08:  # boolean
            out[key] = buf[pos] != 0
            pos += 1
        elif type_byte == 0x10:  # int32
            (val,) = struct.unpack_from("<i", buf, pos)
            pos += 4
            out[key] = val
        elif type_byte == 0x12:  # int64
            (val,) = struct.unpack_from("<q", buf, pos)
            pos += 8
            out[key] = val
        else:
            # Unknown element type: stop rather than risk desyncing.
            break
    return out


def _op_query(command_doc: bytes, request_id: int) -> bytes:
    """Build an OP_QUERY message targeting the ``admin.$cmd`` collection.

    Wire layout (all little-endian):
      header: int32 messageLength, int32 requestID, int32 responseTo,
              int32 opCode (2004)
      body:   int32 flags(0), cstring fullCollectionName ("admin.$cmd"),
              int32 numberToSkip(0), int32 numberToReturn(-1), document query
    """
    body = (
        struct.pack("<i", 0)
        + b"admin.$cmd\x00"
        + struct.pack("<i", 0)
        + struct.pack("<i", -1)
        + command_doc
    )
    length = 16 + len(body)
    header = struct.pack("<iiii", length, request_id, 0, _OP_QUERY)
    return header + body


def _parse_reply(raw: bytes) -> dict[str, Any] | None:
    """Parse an OP_REPLY message and return its first result document.

    Returns None when the bytes are not a well-formed OP_REPLY (wrong length,
    wrong opcode, or no document present) — that is how a non-MongoDB service
    that happened to answer on the port is rejected.
    """
    if len(raw) < 36:
        return None
    msg_len, _req_id, _resp_to, opcode = struct.unpack_from("<iiii", raw, 0)
    if opcode != _OP_REPLY:
        return None
    # OP_REPLY body after the 16-byte header:
    #   int32 responseFlags, int64 cursorID, int32 startingFrom,
    #   int32 numberReturned, then the documents.
    docs_offset = 16 + 4 + 8 + 4 + 4
    if len(raw) < docs_offset + 5:
        return None
    return _bson_to_dict(raw[docs_offset:msg_len])


def _exchange(host: str, port: int, request: bytes) -> bytes | None:
    """Open a TCP connection, send ``request``, return the raw reply bytes.

    Reads until the server-declared message length is satisfied (or the socket
    closes / times out). Returns ``None`` on any socket error so one dead port
    never aborts the run. The connection is always closed; nothing is written
    beyond ``request``.
    """
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            sock.settimeout(_TIMEOUT)
            sock.sendall(request)
            chunks: list[bytes] = []
            total = 0
            expected: int | None = None
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if expected is None and total >= 4:
                    buf = b"".join(chunks)
                    (expected,) = struct.unpack_from("<i", buf, 0)
                if expected is not None and (total >= expected or total >= _MAX_REPLY):
                    break
    except OSError:
        return None
    return b"".join(chunks)


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open MongoDB-ish ports; else the port hints."""
    open_ports = target.open_ports()
    if open_ports:
        mongo_like = [
            port
            for port in open_ports
            if "mongo" in target.service(port).get("name", "").lower()
            or port in metadata["port_hint"]
        ]
        return mongo_like or open_ports
    return list(metadata["port_hint"])


def _is_auth_error(reply: dict[str, Any]) -> bool:
    """True when a reply indicates authentication is required/enforced."""
    if reply.get("ok") == 1.0 or reply.get("ok") == 1:
        return False
    if reply.get("code") == _UNAUTHORIZED_CODE:
        return True
    errmsg = str(reply.get("errmsg", "")).lower()
    return (
        "unauthorized" in errmsg
        or "requires authentication" in errmsg
        or "not authorized" in errmsg
        or "authentication" in errmsg
    )


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        # Step 1: buildInfo — fingerprints MongoDB and yields the version.
        build_raw = _exchange(target.host, port, _op_query(_command_query("buildInfo"), 1))
        if build_raw is None:
            continue
        build = _parse_reply(build_raw)
        if build is None:
            continue
        # Must look like MongoDB answering buildInfo: ok and a version string.
        if not (build.get("ok") in (1.0, 1) and isinstance(build.get("version"), str)):
            continue

        version = build.get("version")

        # Step 2: listDatabases — does unauth access reach privileged metadata?
        list_raw = _exchange(
            target.host, port, _op_query(_command_query("listDatabases"), 2)
        )
        list_reply = _parse_reply(list_raw) if list_raw is not None else None

        if list_reply is None or _is_auth_error(list_reply):
            # buildInfo answered (it does pre-auth even on hardened servers) but
            # privileged listDatabases is gated — not the misconfiguration we
            # report. No finding.
            continue

        databases = list_reply.get("databases")
        if not isinstance(databases, list):
            # ok-ish reply but no database array we can confirm; be conservative.
            continue

        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="high",
            evidence={
                "host": target.host,
                "port": port,
                "mongodb_version": version,
                "database_count": len(databases),
                "fingerprint_command": "buildInfo",
                "enumeration_command": "listDatabases",
                "note": (
                    "MongoDB answered the privileged listDatabases admin command "
                    "without any authentication. Only the database count is "
                    "recorded — no database names, collection names, or document "
                    "contents were read, and nothing was written or deleted."
                ),
            },
            description=metadata["description"],
        )

    return None
