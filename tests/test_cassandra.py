"""Tests for the Apache Cassandra unauthenticated native-protocol probe
(MIASMA-CASSANDRA-001).

All TCP is mocked — no live network. We monkeypatch ``socket.create_connection``
on the plugin module and hand back a fake socket that records what was sent and
replies with canned bytes for each request frame. Cassandra opens a single
long-lived TCP connection for the OPTIONS + STARTUP handshake (the probe never
re-opens the socket between the two frames), so the fake socket replies based on
the request opcode it observed on the most recent ``sendall``. This mirrors the
project's mock-at-the-seam convention (tests/test_zookeeper.py mocks the same
raw-socket seam; tests/test_memcached.py mocks the same seam).
"""

from __future__ import annotations

import struct

import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_cassandra_001"

# Native-protocol v4 opcodes (mirrored from the plugin so the tests can
# construct realistic response frames without importing private constants).
_OPCODE_ERROR = 0x00
_OPCODE_STARTUP = 0x01
_OPCODE_READY = 0x02
_OPCODE_AUTHENTICATE = 0x03
_OPCODE_OPTIONS = 0x05
_OPCODE_SUPPORTED = 0x06

_RESP_DIRECTION = 0x84  # v4 response direction byte (top bit set on 0x04).


def _build_response_frame(opcode: int, body: bytes = b"") -> bytes:
    """Build a Cassandra v4 response frame: header (9 bytes) + body."""
    return struct.pack("!BBhBI", _RESP_DIRECTION, 0, 0, opcode, len(body)) + body


def _encode_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


def _encode_string_multimap(entries: dict[str, list[str]]) -> bytes:
    """Encode the body of a SUPPORTED frame (u16 count + n*(string, string-list))."""
    body = struct.pack("!H", len(entries))
    for key, values in entries.items():
        body += _encode_string(key)
        body += struct.pack("!H", len(values))
        for value in values:
            body += _encode_string(value)
    return body


# Canonical SUPPORTED body fragment a real Cassandra 4.x node returns.
_SUPPORTED_BODY = _encode_string_multimap(
    {
        "CQL_VERSION": ["3.4.5"],
        "COMPRESSION": ["snappy", "lz4"],
        "PROTOCOL_VERSIONS": ["3/v3", "4/v4", "5/v5"],
    }
)

_SUPPORTED_FRAME = _build_response_frame(_OPCODE_SUPPORTED, _SUPPORTED_BODY)
_READY_FRAME = _build_response_frame(_OPCODE_READY, b"")
_AUTHENTICATE_FRAME = _build_response_frame(
    _OPCODE_AUTHENTICATE,
    _encode_string("org.apache.cassandra.auth.PasswordAuthenticator"),
)
_ERROR_FRAME = _build_response_frame(
    _OPCODE_ERROR,
    struct.pack("!I", 0x000A) + _encode_string("Invalid or unsupported protocol version"),
)


class _FakeSocket:
    """Context-manager socket that replies per request opcode observed.

    The probe writes a v4 request frame (header: direction|flags|stream|opcode|len
    followed by body). We inspect the opcode byte (offset 4 in the header) on
    each ``sendall`` and serve the matching canned reply byte-by-byte across
    subsequent ``recv`` calls. This models a real TCP stream where the kernel
    may fragment one logical frame across recvs.
    """

    def __init__(
        self,
        replies_by_opcode: dict[int, bytes],
        sent_opcodes: list[int],
        sent_payloads: list[bytes] | None = None,
    ):
        self._replies = replies_by_opcode
        self._sent_opcodes = sent_opcodes
        self._sent_payloads = sent_payloads
        # Pending bytes to hand out via successive recvs.
        self._pending = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, _t):
        pass

    def sendall(self, data: bytes):
        if self._sent_payloads is not None:
            self._sent_payloads.append(data)
        # Header is 9 bytes; opcode at byte offset 4 (direction, flags, stream
        # high, stream low, opcode, len[4]). The probe always sends one frame
        # per sendall, so reading byte 4 is safe.
        if len(data) >= 5:
            opcode = data[4]
            self._sent_opcodes.append(opcode)
            reply = self._replies.get(opcode, b"")
            self._pending.extend(reply)

    def recv(self, n: int) -> bytes:
        if not self._pending:
            return b""
        take = min(n, len(self._pending))
        chunk = bytes(self._pending[:take])
        del self._pending[:take]
        return chunk


def _make_fake_create_connection(
    replies_by_opcode: dict[int, bytes],
    sent_opcodes: list[int],
    addresses: list | None = None,
    sent_payloads: list[bytes] | None = None,
):
    """Return a fake create_connection yielding a canned _FakeSocket."""

    def fake_create_connection(address, timeout=None):
        if addresses is not None:
            addresses.append(address)
        return _FakeSocket(replies_by_opcode, sent_opcodes, sent_payloads)

    return fake_create_connection


def _target() -> Target:
    """A single open Cassandra port keeps the probe surface deterministic."""
    return Target(
        host="10.0.0.42", ports={9042: {"state": "open", "name": "cassandra"}}
    )


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-CASSANDRA-001"
    assert "Cassandra" in module.metadata["name"]
    assert module.metadata["port_hint"] == [9042, 9043, 9142]
    assert "cassandra" in module.metadata["service_hint"]
    assert callable(module.probe)


def test_options_supported_plus_ready_is_high(monkeypatch):
    """OPTIONS=>SUPPORTED, STARTUP=>READY: unauthenticated session => HIGH."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _READY_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-CASSANDRA-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.42"
    assert finding.evidence["port"] == 9042
    assert finding.evidence["supported_frame"] is True
    assert finding.evidence["cql_versions"] == ["3.4.5"]
    assert finding.evidence["compression"] == ["snappy", "lz4"]
    assert finding.evidence["protocol_versions"] == ["3/v3", "4/v4", "5/v5"]
    assert finding.evidence["startup_response"] == "READY"
    assert finding.evidence["unauthenticated_session"] is True
    assert finding.evidence["protocol_version"] == 0x04
    # Two opcodes exchanged: OPTIONS first, then STARTUP. No QUERY / EXECUTE /
    # PREPARE / BATCH / AUTH_RESPONSE may ever be sent.
    assert sent_opcodes == [_OPCODE_OPTIONS, _OPCODE_STARTUP]


def test_options_supported_plus_authenticate_is_medium(monkeypatch):
    """OPTIONS=>SUPPORTED, STARTUP=>AUTHENTICATE: surface confirmed, auth set."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    replies = {
        _OPCODE_OPTIONS: _SUPPORTED_FRAME,
        _OPCODE_STARTUP: _AUTHENTICATE_FRAME,
    }
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["startup_response"] == "AUTHENTICATE"
    assert (
        finding.evidence["authenticator"]
        == "org.apache.cassandra.auth.PasswordAuthenticator"
    )
    assert "unauthenticated_session" not in finding.evidence
    assert sent_opcodes == [_OPCODE_OPTIONS, _OPCODE_STARTUP]


def test_options_supported_plus_error_is_medium(monkeypatch):
    """OPTIONS=>SUPPORTED, STARTUP=>ERROR: Cassandra confirmed, posture unknown."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _ERROR_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["supported_frame"] is True
    assert finding.evidence["startup_response_opcode"] == _OPCODE_ERROR
    assert "unauthenticated_session" not in finding.evidence
    assert "startup_response" not in finding.evidence
    assert sent_opcodes == [_OPCODE_OPTIONS, _OPCODE_STARTUP]


def test_no_supported_frame_is_no_finding(monkeypatch):
    """If OPTIONS does not get a SUPPORTED frame back, no Cassandra finding."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    # SSH greeting bytes — not a Cassandra v4 response frame.
    replies = {_OPCODE_OPTIONS: b"SSH-2.0-OpenSSH_9.6\r\n"}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is None
    # On a failed fingerprint we must NOT follow up with a STARTUP frame.
    assert _OPCODE_STARTUP not in sent_opcodes


def test_options_returns_error_opcode_no_finding(monkeypatch):
    """A non-SUPPORTED Cassandra-shaped reply to OPTIONS is not a positive match.

    We are strict: only opcode 0x06 (SUPPORTED) counts as the Cassandra
    fingerprint. An ERROR opcode response could come from any v4-speaking
    proxy or relay; we do not claim Cassandra in that case.
    """
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    replies = {_OPCODE_OPTIONS: _ERROR_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is None
    assert _OPCODE_STARTUP not in sent_opcodes


def test_request_direction_response_rejected(monkeypatch):
    """A v4-shaped reply with the REQUEST direction byte must not fingerprint.

    Cassandra responses set the top bit of the direction byte (0x84 for v4);
    a frame whose direction byte is still the request value (0x04) is malformed
    or hostile and must not count as a positive fingerprint.
    """
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    # Build a SUPPORTED-shaped frame but with the REQUEST direction byte.
    bad_direction_frame = struct.pack(
        "!BBhBI", 0x04, 0, 0, _OPCODE_SUPPORTED, len(_SUPPORTED_BODY)
    ) + _SUPPORTED_BODY
    replies = {_OPCODE_OPTIONS: bad_direction_frame}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is None
    assert _OPCODE_STARTUP not in sent_opcodes


def test_supported_then_no_startup_response_is_medium(monkeypatch):
    """SUPPORTED comes back but STARTUP gets no readable frame => MEDIUM."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    # Only OPTIONS is mapped; STARTUP yields empty bytes (recv returns b"").
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["supported_frame"] is True
    assert "unauthenticated_session" not in finding.evidence
    assert "startup_response" not in finding.evidence
    assert "startup_response_opcode" not in finding.evidence
    assert sent_opcodes == [_OPCODE_OPTIONS, _OPCODE_STARTUP]


def test_connection_error_is_no_finding(monkeypatch):
    """A socket error on every candidate port => no finding, no raise."""
    module = load_plugin(PLUGIN)

    def boom(address, timeout=None):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(module.socket, "create_connection", boom)

    assert module.probe(_target()) is None


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _READY_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-CASSANDRA-001"
    assert findings[0].confidence == "high"


def test_port_hints_used_when_no_recon(monkeypatch):
    """With no open ports from recon, probe falls back to the port hints."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _READY_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, [], addresses),
    )

    finding = module.probe(Target(host="10.0.0.43"))

    assert finding is not None
    # Short-circuits on the first reachable Cassandra port (9042).
    assert addresses[0] == ("10.0.0.43", 9042)


def test_default_port_9042_used_first(monkeypatch):
    """9042 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout=None):
        addresses.append(address)
        # Never reply with anything so the probe walks every candidate.
        return _FakeSocket({}, [])

    monkeypatch.setattr(module.socket, "create_connection", fake_create_connection)
    module.probe(Target(host="h"))

    contacted_ports = [p for _, p in addresses]
    assert contacted_ports == [9042, 9043, 9142]


def test_no_query_or_execute_or_auth_opcodes_ever_sent(monkeypatch):
    """The probe MUST NEVER emit a QUERY, EXECUTE, PREPARE, BATCH, or
    AUTH_RESPONSE opcode under any branch."""
    module = load_plugin(PLUGIN)
    forbidden_opcodes = {
        0x07,  # QUERY
        0x09,  # PREPARE
        0x0A,  # EXECUTE
        0x0B,  # REGISTER (would subscribe to event stream)
        0x0D,  # BATCH
        0x0F,  # AUTH_RESPONSE
    }

    for startup_reply in (
        _READY_FRAME,
        _AUTHENTICATE_FRAME,
        _ERROR_FRAME,
        b"",  # no STARTUP response
    ):
        sent_opcodes: list[int] = []
        replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME}
        if startup_reply:
            replies[_OPCODE_STARTUP] = startup_reply
        monkeypatch.setattr(
            module.socket,
            "create_connection",
            _make_fake_create_connection(replies, sent_opcodes),
        )
        module.probe(_target())
        for opcode in sent_opcodes:
            assert opcode not in forbidden_opcodes, (
                f"forbidden opcode 0x{opcode:02x} was sent during a probe "
                f"branch with startup_reply={startup_reply!r}"
            )


def test_startup_payload_contains_cql_version_only(monkeypatch):
    """STARTUP body must be a string map with exactly one key: CQL_VERSION."""
    module = load_plugin(PLUGIN)
    sent_payloads: list[bytes] = []
    sent_opcodes: list[int] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _READY_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(
            replies, sent_opcodes, sent_payloads=sent_payloads
        ),
    )

    module.probe(_target())

    # Find the STARTUP frame in what was sent.
    startup_payloads = [p for p in sent_payloads if len(p) >= 5 and p[4] == _OPCODE_STARTUP]
    assert len(startup_payloads) == 1
    payload = startup_payloads[0]
    # Header is 9 bytes; body starts at offset 9.
    body = payload[9:]
    # u16 entry count == 1
    (entry_count,) = struct.unpack_from("!H", body, 0)
    assert entry_count == 1
    # The single key is "CQL_VERSION".
    (key_len,) = struct.unpack_from("!H", body, 2)
    key = body[4 : 4 + key_len].decode("utf-8")
    assert key == "CQL_VERSION"


def test_evidence_never_contains_credential_or_keyspace_data(monkeypatch):
    """Evidence dict must only carry the documented fingerprint keys."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _READY_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {
        "host",
        "port",
        "protocol_version",
        "supported_frame",
        "cql_versions",
        "compression",
        "protocol_versions",
        "startup_response",
        "unauthenticated_session",
        "authenticator",
        "startup_response_opcode",
    }
    assert set(finding.evidence.keys()).issubset(allowed_keys)


def test_recon_service_name_matches_cassandra(monkeypatch):
    """A non-default port marked as a cassandra service in recon is probed."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _READY_FRAME}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, [], addresses),
    )

    # Cassandra listening on a non-default port; recon labels it cassandra.
    target = Target(
        host="10.0.0.44",
        ports={33333: {"state": "open", "name": "cassandra"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 33333
    assert addresses[0] == ("10.0.0.44", 33333)


def test_supported_multimap_parser_handles_minimum_body():
    """A bare ``CQL_VERSION``-only multimap (no COMPRESSION / no PROTOCOL_VERSIONS)
    still fingerprints and reports the single CQL version."""
    module = load_plugin(PLUGIN)
    body = _encode_string_multimap({"CQL_VERSION": ["3.0.0"]})
    parsed = module._parse_string_multimap(body)
    assert parsed == {"CQL_VERSION": ["3.0.0"]}


def test_supported_multimap_parser_handles_empty_body():
    """An empty / truncated multimap body must not raise — returns {}."""
    module = load_plugin(PLUGIN)
    assert module._parse_string_multimap(b"") == {}
    assert module._parse_string_multimap(b"\x00") == {}  # too short for count


def test_supported_multimap_parser_handles_truncated_entry():
    """A truncated entry (count says 2, only 1 present) returns what it could
    parse rather than raising."""
    module = load_plugin(PLUGIN)
    # claim 2 entries, supply only 1
    body = (
        struct.pack("!H", 2)
        + _encode_string("CQL_VERSION")
        + struct.pack("!H", 1)
        + _encode_string("3.0.0")
        # entry 2 missing entirely
    )
    parsed = module._parse_string_multimap(body)
    assert parsed == {"CQL_VERSION": ["3.0.0"]}


def test_response_frame_with_oversized_length_rejected(monkeypatch):
    """A response header claiming a body larger than the recv cap is rejected."""
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    # Header claims 10MB body; we never send the body. The probe must time out
    # / reject gracefully and produce no finding.
    oversized_header = struct.pack(
        "!BBhBI", _RESP_DIRECTION, 0, 0, _OPCODE_SUPPORTED, 10 * 1024 * 1024
    )
    replies = {_OPCODE_OPTIONS: oversized_header}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent_opcodes),
    )

    finding = module.probe(_target())

    assert finding is None
    assert _OPCODE_STARTUP not in sent_opcodes


def test_fragmented_recv_still_reassembles_frame(monkeypatch):
    """The probe must reassemble a frame even when recv hands back tiny chunks.

    The _FakeSocket queues bytes and serves them n-at-a-time per recv(n); the
    helper _recv_exact in the plugin must loop until the requested length is
    in hand. This guards the contract that the plugin never assumes a single
    recv returns a whole frame.
    """
    module = load_plugin(PLUGIN)
    sent_opcodes: list[int] = []
    replies = {_OPCODE_OPTIONS: _SUPPORTED_FRAME, _OPCODE_STARTUP: _READY_FRAME}
    fake_factory = _make_fake_create_connection(replies, sent_opcodes)

    def fragmenting_factory(address, timeout=None):
        sock = fake_factory(address, timeout=timeout)
        # Wrap recv so it never returns more than 1 byte at a time.
        original_recv = sock.recv

        def one_byte_recv(_n):
            return original_recv(1)

        sock.recv = one_byte_recv  # type: ignore[method-assign]
        return sock

    monkeypatch.setattr(module.socket, "create_connection", fragmenting_factory)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["startup_response"] == "READY"
