"""Tests for the MongoDB unauthenticated access probe (MIASMA-MONGODB-001).

All TCP is mocked — no live network. We monkeypatch ``socket.create_connection``
on the plugin module and hand back a fake socket that records what was sent and
replies with canned bytes built from real BSON-encoded OP_REPLY messages keyed
on the command embedded in the sent OP_QUERY. This mirrors the project's
mock-at-the-seam convention (tests/test_redis.py mocks the socket seam,
tests/test_actuator.py mocks the httpx seam).

The probe reads the reply with a length-prefixed recv loop, so the fake socket
serves the full canned reply on the first ``recv`` and an empty bytes object
thereafter (signalling the peer closed the stream).
"""

from __future__ import annotations

import struct

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_mongodb_001"


# --- BSON / OP_REPLY builders (test-side, independent of the plugin) ---------


def _bson_double(name: str, val: float) -> bytes:
    return b"\x01" + name.encode() + b"\x00" + struct.pack("<d", val)


def _bson_int32(name: str, val: int) -> bytes:
    return b"\x10" + name.encode() + b"\x00" + struct.pack("<i", val)


def _bson_str(name: str, val: str) -> bytes:
    enc = val.encode() + b"\x00"
    return b"\x02" + name.encode() + b"\x00" + struct.pack("<i", len(enc)) + enc


def _bson_doc(fields: bytes) -> bytes:
    body = fields + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _bson_array(name: str, docs: list[bytes]) -> bytes:
    # Array elements are length-prefixed embedded documents keyed "0","1",...
    inner = b"".join(
        b"\x03" + str(i).encode() + b"\x00" + _bson_doc(d) for i, d in enumerate(docs)
    )
    return b"\x04" + name.encode() + b"\x00" + _bson_doc(inner)


def _op_reply(doc: bytes, response_to: int = 0) -> bytes:
    reply_body = (
        struct.pack("<i", 0)  # responseFlags
        + struct.pack("<q", 0)  # cursorID
        + struct.pack("<i", 0)  # startingFrom
        + struct.pack("<i", 1)  # numberReturned
        + doc
    )
    return struct.pack("<iiii", 16 + len(reply_body), 1, response_to, 1) + reply_body


def _buildinfo_reply(version: str = "7.0.5") -> bytes:
    return _op_reply(_bson_doc(_bson_double("ok", 1.0) + _bson_str("version", version)))


def _listdb_reply(db_count: int = 3) -> bytes:
    dbs = [_bson_str("name", f"db{i}") for i in range(db_count)]
    return _op_reply(_bson_doc(_bson_double("ok", 1.0) + _bson_array("databases", dbs)))


def _auth_error_reply() -> bytes:
    doc = _bson_doc(
        _bson_double("ok", 0.0)
        + _bson_int32("code", 13)
        + _bson_str("errmsg", "command listDatabases requires authentication")
    )
    return _op_reply(doc)


# --- Fake socket keyed on the embedded command ------------------------------


def _command_in(request: bytes) -> str:
    if b"buildInfo" in request:
        return "buildInfo"
    if b"listDatabases" in request:
        return "listDatabases"
    return ""


class _FakeSocket:
    """A context-manager socket that replies per embedded command.

    ``replies`` maps a command name ("buildInfo"/"listDatabases") to canned
    reply bytes. The full reply is served on the first ``recv`` after a
    ``sendall``; the next ``recv`` returns b"" to signal the peer closed.
    """

    def __init__(self, replies: dict[str, bytes], sent: list[bytes]):
        self._replies = replies
        self._sent = sent
        self._pending = b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, _t):
        pass

    def sendall(self, data: bytes):
        self._sent.append(data)
        self._pending = self._replies.get(_command_in(data), b"")

    def recv(self, _n: int) -> bytes:
        out, self._pending = self._pending, b""
        return out


def _make_fake_create_connection(replies, sent, addresses=None):
    def fake_create_connection(address, timeout=None):
        if addresses is not None:
            addresses.append(address)
        return _FakeSocket(replies, sent)

    return fake_create_connection


def _target() -> Target:
    """A single open MongoDB port keeps the probe surface deterministic."""
    return Target(host="10.0.0.8", ports={27017: {"state": "open", "name": "mongodb"}})


# --- Tests ------------------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-MONGODB-001"
    assert module.metadata["name"] == "MongoDB Unauthenticated Access"
    assert module.metadata["port_hint"] == [27017, 27018, 27019]
    assert callable(module.probe)


def test_listdatabases_succeeds_is_high(monkeypatch):
    """buildInfo + unauthenticated listDatabases => HIGH with version+count."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        "buildInfo": _buildinfo_reply("7.0.5"),
        "listDatabases": _listdb_reply(3),
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-MONGODB-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.8"
    assert finding.evidence["port"] == 27017
    assert finding.evidence["mongodb_version"] == "7.0.5"
    assert finding.evidence["database_count"] == 3
    # buildInfo must be sent before listDatabases; only those two commands.
    assert _command_in(sent[0]) == "buildInfo"
    assert any(_command_in(s) == "listDatabases" for s in sent)
    assert all(_command_in(s) in ("buildInfo", "listDatabases") for s in sent)


def test_auth_enforced_on_listdatabases_is_no_finding(monkeypatch):
    """buildInfo answers but listDatabases requires auth => not vulnerable."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        "buildInfo": _buildinfo_reply("7.0.5"),
        "listDatabases": _auth_error_reply(),
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is None
    # listDatabases was attempted (buildInfo answered) but gated.
    assert any(_command_in(s) == "listDatabases" for s in sent)


def test_not_mongodb_is_no_finding(monkeypatch):
    """A non-Mongo service that returns junk to buildInfo => no finding."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {"buildInfo": b"HTTP/1.1 400 Bad Request\r\n\r\n"}
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is None
    # Never reached listDatabases — buildInfo didn't fingerprint MongoDB.
    assert all(_command_in(s) != "listDatabases" for s in sent)


def test_connection_error_is_no_finding(monkeypatch):
    """A socket error on every candidate port => no finding, no raise."""
    module = load_plugin(PLUGIN)

    def boom(address, timeout=None):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(module.socket, "create_connection", boom)

    assert module.probe(_target()) is None


def test_listdatabases_empty_array_still_high(monkeypatch):
    """An empty databases array still confirms unauthenticated access (count 0)."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        "buildInfo": _buildinfo_reply("6.0.1"),
        "listDatabases": _listdb_reply(0),
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["database_count"] == 0
    assert finding.evidence["mongodb_version"] == "6.0.1"


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        "buildInfo": _buildinfo_reply("5.0.9"),
        "listDatabases": _listdb_reply(2),
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-MONGODB-001"
    assert findings[0].confidence == "high"


def test_port_hints_used_when_no_recon(monkeypatch):
    """With no open ports from recon, probe falls back to the port hints."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []
    replies = {
        "buildInfo": _buildinfo_reply("7.0.5"),
        "listDatabases": _listdb_reply(1),
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, [], addresses),
    )

    finding = module.probe(Target(host="10.0.0.9"))  # no ports => hints

    assert finding is not None
    # Short-circuits on the first reachable vulnerable port (27017).
    assert addresses[0] == ("10.0.0.9", 27017)


def test_default_port_27017_used_first(monkeypatch):
    """27017 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout=None):
        addresses.append(address)
        # Never fingerprint Mongo so the probe walks every candidate port.
        return _FakeSocket({}, [])

    monkeypatch.setattr(module.socket, "create_connection", fake_create_connection)
    module.probe(Target(host="h"))

    contacted_ports = [p for _, p in addresses]
    assert contacted_ports == [27017, 27018, 27019]
