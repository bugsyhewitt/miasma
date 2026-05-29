"""Tests for the Apache ZooKeeper unauthenticated access probe (MIASMA-ZOOKEEPER-001).

All TCP is mocked — no live network. We monkeypatch ``socket.create_connection``
on the plugin module and hand back a fake socket that records what was sent and
replies with canned bytes keyed on the four-letter-word request. ZooKeeper opens
a fresh connection per 4lw command, so the fake socket replies based on the most
recent ``sendall`` payload. This mirrors the project's mock-at-the-seam
convention (tests/test_redis.py mocks the same raw-socket seam; tests/test_etcd.py
mocks the httpx seam).
"""

from __future__ import annotations

import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_zookeeper_001"


class _FakeSocket:
    """A context-manager socket that replies per sent 4lw command.

    ``replies`` maps a sent-request bytes value to canned reply bytes. A request
    with no mapping yields an empty reply (recv returns b"").
    """

    def __init__(self, replies: dict[bytes, bytes], sent: list[bytes]):
        self._replies = replies
        self._sent = sent
        self._last = b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, _t):
        pass

    def sendall(self, data: bytes):
        self._sent.append(data)
        self._last = data

    def recv(self, _n: int) -> bytes:
        return self._replies.get(self._last, b"")


def _make_fake_create_connection(
    replies: dict[bytes, bytes], sent: list[bytes], addresses: list | None = None
):
    """Return a fake create_connection yielding a canned _FakeSocket."""

    def fake_create_connection(address, timeout=None):
        if addresses is not None:
            addresses.append(address)
        return _FakeSocket(replies, sent)

    return fake_create_connection


def _target() -> Target:
    """A single open ZooKeeper port keeps the probe surface deterministic."""
    return Target(
        host="10.0.0.8", ports={2181: {"state": "open", "name": "zookeeper"}}
    )


# A realistic srvr reply block, abbreviated. Note the version line's label is
# the single word "Zookeeper version".
_SRVR_REPLY = (
    b"Zookeeper version: 3.8.4-9316c2a7a97e1666d8f4593f34dd6fc36ecc436c, "
    b"built on 2024-02-12 22:16 UTC\r\n"
    b"Latency min/avg/max: 0/0.0/0\r\n"
    b"Received: 12\r\n"
    b"Sent: 11\r\n"
    b"Connections: 1\r\n"
    b"Outstanding: 0\r\n"
    b"Zxid: 0x0\r\n"
    b"Mode: standalone\r\n"
    b"Node count: 5\r\n"
)


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-ZOOKEEPER-001"
    assert module.metadata["name"] == "Apache ZooKeeper Unauthenticated Access"
    assert module.metadata["port_hint"] == [2181, 2182, 2183, 2281]
    assert callable(module.probe)


def test_ruok_and_srvr_is_high_with_version_and_mode(monkeypatch):
    """imok + srvr summary => HIGH finding carrying version and mode."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"ruok": b"imok",
        b"srvr": _SRVR_REPLY,
        b"envi": b"Environment:\r\njava.version=17.0.9\r\nuser.dir=/opt/zk\r\n",
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-ZOOKEEPER-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.8"
    assert finding.evidence["port"] == 2181
    assert finding.evidence["ruok_reply"] == "imok"
    assert finding.evidence["admin_4lw_unauthenticated"] is True
    assert finding.evidence["version"].startswith("3.8.4")
    assert finding.evidence["mode"] == "standalone"
    # No credential property in this envi => no escalation flag.
    assert "env_properties_leak_credentials" not in finding.evidence
    # ruok must be sent first; only benign read-only 4lw commands issued.
    assert sent[0] == b"ruok"
    assert all(cmd in (b"ruok", b"srvr", b"envi") for cmd in sent)


def test_envi_credential_property_escalates_and_does_not_store_value(monkeypatch):
    """A credential-bearing property NAME in envi => HIGH; value never stored."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    secret_value = "S3cr3tP@ss-do-not-store"
    replies = {
        b"ruok": b"imok",
        b"srvr": _SRVR_REPLY,
        b"envi": (
            b"Environment:\r\n"
            b"java.version=17.0.9\r\n"
            + f"javax.net.ssl.keyStorePassword={secret_value}\r\n".encode()
        ),
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["env_properties_leak_credentials"] is True
    assert "credential-bearing" in finding.description
    # The probe must NEVER store the property VALUE anywhere in the finding.
    assert secret_value not in repr(finding.to_dict())


def test_ruok_only_is_medium_when_srvr_blocked(monkeypatch):
    """imok but srvr whitelisted/blocked (empty reply) => MEDIUM finding."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {b"ruok": b"imok"}  # srvr/envi unmapped => empty reply
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["ruok_reply"] == "imok"
    assert "admin_4lw_unauthenticated" not in finding.evidence
    assert "version" not in finding.evidence


def test_no_imok_is_no_finding(monkeypatch):
    """A non-imok reply (not ZooKeeper / whitelist locked) => no finding."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    # Some services echo or send junk; ZooKeeper with ruok whitelisted returns
    # nothing. Neither is the exact "imok" fingerprint.
    replies = {b"ruok": b"SSH-2.0-OpenSSH_9.6\r\n"}
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is None
    # On a failed fingerprint we must NOT follow up with srvr/envi.
    assert b"srvr" not in sent
    assert b"envi" not in sent


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
    sent: list[bytes] = []
    replies = {b"ruok": b"imok", b"srvr": _SRVR_REPLY}
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-ZOOKEEPER-001"
    assert findings[0].confidence == "high"


def test_port_hints_used_when_no_recon(monkeypatch):
    """With no open ports from recon, probe falls back to the port hints."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []
    replies = {b"ruok": b"imok", b"srvr": _SRVR_REPLY}
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, [], addresses),
    )

    finding = module.probe(Target(host="10.0.0.9"))  # no ports => hints

    assert finding is not None
    # Short-circuits on the first reachable ZooKeeper port (2181).
    assert addresses[0] == ("10.0.0.9", 2181)


def test_default_port_2181_used_first(monkeypatch):
    """2181 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout=None):
        addresses.append(address)
        # Never reply imok so the probe walks every candidate port.
        return _FakeSocket({}, [])

    monkeypatch.setattr(module.socket, "create_connection", fake_create_connection)
    module.probe(Target(host="h"))

    contacted_ports = [p for _, p in addresses]
    assert contacted_ports == [2181, 2182, 2183, 2281]


def test_version_line_parsed_from_zookeeper_label(monkeypatch):
    """The 'Zookeeper version:' label is correctly parsed into evidence.version."""
    module = load_plugin(PLUGIN)
    parsed = module._parse_srvr(_SRVR_REPLY.decode())
    assert parsed["version"].startswith("3.8.4")
    assert parsed["mode"] == "standalone"
