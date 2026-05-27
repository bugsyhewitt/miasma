"""Tests for the Redis unauthenticated access probe (MIASMA-REDIS-001).

All TCP is mocked — no live network. We monkeypatch ``socket.create_connection``
on the plugin module and hand back a fake socket that records what was sent and
replies with canned bytes keyed on the request. This mirrors the project's
mock-at-the-seam convention (tests/test_actuator.py mocks the httpx seam;
tests/test_recon.py mocks the nmap-wrapper seam).
"""

from __future__ import annotations

import socket

import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_redis_001"


class _FakeSocket:
    """A context-manager socket that replies per request line.

    ``replies`` maps a sent-request bytes value to the canned reply bytes.
    A request with no mapping yields an empty reply (recv returns b"").
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


def _make_fake_create_connection(replies: dict[bytes, bytes], sent: list[bytes]):
    """Return a fake create_connection yielding a canned _FakeSocket."""

    def fake_create_connection(address, timeout=None):
        return _FakeSocket(replies, sent)

    return fake_create_connection


def _target() -> Target:
    """A single open Redis port keeps the probe surface deterministic."""
    return Target(host="10.0.0.7", ports={6379: {"state": "open", "name": "redis"}})


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-REDIS-001"
    assert module.metadata["name"] == "Redis Unauthenticated Access"
    assert module.metadata["port_hint"] == [6379, 6380, 16379]
    assert callable(module.probe)


def test_pong_confirms_unauthenticated_access_is_high(monkeypatch):
    """+PONG with a version banner => HIGH finding carrying the version."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"PING\r\n": b"+PONG\r\n",
        b"INFO server\r\n": (
            b"$120\r\n# Server\r\nredis_version:7.4.0\r\n"
            b"redis_mode:standalone\r\ntcp_port:6379\r\n"
        ),
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-REDIS-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.7"
    assert finding.evidence["port"] == 6379
    assert finding.evidence["ping_reply"] == "+PONG"
    assert finding.evidence["redis_version"] == "7.4.0"
    # 7.4.0 <= 8.2.1 => RediShell scope flagged.
    assert finding.evidence.get("cve_2025_49844_in_scope") is True
    assert "CVE-2025-49844" in finding.description
    # PING must be sent before INFO; no other commands issued.
    assert sent[0] == b"PING\r\n"
    assert b"INFO server\r\n" in sent
    assert all(cmd in (b"PING\r\n", b"INFO server\r\n") for cmd in sent)


def test_auth_required_is_no_finding(monkeypatch):
    """-NOAUTH / -ERR authentication required => not vulnerable (no finding)."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {b"PING\r\n": b"-NOAUTH Authentication required.\r\n"}
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is None
    # On auth challenge we must NOT follow up with INFO.
    assert sent == [b"PING\r\n", b"PING\r\n", b"PING\r\n"][: len(sent)]
    assert b"INFO server\r\n" not in sent


def test_err_auth_required_is_no_finding(monkeypatch):
    """The classic ``-ERR ... AUTH ...`` form is also treated as not-vuln."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {b"PING\r\n": b"-ERR Client sent AUTH, but no password is set\r\n"}
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )
    # Only the open Redis port; reply does not start with +PONG => skipped.
    finding = module.probe(_target())
    assert finding is None
    assert b"INFO server\r\n" not in sent


def test_connection_error_is_no_finding(monkeypatch):
    """A socket error on every candidate port => no finding, no raise."""
    module = load_plugin(PLUGIN)

    def boom(address, timeout=None):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(module.socket, "create_connection", boom)

    assert module.probe(_target()) is None


def test_pong_without_version_still_high(monkeypatch):
    """+PONG but INFO unparsable => still HIGH; no version, no CVE flag."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"PING\r\n": b"+PONG\r\n",
        b"INFO server\r\n": b"$5\r\nhello\r\n",  # no redis_version line
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert "redis_version" not in finding.evidence
    assert "cve_2025_49844_in_scope" not in finding.evidence
    # No version => no "within scope of" scoping sentence is appended.
    assert "within scope of" not in finding.description


def test_modern_version_not_in_redishell_scope(monkeypatch):
    """+PONG with version > 8.2.1 => HIGH but no CVE-2025-49844 flag."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"PING\r\n": b"+PONG\r\n",
        b"INFO server\r\n": b"# Server\r\nredis_version:8.4.0\r\n",
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["redis_version"] == "8.4.0"
    assert "cve_2025_49844_in_scope" not in finding.evidence
    # Out-of-scope version => no "within scope of" scoping sentence appended.
    assert "within scope of" not in finding.description


def test_boundary_version_8_2_1_in_scope(monkeypatch):
    """Exactly 8.2.1 is the inclusive upper bound for CVE-2025-49844."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"PING\r\n": b"+PONG\r\n",
        b"INFO server\r\n": b"redis_version:8.2.1\r\n",
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.evidence.get("cve_2025_49844_in_scope") is True


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"PING\r\n": b"+PONG\r\n",
        b"INFO server\r\n": b"redis_version:6.2.6\r\n",
    }
    monkeypatch.setattr(
        module.socket, "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-REDIS-001"
    assert findings[0].confidence == "high"


def test_port_hints_used_when_no_recon(monkeypatch):
    """With no open ports from recon, probe falls back to the port hints."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout=None):
        addresses.append(address)
        return _FakeSocket({b"PING\r\n": b"+PONG\r\n"}, [])

    monkeypatch.setattr(module.socket, "create_connection", fake_create_connection)

    finding = module.probe(Target(host="10.0.0.9"))  # no ports => hints

    assert finding is not None
    # Short-circuits on the first reachable vulnerable port (6379).
    assert addresses[0] == ("10.0.0.9", 6379)


def test_default_port_6379_used_first(monkeypatch):
    """6379 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout=None):
        addresses.append(address)
        # Never reply +PONG so the probe walks every candidate port.
        return _FakeSocket({}, [])

    monkeypatch.setattr(module.socket, "create_connection", fake_create_connection)
    module.probe(Target(host="h"))

    contacted_ports = [p for _, p in addresses]
    assert contacted_ports == [6379, 6380, 16379]
