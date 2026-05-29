"""Tests for the Memcached unrestricted access probe (MIASMA-MEMCACHED-001).

All TCP is mocked — no live network. We monkeypatch ``socket.create_connection``
on the plugin module and hand back a fake socket that records what was sent and
replies with canned bytes keyed on the most recent ASCII command. Memcached
opens a fresh short-lived connection per command in this probe, so the fake
socket replies based on the last ``sendall`` payload. This mirrors the project's
mock-at-the-seam convention (tests/test_zookeeper.py mocks the same raw-socket
seam; tests/test_redis.py mocks the same seam).
"""

from __future__ import annotations

import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_memcached_001"


class _FakeSocket:
    """A context-manager socket that replies per sent ASCII command.

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
    """A single open Memcached port keeps the probe surface deterministic."""
    return Target(
        host="10.0.0.11", ports={11211: {"state": "open", "name": "memcache"}}
    )


# A realistic stats reply with a live cache (curr_items > 0).
_STATS_REPLY_LIVE = (
    b"STAT pid 1\r\n"
    b"STAT uptime 12345\r\n"
    b"STAT time 1700000000\r\n"
    b"STAT version 1.6.21\r\n"
    b"STAT libevent 2.1.12-stable\r\n"
    b"STAT pointer_size 64\r\n"
    b"STAT curr_connections 7\r\n"
    b"STAT total_connections 19\r\n"
    b"STAT auth_cmds 0\r\n"
    b"STAT auth_errors 0\r\n"
    b"STAT curr_items 4096\r\n"
    b"STAT total_items 100000\r\n"
    b"STAT bytes 1048576\r\n"
    b"END\r\n"
)

_STATS_REPLY_EMPTY = (
    b"STAT pid 1\r\n"
    b"STAT uptime 30\r\n"
    b"STAT version 1.6.21\r\n"
    b"STAT curr_connections 2\r\n"
    b"STAT curr_items 0\r\n"
    b"STAT total_items 0\r\n"
    b"STAT bytes 0\r\n"
    b"END\r\n"
)


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-MEMCACHED-001"
    assert module.metadata["name"] == "Memcached Unrestricted Access"
    assert module.metadata["port_hint"] == [11211, 11210, 11212]
    assert "memcached" in module.metadata["service_hint"]
    assert callable(module.probe)


def test_version_and_stats_with_live_cache_is_high(monkeypatch):
    """VERSION + stats with curr_items > 0 => HIGH finding with inventory."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"version\r\n": b"VERSION 1.6.21\r\n",
        b"stats\r\n": _STATS_REPLY_LIVE,
    }
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-MEMCACHED-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.11"
    assert finding.evidence["port"] == 11211
    assert finding.evidence["version_banner"] is True
    assert finding.evidence["stats_unauthenticated"] is True
    assert finding.evidence["version"] == "1.6.21"
    assert finding.evidence["curr_items"] == 4096
    assert finding.evidence["total_items"] == 100000
    assert finding.evidence["bytes"] == 1048576
    assert finding.evidence["pid"] == 1
    assert finding.evidence["uptime"] == 12345
    assert finding.evidence["curr_connections"] == 7
    assert finding.evidence["auth_cmds"] == 0
    assert finding.evidence["auth_errors"] == 0
    # version must be sent first; only benign read-only commands ever issued.
    assert sent[0] == b"version\r\n"
    assert all(cmd in (b"version\r\n", b"stats\r\n") for cmd in sent)
    # The probe must NEVER send a mutating or per-key command.
    for cmd in sent:
        for forbidden in (b"set ", b"add ", b"replace ", b"delete ", b"flush_all",
                          b"incr ", b"decr ", b"get ", b"cache_memlimit",
                          b"stats items", b"stats slabs", b"stats cachedump"):
            assert forbidden not in cmd


def test_version_and_stats_with_empty_cache_is_medium(monkeypatch):
    """VERSION + stats but curr_items == 0 => MEDIUM (admin surface still open)."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"version\r\n": b"VERSION 1.6.21\r\n",
        b"stats\r\n": _STATS_REPLY_EMPTY,
    }
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["stats_unauthenticated"] is True
    assert finding.evidence["curr_items"] == 0
    assert finding.evidence["version"] == "1.6.21"
    assert "no application data is exposed right now" in finding.description


def test_version_only_is_medium_when_stats_refused(monkeypatch):
    """VERSION banner but stats refused/empty => MEDIUM finding."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {b"version\r\n": b"VERSION 1.6.21\r\n"}  # stats unmapped => empty
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version_banner"] is True
    assert finding.evidence["version"] == "1.6.21"
    assert "stats_unauthenticated" not in finding.evidence
    assert "curr_items" not in finding.evidence
    assert "stats command was refused" in finding.description


def test_no_version_banner_is_no_finding(monkeypatch):
    """A non-VERSION reply (not Memcached / SASL-only) => no finding."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    # SSH greeting, or a Redis "-ERR unknown command" response: neither begins
    # with "VERSION " so they must not be confused for Memcached.
    replies = {b"version\r\n": b"SSH-2.0-OpenSSH_9.6\r\n"}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is None
    # On a failed fingerprint we must NOT follow up with stats.
    assert b"stats\r\n" not in sent


def test_redis_error_not_confused_for_memcached(monkeypatch):
    """A Redis-style ``-ERR unknown command 'version'`` is not a Memcached match."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {b"version\r\n": b"-ERR unknown command 'version'\r\n"}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is None
    assert b"stats\r\n" not in sent


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
    replies = {
        b"version\r\n": b"VERSION 1.6.21\r\n",
        b"stats\r\n": _STATS_REPLY_LIVE,
    }
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-MEMCACHED-001"
    assert findings[0].confidence == "high"


def test_port_hints_used_when_no_recon(monkeypatch):
    """With no open ports from recon, probe falls back to the port hints."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []
    replies = {
        b"version\r\n": b"VERSION 1.6.21\r\n",
        b"stats\r\n": _STATS_REPLY_LIVE,
    }
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, [], addresses),
    )

    finding = module.probe(Target(host="10.0.0.12"))  # no ports => hints

    assert finding is not None
    # Short-circuits on the first reachable Memcached port (11211).
    assert addresses[0] == ("10.0.0.12", 11211)


def test_default_port_11211_used_first(monkeypatch):
    """11211 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout=None):
        addresses.append(address)
        # Never reply with a VERSION banner so the probe walks every candidate.
        return _FakeSocket({}, [])

    monkeypatch.setattr(module.socket, "create_connection", fake_create_connection)
    module.probe(Target(host="h"))

    contacted_ports = [p for _, p in addresses]
    assert contacted_ports == [11211, 11210, 11212]


def test_version_banner_parsed():
    """The ``VERSION <semver>`` banner is correctly parsed into evidence.version."""
    module = load_plugin(PLUGIN)
    assert module._parse_version_banner("VERSION 1.6.21\r\n") == "1.6.21"
    assert module._parse_version_banner("  VERSION 1.5.22\r\n") == "1.5.22"
    assert module._parse_version_banner("ERROR\r\n") is None
    assert module._parse_version_banner("") is None


def test_stats_parser_extracts_documented_keys():
    """_parse_stats coerces numeric keys to int and keeps version as string."""
    module = load_plugin(PLUGIN)
    parsed = module._parse_stats(_STATS_REPLY_LIVE.decode())
    assert parsed["version"] == "1.6.21"
    assert parsed["pid"] == 1
    assert parsed["uptime"] == 12345
    assert parsed["curr_items"] == 4096
    assert parsed["total_items"] == 100000
    assert parsed["bytes"] == 1048576
    assert parsed["curr_connections"] == 7
    # Unknown / non-tracked keys must not pollute the dict.
    assert "libevent" not in parsed
    assert "pointer_size" not in parsed
    assert "time" not in parsed


def test_stats_parser_handles_malformed_lines():
    """Garbage in the stats reply must not raise; unknown keys ignored."""
    module = load_plugin(PLUGIN)
    parsed = module._parse_stats(
        "STAT pid not_an_int\r\n"
        "STAT\r\n"  # truncated
        "garbage line\r\n"
        "STAT curr_items 7\r\n"
        "END\r\n"
    )
    assert parsed == {"curr_items": 7}


def test_sasl_only_server_no_version_no_finding(monkeypatch):
    """A SASL-enforcing server typically refuses ``version`` => no finding."""
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {b"version\r\n": b"CLIENT_ERROR unauthenticated\r\n"}
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is None
    assert b"stats\r\n" not in sent


def test_finding_never_contains_per_key_data(monkeypatch):
    """The finding evidence must not contain anything that looks like a key/value.

    The probe only issues ``version`` and ``stats``; it never reads individual
    cache keys. The evidence dict should only carry the documented inventory
    counters plus the version banner — no application data.
    """
    module = load_plugin(PLUGIN)
    sent: list[bytes] = []
    replies = {
        b"version\r\n": b"VERSION 1.6.21\r\n",
        b"stats\r\n": _STATS_REPLY_LIVE,
    }
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, sent),
    )

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {
        "host",
        "port",
        "version_banner",
        "version",
        "stats_unauthenticated",
        "pid",
        "uptime",
        "curr_items",
        "total_items",
        "bytes",
        "curr_connections",
        "auth_cmds",
        "auth_errors",
    }
    assert set(finding.evidence.keys()).issubset(allowed_keys)


def test_recon_service_name_matches_memcache(monkeypatch):
    """A non-default port marked as a memcached service in recon is probed."""
    module = load_plugin(PLUGIN)
    addresses: list[tuple[str, int]] = []
    replies = {
        b"version\r\n": b"VERSION 1.6.21\r\n",
        b"stats\r\n": _STATS_REPLY_LIVE,
    }
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        _make_fake_create_connection(replies, [], addresses),
    )

    # Memcached listening on a non-default port; recon labels it memcached.
    target = Target(
        host="10.0.0.13",
        ports={22222: {"state": "open", "name": "memcached"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 22222
    assert addresses[0] == ("10.0.0.13", 22222)
