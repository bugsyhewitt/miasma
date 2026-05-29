"""Tests for the Fortinet FortiOS/FortiProxy auth-bypass probe (CVE-2024-55591).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's existing mock-at-the-seam testing convention
(see tests/test_fortiweb.py and tests/test_actuator.py).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2024_55591"

# A realistic privileged status JSON body (carries the markers the probe checks).
_STATUS_JSON = (
    '{"http_method":"GET","results":{"serial":"FGVM01TM0000ABCD",'
    '"version":"7.4.3","build":"2573"},"status":"success"}'
)

# FortiOS login page body marker.
_FORTIOS_LOGIN = "<title>FortiGate</title><body>Please Login</body>"


def _resp(status: int, text: str = "", headers=None):
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        text=text,
        headers=headers or {},
        request=request,
    )


# A single open HTTPS-ish port keeps the probe surface small and deterministic.
def _target() -> Target:
    return Target(host="10.0.0.7", ports={443: {"state": "open", "name": "https"}})


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2024-55591"
    assert callable(module.probe)


def test_confirmed_bypass_returns_high(monkeypatch):
    """Privileged status via the ws namespace while the direct path refuses → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/login":
            return _resp(200, _FORTIOS_LOGIN)
        # Direct authenticated endpoint refuses without a session.
        if path == "/api/v2/cmdb/system/status":
            return _resp(401, "unauthorized")
        # ...but the websocket-namespace shape leaks the privileged status JSON.
        if path.startswith("/ws"):
            return _resp(200, _STATUS_JSON)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2024-55591"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.7"
    assert finding.evidence["direct_status"] == 401
    assert finding.evidence["bypass_status"] == 200
    assert finding.evidence["bypass_path"].startswith("/ws")


def test_forti_via_server_header(monkeypatch):
    """Fingerprint via the Server header alone still confirms a bypass → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            return _resp(200, "ok", headers={"server": "FortiProxy"})
        if path == "/api/v2/cmdb/system/status":
            return _resp(403)
        if path.startswith("/ws"):
            return _resp(200, _STATUS_JSON)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"


def test_forti_but_bypass_blocked_returns_none(monkeypatch):
    """FortiOS fingerprinted but every bypass path is correctly blocked → none."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/login":
            return _resp(200, _FORTIOS_LOGIN)
        if path == "/api/v2/cmdb/system/status":
            return _resp(401)
        # Every websocket-namespace attempt is correctly rejected.
        return _resp(403)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_forti_suspicious_200_without_markers_is_medium(monkeypatch):
    """Bypass path returns a 200 with no status markers → MEDIUM, not HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/login":
            return _resp(200, _FORTIOS_LOGIN)
        if path == "/api/v2/cmdb/system/status":
            return _resp(401)
        # A 200 that does NOT look like privileged status data — suspicious but
        # not a confirmed read.
        return _resp(200, "<html>generic page</html>")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert "note" in finding.evidence


def test_forti_direct_not_refusing_is_medium(monkeypatch):
    """Bypass leaks status but the direct path didn't refuse → MEDIUM (no clean control)."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/login":
            return _resp(200, _FORTIOS_LOGIN)
        # Direct path also answers 200 — appliance wide open by misconfig, not a
        # clean CVE-2024-55591 bypass control. Probe must not claim HIGH.
        if path == "/api/v2/cmdb/system/status":
            return _resp(200, _STATUS_JSON)
        if path.startswith("/ws"):
            return _resp(200, _STATUS_JSON)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"


def test_non_forti_host_returns_none(monkeypatch):
    """A non-Forti host with odd 200s must not be flagged (no false positive)."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            return _resp(200, "ok", headers={"server": "nginx/1.25.0"})
        # Even a 200 here must not flag — not FortiOS.
        return _resp(200, _STATUS_JSON)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_high_wins_over_medium_across_ports(monkeypatch):
    """A MEDIUM hint on one port must not mask a confirmed HIGH on another."""
    module = load_plugin(PLUGIN)
    target = Target(
        host="h",
        ports={
            80: {"state": "open", "name": "http"},
            443: {"state": "open", "name": "https"},
        },
    )

    def fake_get(url, *args, **kwargs):
        parsed = urlparse(url)
        path = parsed.path
        port = parsed.port
        if path == "/login":
            return _resp(200, _FORTIOS_LOGIN)
        if path == "/api/v2/cmdb/system/status":
            return _resp(401)
        # Port 80: suspicious 200 with no markers (would be MEDIUM on its own).
        if port == 80 and path.startswith("/ws"):
            return _resp(200, "<html>landing</html>")
        # Port 443: confirmed privileged status leak (HIGH).
        if port == 443 and path.startswith("/ws"):
            return _resp(200, _STATUS_JSON)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(target)

    assert finding is not None
    assert finding.confidence == "high"
    assert ":443" in finding.evidence["base_url"]


def test_network_error_is_tolerated(monkeypatch):
    """Connection errors are swallowed; the probe returns None, never raises."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_default_ports_used_when_no_recon(monkeypatch):
    """With no open ports from recon, the probe falls back to default ports."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == "/login":
            return _resp(200, _FORTIOS_LOGIN)
        if path == "/api/v2/cmdb/system/status":
            return _resp(401)
        if path.startswith("/ws"):
            return _resp(200, _STATUS_JSON)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(Target(host="10.0.0.9"))  # no ports → defaults

    assert finding is not None
    assert finding.confidence == "high"
    # The first default port (443) should have been probed.
    assert any(":443/" in u for u in requested)
    assert 443 in module.metadata["default_ports"]


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/login":
            return _resp(200, _FORTIOS_LOGIN)
        if path == "/api/v2/cmdb/system/status":
            return _resp(401)
        if path.startswith("/ws"):
            return _resp(200, _STATUS_JSON)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2024-55591"
    assert findings[0].confidence == "high"


@pytest.mark.parametrize(
    "port,expected_scheme",
    [(443, "https"), (8443, "https"), (10443, "https"), (80, "http")],
)
def test_scheme_selection_per_port(monkeypatch, port, expected_scheme):
    """https is used for 443/8443/10443; http otherwise."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)
    module.probe(Target(host="h", ports={port: {"state": "open", "name": "http"}}))

    assert any(u.startswith(f"{expected_scheme}://h:{port}/") for u in requested)
