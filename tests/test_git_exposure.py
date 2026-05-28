"""Tests for the exposed .git directory probe (MIASMA-GIT-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (tests/test_elastic.py).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_git_001"

# --- helpers ----------------------------------------------------------------

_HEAD_BODY = "ref: refs/heads/main\n"
_HEAD_DETACHED_BODY = "0123456789abcdef0123456789abcdef01234567\n"
_CONFIG_PLAIN = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    '[remote "origin"]\n'
    "\turl = https://github.com/bugsyhewitt/secret-repo.git\n"
)
_CONFIG_WITH_CREDS = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    '[remote "origin"]\n'
    "\turl = https://deploy:s3cr3tpass@git.internal/app.git\n"
)
_SPA_INDEX = "<!DOCTYPE html><html><body>app</body></html>"


def _resp(status: int, body: str = "", headers: dict | None = None) -> httpx.Response:
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers=headers or {},
        request=request,
    )


def _make_fake_get(path_map: dict[str, httpx.Response], record: list | None = None):
    """Return a fake httpx.get routing by URL path. Unknown paths yield 404."""

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path = urlparse(url).path or "/"
        return path_map.get(path, _resp(404))

    return fake_get


def _target() -> Target:
    """Single open web port keeps the probe surface small and deterministic."""
    return Target(host="10.0.0.20", ports={80: {"state": "open", "name": "http"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-GIT-001"
    assert module.metadata["name"] == "Exposed .git Directory"
    assert 80 in module.metadata["port_hint"]
    assert 443 in module.metadata["port_hint"]
    assert callable(module.probe)


# --- exposed .git (HEAD present) --------------------------------------------


def test_exposed_head_returns_high_finding(monkeypatch):
    """/.git/HEAD returns a symbolic ref => HIGH, head_exposed=True."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/.git/HEAD": _resp(200, _HEAD_BODY),
        "/.git/config": _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-GIT-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.20"
    assert finding.evidence["head_exposed"] is True
    assert finding.evidence["port"] == 80
    assert finding.evidence["url"] == "http://10.0.0.20:80/.git/HEAD"


def test_exposed_head_detached_sha_returns_finding(monkeypatch):
    """A detached-HEAD repo stores a raw 40-hex SHA in HEAD => still flagged."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/.git/HEAD": _resp(200, _HEAD_DETACHED_BODY),
        "/.git/config": _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["head_exposed"] is True


# --- credential leak in /.git/config ----------------------------------------


def test_config_credentials_are_flagged_and_redacted(monkeypatch):
    """/.git/config remote URL embeds creds => flagged, password redacted."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/.git/HEAD": _resp(200, _HEAD_BODY),
        "/.git/config": _resp(200, _CONFIG_WITH_CREDS),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence.get("config_exposed") is True
    leaked = finding.evidence["credential_in_remote_url"]
    # The marker is present...
    assert "deploy" in leaked
    assert "@" in leaked
    # ...but the actual password is redacted (never persisted verbatim).
    assert "s3cr3tpass" not in leaked
    assert "***" in leaked
    assert "s3cr3tpass" not in finding.description


def test_config_without_creds_is_not_flagged(monkeypatch):
    """Exposed config with a plain (no-cred) remote URL => no config flag."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/.git/HEAD": _resp(200, _HEAD_BODY),
        "/.git/config": _resp(200, _CONFIG_PLAIN),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"  # HEAD exposure still a finding
    assert "config_exposed" not in finding.evidence
    assert "credential_in_remote_url" not in finding.evidence


# --- false-positive guards --------------------------------------------------


def test_spa_index_html_is_not_flagged(monkeypatch):
    """A server returning index.html (200) for every path must NOT be flagged."""
    module = load_plugin(PLUGIN)
    path_map = {"/.git/HEAD": _resp(200, _SPA_INDEX)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_head_404_is_no_finding(monkeypatch):
    """/.git/HEAD 404 => directory not exposed => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/.git/HEAD": _resp(404)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_head_403_is_no_finding(monkeypatch):
    """/.git/HEAD 403 (denied) => not exposed => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/.git/HEAD": _resp(403)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- connection / timeout errors --------------------------------------------


def test_connection_error_is_no_finding(monkeypatch):
    """A socket error on every candidate port => no finding, no exception."""
    module = load_plugin(PLUGIN)

    def boom(url, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(module.httpx, "get", boom)

    assert module.probe(_target()) is None


def test_timeout_is_no_finding(monkeypatch):
    """A timeout on every candidate port => no finding, no exception raised."""
    module = load_plugin(PLUGIN)

    def timeout(url, *args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(module.httpx, "get", timeout)

    assert module.probe(_target()) is None


# --- scheme / port handling -------------------------------------------------


def test_https_scheme_used_for_tls_ports(monkeypatch):
    """Port 443 is probed over https, not http."""
    module = load_plugin(PLUGIN)
    requested: list = []
    path_map = {"/.git/HEAD": _resp(200, _HEAD_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    target = Target(host="10.0.0.21", ports={443: {"state": "open", "name": "https"}})
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 443
    assert any(u.startswith("https://10.0.0.21:443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [80, 443, 8080, 8443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.22"))  # no ports key → default_ports

    assert 80 in contacted_ports
    assert 443 in contacted_ports
    assert 8080 in contacted_ports
    assert 8443 in contacted_ports


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {"/.git/HEAD": _resp(200, _HEAD_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-GIT-001"
    assert findings[0].confidence == "high"
