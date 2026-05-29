"""Tests for Docker daemon unauthenticated TCP API probe (MIASMA-DOCKER-001).

All HTTP is mocked — no live network. httpx.get is monkeypatched on the plugin
module and routes each request to a canned response keyed by URL path.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_docker_001"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resp(status: int, body=None, *, json_array: bool = False):
    """Build a real httpx.Response with no network round-trip."""
    request = httpx.Request("GET", "http://example.test")
    if json_array:
        import json as _json
        content = _json.dumps(body or []).encode()
        return httpx.Response(
            status_code=status,
            content=content,
            headers={"content-type": "application/json"},
            request=request,
        )
    return httpx.Response(
        status_code=status,
        json=body if body is not None else {},
        request=request,
    )


def _make_fake_get(path_map: dict[str, httpx.Response]):
    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        return path_map.get(path, _resp(404))
    return fake_get


def _version_body():
    return {
        "Version": "24.0.5",
        "ApiVersion": "1.43",
        "MinAPIVersion": "1.12",
        "Platform": {"Name": "Docker Engine - Community"},
    }


def _target(ports=None) -> Target:
    if ports is None:
        ports = {2375: {"state": "open", "name": "http"}}
    return Target(host="10.0.0.5", ports=ports)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def test_plugin_is_discoverable():
    assert PLUGIN in available_plugins()


def test_plugin_metadata_valid():
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-DOCKER-001"
    assert callable(module.probe)
    assert "port_hint" in module.metadata


# ---------------------------------------------------------------------------
# HIGH — container list accessible
# ---------------------------------------------------------------------------

def test_high_finding_when_containers_accessible(monkeypatch):
    """HIGH when /containers/json returns a non-empty list."""
    module = load_plugin(PLUGIN)
    containers = [{"Id": "abc123", "Names": ["/web"]}]
    path_map = {
        "/version": _resp(200, _version_body()),
        "/containers/json": _resp(200, containers, json_array=True),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    finding = module.probe(_target())
    assert finding is not None
    assert finding.vuln_id == "MIASMA-DOCKER-001"
    assert finding.confidence == "high"
    assert finding.evidence["running_container_count"] == 1
    assert finding.evidence["docker_version"] == "24.0.5"
    assert finding.evidence["api_version"] == "1.43"


def test_high_finding_empty_container_list(monkeypatch):
    """HIGH even when container list is empty (zero containers running)."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/version": _resp(200, _version_body()),
        "/containers/json": _resp(200, [], json_array=True),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    finding = module.probe(_target())
    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["running_container_count"] == 0


def test_high_finding_multiple_containers(monkeypatch):
    """Running container count is recorded correctly for multiple containers."""
    module = load_plugin(PLUGIN)
    containers = [{"Id": f"abc{i}"} for i in range(5)]
    path_map = {
        "/version": _resp(200, _version_body()),
        "/containers/json": _resp(200, containers, json_array=True),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    finding = module.probe(_target())
    assert finding is not None
    assert finding.evidence["running_container_count"] == 5


# ---------------------------------------------------------------------------
# MEDIUM — version exposed but containers refused
# ---------------------------------------------------------------------------

def test_medium_finding_when_containers_refused(monkeypatch):
    """MEDIUM when /version is open but /containers/json returns 401."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/version": _resp(200, _version_body()),
        "/containers/json": _resp(401),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    finding = module.probe(_target())
    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["containers_status"] == 401


def test_medium_finding_containers_returns_non_array(monkeypatch):
    """MEDIUM when /containers/json returns 200 but with a JSON object body."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/version": _resp(200, _version_body()),
        # A proxy 200 with a JSON object body — not a real Docker response.
        "/containers/json": _resp(200, {"message": "ok"}),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    finding = module.probe(_target())
    assert finding is not None
    assert finding.confidence == "medium"


# ---------------------------------------------------------------------------
# No finding
# ---------------------------------------------------------------------------

def test_no_finding_when_version_not_docker(monkeypatch):
    """/version returns 200 but is not a Docker API response — no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/version": _resp(200, {"message": "Hello World"}),
        "/containers/json": _resp(200, [], json_array=True),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    assert module.probe(_target()) is None


def test_no_finding_when_version_returns_404(monkeypatch):
    """Port returns 404 on /version — no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/version": _resp(404)}
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    assert module.probe(_target()) is None


def test_no_finding_when_no_open_ports(monkeypatch):
    """Target has no open ports and no Docker listener — no finding."""
    module = load_plugin(PLUGIN)
    # Simulate connection failure (all requests return None).
    path_map: dict = {}

    def _failing_get(url, *args, **kwargs):
        raise httpx.ConnectError("refused")

    import types
    fake = types.SimpleNamespace(get=_failing_get, HTTPError=httpx.HTTPError)
    monkeypatch.setattr(module, "httpx", fake)
    assert module.probe(Target(host="10.0.0.5")) is None


# ---------------------------------------------------------------------------
# Port selection and run_plugins integration
# ---------------------------------------------------------------------------

def test_uses_recon_port_when_available(monkeypatch):
    """Probe prefers recon-discovered open port over default port hints."""
    module = load_plugin(PLUGIN)
    containers = [{"Id": "xyz"}]
    path_map = {
        "/version": _resp(200, _version_body()),
        "/containers/json": _resp(200, containers, json_array=True),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    # Target with a non-default docker port in recon.
    target = Target(host="10.0.0.5", ports={9999: {"state": "open", "name": "docker"}})
    finding = module.probe(target)
    assert finding is not None
    assert ":9999" in finding.evidence["base_url"]


def test_run_plugins_discovers_docker_finding(monkeypatch):
    """run_plugins picks up Docker findings from the runner."""
    module = load_plugin(PLUGIN)
    containers = [{"Id": "abc"}]
    path_map = {
        "/version": _resp(200, _version_body()),
        "/containers/json": _resp(200, containers, json_array=True),
    }
    monkeypatch.setattr(module, "httpx", _patched_httpx(path_map))
    target = _target()
    findings = run_plugins(target, plugin_names=[PLUGIN])
    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-DOCKER-001"


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _patched_httpx(path_map: dict[str, httpx.Response]):
    """Return a SimpleNamespace that replaces the httpx module on the plugin."""
    import types

    fake_get = _make_fake_get(path_map)

    return types.SimpleNamespace(
        get=fake_get,
        HTTPError=httpx.HTTPError,
    )
