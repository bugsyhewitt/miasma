"""Tests for the Jupyter Notebook/Lab unauthenticated code-execution probe
(MIASMA-JUPYTER-001).

All HTTP is mocked — no live network.  We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path.
Mirrors the project's mock-at-the-seam convention from test_grafana.py /
test_prometheus.py / test_activemq.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin

PLUGIN = "miasma_jupyter_001"

# --- canned response bodies ---------------------------------------------------

# Jupyter /api response body (Notebook 6.x).
_JUPYTER_API_BODY = '{"version": "6.4.12"}'

# Jupyter /api response body (JupyterLab 3.x).
_JUPYTERLAB_API_BODY = '{"version": "3.6.0"}'

# Jupyter /api/kernels response (no running kernels — but 200 = accessible).
_KERNELS_EMPTY_BODY = "[]"

# Jupyter /api/kernels response (one running kernel).
_KERNELS_ONE_BODY = (
    '[{"id":"abc123","name":"python3","last_activity":"2026-06-05T18:00:00Z",'
    '"execution_state":"idle","connections":1}]'
)

# Jupyter /api/kernelspecs response.
_KERNELSPECS_BODY = (
    '{"default":"python3","kernelspecs":{"python3":{"name":"python3",'
    '"spec":{"display_name":"Python 3"}}}}'
)

# Non-Jupyter 200 body (Tomcat) — must not be fingerprinted.
_NOT_JUPYTER_BODY = "<html><title>Apache Tomcat</title></html>"

# /api body with no "version" key — must not be fingerprinted.
_JUPYTER_NO_VERSION_BODY = '{"status": "ok"}'


def _resp(
    status: int, body: str = "", headers: dict | None = None
) -> httpx.Response:
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers=headers or {},
        request=request,
    )


def _make_fake_get(path_map: dict[str, httpx.Response], record: list | None = None):
    """Fake httpx.get routing by URL path."""

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path = urlparse(url).path or "/"
        return path_map.get(path, _resp(404))

    return fake_get


def _target(port: int = 8888) -> Target:
    return Target(
        host="10.0.0.90", ports={port: {"state": "open", "name": "jupyter"}}
    )


# --- discoverability ----------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-JUPYTER-001"
    assert "Jupyter" in module.metadata["name"]
    assert 8888 in module.metadata["port_hint"]
    assert 8888 in module.metadata["default_ports"]
    assert "jupyter" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- CRITICAL: kernels accessible (RCE) --------------------------------------


def test_kernels_accessible_is_critical(monkeypatch):
    """/api fingerprints Jupyter AND /api/kernels returns 200 => critical."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(200, _KERNELS_EMPTY_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-JUPYTER-001"
    assert finding.confidence == "critical"
    assert finding.host == "10.0.0.90"
    assert finding.evidence["kernels_accessible"] is True
    assert finding.evidence["version"] == "6.4.12"
    assert finding.evidence["port"] == 8888


def test_kernels_accessible_running_kernels_is_critical(monkeypatch):
    """/api/kernels returns 200 with a running kernel list => critical."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(200, _KERNELS_ONE_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "critical"
    assert finding.evidence["kernels_accessible"] is True


def test_critical_finding_includes_rce_path(monkeypatch):
    """CRITICAL finding evidence must describe the RCE path."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTERLAB_API_BODY),
        "/api/kernels": _resp(200, _KERNELS_EMPTY_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert "rce_path" in finding.evidence
    assert "POST" in finding.evidence["rce_path"]


def test_kernels_accessible_skips_kernelspecs_probe(monkeypatch):
    """When /api/kernels is accessible, /api/kernelspecs is not probed."""
    module = load_plugin(PLUGIN)
    contacted: list[str] = []
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(200, _KERNELS_EMPTY_BODY),
        "/api/kernelspecs": _resp(200, _KERNELSPECS_BODY),
    }
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=contacted)
    )

    module.probe(_target())

    kernelspecs_urls = [u for u in contacted if "kernelspecs" in u]
    assert kernelspecs_urls == [], (
        "expected no /api/kernelspecs request when /api/kernels is already open"
    )


# --- HIGH: kernelspecs accessible but kernels gated --------------------------


def test_kernelspecs_accessible_is_high(monkeypatch):
    """/api fingerprints Jupyter, /api/kernels 401, /api/kernelspecs 200 => high."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(401),
        "/api/kernelspecs": _resp(200, _KERNELSPECS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["kernels_accessible"] is False
    assert finding.evidence["kernelspecs_accessible"] is True
    assert finding.evidence["version"] == "6.4.12"


def test_kernelspecs_accessible_is_high_jupyterlab(monkeypatch):
    """Same check with JupyterLab version string in /api body."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTERLAB_API_BODY),
        "/api/kernels": _resp(401),
        "/api/kernelspecs": _resp(200, _KERNELSPECS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version"] == "3.6.0"


# --- MEDIUM: /api accessible, both sub-endpoints gated -----------------------


def test_api_only_accessible_is_medium(monkeypatch):
    """/api 200 but /api/kernels and /api/kernelspecs both return 401 => medium."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(401),
        "/api/kernelspecs": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["kernels_accessible"] is False
    assert finding.evidence["kernelspecs_accessible"] is False


def test_medium_evidence_includes_version(monkeypatch):
    """MEDIUM finding evidence carries the fingerprinted version."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(403),
        "/api/kernelspecs": _resp(403),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.evidence["version"] == "6.4.12"


# --- no finding cases ---------------------------------------------------------


def test_not_jupyter_no_finding(monkeypatch):
    """/api returns 200 but body has no 'version' key => not Jupyter => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/api": _resp(200, _NOT_JUPYTER_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_api_version_key_missing_no_finding(monkeypatch):
    """/api returns 200 with JSON but no 'version' key => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/api": _resp(200, _JUPYTER_NO_VERSION_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_api_401_no_finding(monkeypatch):
    """/api returns 401 (auth required) => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/api": _resp(401)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_api_connection_error_no_finding(monkeypatch):
    """Transport error on /api (port closed, timeout) => None."""
    module = load_plugin(PLUGIN)

    def raise_error(url, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(module.httpx, "get", raise_error)

    assert module.probe(_target()) is None


def test_no_open_ports_uses_defaults_and_returns_none_on_closed(monkeypatch):
    """Target with no recon data falls back to default ports; closed => None."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(module.httpx, "get", lambda *a, **kw: None)

    # Target with no ports dict — all default ports will be tried and return None.
    target = Target(host="10.0.0.1", ports={})
    assert module.probe(target) is None


# --- port selection ----------------------------------------------------------


def test_recon_port_preferred_over_defaults(monkeypatch):
    """When recon provides a Jupyter-labelled port, it is tried first."""
    module = load_plugin(PLUGIN)
    contacted: list[str] = []
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(401),
        "/api/kernelspecs": _resp(401),
    }
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=contacted)
    )

    # nmap named this port "jupyter-hub" — the probe should pick it up.
    target = Target(
        host="10.0.0.90",
        ports={9999: {"state": "open", "name": "jupyter-hub"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 9999
    assert any(":9999" in url for url in contacted)


def test_non_jupyter_recon_port_uses_that_port(monkeypatch):
    """When recon provides a non-default, non-Jupyter-named port that responds
    to the Jupyter fingerprint, the finding records the recon port."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(200, _KERNELS_EMPTY_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    target = Target(
        host="10.0.0.90",
        ports={12345: {"state": "open", "name": "unknown"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 12345


# --- evidence completeness ---------------------------------------------------


def test_evidence_includes_scheme(monkeypatch):
    """Evidence must carry the scheme used to reach the Jupyter instance."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(200, _KERNELS_EMPTY_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.evidence["scheme"] == "http"


def test_https_port_uses_https_scheme(monkeypatch):
    """Port 443 must use 'https' as the scheme in evidence."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api": _resp(200, _JUPYTER_API_BODY),
        "/api/kernels": _resp(200, _KERNELS_EMPTY_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    target = Target(host="10.0.0.90", ports={443: {"state": "open", "name": "https"}})
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["scheme"] == "https"
    assert finding.evidence["port"] == 443
