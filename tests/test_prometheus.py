"""Tests for the Prometheus unauthenticated HTTP API probe (MIASMA-PROMETHEUS-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention established in
tests/test_solr.py and tests/test_grafana.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_prometheus_001"

# --- canned response bodies -------------------------------------------------

_BUILDINFO_BODY = (
    '{"status":"success","data":{"version":"2.53.0",'
    '"revision":"abcd1234","branch":"HEAD","buildUser":"root@host",'
    '"goVersion":"go1.22.4"}}'
)
_TARGETS_BODY = (
    '{"status":"success","data":{"activeTargets":['
    '{"scrapeUrl":"http://10.0.0.5:9100/metrics","health":"up"},'
    '{"scrapeUrl":"http://10.0.0.6:9100/metrics","health":"up"}],'
    '"droppedTargets":[]}}'
)
_TARGETS_EMPTY_BODY = (
    '{"status":"success","data":{"activeTargets":[],"droppedTargets":[]}}'
)
_CONFIG_WITH_CREDS_BODY = (
    '{"status":"success","data":{"yaml":'
    '"scrape_configs:\\n- job_name: secured\\n  basic_auth:\\n'
    '    password: hunter2\\n"}}'
)
_CONFIG_NO_CREDS_BODY = (
    '{"status":"success","data":{"yaml":'
    '"global:\\n  scrape_interval: 15s\\nscrape_configs:\\n'
    '- job_name: node\\n"}}'
)
_NOT_PROM_BUILDINFO = '{"status":"success","data":{"foo":"bar"}}'


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
    """Single open Prometheus port keeps the probe surface deterministic."""
    return Target(host="10.0.0.40", ports={9090: {"state": "open", "name": "prometheus"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-PROMETHEUS-001"
    assert module.metadata["name"] == "Prometheus Unauthenticated HTTP API Access"
    assert 9090 in module.metadata["port_hint"]
    assert 9090 in module.metadata["default_ports"]
    assert callable(module.probe)


# --- credential leak via config (HIGH) --------------------------------------


def test_config_credential_leak_is_high(monkeypatch):
    """buildinfo OK + /status/config leaks a password => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, _BUILDINFO_BODY),
        "/api/v1/targets": _resp(200, _TARGETS_BODY),
        "/api/v1/status/config": _resp(200, _CONFIG_WITH_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-PROMETHEUS-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.40"
    assert finding.evidence["api_unauthenticated"] is True
    assert finding.evidence["port"] == 9090
    assert finding.evidence["version"] == "2.53.0"
    assert finding.evidence["config_leaks_credentials"] is True
    assert finding.evidence["active_target_count"] == 2


def test_config_yaml_is_not_stored_in_evidence(monkeypatch):
    """The raw config YAML must never be copied into the finding evidence."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, _BUILDINFO_BODY),
        "/api/v1/targets": _resp(200, _TARGETS_BODY),
        "/api/v1/status/config": _resp(200, _CONFIG_WITH_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    serialized = str(finding.to_dict())
    assert "hunter2" not in serialized
    assert "yaml" not in finding.evidence


# --- target inventory (HIGH) ------------------------------------------------


def test_target_enumeration_is_high(monkeypatch):
    """buildinfo OK + /targets lists active targets, config has no creds => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, _BUILDINFO_BODY),
        "/api/v1/targets": _resp(200, _TARGETS_BODY),
        "/api/v1/status/config": _resp(200, _CONFIG_NO_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["targets_exposed"] is True
    assert finding.evidence["active_target_count"] == 2
    assert finding.evidence["config_leaks_credentials"] is False


def test_target_enumeration_high_even_when_config_gated(monkeypatch):
    """Targets readable but config 401 => still HIGH on the inventory leak."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, _BUILDINFO_BODY),
        "/api/v1/targets": _resp(200, _TARGETS_BODY),
        "/api/v1/status/config": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["active_target_count"] == 2
    assert "config_readable" not in finding.evidence


# --- partial / empty surface (MEDIUM) ---------------------------------------


def test_empty_targets_is_medium(monkeypatch):
    """Targets endpoint readable but empty, no creds => MEDIUM."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, _BUILDINFO_BODY),
        "/api/v1/targets": _resp(200, _TARGETS_EMPTY_BODY),
        "/api/v1/status/config": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["active_target_count"] == 0


def test_only_buildinfo_readable_is_medium(monkeypatch):
    """buildinfo answers but targets + config are auth-gated => MEDIUM."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, _BUILDINFO_BODY),
        "/api/v1/targets": _resp(401),
        "/api/v1/status/config": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version"] == "2.53.0"
    assert "active_target_count" not in finding.evidence


# --- not Prometheus / not vulnerable ----------------------------------------


def test_buildinfo_present_but_not_prometheus_is_no_finding(monkeypatch):
    """A success buildinfo lacking the Prometheus keys => not Prometheus => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/v1/status/buildinfo": _resp(200, _NOT_PROM_BUILDINFO)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_buildinfo_non_200_is_no_finding(monkeypatch):
    """/api/v1/status/buildinfo returns 401 (auth-gated) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/v1/status/buildinfo": _resp(401)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_no_followup_requests_without_prometheus_fingerprint(monkeypatch):
    """The targets/config requests must NOT fire against a non-Prometheus service."""
    module = load_plugin(PLUGIN)
    requested: list = []
    path_map = {"/api/v1/status/buildinfo": _resp(200, _NOT_PROM_BUILDINFO)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    module.probe(_target())

    assert not any("/api/v1/targets" in url for url in requested)
    assert not any("/api/v1/status/config" in url for url in requested)


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


# --- port fallback ----------------------------------------------------------


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [9090, 80, 443, 8080, 9091]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.41"))  # no ports key → default_ports

    assert 9090 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports
    assert 8080 in contacted_ports
    assert 9091 in contacted_ports


def test_https_scheme_used_for_port_443(monkeypatch):
    """Port 443 is contacted over HTTPS; other ports over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.42"))  # no recon → default ports

    assert any(u.startswith("https://10.0.0.42:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.42:9090/") for u in urls)


# --- version parsing edge cases ---------------------------------------------


def test_missing_version_does_not_break_finding(monkeypatch):
    """A buildinfo body with the required keys but empty version still works."""
    module = load_plugin(PLUGIN)
    buildinfo_no_version = (
        '{"status":"success","data":{"version":"","revision":"x",'
        '"goVersion":"go1.22"}}'
    )
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, buildinfo_no_version),
        "/api/v1/targets": _resp(200, _TARGETS_BODY),
        "/api/v1/status/config": _resp(200, _CONFIG_NO_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version"] is None


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/v1/status/buildinfo": _resp(200, _BUILDINFO_BODY),
        "/api/v1/targets": _resp(200, _TARGETS_BODY),
        "/api/v1/status/config": _resp(200, _CONFIG_NO_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-PROMETHEUS-001"
    assert findings[0].confidence == "high"
