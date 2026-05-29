"""Tests for the Apache Solr unauthenticated Admin API probe (MIASMA-SOLR-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention established in
tests/test_grafana.py and tests/test_actuator.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_solr_001"

# --- canned response bodies -------------------------------------------------

_SYSTEM_BODY = (
    '{"responseHeader":{"status":0},'
    '"lucene":{"solr-spec-version":"9.4.0","lucene-spec-version":"9.8.0"},'
    '"jvm":{"version":"17.0.9"},"solr_home":"/var/solr/data"}'
)
_CORES_BODY = (
    '{"responseHeader":{"status":0},'
    '"status":{"products":{"name":"products"},"users":{"name":"users"}}}'
)
_CORES_EMPTY_BODY = '{"responseHeader":{"status":0},"status":{}}'
_NOT_SOLR_SYSTEM = '{"status":"ok"}'


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
    """Single open Solr port keeps the probe surface deterministic."""
    return Target(host="10.0.0.30", ports={8983: {"state": "open", "name": "solr"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-SOLR-001"
    assert module.metadata["name"] == "Apache Solr Unauthenticated Admin API Access"
    assert 8983 in module.metadata["port_hint"]
    assert 8983 in module.metadata["default_ports"]
    assert callable(module.probe)


# --- core enumeration (HIGH) ------------------------------------------------


def test_core_enumeration_is_high(monkeypatch):
    """Solr system OK + /admin/cores lists cores => HIGH, cores captured."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/solr/admin/info/system": _resp(200, _SYSTEM_BODY),
        "/solr/admin/cores": _resp(200, _CORES_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-SOLR-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.30"
    assert finding.evidence["admin_api_unauthenticated"] is True
    assert finding.evidence["port"] == 8983
    assert finding.evidence["version"] == "9.4.0"
    assert set(finding.evidence["cores"]) == {"products", "users"}
    assert finding.evidence["core_count"] == 2


def test_core_enumeration_empty_status_still_high(monkeypatch):
    """A 200 /admin/cores with an empty status object still proves unauth access."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/solr/admin/info/system": _resp(200, _SYSTEM_BODY),
        "/solr/admin/cores": _resp(200, _CORES_EMPTY_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["cores"] == []
    assert finding.evidence["core_count"] == 0


# --- partial Admin surface (MEDIUM) -----------------------------------------


def test_system_reachable_cores_gated_is_medium(monkeypatch):
    """system-info answers but /admin/cores is 401 => MEDIUM partial exposure."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/solr/admin/info/system": _resp(200, _SYSTEM_BODY),
        "/solr/admin/cores": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["system_info_reachable"] is True
    assert finding.evidence["version"] == "9.4.0"
    assert "cores" not in finding.evidence


# --- not Solr / not vulnerable ----------------------------------------------


def test_system_present_but_not_solr_is_no_finding(monkeypatch):
    """A 200 /admin/info/system lacking the Solr keys => not Solr => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/solr/admin/info/system": _resp(200, _NOT_SOLR_SYSTEM)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_system_non_200_is_no_finding(monkeypatch):
    """/admin/info/system returns 401 (auth-gated) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/solr/admin/info/system": _resp(401)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_no_cores_request_without_solr_fingerprint(monkeypatch):
    """The /admin/cores request must NOT fire against a non-Solr service."""
    module = load_plugin(PLUGIN)
    requested: list = []
    path_map = {"/solr/admin/info/system": _resp(200, _NOT_SOLR_SYSTEM)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    module.probe(_target())

    assert not any("/solr/admin/cores" in url for url in requested)


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
    """With no recon data the probe falls back to [8983, 8984, 80, 443, 8080]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.31"))  # no ports key → default_ports

    assert 8983 in contacted_ports
    assert 8984 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports
    assert 8080 in contacted_ports


def test_https_scheme_used_for_port_443(monkeypatch):
    """Port 443 is contacted over HTTPS; other ports over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.32"))  # no recon → default ports

    assert any(u.startswith("https://10.0.0.32:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.32:8983/") for u in urls)


# --- version parsing edge cases ---------------------------------------------


def test_missing_version_does_not_break_finding(monkeypatch):
    """A Solr system body without a spec-version still yields a finding."""
    module = load_plugin(PLUGIN)
    system_no_version = (
        '{"lucene":{"lucene-spec-version":"9.8.0"},"jvm":{"version":"17"}}'
    )
    path_map = {
        "/solr/admin/info/system": _resp(200, system_no_version),
        "/solr/admin/cores": _resp(200, _CORES_BODY),
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
        "/solr/admin/info/system": _resp(200, _SYSTEM_BODY),
        "/solr/admin/cores": _resp(200, _CORES_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-SOLR-001"
    assert findings[0].confidence == "high"
