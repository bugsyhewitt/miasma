"""Tests for the Consul unauthenticated HTTP API probe (MIASMA-CONSUL-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention established in
tests/test_prometheus.py and tests/test_grafana.py.
"""

from __future__ import annotations

import base64
from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_consul_001"

# --- canned response bodies -------------------------------------------------

_AGENT_SELF_BODY = (
    '{"Config":{"Datacenter":"dc1","NodeName":"node-1","Version":"1.18.1"},'
    '"Member":{"Name":"node-1","Addr":"10.0.0.40",'
    '"Tags":{"build":"1.18.1:abc1234","dc":"dc1"}}}'
)
_AGENT_SELF_NO_VERSION = (
    '{"Config":{"Datacenter":"dc1","NodeName":"node-1"},'
    '"Member":{"Name":"node-1","Tags":{"build":"1.17.0:deadbeef"}}}'
)
_AGENT_SELF_NO_VERSION_ANYWHERE = (
    '{"Config":{"Datacenter":"dc1"},"Member":{"Name":"node-1","Tags":{}}}'
)
_NOT_CONSUL_BODY = '{"foo":"bar","baz":123}'

_SERVICES_BODY = '{"consul":[],"web":["v1","canary"],"postgres":["primary"]}'
_SERVICES_EMPTY_BODY = "{}"


def _kv_entry(key: str, value: str) -> str:
    encoded = base64.b64encode(value.encode()).decode()
    return (
        '{"LockIndex":0,"Key":"' + key + '","Flags":0,'
        '"Value":"' + encoded + '","CreateIndex":1,"ModifyIndex":1}'
    )


_KV_WITH_CREDS_BODY = "[" + _kv_entry("app/db/password", "hunter2") + "]"
_KV_CRED_IN_KEYNAME_BODY = "[" + _kv_entry("services/api_key", "ZZZ") + "]"
_KV_NO_CREDS_BODY = "[" + _kv_entry("app/feature/enabled", "true") + "]"


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
    """Single open Consul port keeps the probe surface deterministic."""
    return Target(host="10.0.0.40", ports={8500: {"state": "open", "name": "consul"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-CONSUL-001"
    assert module.metadata["name"] == "Consul Unauthenticated HTTP API Access"
    assert 8500 in module.metadata["port_hint"]
    assert 8500 in module.metadata["default_ports"]
    assert callable(module.probe)


# --- credential leak via KV (HIGH) ------------------------------------------


def test_kv_credential_leak_is_high(monkeypatch):
    """agent/self OK + /v1/kv leaks a password value => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(200, _SERVICES_BODY),
        "/v1/kv/": _resp(200, _KV_WITH_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-CONSUL-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.40"
    assert finding.evidence["api_unauthenticated"] is True
    assert finding.evidence["port"] == 8500
    assert finding.evidence["version"] == "1.18.1"
    assert finding.evidence["kv_leaks_credentials"] is True
    assert finding.evidence["service_count"] == 3


def test_kv_credential_marker_in_key_name_is_high(monkeypatch):
    """A credential marker in the KV key path (not value) still escalates."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(401),
        "/v1/kv/": _resp(200, _KV_CRED_IN_KEYNAME_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["kv_leaks_credentials"] is True


def test_kv_value_is_not_stored_in_evidence(monkeypatch):
    """The decoded KV value must never be copied into the finding evidence."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(200, _SERVICES_BODY),
        "/v1/kv/": _resp(200, _KV_WITH_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    serialized = str(finding.to_dict())
    assert "hunter2" not in serialized
    assert "Value" not in finding.evidence
    assert "kv" not in str(finding.evidence.get("kv_value", ""))


# --- service catalog (HIGH) -------------------------------------------------


def test_catalog_enumeration_is_high(monkeypatch):
    """agent/self OK + catalog lists services, KV has no creds => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(200, _SERVICES_BODY),
        "/v1/kv/": _resp(200, _KV_NO_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["services_exposed"] is True
    assert finding.evidence["service_count"] == 3
    assert finding.evidence["kv_leaks_credentials"] is False


def test_catalog_enumeration_high_even_when_kv_gated(monkeypatch):
    """Catalog readable but KV 403 => still HIGH on the inventory leak."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(200, _SERVICES_BODY),
        "/v1/kv/": _resp(403),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["service_count"] == 3
    assert "kv_readable" not in finding.evidence


# --- partial / empty surface (MEDIUM) ---------------------------------------


def test_empty_catalog_is_medium(monkeypatch):
    """Catalog endpoint readable but empty, no KV creds => MEDIUM."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(200, _SERVICES_EMPTY_BODY),
        "/v1/kv/": _resp(403),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["service_count"] == 0


def test_only_agent_self_readable_is_medium(monkeypatch):
    """agent/self answers but catalog + KV are token-gated => MEDIUM."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(403),
        "/v1/kv/": _resp(403),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version"] == "1.18.1"
    assert "service_count" not in finding.evidence


# --- not Consul / not vulnerable --------------------------------------------


def test_agent_self_present_but_not_consul_is_no_finding(monkeypatch):
    """A 200 body lacking the Config/Member keys => not Consul => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/v1/agent/self": _resp(200, _NOT_CONSUL_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_agent_self_non_200_is_no_finding(monkeypatch):
    """/v1/agent/self returns 403 (ACL token required) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/v1/agent/self": _resp(403)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_no_followup_requests_without_consul_fingerprint(monkeypatch):
    """The catalog/KV requests must NOT fire against a non-Consul service."""
    module = load_plugin(PLUGIN)
    requested: list = []
    path_map = {"/v1/agent/self": _resp(200, _NOT_CONSUL_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    module.probe(_target())

    assert not any("/v1/catalog/services" in url for url in requested)
    assert not any("/v1/kv/" in url for url in requested)


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
    """With no recon data the probe falls back to [8500, 80, 443, 8501]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.41"))  # no ports key → default_ports

    assert 8500 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports
    assert 8501 in contacted_ports


def test_https_scheme_used_for_tls_ports(monkeypatch):
    """Ports 443 and 8501 are contacted over HTTPS; 8500 over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.42"))  # no recon → default ports

    assert any(u.startswith("https://10.0.0.42:443/") for u in urls)
    assert any(u.startswith("https://10.0.0.42:8501/") for u in urls)
    assert any(u.startswith("http://10.0.0.42:8500/") for u in urls)


# --- version parsing edge cases ---------------------------------------------


def test_version_from_member_tags_build(monkeypatch):
    """When Config.Version is absent the version is read from Member.Tags.build."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_NO_VERSION),
        "/v1/catalog/services": _resp(200, _SERVICES_BODY),
        "/v1/kv/": _resp(200, _KV_NO_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version"] == "1.17.0"


def test_missing_version_does_not_break_finding(monkeypatch):
    """An agent/self with the required keys but no version still works."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/v1/agent/self": _resp(200, _AGENT_SELF_NO_VERSION_ANYWHERE),
        "/v1/catalog/services": _resp(200, _SERVICES_BODY),
        "/v1/kv/": _resp(200, _KV_NO_CREDS_BODY),
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
        "/v1/agent/self": _resp(200, _AGENT_SELF_BODY),
        "/v1/catalog/services": _resp(200, _SERVICES_BODY),
        "/v1/kv/": _resp(200, _KV_NO_CREDS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-CONSUL-001"
    assert findings[0].confidence == "high"
