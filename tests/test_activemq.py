"""Tests for the Apache ActiveMQ default-credential / unauthenticated admin
console probe (MIASMA-ACTIVEMQ-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path
and optional auth parameter. Mirrors the project's mock-at-the-seam convention
established in tests/test_grafana.py / test_couchdb.py / test_influxdb.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_activemq_001"

# --- canned response bodies ---------------------------------------------------

# ActiveMQ admin console root (unauthenticated 200).
_ACTIVEMQ_ROOT_BODY = (
    "<!DOCTYPE html>\n"
    "<html><head><title>ActiveMQ Web Console</title></head>\n"
    "<body><h1>Welcome to ActiveMQ</h1></body></html>"
)

# A non-ActiveMQ 200 on / — must not be flagged.
_NOT_ACTIVEMQ_BODY = "<html><title>Apache Tomcat</title></html>"

# ActiveMQ Jolokia API BrokerName response.
_JOLOKIA_BROKER_BODY = (
    '{"request":{"mbean":"org.apache.activemq:type=Broker",'
    '"attribute":"BrokerName","type":"read"},'
    '"value":"localhost","timestamp":1700000000,"status":200}'
)

# Jolokia response with no "value" key — should not produce a finding.
_JOLOKIA_NO_VALUE_BODY = '{"status":200,"request":{}}'


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


def _make_fake_get(
    path_map: dict[str, httpx.Response],
    auth_map: dict[tuple[str, str], dict[str, httpx.Response]] | None = None,
    record: list | None = None,
):
    """Fake httpx.get that routes by path, with optional per-auth overrides."""

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path = urlparse(url).path or "/"
        auth = kwargs.get("auth")
        if auth is not None and auth_map is not None and auth in auth_map:
            return auth_map[auth].get(path, _resp(404))
        return path_map.get(path, _resp(404))

    return fake_get


def _target(port: int = 8161) -> Target:
    return Target(
        host="10.0.0.70", ports={port: {"state": "open", "name": "activemq"}}
    )


# --- discoverability ----------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-ACTIVEMQ-001"
    assert "ActiveMQ" in module.metadata["name"]
    assert 8161 in module.metadata["port_hint"]
    assert 8161 in module.metadata["default_ports"]
    assert "activemq" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- unauthenticated console (HIGH) ------------------------------------------


def test_unauthenticated_console_is_high(monkeypatch):
    """/ returns 200 + ActiveMQ marker without auth challenge => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-ACTIVEMQ-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.70"
    assert finding.evidence["auth_required"] is False
    assert finding.evidence["port"] == 8161


def test_unauthenticated_console_no_jolokia_attempt(monkeypatch):
    """When the console is open, no Jolokia request is made."""
    module = load_plugin(PLUGIN)
    contacted: list[str] = []
    path_map = {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=contacted)
    )

    module.probe(_target())

    jolokia_urls = [u for u in contacted if "jolokia" in u.lower()]
    assert jolokia_urls == [], (
        "expected no Jolokia request when console is already open"
    )


# --- default credentials (CRITICAL) ------------------------------------------


def test_default_creds_accepted_is_critical(monkeypatch):
    """/ returns 401 + admin:admin accepted => CRITICAL."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(401, headers={"WWW-Authenticate": "Basic realm=ActiveMQ"})}
    auth_map = {("admin", "admin"): {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, auth_map=auth_map)
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "critical"
    assert finding.evidence["auth_required"] is True
    assert finding.evidence["default_creds"] is True
    assert finding.evidence["matched_user"] == "admin"
    assert finding.evidence["port"] == 8161


def test_default_creds_rejected_is_no_finding(monkeypatch):
    """/ returns 401 + admin:admin also rejected + no Jolokia => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(401),
        module._JOLOKIA_PATH: _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_default_creds_rejected_no_activemq_marker_is_no_finding(monkeypatch):
    """/ returns 401 + admin:admin accepted but body has no ActiveMQ marker."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(401)}
    auth_map = {("admin", "admin"): {"/": _resp(200, _NOT_ACTIVEMQ_BODY)}}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, auth_map=auth_map)
    )

    assert module.probe(_target()) is None


# --- Jolokia API open (MEDIUM) ------------------------------------------------


def test_jolokia_open_is_medium(monkeypatch):
    """401 on /, creds rejected, but Jolokia API is open => MEDIUM."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(401),
        module._JOLOKIA_PATH: _resp(200, _JOLOKIA_BROKER_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["jolokia_open"] is True
    assert finding.evidence["broker_name"] == "localhost"
    assert finding.evidence["port"] == 8161


def test_jolokia_no_value_is_no_finding(monkeypatch):
    """Jolokia responds 200 but has no 'value' key => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(401),
        module._JOLOKIA_PATH: _resp(200, _JOLOKIA_NO_VALUE_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_jolokia_non_json_is_no_finding(monkeypatch):
    """Jolokia responds 200 with HTML => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(401),
        module._JOLOKIA_PATH: _resp(200, "<html>not json</html>"),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- false-positive guards ----------------------------------------------------


def test_non_activemq_200_is_no_finding(monkeypatch):
    """A 200 with no ActiveMQ marker in the body => not ActiveMQ => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _NOT_ACTIVEMQ_BODY),
        module._JOLOKIA_PATH: _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_404_root_is_no_finding(monkeypatch):
    """A 404 on / => not ActiveMQ => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(404)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_redirect_root_is_no_finding(monkeypatch):
    """A 302 on / (auth gateway) with no ActiveMQ probe path => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(302, headers={"location": "/login"}),
        module._JOLOKIA_PATH: _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- connection / timeout errors ----------------------------------------------


def test_connection_error_is_no_finding(monkeypatch):
    module = load_plugin(PLUGIN)

    def boom(url, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(module.httpx, "get", boom)

    assert module.probe(_target()) is None


def test_timeout_is_no_finding(monkeypatch):
    module = load_plugin(PLUGIN)

    def timeout(url, *args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(module.httpx, "get", timeout)

    assert module.probe(_target()) is None


# --- port fallback / scheme ---------------------------------------------------


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [8161, 80, 443, 8080]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.71"))

    assert 8161 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports
    assert 8080 in contacted_ports


def test_https_scheme_used_for_port_443(monkeypatch):
    """Port 443 is contacted over HTTPS; 8161/80/8080 over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.72"))

    assert any(u.startswith("https://10.0.0.72:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.72:8161/") for u in urls)
    assert any(u.startswith("http://10.0.0.72:80/") for u in urls)
    assert any(u.startswith("http://10.0.0.72:8080/") for u in urls)


def test_default_port_8161_used_first(monkeypatch):
    """8161 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="h"))

    assert contacted_ports[0] == 8161


def test_recon_service_name_activemq_is_probed(monkeypatch):
    """A non-default port marked as activemq in recon is probed."""
    module = load_plugin(PLUGIN)
    contacted: list[str] = []
    path_map = {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=contacted)
    )

    target = Target(
        host="10.0.0.73",
        ports={18161: {"state": "open", "name": "activemq"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 18161
    assert contacted[0].startswith("http://10.0.0.73:18161/")


# --- evidence constraints -----------------------------------------------------


def test_critical_finding_evidence_shape(monkeypatch):
    """CRITICAL finding evidence keys are exactly the expected set."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(401)}
    auth_map = {("admin", "admin"): {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, auth_map=auth_map)
    )

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {"host", "port", "url", "auth_required", "default_creds", "matched_user"}
    assert set(finding.evidence.keys()) == allowed_keys


def test_high_finding_evidence_shape(monkeypatch):
    """HIGH finding evidence keys are exactly the expected set."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {"host", "port", "url", "auth_required"}
    assert set(finding.evidence.keys()) == allowed_keys


def test_finding_evidence_never_leaks_password(monkeypatch):
    """Evidence must never contain the credential password."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(401)}
    auth_map = {("admin", "admin"): {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, auth_map=auth_map)
    )

    finding = module.probe(_target())

    assert finding is not None
    serialised = repr(finding.evidence)
    # The matched_user key stores the username, not the password.
    assert "admin" in serialised  # username is OK in evidence
    # But the PASSWORD itself must never appear in a dedicated "password" key.
    assert "password" not in finding.evidence
    assert "matched_pass" not in finding.evidence


# --- runner integration -------------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(200, _ACTIVEMQ_ROOT_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-ACTIVEMQ-001"
    assert findings[0].confidence == "high"
