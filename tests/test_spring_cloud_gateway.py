"""Tests for the Spring Cloud Gateway actuator probe (CVE-2025-41243).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (tests/test_env_exposure.py).
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2025_41243"

# --- canned bodies ----------------------------------------------------------

# A genuine Spring Cloud Gateway route table: a JSON array of route objects.
_ROUTE_TABLE = json.dumps(
    [
        {
            "route_id": "service-a",
            "uri": "lb://service-a",
            "predicate": "Paths: [/a/**]",
            "filters": [],
        },
        {
            "route_id": "service-b",
            "uri": "lb://service-b",
            "predicate": "Paths: [/b/**]",
            "filters": [],
        },
    ]
)
# The gateway actuator base: a JSON object listing sub-endpoints.
_GATEWAY_BASE = json.dumps(
    {
        "_links": {
            "self": {"href": "http://host/actuator/gateway"},
            "routes": {"href": "http://host/actuator/gateway/routes"},
        }
    }
)
_EMPTY_ROUTE_TABLE = json.dumps([])
_SPA_INDEX = "<!DOCTYPE html><html><body>app</body></html>"
_EMPTY = ""


def _resp(status: int, body: str = "", headers: dict | None = None) -> httpx.Response:
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    hdrs = {"content-type": "application/json"}
    if headers:
        hdrs.update(headers)
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers=hdrs,
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
    return Target(host="10.0.0.40", ports={8080: {"state": "open", "name": "http"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2025-41243"
    assert module.metadata["name"] == "Spring Cloud Gateway exposed actuator"
    assert 8080 in module.metadata["port_hint"]
    assert 8443 in module.metadata["port_hint"]
    assert callable(module.probe)


# --- exposed route table (HIGH) ---------------------------------------------


def test_exposed_route_table_returns_high_finding(monkeypatch):
    """/actuator/gateway/routes returns a JSON array => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {"/actuator/gateway/routes": _resp(200, _ROUTE_TABLE)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2025-41243"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.40"
    assert finding.evidence["path"] == "/actuator/gateway/routes"
    assert finding.evidence["url"] == "http://10.0.0.40:8080/actuator/gateway/routes"
    assert finding.evidence["route_count"] == 2
    assert finding.evidence["route_ids"] == ["service-a", "service-b"]


def test_empty_route_table_is_still_high(monkeypatch):
    """An empty-but-served route array still confirms the exposed surface."""
    module = load_plugin(PLUGIN)
    path_map = {"/actuator/gateway/routes": _resp(200, _EMPTY_ROUTE_TABLE)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["route_count"] == 0
    assert finding.evidence["route_ids"] == []


def test_route_id_fallback_to_id_field(monkeypatch):
    """Routes carrying `id` rather than `route_id` are still labelled."""
    module = load_plugin(PLUGIN)
    body = json.dumps([{"id": "legacy-route", "uri": "lb://legacy"}])
    path_map = {"/actuator/gateway/routes": _resp(200, body)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["route_ids"] == ["legacy-route"]


# --- gateway base only (MEDIUM) ---------------------------------------------


def test_gateway_base_only_returns_medium_finding(monkeypatch):
    """Route table blocked but /actuator/gateway base 200 JSON => MEDIUM."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/actuator/gateway/routes": _resp(401),
        "/actuator/gateway": _resp(200, _GATEWAY_BASE),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["path"] == "/actuator/gateway"
    assert "note" in finding.evidence


# --- false-positive guards --------------------------------------------------


def test_spa_index_html_routes_is_not_flagged(monkeypatch):
    """A 200 index.html (not JSON) for the routes path must NOT be flagged."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/actuator/gateway/routes": _resp(
            200, _SPA_INDEX, headers={"content-type": "text/html"}
        ),
        "/actuator/gateway": _resp(
            200, _SPA_INDEX, headers={"content-type": "text/html"}
        ),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_routes_json_object_is_not_high(monkeypatch):
    """A JSON *object* (not an array) at the routes path is not a route table.

    It falls through to the gateway-base check, which (also an object) => MEDIUM.
    """
    module = load_plugin(PLUGIN)
    obj_body = json.dumps({"unexpected": "shape"})
    path_map = {
        "/actuator/gateway/routes": _resp(200, obj_body),
        "/actuator/gateway": _resp(200, _GATEWAY_BASE),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"


def test_empty_200_body_is_not_flagged(monkeypatch):
    """A 200 with an empty body is neither array nor object => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/actuator/gateway/routes": _resp(200, _EMPTY),
        "/actuator/gateway": _resp(200, _EMPTY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_routes_404_and_gateway_404_is_no_finding(monkeypatch):
    """Both endpoints 404 => not exposed => no finding."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(module.httpx, "get", _make_fake_get({}))  # all 404

    assert module.probe(_target()) is None


def test_routes_401_no_gateway_base_is_no_finding(monkeypatch):
    """Routes 401 (auth required) and no gateway base => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/actuator/gateway/routes": _resp(401),
        "/actuator/gateway": _resp(401),
    }
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
    """Port 8443 is probed over https, not http."""
    module = load_plugin(PLUGIN)
    requested: list = []
    path_map = {"/actuator/gateway/routes": _resp(200, _ROUTE_TABLE)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    target = Target(host="10.0.0.41", ports={8443: {"state": "open", "name": "https"}})
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 8443
    assert any(u.startswith("https://10.0.0.41:8443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [8080, 8443, 80, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.42"))  # no ports key → default_ports

    assert 8080 in contacted_ports
    assert 8443 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {"/actuator/gateway/routes": _resp(200, _ROUTE_TABLE)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2025-41243"
    assert findings[0].confidence == "high"
