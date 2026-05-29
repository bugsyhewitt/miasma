"""Tests for the Grafana unauthenticated / default-credential probe
(MIASMA-GRAFANA-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` and
``httpx.post`` on the plugin module and route each request to a canned response
keyed by URL path. This mirrors the project's mock-at-the-seam convention
established in tests/test_elastic.py and tests/test_actuator.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_grafana_001"

# --- canned response bodies -------------------------------------------------

_HEALTH_BODY = '{"commit":"abc1234","database":"ok","version":"10.4.0"}'
_ORG_BODY = '{"id":1,"name":"Main Org."}'
_NOT_GRAFANA_HEALTH = '{"status":"ok"}'


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


def _make_fake_post(
    login_resp: httpx.Response, record: list | None = None
):
    """Return a fake httpx.post answering the /login attempt with login_resp."""

    def fake_post(url, *args, json=None, **kwargs):
        if record is not None:
            record.append((url, json))
        if urlparse(url).path == "/login":
            return login_resp
        return _resp(404)

    return fake_post


def _target() -> Target:
    """Single open Grafana port keeps the probe surface deterministic."""
    return Target(host="10.0.0.20", ports={3000: {"state": "open", "name": "grafana"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-GRAFANA-001"
    assert module.metadata["name"] == "Grafana Unauthenticated / Default-Credential Access"
    assert 3000 in module.metadata["port_hint"]
    assert 3000 in module.metadata["default_ports"]
    assert callable(module.probe)


# --- default credentials (CRITICAL) -----------------------------------------


def test_default_creds_admin_admin_is_critical(monkeypatch):
    """Grafana health OK + admin:admin login 200 => CRITICAL, default_creds=True."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/health": _resp(200, _HEALTH_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(module.httpx, "post", _make_fake_post(_resp(200)))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-GRAFANA-001"
    assert finding.confidence == "critical"
    assert finding.host == "10.0.0.20"
    assert finding.evidence["default_creds"] is True
    assert finding.evidence["matched_user"] == "admin"
    assert finding.evidence["port"] == 3000
    assert finding.evidence["version"] == "10.4.0"


def test_default_creds_login_attempts_factory_pair(monkeypatch):
    """The single attempted login uses the documented admin:admin pair only."""
    module = load_plugin(PLUGIN)
    posted: list = []
    path_map = {"/api/health": _resp(200, _HEALTH_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(
        module.httpx, "post", _make_fake_post(_resp(200), record=posted)
    )

    module.probe(_target())

    bodies = [body for _, body in posted]
    assert {"user": "admin", "password": "admin"} in bodies
    # Exactly one credential pair attempted — this is not a brute force.
    assert len(bodies) == 1


# --- anonymous access (HIGH) ------------------------------------------------


def test_anonymous_org_is_high(monkeypatch):
    """Default login fails (401) but /api/org returns org => HIGH, anon=True."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/health": _resp(200, _HEALTH_BODY),
        "/api/org": _resp(200, _ORG_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(module.httpx, "post", _make_fake_post(_resp(401)))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["anonymous_access"] is True
    assert finding.evidence["org_name"] == "Main Org."
    assert finding.evidence["version"] == "10.4.0"


def test_default_creds_take_precedence_over_anonymous(monkeypatch):
    """When both default creds AND anonymous access exist, CRITICAL wins."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/health": _resp(200, _HEALTH_BODY),
        "/api/org": _resp(200, _ORG_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(module.httpx, "post", _make_fake_post(_resp(200)))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "critical"
    assert finding.evidence["default_creds"] is True


# --- auth enforced / not vulnerable -----------------------------------------


def test_auth_enforced_is_no_finding(monkeypatch):
    """Grafana fingerprinted but login 401 and /api/org 401 => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/health": _resp(200, _HEALTH_BODY),
        "/api/org": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(module.httpx, "post", _make_fake_post(_resp(401)))

    assert module.probe(_target()) is None


def test_health_present_but_not_grafana_is_no_finding(monkeypatch):
    """A 200 /api/health lacking the Grafana keys => not Grafana => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/health": _resp(200, _NOT_GRAFANA_HEALTH)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(module.httpx, "post", _make_fake_post(_resp(200)))

    # Even if a login would 200, we never reach it without a Grafana fingerprint.
    assert module.probe(_target()) is None


def test_health_non_200_is_no_finding(monkeypatch):
    """/api/health returns 404 (not Grafana on this port) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/health": _resp(404)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(module.httpx, "post", _make_fake_post(_resp(200)))

    assert module.probe(_target()) is None


def test_no_login_attempt_without_grafana_fingerprint(monkeypatch):
    """Default-credential POST must NOT fire against a non-Grafana service."""
    module = load_plugin(PLUGIN)
    posted: list = []
    path_map = {"/api/health": _resp(200, _NOT_GRAFANA_HEALTH)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(
        module.httpx, "post", _make_fake_post(_resp(200), record=posted)
    )

    module.probe(_target())

    assert posted == []  # never attempted a login against a non-Grafana host


# --- connection / timeout errors --------------------------------------------


def test_connection_error_is_no_finding(monkeypatch):
    """A socket error on every candidate port => no finding, no exception."""
    module = load_plugin(PLUGIN)

    def boom(url, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(module.httpx, "get", boom)
    monkeypatch.setattr(module.httpx, "post", boom)

    assert module.probe(_target()) is None


def test_timeout_is_no_finding(monkeypatch):
    """A timeout on every candidate port => no finding, no exception raised."""
    module = load_plugin(PLUGIN)

    def timeout(url, *args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(module.httpx, "get", timeout)
    monkeypatch.setattr(module.httpx, "post", timeout)

    assert module.probe(_target()) is None


# --- port fallback ----------------------------------------------------------


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [3000, 80, 443, 8080]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.httpx, "post", fake_get)

    module.probe(Target(host="10.0.0.21"))  # no ports key → default_ports

    assert 3000 in contacted_ports
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
    monkeypatch.setattr(module.httpx, "post", fake_get)

    module.probe(Target(host="10.0.0.22"))  # no recon → default ports

    assert any(u.startswith("https://10.0.0.22:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.22:3000/") for u in urls)


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/health": _resp(200, _HEALTH_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))
    monkeypatch.setattr(module.httpx, "post", _make_fake_post(_resp(200)))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-GRAFANA-001"
    assert findings[0].confidence == "critical"
