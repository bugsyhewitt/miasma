"""Tests for the Elasticsearch unauthenticated access probe (MIASMA-ELASTIC-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path (and,
for the auth tests, by the ``auth`` kwarg). This mirrors the project's
mock-at-the-seam convention established in tests/test_actuator.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_elastic_001"

# --- helpers ----------------------------------------------------------------

_ES_ROOT_BODY = (
    '{"name":"es-node-1","cluster_name":"my-cluster",'
    '"tagline":"You Know, for Search"}'
)
_CAT_INDICES_BODY = (
    "health status index uuid pri rep docs.count\n"
    "green  open   .kibana abc123  1   0       11\n"
    "yellow open   logs    def456  5   1    12345\n"
)


def _resp(status: int, body: str = "", headers: dict | None = None) -> httpx.Response:
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    content = body.encode()
    return httpx.Response(
        status_code=status,
        content=content,
        headers=headers or {},
        request=request,
    )


def _make_fake_get(
    path_map: dict[str, httpx.Response],
    auth_map: dict[tuple[str, str], httpx.Response] | None = None,
    record: list | None = None,
):
    """Return a fake httpx.get routing by path (and optionally by auth tuple).

    ``auth_map`` maps ``(username, password)`` to a response; used to simulate
    the default-credential probe path. If ``auth`` is provided but not in
    ``auth_map``, the function returns a 401. Paths not in ``path_map`` yield 404.
    """

    def fake_get(url, *args, auth=None, **kwargs):
        if record is not None:
            record.append((url, auth))
        if auth is not None and auth_map is not None:
            return auth_map.get(auth, _resp(401))
        if auth is not None:
            return _resp(401)
        path = urlparse(url).path or "/"
        # Root path normalisation: "" or "/" both hit the "" key or "/" key.
        return path_map.get(path, path_map.get("/", _resp(404)))

    return fake_get


def _target() -> Target:
    """Single open ES port keeps the probe surface small and deterministic."""
    return Target(
        host="10.0.0.10",
        ports={9200: {"state": "open", "name": "elasticsearch"}},
    )


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-ELASTIC-001"
    assert module.metadata["name"] == "Elasticsearch Unauthenticated Access"
    assert 9200 in module.metadata["default_ports"]
    assert 9201 in module.metadata["default_ports"]
    assert 9300 in module.metadata["default_ports"]
    assert callable(module.probe)


# --- open access (no auth) --------------------------------------------------


def test_open_access_returns_high_finding(monkeypatch):
    """Root responds 200 with 'You Know, for Search' => HIGH, open_access=True."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _ES_ROOT_BODY),
        "/_cat/indices": _resp(404),  # no indices endpoint
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-ELASTIC-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.10"
    assert finding.evidence["open_access"] is True
    assert finding.evidence["port"] == 9200


def test_open_access_with_indices_exposed(monkeypatch):
    """Open access + /_cat/indices?v listing => open_access + indices_exposed."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _ES_ROOT_BODY),
        "/_cat/indices": _resp(200, _CAT_INDICES_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["open_access"] is True
    assert finding.evidence.get("indices_exposed") is True
    assert "indices_preview" in finding.evidence


def test_no_es_signature_is_no_finding(monkeypatch):
    """200 response without 'You Know, for Search' => not Elasticsearch => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(200, '{"status":"ok"}')}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_non_200_non_401_is_no_finding(monkeypatch):
    """Port responds with 403 (not ES open, not 401) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(403)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- default credentials (401 path) -----------------------------------------


def test_default_creds_elastic_changeme_is_critical(monkeypatch):
    """401 root + elastic:changeme accepted => CRITICAL, default_creds=True."""
    module = load_plugin(PLUGIN)
    auth_map = {
        ("elastic", "changeme"): _resp(200, _ES_ROOT_BODY),
    }
    path_map = {"/": _resp(401)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, auth_map=auth_map)
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "critical"
    assert finding.evidence["default_creds"] is True
    assert finding.evidence["matched_user"] == "elastic"


def test_default_creds_admin_elasticadmin_is_critical(monkeypatch):
    """401 root + admin:elasticadmin accepted => CRITICAL, default_creds=True."""
    module = load_plugin(PLUGIN)
    auth_map = {
        ("elastic", "changeme"): _resp(401),  # first pair fails
        ("admin", "elasticadmin"): _resp(200, _ES_ROOT_BODY),
    }
    path_map = {"/": _resp(401)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, auth_map=auth_map)
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "critical"
    assert finding.evidence["default_creds"] is True
    assert finding.evidence["matched_user"] == "admin"


def test_auth_enforced_no_default_creds_is_no_finding(monkeypatch):
    """401 root + all default creds rejected => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(401)}
    auth_map: dict = {}  # all auth attempts → 401 (fallback in fake_get)
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, auth_map=auth_map)
    )

    assert module.probe(_target()) is None


def test_both_default_cred_pairs_tried_on_401(monkeypatch):
    """Both credential pairs are tried when the first fails."""
    module = load_plugin(PLUGIN)
    tried_auth: list = []
    path_map = {"/": _resp(401)}
    auth_map: dict = {}  # all fail

    monkeypatch.setattr(
        module.httpx,
        "get",
        _make_fake_get(path_map, auth_map=auth_map, record=tried_auth),
    )
    module.probe(_target())

    auth_values = [auth for _, auth in tried_auth if auth is not None]
    assert ("elastic", "changeme") in auth_values
    assert ("admin", "elasticadmin") in auth_values


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


def test_probe_tries_9201_when_9200_fails(monkeypatch):
    """When port 9200 is unavailable, probe falls back to 9201."""
    module = load_plugin(PLUGIN)
    requested: list = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        if ":9200" in url:
            raise httpx.ConnectError("refused")
        # Port 9201 responds with open ES.
        return _resp(200, _ES_ROOT_BODY)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(Target(host="10.0.0.11"))  # no recon → default ports

    assert finding is not None
    assert finding.evidence["port"] == 9201


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [9200, 9201, 9300]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.12"))  # no ports key → default_ports

    assert 9200 in contacted_ports
    assert 9201 in contacted_ports
    assert 9300 in contacted_ports


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {"/": _resp(200, _ES_ROOT_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-ELASTIC-001"
    assert findings[0].confidence == "high"
