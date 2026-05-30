"""Tests for the InfluxDB unauthenticated HTTP API exposure probe
(MIASMA-INFLUXDB-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path.
Mirrors the project's mock-at-the-seam convention established in
tests/test_kibana.py / test_grafana.py / test_solr.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_influxdb_001"

# --- canned response bodies -------------------------------------------------

# InfluxDB 2.x /health — name == "influxdb" plus a parseable version.
_INFLUXDB_2X_HEALTH_BODY = (
    '{"name":"influxdb","message":"ready for queries and writes",'
    '"status":"pass","version":"2.7.5","commit":"abc1234"}'
)

# InfluxDB 2.x /api/v2/setup — uninitialised: any peer can claim the admin
# token. This is the HIGH-severity 2.x condition.
_INFLUXDB_2X_SETUP_ALLOWED_BODY = '{"allowed":true}'

# InfluxDB 2.x /api/v2/setup — already initialised; clean negative.
_INFLUXDB_2X_SETUP_DISALLOWED_BODY = '{"allowed":false}'

# InfluxDB 1.x /query?q=SHOW DATABASES — privileged metadata answered with no
# credential. The values array carries the cluster-wide database inventory.
_INFLUXDB_1X_SHOW_DATABASES_BODY = (
    '{"results":[{"statement_id":0,"series":[{"name":"databases",'
    '"columns":["name"],"values":[["_internal"],["telegraf"],["app_metrics"]]}]}]}'
)

# A non-InfluxDB JSON 200 on /health — must not be flagged as InfluxDB.
_NOT_INFLUXDB_HEALTH_BODY = '{"status":"ok","service":"other"}'

# A JSON 200 with the right shape but the wrong product name.
_WRONG_NAME_HEALTH_BODY = '{"name":"telegraf","version":"1.28.0","status":"pass"}'


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
    record: list | None = None,
):
    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path_with_query = urlparse(url).path or "/"
        # /query carries a query string but routing by path alone is enough.
        return path_map.get(path_with_query, _resp(404))

    return fake_get


def _target() -> Target:
    return Target(
        host="10.0.0.50", ports={8086: {"state": "open", "name": "influxdb"}}
    )


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-INFLUXDB-001"
    assert (
        module.metadata["name"]
        == "InfluxDB Unauthenticated HTTP API Exposure"
    )
    assert 8086 in module.metadata["port_hint"]
    assert 8086 in module.metadata["default_ports"]
    assert "influxdb" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- InfluxDB 2.x: setup allowed (HIGH) -------------------------------------


def test_2x_setup_allowed_is_high(monkeypatch):
    """2.x /health fingerprints AND /api/v2/setup => allowed:true => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(200, _INFLUXDB_2X_HEALTH_BODY),
        "/api/v2/setup": _resp(200, _INFLUXDB_2X_SETUP_ALLOWED_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-INFLUXDB-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.50"
    assert finding.evidence["influxdb_major"] == "2.x"
    assert finding.evidence["influxdb_version"] == "2.7.5"
    assert finding.evidence["setup_allowed"] is True
    assert finding.evidence["port"] == 8086
    assert finding.evidence["commit"] == "abc1234"


def test_2x_setup_disallowed_is_no_finding(monkeypatch):
    """2.x fingerprints but allowed:false => already initialised => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(200, _INFLUXDB_2X_HEALTH_BODY),
        "/api/v2/setup": _resp(200, _INFLUXDB_2X_SETUP_DISALLOWED_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_2x_setup_401_is_no_finding(monkeypatch):
    """2.x fingerprints but /api/v2/setup refused => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(200, _INFLUXDB_2X_HEALTH_BODY),
        "/api/v2/setup": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- InfluxDB 1.x: SHOW DATABASES (HIGH) ------------------------------------


def test_1x_show_databases_is_high(monkeypatch):
    """1.x /ping fingerprints AND /query returns inventory => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        # /health: no 2.x fingerprint (404)
        "/health": _resp(404),
        # /ping: 204 with X-Influxdb-Version header → 1.x fingerprint
        "/ping": _resp(
            204,
            headers={
                "x-influxdb-version": "1.8.10",
                "x-influxdb-build": "OSS",
            },
        ),
        "/query": _resp(200, _INFLUXDB_1X_SHOW_DATABASES_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-INFLUXDB-001"
    assert finding.confidence == "high"
    assert finding.evidence["influxdb_major"] == "1.x"
    assert finding.evidence["influxdb_version"] == "1.8.10"
    assert finding.evidence["database_count"] == 3
    assert finding.evidence["build"] == "OSS"
    assert finding.evidence["port"] == 8086


def test_1x_ping_200_verbose_is_high(monkeypatch):
    """1.x /ping?verbose=true answers 200 with the version header; still HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(404),
        "/ping": _resp(200, headers={"x-influxdb-version": "1.7.11"}),
        "/query": _resp(200, _INFLUXDB_1X_SHOW_DATABASES_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.evidence["influxdb_major"] == "1.x"
    assert finding.evidence["influxdb_version"] == "1.7.11"
    # No X-Influxdb-Build header in this reply — must simply be omitted.
    assert "build" not in finding.evidence


def test_1x_query_401_is_no_finding(monkeypatch):
    """1.x /ping fingerprints but /query refused (auth enabled) => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(404),
        "/ping": _resp(204, headers={"x-influxdb-version": "1.8.10"}),
        "/query": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_1x_query_empty_series_is_no_finding(monkeypatch):
    """A /query 200 without the expected series shape is not flagged."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(404),
        "/ping": _resp(204, headers={"x-influxdb-version": "1.8.10"}),
        "/query": _resp(200, '{"results":[{"error":"unauthorized"}]}'),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- false-positive guards --------------------------------------------------


def test_non_influxdb_health_is_no_finding(monkeypatch):
    """A 200 JSON without name=='influxdb' AND no /ping header => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(200, _NOT_INFLUXDB_HEALTH_BODY),
        "/ping": _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_wrong_product_name_is_no_finding(monkeypatch):
    """A /health body for a different product (e.g. telegraf) => not flagged."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(200, _WRONG_NAME_HEALTH_BODY),
        "/ping": _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_ping_without_version_header_is_no_finding(monkeypatch):
    """/ping that answers but lacks X-Influxdb-Version => not InfluxDB => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(404),
        # 204 No Content but no Influx-specific header — not InfluxDB.
        "/ping": _resp(204),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_html_200_health_is_no_finding(monkeypatch):
    """A 200 with HTML body on /health => not InfluxDB => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(200, "<html><body>hello</body></html>"),
        "/ping": _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_redirect_on_health_is_no_finding(monkeypatch):
    """A 302 on /health (auth gateway in front) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(302, headers={"location": "/login"}),
        "/ping": _resp(404),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- connection / timeout errors --------------------------------------------


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


# --- port fallback / scheme -------------------------------------------------


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [8086, 8087, 80, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.51"))

    assert 8086 in contacted_ports
    assert 8087 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports


def test_https_scheme_used_for_tls_port(monkeypatch):
    """Port 443 contacted over HTTPS; 8086 / 8087 / 80 over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.52"))

    assert any(u.startswith("https://10.0.0.52:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.52:8086/") for u in urls)
    assert any(u.startswith("http://10.0.0.52:8087/") for u in urls)
    assert any(u.startswith("http://10.0.0.52:80/") for u in urls)


def test_default_port_8086_used_first(monkeypatch):
    """8086 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="h"))

    assert contacted_ports[0] == 8086


def test_recon_service_name_matches_influx(monkeypatch):
    """A non-default port marked as an influxdb service in recon is probed."""
    module = load_plugin(PLUGIN)
    contacted: list = []
    path_map = {
        "/health": _resp(200, _INFLUXDB_2X_HEALTH_BODY),
        "/api/v2/setup": _resp(200, _INFLUXDB_2X_SETUP_ALLOWED_BODY),
    }
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=contacted)
    )

    target = Target(
        host="10.0.0.53",
        ports={18086: {"state": "open", "name": "influxdb"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 18086
    assert contacted[0].startswith("http://10.0.0.53:18086/")


# --- evidence redaction -----------------------------------------------------


def test_finding_evidence_never_contains_inventory(monkeypatch):
    """Evidence keys are strictly the allowlist — never database names."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(404),
        "/ping": _resp(
            204,
            headers={
                "x-influxdb-version": "1.8.10",
                "x-influxdb-build": "OSS",
            },
        ),
        "/query": _resp(200, _INFLUXDB_1X_SHOW_DATABASES_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {
        "host",
        "port",
        "influxdb_major",
        "influxdb_version",
        "database_count",
        "setup_allowed",
        "build",
        "commit",
    }
    assert set(finding.evidence.keys()).issubset(allowed_keys)
    # Sanity: the actual database names from the canned body must not leak.
    serialised = repr(finding.evidence)
    assert "_internal" not in serialised
    assert "telegraf" not in serialised
    assert "app_metrics" not in serialised


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/health": _resp(200, _INFLUXDB_2X_HEALTH_BODY),
        "/api/v2/setup": _resp(200, _INFLUXDB_2X_SETUP_ALLOWED_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-INFLUXDB-001"
    assert findings[0].confidence == "high"
