"""Tests for the Kibana unauthenticated HTTP API exposure probe
(MIASMA-KIBANA-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path.
This mirrors the project's mock-at-the-seam convention established in
tests/test_grafana.py / test_solr.py / test_rabbitmq.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_kibana_001"

# --- canned response bodies -------------------------------------------------

# A realistic /api/status body trimmed to the keys the probe parses. The
# ``status.overall`` block is the legacy-shape signal; ``version.number`` is
# the build semver. ``name`` defaults to the server hostname in stock
# deployments — we deliberately keep it as a non-"kibana" value here to
# exercise the status-block fingerprint path.
_KIBANA_STATUS_BODY = (
    '{"name":"kibana-prod-01",'
    '"version":{"number":"8.13.4",'
    '"build_number":12345,'
    '"build_hash":"abcdef1234567890"},'
    '"status":{"overall":{"level":"available","since":"2026-05-29T00:00:00.000Z"},'
    '"statuses":[{"id":"core:elasticsearch@8.13.4","level":"available"}]}}'
)

# Older 7.x /api/status shape — ``status.overall`` carried a ``state`` string
# rather than ``level``. The probe must accept either.
_KIBANA_LEGACY_STATUS_BODY = (
    '{"name":"my-kibana",'
    '"version":{"number":"7.17.10","build_number":54321,"build_hash":"deadbeef"},'
    '"status":{"overall":{"state":"green","since":"2024-01-01T00:00:00Z"}}}'
)

# A body whose ``name`` field carries the explicit "kibana" marker but with a
# minimal status shape — exercises the name-marker fingerprint branch.
_KIBANA_NAME_ONLY_BODY = (
    '{"name":"Kibana",'
    '"version":{"number":"8.10.0"}}'
)

# The OpenSearch Dashboards fork. Same /api/status shape, distinct product.
# Must NOT be flagged as Kibana.
_OPENSEARCH_DASHBOARDS_BODY = (
    '{"name":"OpenSearch Dashboards",'
    '"version":{"number":"2.11.1","build_number":67890},'
    '"status":{"overall":{"level":"available"}}}'
)

# A JSON 200 that is NOT Kibana (missing version.number AND no Kibana status
# block). The probe must not be fooled by a coincidental 200 JSON object.
_NOT_KIBANA_BODY = '{"status":"ok","service":"other"}'

# A JSON 200 that has a version.number but no Kibana marker at all — neither
# a "kibana" name nor a status block. Must NOT be flagged.
_VERSION_ONLY_NO_MARKER_BODY = '{"name":"nginx","version":{"number":"1.27.0"}}'


def _resp(
    status: int, body: str = "", headers: dict | None = None
) -> httpx.Response:
    """Build a real httpx.Response (no network) for a canned reply."""
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
    """Return a fake httpx.get routing by URL path.

    ``path_map`` maps URL path -> response.
    """

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path = urlparse(url).path or "/"
        return path_map.get(path, _resp(404))

    return fake_get


def _target() -> Target:
    """Single open Kibana port keeps the probe surface deterministic."""
    return Target(
        host="10.0.0.40", ports={5601: {"state": "open", "name": "kibana"}}
    )


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-KIBANA-001"
    assert (
        module.metadata["name"] == "Kibana Unauthenticated HTTP API Exposure"
    )
    assert 5601 in module.metadata["port_hint"]
    assert 5601 in module.metadata["default_ports"]
    assert "kibana" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- anonymous access (HIGH) ------------------------------------------------


def test_anonymous_status_is_high(monkeypatch):
    """/api/status returns 200 with Kibana body and no auth => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _KIBANA_STATUS_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-KIBANA-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.40"
    assert finding.evidence["anonymous_access"] is True
    assert finding.evidence["kibana_version"] == "8.13.4"
    assert finding.evidence["build_number"] == 12345
    assert finding.evidence["build_hash"] == "abcdef1234567890"
    assert finding.evidence["overall_status"] == "available"
    assert finding.evidence["port"] == 5601


def test_legacy_7x_status_shape_is_high(monkeypatch):
    """A 7.x /api/status with state-not-level is still recognised as Kibana."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _KIBANA_LEGACY_STATUS_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["kibana_version"] == "7.17.10"
    assert finding.evidence["overall_status"] == "green"


def test_name_marker_fingerprint_is_high(monkeypatch):
    """A body whose ``name`` carries the Kibana marker is still flagged."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _KIBANA_NAME_ONLY_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["kibana_version"] == "8.10.0"
    # build_number / build_hash / overall_status absent in this body — they
    # must simply be omitted from evidence, not crash the probe.
    assert "build_number" not in finding.evidence
    assert "build_hash" not in finding.evidence
    assert "overall_status" not in finding.evidence


# --- false-positive guards --------------------------------------------------


def test_opensearch_dashboards_is_no_finding(monkeypatch):
    """The OpenSearch Dashboards fork shares the shape but must NOT be flagged."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _OPENSEARCH_DASHBOARDS_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_non_kibana_200_is_no_finding(monkeypatch):
    """A 200 JSON without version.number or Kibana markers => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _NOT_KIBANA_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_version_only_without_kibana_marker_is_no_finding(monkeypatch):
    """A 200 with version.number but no Kibana name/status fingerprint => None.

    Many services answer ``/api/status`` with a generic ``{"version":
    {"number": ...}}`` shape — we must not flag them as Kibana on the version
    field alone.
    """
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _VERSION_ONLY_NO_MARKER_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_auth_enforced_401_is_no_finding(monkeypatch):
    """A 401 challenge (auth enforced) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/status": _resp(
            401, headers={"www-authenticate": 'Basic realm="Kibana"'}
        )
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_redirect_to_login_is_no_finding(monkeypatch):
    """A 302 to /login (auth enforced) => no finding (redirects not followed)."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(302, headers={"location": "/login"})}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_html_200_is_no_finding(monkeypatch):
    """A 200 with non-JSON HTML body (a default SPA) => not Kibana => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/api/status": _resp(200, "<html><body>hello</body></html>")
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_json_array_at_status_is_no_finding(monkeypatch):
    """A 200 returning a JSON array (not an object) => not Kibana => None."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, "[]")}
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


# --- port fallback / scheme -------------------------------------------------


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [5601, 5602, 80, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.41"))  # no ports → default_ports

    assert 5601 in contacted_ports
    assert 5602 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports


def test_https_scheme_used_for_tls_port(monkeypatch):
    """Port 443 is contacted over HTTPS; 5601 / 5602 / 80 over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.42"))  # no recon → default ports

    assert any(u.startswith("https://10.0.0.42:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.42:5601/") for u in urls)
    assert any(u.startswith("http://10.0.0.42:5602/") for u in urls)
    assert any(u.startswith("http://10.0.0.42:80/") for u in urls)


def test_default_port_5601_used_first(monkeypatch):
    """5601 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="h"))

    assert contacted_ports[0] == 5601


def test_recon_service_name_matches_kibana(monkeypatch):
    """A non-default port marked as a kibana service in recon is probed."""
    module = load_plugin(PLUGIN)
    contacted: list = []
    path_map = {"/api/status": _resp(200, _KIBANA_STATUS_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=contacted)
    )

    # Kibana on a non-default port; recon labels it kibana.
    target = Target(
        host="10.0.0.43",
        ports={18080: {"state": "open", "name": "kibana"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 18080
    assert contacted[0].startswith("http://10.0.0.43:18080/")


# --- evidence redaction -----------------------------------------------------


def test_finding_evidence_never_contains_inventory(monkeypatch):
    """Evidence keys are strictly the allowlist — never saved-object inventory.

    The probe reads /api/status which on richer deployments can carry plugin
    enumeration in ``status.statuses``, but the finding evidence should only
    record host/port/version markers — never the enumerated topology. Mirrors
    the redaction convention used by miasma_env_001 / miasma_rabbitmq_001.
    """
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _KIBANA_STATUS_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {
        "host",
        "port",
        "anonymous_access",
        "kibana_version",
        "build_number",
        "build_hash",
        "overall_status",
    }
    assert set(finding.evidence.keys()).issubset(allowed_keys)


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {"/api/status": _resp(200, _KIBANA_STATUS_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-KIBANA-001"
    assert findings[0].confidence == "high"
