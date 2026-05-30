"""Tests for the CouchDB unauthenticated HTTP API exposure probe
(MIASMA-COUCHDB-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path.
Mirrors the project's mock-at-the-seam convention established in
tests/test_influxdb.py / test_kibana.py / test_grafana.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_couchdb_001"

# --- canned response bodies -------------------------------------------------

# CouchDB / — the welcome banner. couchdb=="Welcome" + parseable version.
_COUCHDB_WELCOME_BODY = (
    '{"couchdb":"Welcome","version":"3.3.3","git_sha":"abc1234",'
    '"uuid":"deadbeefdeadbeefdeadbeefdeadbeef",'
    '"features":["access-ready","partitioned","pluggable-storage-engines",'
    '"reshard","scheduler"],'
    '"vendor":{"name":"The Apache Software Foundation"}}'
)

# CouchDB welcome with no optional fields (still a valid fingerprint).
_COUCHDB_MINIMAL_WELCOME_BODY = '{"couchdb":"Welcome","version":"2.3.1"}'

# CouchDB /_all_dbs — admin party: any peer reads the database list. The
# values themselves never leak into evidence; only the count.
_COUCHDB_ALL_DBS_BODY = '["_replicator","_users","app_data","sessions"]'

# CouchDB /_all_dbs — admin party but the cluster has no user databases yet.
# An empty JSON array still confirms the misconfiguration: the admin-only
# endpoint answered 200 without auth.
_COUCHDB_ALL_DBS_EMPTY_BODY = "[]"

# A non-CouchDB JSON 200 on / — must not be flagged.
_NOT_COUCHDB_WELCOME_BODY = '{"status":"ok","service":"other"}'

# A JSON object with one marker but not both — must not be flagged.
_WRONG_FIELD_WELCOME_BODY = '{"couchdb":"Welcome"}'
_WRONG_VALUE_WELCOME_BODY = '{"couchdb":"Hello","version":"3.3.3"}'


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
        return path_map.get(path_with_query, _resp(404))

    return fake_get


def _target() -> Target:
    return Target(
        host="10.0.0.60", ports={5984: {"state": "open", "name": "couchdb"}}
    )


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-COUCHDB-001"
    assert (
        module.metadata["name"]
        == "CouchDB Unauthenticated HTTP API Exposure"
    )
    assert 5984 in module.metadata["port_hint"]
    assert 6984 in module.metadata["port_hint"]
    assert 5984 in module.metadata["default_ports"]
    assert "couchdb" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- admin party (HIGH) -----------------------------------------------------


def test_admin_party_all_dbs_is_high(monkeypatch):
    """/ fingerprints AND /_all_dbs returns the JSON array => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _COUCHDB_WELCOME_BODY),
        "/_all_dbs": _resp(200, _COUCHDB_ALL_DBS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-COUCHDB-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.60"
    assert finding.evidence["couchdb_version"] == "3.3.3"
    assert finding.evidence["database_count"] == 4
    assert finding.evidence["port"] == 5984
    assert finding.evidence["git_sha"] == "abc1234"
    assert finding.evidence["uuid"] == "deadbeefdeadbeefdeadbeefdeadbeef"
    assert finding.evidence["vendor"] == "The Apache Software Foundation"


def test_admin_party_empty_all_dbs_is_still_high(monkeypatch):
    """An empty [] from the admin-only /_all_dbs is still the positive."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _COUCHDB_MINIMAL_WELCOME_BODY),
        "/_all_dbs": _resp(200, _COUCHDB_ALL_DBS_EMPTY_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["couchdb_version"] == "2.3.1"
    assert finding.evidence["database_count"] == 0
    # Optional welcome fields not present in the minimal body must be omitted.
    assert "git_sha" not in finding.evidence
    assert "uuid" not in finding.evidence
    assert "vendor" not in finding.evidence


def test_all_dbs_401_is_no_finding(monkeypatch):
    """/ fingerprints but /_all_dbs refused (admin configured) => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _COUCHDB_WELCOME_BODY),
        "/_all_dbs": _resp(401),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_all_dbs_403_is_no_finding(monkeypatch):
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _COUCHDB_WELCOME_BODY),
        "/_all_dbs": _resp(403),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_all_dbs_non_array_is_no_finding(monkeypatch):
    """A 200 on /_all_dbs whose body is not an array (e.g. error object)."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _COUCHDB_WELCOME_BODY),
        "/_all_dbs": _resp(200, '{"error":"unauthorized","reason":"You are not a server admin."}'),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- false-positive guards --------------------------------------------------


def test_non_couchdb_welcome_is_no_finding(monkeypatch):
    """A 200 JSON without couchdb=='Welcome' => not CouchDB => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _NOT_COUCHDB_WELCOME_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_missing_version_is_no_finding(monkeypatch):
    """A 200 JSON with couchdb=='Welcome' but no version => not flagged."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _WRONG_FIELD_WELCOME_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_wrong_welcome_value_is_no_finding(monkeypatch):
    """A 200 JSON with couchdb!='Welcome' (e.g. 'Hello') => not flagged."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _WRONG_VALUE_WELCOME_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_html_200_root_is_no_finding(monkeypatch):
    """A 200 with HTML body on / => not CouchDB => None."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, "<html><body>hello</body></html>"),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_redirect_on_root_is_no_finding(monkeypatch):
    """A 302 on / (auth gateway in front) => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(302, headers={"location": "/login"}),
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
    """With no recon data the probe falls back to [5984, 6984, 80, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.61"))

    assert 5984 in contacted_ports
    assert 6984 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports


def test_https_scheme_used_for_tls_ports(monkeypatch):
    """Ports 443 and 6984 contacted over HTTPS; 5984/80 over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.62"))

    assert any(u.startswith("https://10.0.0.62:443/") for u in urls)
    assert any(u.startswith("https://10.0.0.62:6984/") for u in urls)
    assert any(u.startswith("http://10.0.0.62:5984/") for u in urls)
    assert any(u.startswith("http://10.0.0.62:80/") for u in urls)


def test_default_port_5984_used_first(monkeypatch):
    """5984 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="h"))

    assert contacted_ports[0] == 5984


def test_recon_service_name_matches_couch(monkeypatch):
    """A non-default port marked as a couchdb service in recon is probed."""
    module = load_plugin(PLUGIN)
    contacted: list = []
    path_map = {
        "/": _resp(200, _COUCHDB_WELCOME_BODY),
        "/_all_dbs": _resp(200, _COUCHDB_ALL_DBS_BODY),
    }
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=contacted)
    )

    target = Target(
        host="10.0.0.63",
        ports={15984: {"state": "open", "name": "couchdb"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 15984
    assert contacted[0].startswith("http://10.0.0.63:15984/")


# --- evidence redaction -----------------------------------------------------


def test_finding_evidence_never_contains_db_names(monkeypatch):
    """Evidence keys are strictly the allowlist — never database names."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _COUCHDB_WELCOME_BODY),
        "/_all_dbs": _resp(200, _COUCHDB_ALL_DBS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {
        "host",
        "port",
        "couchdb_version",
        "database_count",
        "vendor",
        "git_sha",
        "uuid",
    }
    assert set(finding.evidence.keys()).issubset(allowed_keys)
    serialised = repr(finding.evidence)
    # Sanity: the database names from the canned body must not leak.
    assert "_replicator" not in serialised
    assert "_users" not in serialised
    assert "app_data" not in serialised
    assert "sessions" not in serialised


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, _COUCHDB_WELCOME_BODY),
        "/_all_dbs": _resp(200, _COUCHDB_ALL_DBS_BODY),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-COUCHDB-001"
    assert findings[0].confidence == "high"
