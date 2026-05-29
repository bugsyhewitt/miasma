"""Tests for the etcd unauthenticated client API probe (MIASMA-ETCD-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` and
``httpx.post`` on the plugin module and route each request to a canned response
keyed by URL path. This mirrors the project's mock-at-the-seam convention
established in tests/test_consul.py and tests/test_prometheus.py. etcd's
gRPC-gateway uses GET /version for the fingerprint and POST for the v3 endpoints
(/v3/maintenance/status, /v3/kv/range), so the fake routes both verbs.
"""

from __future__ import annotations

import base64
from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_etcd_001"

# --- canned response bodies -------------------------------------------------

_VERSION_BODY = '{"etcdserver":"3.5.12","etcdcluster":"3.5.0"}'
_VERSION_NO_SERVER = '{"etcdserver":"","etcdcluster":"3.5.0"}'
_NOT_ETCD_BODY = '{"foo":"bar","baz":123}'

_STATUS_BODY = (
    '{"header":{"cluster_id":"14841639068965178418",'
    '"member_id":"10276657743932975437","revision":"42","raft_term":"7"},'
    '"version":"3.5.12","dbSize":"20480","leader":"10276657743932975437",'
    '"raftIndex":"101","raftTerm":"7"}'
)
_STATUS_EMPTY_DB = (
    '{"header":{"cluster_id":"1","member_id":"2","revision":"1","raft_term":"1"},'
    '"version":"3.5.12","dbSize":"24576","leader":"2"}'
)

_RANGE_COUNT_3 = '{"header":{"revision":"42"},"count":"3"}'
_RANGE_COUNT_0 = '{"header":{"revision":"1"},"count":"0"}'


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _keys_only_body(key_names: list[str]) -> str:
    """A keys_only range reply: kvs with key set, value empty."""
    entries = ",".join(
        '{"key":"' + _b64(name) + '","value":"","create_revision":"1",'
        '"mod_revision":"1","version":"1"}'
        for name in key_names
    )
    return '{"header":{"revision":"42"},"kvs":[' + entries + '],"count":"' + str(
        len(key_names)
    ) + '"}'


_KEYS_K8S_SECRET = _keys_only_body(
    ["/registry/secrets/default/db-creds", "/registry/pods/default/web"]
)
_KEYS_NO_CREDS = _keys_only_body(
    ["/registry/pods/default/web", "/registry/services/default/api"]
)
_KEYS_EMPTY = _keys_only_body([])


def _resp(status: int, body: str = "", headers: dict | None = None) -> httpx.Response:
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("POST", "http://example.test")
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers=headers or {},
        request=request,
    )


def _make_fake(
    get_map: dict[str, httpx.Response],
    post_map: dict[str, list[httpx.Response]] | None = None,
    record: list | None = None,
):
    """Return (fake_get, fake_post) routing by URL path.

    ``post_map`` values are lists so a path hit more than once (e.g. /v3/kv/range
    is hit twice: count_only then keys_only) returns each canned response in
    order; the last response repeats once the list is exhausted. Unknown paths
    yield 404.
    """
    post_map = post_map or {}
    # mutable per-path cursors
    cursors: dict[str, int] = {p: 0 for p in post_map}

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(("GET", url))
        path = urlparse(url).path or "/"
        return get_map.get(path, _resp(404))

    def fake_post(url, *args, **kwargs):
        if record is not None:
            record.append(("POST", url))
        path = urlparse(url).path or "/"
        responses = post_map.get(path)
        if not responses:
            return _resp(404)
        idx = min(cursors[path], len(responses) - 1)
        cursors[path] += 1
        return responses[idx]

    return fake_get, fake_post


def _install(monkeypatch, module, get_map, post_map=None, record=None):
    fake_get, fake_post = _make_fake(get_map, post_map, record)
    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.httpx, "post", fake_post)


def _target() -> Target:
    """Single open etcd port keeps the probe surface deterministic."""
    return Target(host="10.0.0.50", ports={2379: {"state": "open", "name": "etcd"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-ETCD-001"
    assert module.metadata["name"] == "etcd Unauthenticated Client API Access"
    assert 2379 in module.metadata["port_hint"]
    assert 2379 in module.metadata["default_ports"]
    assert callable(module.probe)


# --- credential leak via key names (HIGH) -----------------------------------


def test_k8s_secret_key_name_is_high(monkeypatch):
    """version + status OK + a /registry/secrets/ key name => HIGH."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={
            "/v3/maintenance/status": [_resp(200, _STATUS_BODY)],
            # first call count_only, second call keys_only
            "/v3/kv/range": [_resp(200, _RANGE_COUNT_3), _resp(200, _KEYS_K8S_SECRET)],
        },
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-ETCD-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.50"
    assert finding.evidence["api_unauthenticated"] is True
    assert finding.evidence["port"] == 2379
    assert finding.evidence["version"] == "3.5.12"
    assert finding.evidence["key_names_leak_credentials"] is True
    assert finding.evidence["key_count"] == 3


def test_secret_key_name_is_not_stored_in_evidence(monkeypatch):
    """The decoded key NAMES must never be copied into the finding evidence."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={
            "/v3/maintenance/status": [_resp(200, _STATUS_BODY)],
            "/v3/kv/range": [_resp(200, _RANGE_COUNT_3), _resp(200, _KEYS_K8S_SECRET)],
        },
    )

    finding = module.probe(_target())

    assert finding is not None
    serialized = str(finding.to_dict())
    assert "db-creds" not in serialized
    assert "/registry/secrets/" not in serialized


# --- keyspace readable (HIGH) -----------------------------------------------


def test_nonempty_keyspace_is_high(monkeypatch):
    """status OK + range reports keys, no cred markers in names => HIGH."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={
            "/v3/maintenance/status": [_resp(200, _STATUS_BODY)],
            "/v3/kv/range": [_resp(200, _RANGE_COUNT_3), _resp(200, _KEYS_NO_CREDS)],
        },
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["keyspace_readable"] is True
    assert finding.evidence["key_count"] == 3
    assert finding.evidence["key_names_leak_credentials"] is False
    assert finding.evidence["db_size"] == "20480"


# --- partial / empty surface (MEDIUM) ---------------------------------------


def test_empty_keyspace_is_medium(monkeypatch):
    """status OK but range reports zero keys => MEDIUM."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={
            "/v3/maintenance/status": [_resp(200, _STATUS_EMPTY_DB)],
            "/v3/kv/range": [_resp(200, _RANGE_COUNT_0), _resp(200, _KEYS_EMPTY)],
        },
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["key_count"] == 0


def test_status_only_when_range_gated_is_medium(monkeypatch):
    """status answers unauthenticated but /v3/kv/range is 401 => MEDIUM."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={
            "/v3/maintenance/status": [_resp(200, _STATUS_BODY)],
            "/v3/kv/range": [_resp(401)],
        },
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version"] == "3.5.12"
    assert "key_count" not in finding.evidence


# --- not etcd / not vulnerable ----------------------------------------------


def test_version_present_but_not_etcd_is_no_finding(monkeypatch):
    """A 200 /version body lacking the etcd keys => not etcd => None."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _NOT_ETCD_BODY)},
    )

    assert module.probe(_target()) is None


def test_v3_api_auth_gated_is_no_finding(monkeypatch):
    """etcd fingerprinted but /v3/maintenance/status returns 401 => no finding."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={"/v3/maintenance/status": [_resp(401)]},
    )

    assert module.probe(_target()) is None


def test_no_v3_requests_without_etcd_fingerprint(monkeypatch):
    """The v3 POST requests must NOT fire against a non-etcd service."""
    module = load_plugin(PLUGIN)
    requested: list = []
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _NOT_ETCD_BODY)},
        record=requested,
    )

    module.probe(_target())

    assert not any(verb == "POST" for verb, _ in requested)


def test_no_range_request_when_status_gated(monkeypatch):
    """No /v3/kv/range request fires once /v3/maintenance/status is 401."""
    module = load_plugin(PLUGIN)
    requested: list = []
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={"/v3/maintenance/status": [_resp(401)]},
        record=requested,
    )

    module.probe(_target())

    assert not any(url.endswith("/v3/kv/range") for _, url in requested)


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
    """With no recon data the probe falls back to [2379, 4001, 2380, 80, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.httpx, "post", fake_get)

    module.probe(Target(host="10.0.0.51"))  # no ports key → default_ports

    assert 2379 in contacted_ports
    assert 4001 in contacted_ports
    assert 2380 in contacted_ports
    assert 443 in contacted_ports


def test_https_scheme_used_for_443(monkeypatch):
    """Port 443 is contacted over HTTPS; 2379 over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.httpx, "post", fake_get)

    module.probe(Target(host="10.0.0.52"))  # no recon → default ports

    assert any(u.startswith("https://10.0.0.52:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.52:2379/") for u in urls)


# --- version parsing edge cases ---------------------------------------------


def test_empty_server_version_still_works(monkeypatch):
    """etcdserver present-but-empty still fingerprints etcd; version is None."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_NO_SERVER)},
        post_map={
            "/v3/maintenance/status": [_resp(200, _STATUS_BODY)],
            "/v3/kv/range": [_resp(200, _RANGE_COUNT_3), _resp(200, _KEYS_NO_CREDS)],
        },
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version"] is None


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    _install(
        monkeypatch,
        module,
        get_map={"/version": _resp(200, _VERSION_BODY)},
        post_map={
            "/v3/maintenance/status": [_resp(200, _STATUS_BODY)],
            "/v3/kv/range": [_resp(200, _RANGE_COUNT_3), _resp(200, _KEYS_NO_CREDS)],
        },
    )

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-ETCD-001"
    assert findings[0].confidence == "high"
