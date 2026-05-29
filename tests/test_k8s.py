"""Tests for the Kubernetes API server anonymous-access probe (MIASMA-K8S-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (see tests/test_kace_sma.py
and tests/test_commvault.py).

The probe is ENUMERATION-ONLY: it must never send credentials/tokens, never read
secret contents, and never mutate a resource. HIGH is gated on a Kubernetes
fingerprint (/version) PLUS anonymous namespace enumeration; MEDIUM on the
/version leak alone.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_k8s_001"

# --- canned bodies ----------------------------------------------------------

# A realistic anonymous /version response from a Kubernetes API server.
_VERSION_BODY = json.dumps(
    {
        "major": "1",
        "minor": "29",
        "gitVersion": "v1.29.3",
        "gitCommit": "abc123",
        "platform": "linux/amd64",
    }
)

# A genuine NamespaceList with three namespaces (names must NOT leak into
# evidence — only the count).
_NAMESPACES_BODY = json.dumps(
    {
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "items": [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "kube-system"}},
            {"metadata": {"name": "production"}},
        ],
    }
)

# An empty-but-valid NamespaceList (still HIGH — anonymous access is confirmed).
_NAMESPACES_EMPTY = json.dumps({"kind": "NamespaceList", "apiVersion": "v1", "items": []})

# A non-Kubernetes JSON 200 (e.g. an SPA API) — must NOT fingerprint.
_NOT_K8S_JSON = json.dumps({"status": "ok", "service": "frontend"})

# An HTML page that happens to answer /version — must NOT fingerprint.
_HTML_PAGE = "<!DOCTYPE html><html><body><h1>It works!</h1></body></html>"


def _resp(status: int, text: str = "", headers=None):
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "https://example.test")
    return httpx.Response(
        status_code=status,
        text=text,
        headers=headers or {},
        request=request,
    )


def _target() -> Target:
    """A single open 6443 API-server port keeps the probe surface deterministic."""
    return Target(host="10.0.0.90", ports={6443: {"state": "open", "name": "https"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-K8S-001"
    assert module.metadata["name"].startswith("Kubernetes")
    assert 6443 in module.metadata["port_hint"]
    assert "https" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- anonymous namespace enumeration (HIGH) ---------------------------------


def test_anonymous_namespace_listing_returns_high(monkeypatch):
    """K8s fingerprint + anonymous namespace list → HIGH (count only)."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-K8S-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.90"
    assert finding.evidence["git_version"] == "v1.29.3"
    assert finding.evidence["namespace_count"] == 3
    # Namespace NAMES must never appear in evidence — only the count.
    blob = json.dumps(finding.evidence)
    assert "kube-system" not in blob
    assert "production" not in blob


def test_empty_namespace_list_still_high(monkeypatch):
    """An empty-but-valid NamespaceList still confirms anonymous access → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_EMPTY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["namespace_count"] == 0


def test_version_via_major_minor_only(monkeypatch):
    """A /version object with no gitVersion still fingerprints via major/minor."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, json.dumps({"major": "1", "minor": "27"}))
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["git_version"] == "1.27"


# --- version leak only (MEDIUM) ---------------------------------------------


def test_version_leak_but_namespaces_refused_returns_medium(monkeypatch):
    """K8s /version anonymous but namespace enumeration 403 → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        if path == "/api/v1/namespaces":
            return _resp(403, '{"kind":"Status","code":403}')
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["git_version"] == "v1.29.3"
    assert finding.evidence["namespace_status"] == 403
    assert "namespace_count" not in finding.evidence


def test_namespaces_401_is_medium(monkeypatch):
    """A 401 on the namespace endpoint is the secure refusal → MEDIUM, not HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        if path == "/api/v1/namespaces":
            return _resp(401)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["namespace_status"] == 401


# --- false-positive guards --------------------------------------------------


def test_non_k8s_json_is_never_flagged(monkeypatch):
    """A 200 JSON that isn't a Kubernetes /version object must NOT flag."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _NOT_K8S_JSON)
        # Even if namespaces would 200, no fingerprint means no flag.
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_html_version_page_is_never_flagged(monkeypatch):
    """A non-JSON (HTML) /version response is not a Kubernetes fingerprint."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _HTML_PAGE)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_locked_down_api_server_is_not_flagged(monkeypatch):
    """A K8s server that refuses /version anonymously (401) → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(401)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_bare_200_namespaces_without_fingerprint_not_high(monkeypatch):
    """A NamespaceList 200 reached only because /version refused → no finding.

    Without the /version fingerprint we never consult namespaces, and a host
    that refuses /version is not flagged even if namespaces would answer.
    """
    module = load_plugin(PLUGIN)
    contacted: list[str] = []

    def fake_get(url, *args, **kwargs):
        contacted.append(urlparse(url).path)
        path = urlparse(url).path
        if path == "/version":
            return _resp(403)
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None
    # The namespace endpoint must never be consulted without a fingerprint.
    assert "/api/v1/namespaces" not in contacted


# --- no-credentials guard ---------------------------------------------------


def test_no_credentials_or_tokens_are_ever_sent(monkeypatch):
    """No Authorization header / bearer token may accompany any request."""
    module = load_plugin(PLUGIN)
    seen_kwargs: list[dict] = []
    contacted_paths: list[str] = []

    def fake_get(url, *args, **kwargs):
        seen_kwargs.append(kwargs)
        contacted_paths.append(urlparse(url).path)
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(_target())

    for kwargs in seen_kwargs:
        headers = kwargs.get("headers") or {}
        lowered = {k.lower(): v for k, v in headers.items()}
        assert "authorization" not in lowered
        assert "auth" not in kwargs  # no httpx Basic/Bearer auth object
    # Only the two benign read endpoints are ever contacted.
    assert set(contacted_paths) <= {"/version", "/api/v1/namespaces"}


# --- scheme / port handling -------------------------------------------------


def test_https_scheme_used_for_api_server_port(monkeypatch):
    """Port 6443 is probed over https."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert any(u.startswith("https://10.0.0.90:6443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [6443, 8443, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.91"))  # no ports key → default_ports

    assert 6443 in contacted_ports
    assert 8443 in contacted_ports
    assert 443 in contacted_ports


def test_high_wins_over_medium_across_ports(monkeypatch):
    """A version-only leak on one port, full namespace access on another → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        parsed = urlparse(url)
        port = parsed.port
        path = parsed.path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        # 6443 refuses namespaces (MEDIUM); 8443 allows them (HIGH wins).
        if path == "/api/v1/namespaces":
            if port == 6443:
                return _resp(403)
            if port == 8443:
                return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    # No recon → default_ports [6443, 8443, 443] are probed in order.
    finding = module.probe(Target(host="10.0.0.92"))

    assert finding is not None
    assert finding.confidence == "high"


# --- connection / timeout errors --------------------------------------------


def test_connection_error_is_no_finding(monkeypatch):
    """A socket error on every candidate port → no finding, no exception."""
    module = load_plugin(PLUGIN)

    def boom(url, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(module.httpx, "get", boom)

    assert module.probe(_target()) is None


def test_timeout_is_no_finding(monkeypatch):
    """A timeout on every candidate port → no finding, no exception raised."""
    module = load_plugin(PLUGIN)

    def timeout(url, *args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(module.httpx, "get", timeout)

    assert module.probe(_target()) is None


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/version":
            return _resp(200, _VERSION_BODY)
        if path == "/api/v1/namespaces":
            return _resp(200, _NAMESPACES_BODY)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-K8S-001"
    assert findings[0].confidence == "high"
