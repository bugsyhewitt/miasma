"""Tests for the Langflow unauthenticated RCE probe (CVE-2025-3248).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (see tests/test_commvault.py
and tests/test_k8s.py).

The probe is VERSION-FINGERPRINT ONLY: it must never POST, never contact the
vulnerable /api/v1/validate/code endpoint, and never execute code. HIGH is gated
on a Langflow fingerprint PLUS an affected (< 1.3.0) version; MEDIUM on a
Langflow fingerprint with no readable version; a patched (>= 1.3.0) build is a
clean negative.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2025_3248"

# --- canned bodies ----------------------------------------------------------


def _version_body(version: str) -> str:
    """A realistic unauthenticated /api/v1/version response from Langflow."""
    return json.dumps({"version": version, "package": "Langflow", "main": "langflow"})


# An affected (< 1.3.0) version.
_AFFECTED = _version_body("1.2.0")
# A patched (>= 1.3.0) version.
_PATCHED = _version_body("1.3.0")
_PATCHED_NEWER = _version_body("1.4.2")

# A non-Langflow JSON 200 that happens to carry a "version" field — must NOT
# fingerprint as Langflow.
_NOT_LANGFLOW_JSON = json.dumps({"version": "1.2.0", "service": "billing-api"})

# A Langflow root page with no version string (hardened deployment).
_LANGFLOW_HTML_NO_VERSION = (
    "<!DOCTYPE html><html><head><title>Langflow</title></head>"
    "<body><div id='root'></div></body></html>"
)


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
    """A single open 7860 Langflow port keeps the probe surface deterministic."""
    return Target(host="10.0.0.70", ports={7860: {"state": "open", "name": "http"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2025-3248"
    assert "Langflow" in module.metadata["name"]
    assert 7860 in module.metadata["port_hint"]
    assert "http" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- affected version (HIGH) ------------------------------------------------


def test_affected_version_returns_high(monkeypatch):
    """Langflow fingerprint + affected < 1.3.0 build → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2025-3248"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.70"
    assert finding.evidence["version_detected"] == "1.2.0"
    assert finding.evidence["fingerprint_path"] == "/api/v1/version"
    assert finding.evidence["fixed_version"] == "1.3.0"


def test_old_zero_dot_version_is_high(monkeypatch):
    """A 0.x build is well below the fix → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _version_body("0.6.19"))
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "0.6.19"


def test_fingerprint_via_root_then_version_endpoint_high(monkeypatch):
    """Root page fingerprints Langflow; the version endpoint supplies the build."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/v1/version":
            # First call (fingerprint loop) AND the explicit re-read both hit this.
            return _resp(200, _AFFECTED)
        if path == "/":
            return _resp(200, _LANGFLOW_HTML_NO_VERSION)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "1.2.0"


# --- patched version (clean negative) ---------------------------------------


def test_patched_exact_fix_is_not_flagged(monkeypatch):
    """Exactly 1.3.0 is the fixed line → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _PATCHED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_patched_newer_version_is_not_flagged(monkeypatch):
    """A newer 1.4.2 build is patched → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _PATCHED_NEWER)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


# --- no readable version (MEDIUM) -------------------------------------------


def test_langflow_without_version_is_medium(monkeypatch):
    """Langflow fingerprints via root but no version string is readable → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        # No version endpoint; root fingerprints Langflow with no version token.
        if path == "/":
            return _resp(200, _LANGFLOW_HTML_NO_VERSION)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version_detected"] is None
    assert finding.evidence["fingerprint_path"] == "/"


# --- false-positive guards --------------------------------------------------


def test_non_langflow_json_with_version_is_never_flagged(monkeypatch):
    """A 200 JSON with a version field but no Langflow marker must NOT flag."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _NOT_LANGFLOW_JSON)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_non_langflow_host_is_never_flagged(monkeypatch):
    """A host with no Langflow markers anywhere → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        return _resp(200, "<html><body>It works!</body></html>")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


# --- the vulnerable endpoint is NEVER contacted -----------------------------


def test_vulnerable_endpoint_is_never_contacted(monkeypatch):
    """The probe must never request /api/v1/validate/code and never POST."""
    module = load_plugin(PLUGIN)
    contacted: list[str] = []

    def fake_get(url, *args, **kwargs):
        contacted.append(urlparse(url).path)
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _AFFECTED)
        return _resp(404)

    def fake_post(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("probe must never POST")

    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.httpx, "post", fake_post, raising=False)

    module.probe(_target())

    assert "/api/v1/validate/code" not in contacted


def test_no_credentials_are_ever_sent(monkeypatch):
    """No Authorization header / auth object may accompany any request."""
    module = load_plugin(PLUGIN)
    seen_kwargs: list[dict] = []

    def fake_get(url, *args, **kwargs):
        seen_kwargs.append(kwargs)
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(_target())

    for kwargs in seen_kwargs:
        headers = kwargs.get("headers") or {}
        lowered = {k.lower(): v for k, v in headers.items()}
        assert "authorization" not in lowered
        assert "auth" not in kwargs


# --- scheme / port handling -------------------------------------------------


def test_https_scheme_used_for_tls_port(monkeypatch):
    """Port 8443 is probed over https."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == "/api/v1/version":
            return _resp(200, _AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    target = Target(host="10.0.0.71", ports={8443: {"state": "open", "name": "https"}})
    finding = module.probe(target)

    assert finding is not None
    assert any(u.startswith("https://10.0.0.71:8443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to the default port list."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.72"))  # no ports key → default_ports

    assert 7860 in contacted_ports
    assert 443 in contacted_ports


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
        if path == "/api/v1/version":
            return _resp(200, _AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2025-3248"
    assert findings[0].confidence == "high"
