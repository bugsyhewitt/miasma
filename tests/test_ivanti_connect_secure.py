"""Tests for the Ivanti Connect Secure pre-auth RCE probe (CVE-2025-0282).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (see tests/test_langflow.py
and tests/test_commvault.py).

The probe is VERSION-FINGERPRINT ONLY: it must never POST, never send an
overflow payload, and never trigger the memory-corruption RCE. HIGH is gated on
an Ivanti fingerprint PLUS an affected (< 22.7R2.5) version; MEDIUM on an Ivanti
fingerprint with no readable version; a patched (>= 22.7R2.5) build is a clean
negative.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2025_0282"

_VERSION_PATH = "/dana-na/nc/nc_gina_ver.txt"
_WELCOME_PATH = "/dana-na/auth/url_default/welcome.cgi"

# --- canned bodies ----------------------------------------------------------


def _gina_ver_body(version: str) -> str:
    """A realistic unauthenticated GINA version file from Ivanti Connect Secure."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<DSGINAVersion product="Ivanti Connect Secure" version="{version}"/>'
    )


# An affected (< 22.7R2.5) version.
_AFFECTED = _gina_ver_body("22.7R2.4")
# A patched (>= 22.7R2.5) version.
_PATCHED = _gina_ver_body("22.7R2.5")
_PATCHED_NEWER = _gina_ver_body("22.7R2.6")

# An Ivanti welcome/login page (fingerprints via /dana-na/ markup) with no
# version token in it (hardened appliance).
_IVANTI_WELCOME_NO_VERSION = (
    "<!DOCTYPE html><html><head><title>Welcome to Ivanti Connect Secure</title>"
    "</head><body><form action='/dana-na/auth/url_default/login.cgi'>"
    "<input name='dsstartpage'></form></body></html>"
)

# A non-Ivanti host that happens to expose a dotted version-looking token — must
# NOT fingerprint as Ivanti.
_NOT_IVANTI = "<html><body>API v22.7 — billing-service</body></html>"


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
    """A single open 443 Ivanti port keeps the probe surface deterministic."""
    return Target(host="10.0.0.82", ports={443: {"state": "open", "name": "https"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2025-0282"
    assert "Ivanti" in module.metadata["name"]
    assert 443 in module.metadata["port_hint"]
    assert "https" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- affected version (HIGH) ------------------------------------------------


def test_affected_version_returns_high(monkeypatch):
    """Ivanti fingerprint + affected < 22.7R2.5 build → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2025-0282"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.82"
    assert finding.evidence["version_detected"] == "22.7R2.4"
    assert finding.evidence["fingerprint_path"] == _VERSION_PATH
    assert finding.evidence["fixed_version"] == "22.7R2.5"


def test_old_9x_version_is_high(monkeypatch):
    """A legacy 9.1Rx Pulse/ICS build is well below the fix → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _gina_ver_body("9.1R18"))
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "9.1R18"


def test_same_release_lower_patch_is_high(monkeypatch):
    """22.7R2.4 is one patch below the 22.7R2.5 fix → HIGH (patch comparison)."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _gina_ver_body("22.7R2.0"))
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"


def test_fingerprint_via_welcome_then_version_file_high(monkeypatch):
    """Welcome page fingerprints Ivanti; the version file supplies the build."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _AFFECTED)
        if path == _WELCOME_PATH:
            return _resp(200, _IVANTI_WELCOME_NO_VERSION)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "22.7R2.4"


# --- patched version (clean negative) ---------------------------------------


def test_patched_exact_fix_is_not_flagged(monkeypatch):
    """Exactly 22.7R2.5 is the fixed line → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _PATCHED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_patched_newer_version_is_not_flagged(monkeypatch):
    """A newer 22.7R2.6 build is patched → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _PATCHED_NEWER)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


# --- no readable version (MEDIUM) -------------------------------------------


def test_ivanti_without_version_is_medium(monkeypatch):
    """Ivanti fingerprints via welcome page but no version is readable → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        # No version file; the welcome page fingerprints Ivanti with no version.
        if path == _WELCOME_PATH:
            return _resp(200, _IVANTI_WELCOME_NO_VERSION)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version_detected"] is None
    assert finding.evidence["fingerprint_path"] == _WELCOME_PATH


# --- false-positive guards --------------------------------------------------


def test_non_ivanti_host_with_version_token_is_never_flagged(monkeypatch):
    """A 200 with a version-looking token but no Ivanti marker must NOT flag."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        return _resp(200, _NOT_IVANTI)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_non_ivanti_host_is_never_flagged(monkeypatch):
    """A host with no Ivanti markers anywhere → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        return _resp(200, "<html><body>It works!</body></html>")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


# --- the overflow is NEVER triggered ----------------------------------------


def test_probe_never_posts_and_sends_no_payload(monkeypatch):
    """The probe must only GET public paths and never POST an overflow payload."""
    module = load_plugin(PLUGIN)
    contacted: list[str] = []

    def fake_get(url, *args, **kwargs):
        contacted.append(urlparse(url).path)
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _AFFECTED)
        return _resp(404)

    def fake_post(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("probe must never POST")

    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.httpx, "post", fake_post, raising=False)

    module.probe(_target())

    # Only the declared benign fingerprint paths may ever be contacted.
    allowed = {
        _VERSION_PATH,
        _WELCOME_PATH,
        "/dana-na/",
        "/",
    }
    for path in contacted:
        assert path in allowed


def test_no_credentials_are_ever_sent(monkeypatch):
    """No Authorization header / auth object may accompany any request."""
    module = load_plugin(PLUGIN)
    seen_kwargs: list[dict] = []

    def fake_get(url, *args, **kwargs):
        seen_kwargs.append(kwargs)
        path = urlparse(url).path
        if path == _VERSION_PATH:
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
    """Port 443 is probed over https."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == _VERSION_PATH:
            return _resp(200, _AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert any(u.startswith("https://10.0.0.82:443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to the default port list."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.83"))  # no ports key → default_ports

    assert 443 in contacted_ports
    assert 80 in contacted_ports


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
        if path == _VERSION_PATH:
            return _resp(200, _AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2025-0282"
    assert findings[0].confidence == "high"
