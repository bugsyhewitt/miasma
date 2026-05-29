"""Tests for the Quest KACE SMA version-fingerprint probe (CVE-2025-32975).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (see tests/test_commvault.py
and tests/test_traccar_lfi.py).

The probe is VERSION-FINGERPRINT ONLY: it must never attempt the authentication
bypass, and HIGH is gated on a KACE SMA fingerprint plus an affected version
(below the fixed 14.1 line).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2025_32975"

# --- canned bodies ----------------------------------------------------------

# A realistic KACE SMA admin login page advertising an affected 14.0 build.
_LOGIN_AFFECTED = (
    "<!DOCTYPE html><html><head><title>KACE Systems Management Appliance</title>"
    "</head><body><div class='kbox-login'>KACE SMA Version 14.0.290"
    "</div></body></html>"
)

# KACE on the fixed 14.1 line — must NOT flag.
_LOGIN_FIXED = (
    "<html><title>KACE SMA</title><body>"
    "KACE Systems Management Version 14.1.32</body></html>"
)

# KACE on a much newer (also fixed) build — must NOT flag.
_LOGIN_FIXED_NEWER = (
    "<html><title>KACE SMA</title><body>KACE SMA Version 15.0.100</body></html>"
)

# KACE whose login page hides the version entirely → MEDIUM.
_LOGIN_NO_VERSION = (
    "<html><title>KACE Systems Management Appliance</title><body>"
    "<form id='loginForm'>Please sign in</form></body></html>"
)

# An unrelated host (nginx welcome) that happens to mention a version — never flag.
_NGINX_WELCOME = "<html><body><h1>Welcome to nginx!</h1></body></html>"


def _resp(status: int, text: str = "", headers=None):
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        text=text,
        headers=headers or {},
        request=request,
    )


def _target() -> Target:
    """A single open https console port keeps the probe surface deterministic."""
    return Target(host="10.0.0.70", ports={443: {"state": "open", "name": "https"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2025-32975"
    assert module.metadata["name"].startswith("Quest KACE")
    assert 443 in module.metadata["port_hint"]
    assert "https" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- affected version (HIGH) ------------------------------------------------


def test_affected_version_returns_high(monkeypatch):
    """KACE fingerprint + affected 14.0 version → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2025-32975"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.70"
    assert finding.evidence["fixed_release"] == "14.1 (March 2025)"
    assert finding.evidence["version_detected"] == "14.0"
    assert finding.evidence["fingerprint_path"] == "/userui/login.php"


def test_affected_version_via_header(monkeypatch):
    """An X-KACE-Version header alone supplies both fingerprint and version."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(
                200,
                "<html><body>sign in</body></html>",
                {"x-kace-version": "14.0.211"},
            )
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "14.0"


def test_fingerprint_via_cookie_marker(monkeypatch):
    """A KACE kboxid login cookie alone can fingerprint the host."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/userui/":
            return _resp(
                200,
                "<html><body>sign in Version 13.2.85</body></html>",
                {"set-cookie": "kboxid=abc123; Path=/"},
            )
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["fingerprint_path"] == "/userui/"
    assert finding.evidence["version_detected"] == "13.2"


# --- MEDIUM (fingerprinted, no version) -------------------------------------


def test_fingerprinted_without_version_returns_medium(monkeypatch):
    """KACE fingerprints but the version is hidden → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(200, _LOGIN_NO_VERSION)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert "note" in finding.evidence
    assert finding.evidence["version_detected"] is None


def test_high_wins_over_medium_across_ports(monkeypatch):
    """A version-less console on one port, an affected one on another → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        parsed = urlparse(url)
        port = parsed.port
        path = parsed.path
        # Port 80: fingerprints but no version (MEDIUM candidate).
        if port == 80 and path == "/userui/login.php":
            return _resp(200, _LOGIN_NO_VERSION)
        # Port 443: fingerprints WITH the affected version (HIGH wins).
        if port == 443 and path == "/userui/login.php":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    # No recon → default_ports [443, 80] are probed; 443 yields HIGH.
    finding = module.probe(Target(host="10.0.0.71"))

    assert finding is not None
    assert finding.confidence == "high"


# --- false-positive guards --------------------------------------------------


def test_non_kace_host_is_never_flagged(monkeypatch):
    """An unrelated host that even exposes a 14.0-ish string must NOT flag."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            # nginx page that coincidentally mentions a version — no KACE fp.
            return _resp(200, _NGINX_WELCOME + " build 14.0.1")
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_kace_fixed_version_is_not_flagged(monkeypatch):
    """KACE on the fixed 14.1 line → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(200, _LOGIN_FIXED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_kace_newer_version_is_not_flagged(monkeypatch):
    """KACE on a newer (15.x) fixed build → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(200, _LOGIN_FIXED_NEWER)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_auth_bypass_is_never_attempted(monkeypatch):
    """No request may carry bypass-style auth/exploit parameters or POST."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(_target())

    # Only the benign fingerprint paths are ever contacted — nothing that looks
    # like an exploit endpoint or a credential submission.
    allowed_paths = {"/userui/login.php", "/userui/", "/adminui/login.php", "/"}
    for url in requested:
        assert urlparse(url).path in allowed_paths


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


# --- scheme / port handling -------------------------------------------------


def test_https_scheme_used_for_tls_ports(monkeypatch):
    """Port 443 is probed over https, not http."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert any(u.startswith("https://10.0.0.70:443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [443, 80]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.72"))  # no ports key → default_ports

    assert 443 in contacted_ports
    assert 80 in contacted_ports


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/userui/login.php":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2025-32975"
    assert findings[0].confidence == "high"
