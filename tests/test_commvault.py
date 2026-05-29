"""Tests for the Commvault Command Center version-fingerprint probe (CVE-2025-34028).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (see tests/test_traccar_lfi.py
and tests/test_tomcat_rewrite.py).

The probe is VERSION-FINGERPRINT ONLY: it must never contact the vulnerable
``/deployWebpackage.do`` endpoint, and HIGH is gated on a Commvault fingerprint
plus an affected 11.38 Innovation Release version string.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2025_34028"

# --- canned bodies ----------------------------------------------------------

# A realistic Command Center login page advertising the affected 11.38 build.
_LOGIN_AFFECTED = (
    "<!DOCTYPE html><html><head><title>Commvault Command Center</title></head>"
    "<body><div class='cv-login'>Commvault Command Center Version 11.38.20"
    "</div></body></html>"
)

# Same console but advertising the build as an SP38 service-pack tag.
_LOGIN_AFFECTED_SP = (
    "<html><title>Command Center</title><body>Commvault Web Console SP38"
    "</body></html>"
)

# Command Center on a NON-affected service pack (11.36) — must NOT flag.
_LOGIN_SAFE = (
    "<html><title>Commvault Command Center</title><body>"
    "Commvault Command Center Version 11.36.40</body></html>"
)

# Command Center whose login page hides the version entirely → MEDIUM.
_LOGIN_NO_VERSION = (
    "<html><title>Commvault Command Center</title><body>"
    "<form id='loginForm'>Please sign in</form></body></html>"
)

# An unrelated host (nginx welcome) that happens to expose something — never flag.
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
    return Target(host="10.0.0.60", ports={443: {"state": "open", "name": "https"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2025-34028"
    assert module.metadata["name"].startswith("Commvault")
    assert 443 in module.metadata["port_hint"]
    assert "https" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- affected version (HIGH) ------------------------------------------------


def test_affected_dotted_version_returns_high(monkeypatch):
    """Commvault fingerprint + dotted 11.38 version → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/commandcenter/":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2025-34028"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.60"
    assert finding.evidence["affected_release"] == "11.38 Innovation Release"
    assert finding.evidence["version_detected"] == "11.38.20"
    assert finding.evidence["fingerprint_path"] == "/commandcenter/"


def test_affected_service_pack_tag_returns_high(monkeypatch):
    """Commvault fingerprint + SP38 service-pack tag → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/commandcenter/":
            return _resp(200, _LOGIN_AFFECTED_SP)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "SP38"


def test_fingerprint_via_cookie_marker(monkeypatch):
    """A Command Center login cookie alone can fingerprint the host."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/commandcenter/login":
            return _resp(
                200,
                "<html><body>sign in Version 11.38.5</body></html>",
                {"set-cookie": "cv_loginLocale=en; Path=/"},
            )
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["fingerprint_path"] == "/commandcenter/login"


# --- MEDIUM (fingerprinted, no version) -------------------------------------


def test_fingerprinted_without_version_returns_medium(monkeypatch):
    """Commvault fingerprints but the version is hidden → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/commandcenter/":
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
        if port == 80 and path == "/commandcenter/":
            return _resp(200, _LOGIN_NO_VERSION)
        # Port 443: fingerprints WITH the affected version (HIGH wins).
        if port == 443 and path == "/commandcenter/":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    # No recon → default_ports [443, 80, 8443] are probed; 443 yields HIGH.
    finding = module.probe(Target(host="10.0.0.61"))

    assert finding is not None
    assert finding.confidence == "high"


# --- false-positive guards --------------------------------------------------


def test_non_commvault_host_is_never_flagged(monkeypatch):
    """An unrelated host that even exposes a 11.38-ish string must NOT flag."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            # nginx page that coincidentally mentions a version — no Commvault fp.
            return _resp(200, _NGINX_WELCOME + " build 11.38")
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_commvault_safe_version_is_not_flagged(monkeypatch):
    """Commvault on a non-affected service pack (11.36) → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/commandcenter/":
            return _resp(200, _LOGIN_SAFE)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_deploy_endpoint_is_never_contacted(monkeypatch):
    """The vulnerable /deployWebpackage.do endpoint must never be requested."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == "/commandcenter/":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(_target())

    assert not any("deploywebpackage" in u.lower() for u in requested)


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
        if path == "/commandcenter/":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert any(u.startswith("https://10.0.0.60:443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [443, 80, 8443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.62"))  # no ports key → default_ports

    assert 443 in contacted_ports
    assert 80 in contacted_ports
    assert 8443 in contacted_ports


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/commandcenter/":
            return _resp(200, _LOGIN_AFFECTED)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2025-34028"
    assert findings[0].confidence == "high"
