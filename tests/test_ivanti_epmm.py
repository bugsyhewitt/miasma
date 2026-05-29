"""Tests for the Ivanti EPMM unauthenticated RCE probe (CVE-2026-1340).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (see
tests/test_ivanti_connect_secure.py and tests/test_langflow.py).

The probe is BENIGN and never triggers the RCE: it must never POST, never
smuggle a Bash command, and never include an injection payload. HIGH is gated on
an EPMM fingerprint PLUS either a routed vulnerable feature endpoint OR an
affected (< 12.8.0.0) readable build; MEDIUM on an EPMM fingerprint with neither
signal; an EPMM host on a patched (>= 12.8.0.0) build with no reachable endpoint
is a clean negative; a non-EPMM host is never flagged.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2026_1340"

_ADMIN_PATH = "/mifs/admin"
_APPSTORE_FOB = "/mifs/c/appstore/fob/"
_AFTSTORE_FOB = "/mifs/c/aftstore/fob/"

# --- canned bodies ----------------------------------------------------------

# The EPMM admin/login surface fingerprints the appliance via the Ivanti User
# Portal title and the /mifs/ path family. No version token is present (EPMM does
# not serve its build unauthenticated on a sane appliance).
_EPMM_LOGIN = (
    "<!DOCTYPE html><html><head><title>Ivanti User Portal: Sign In</title>"
    "</head><body><form action='/mifs/admin/login.html'>"
    "<input name='username'></form></body></html>"
)

# A legacy MobileIron Core login page (still EPMM, older branding).
_MOBILEIRON_LOGIN = (
    "<html><head><title>MobileIron Sign In</title></head>"
    "<body><a href='/mifs/'>portal</a></body></html>"
)

# An EPMM login page that DOES leak a build string (rare, but possible behind a
# proxy that injects the version into a banner). Affected (< 12.8.0.0).
_EPMM_LOGIN_AFFECTED_VER = (
    "<html><head><title>Ivanti User Portal: Sign In</title></head>"
    "<body><!-- EPMM 12.7.0.1 Build 6 (Branch core-12.7.0.1) -->"
    "<a href='/mifs/'>portal</a></body></html>"
)

# An EPMM login page leaking a patched build string (>= 12.8.0.0).
_EPMM_LOGIN_PATCHED_VER = (
    "<html><head><title>Ivanti User Portal: Sign In</title></head>"
    "<body><!-- EPMM 12.8.0.0 Build 1 (Branch core-12.8.0.0) -->"
    "<a href='/mifs/'>portal</a></body></html>"
)

# A non-EPMM host that happens to expose a dotted version-looking token — must
# NOT fingerprint as EPMM.
_NOT_EPMM = "<html><body>API v12.7.0 — billing-service</body></html>"


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
    """A single open 443 EPMM port keeps the probe surface deterministic."""
    return Target(host="10.0.0.91", ports={443: {"state": "open", "name": "https"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2026-1340"
    assert "EPMM" in module.metadata["name"]
    assert 443 in module.metadata["port_hint"]
    assert "https" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- routed vulnerable endpoint (HIGH) --------------------------------------


def test_routed_appstore_endpoint_returns_high(monkeypatch):
    """EPMM fingerprint + a routed (non-404) /mifs/c/appstore/fob/ → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN)
        if path == _APPSTORE_FOB:
            return _resp(200, "")  # routed (legitimate use returns 200)
        if path == _AFTSTORE_FOB:
            return _resp(404)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2026-1340"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.91"
    assert finding.evidence["fingerprint_path"] == _ADMIN_PATH
    assert _APPSTORE_FOB in finding.evidence["routed_endpoints"]
    assert finding.evidence["fixed_version"] == "12.8.0.0"


def test_routed_aftstore_endpoint_with_403_is_high(monkeypatch):
    """A 403 on the aftstore feature endpoint is still 'routed' (non-404) → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN)
        if path == _APPSTORE_FOB:
            return _resp(404)
        if path == _AFTSTORE_FOB:
            return _resp(403)  # routed but refused — the path serves
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert _AFTSTORE_FOB in finding.evidence["routed_endpoints"]


def test_legacy_mobileiron_branding_fingerprints(monkeypatch):
    """The legacy MobileIron login still fingerprints EPMM → HIGH on routed fob."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, _MOBILEIRON_LOGIN)
        if path == _APPSTORE_FOB:
            return _resp(200, "")
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"


# --- affected readable version (HIGH) ---------------------------------------


def test_affected_version_returns_high_even_without_routed_endpoint(monkeypatch):
    """An affected (< 12.8.0.0) readable build is HIGH even if fob 404s."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN_AFFECTED_VER)
        # Both vulnerable endpoints 404 (not routed) — the version drives HIGH.
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "12.7.0.1"
    assert finding.evidence["routed_endpoints"] == []


def test_old_11x_version_is_high(monkeypatch):
    """A legacy 11.10.0.2 EPMM build is well below the fix → HIGH."""
    module = load_plugin(PLUGIN)
    body = (
        "<html><head><title>Ivanti User Portal: Sign In</title></head>"
        "<body><!-- EPMM 11.10.0.2 Build 6 --></body></html>"
    )

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, body)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["version_detected"] == "11.10.0.2"


# --- patched, no reachable endpoint (clean negative) ------------------------


def test_patched_version_with_no_routed_endpoint_is_not_flagged(monkeypatch):
    """A patched (>= 12.8.0.0) build with no reachable fob endpoint → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN_PATCHED_VER)
        return _resp(404)  # both fob endpoints not routed

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_patched_version_but_routed_endpoint_is_still_high(monkeypatch):
    """Even on a patched-version banner, a routed fob endpoint is the live RCE
    surface → HIGH (the endpoint-reachability signal is authoritative)."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN_PATCHED_VER)
        if path == _APPSTORE_FOB:
            return _resp(200, "")
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert _APPSTORE_FOB in finding.evidence["routed_endpoints"]


# --- no signal (MEDIUM) -----------------------------------------------------


def test_epmm_without_version_or_routed_endpoint_is_medium(monkeypatch):
    """EPMM fingerprints but no version and no routed fob endpoint → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN)  # no version token
        return _resp(404)  # both fob endpoints 404

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version_detected"] is None
    assert finding.evidence["routed_endpoints"] == []
    assert finding.evidence["fingerprint_path"] == _ADMIN_PATH


# --- false-positive guards --------------------------------------------------


def test_non_epmm_host_with_version_token_is_never_flagged(monkeypatch):
    """A 200 with a version-looking token but no EPMM marker must NOT flag."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        return _resp(200, _NOT_EPMM)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_non_epmm_host_is_never_flagged(monkeypatch):
    """A host with no EPMM markers anywhere → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        return _resp(200, "<html><body>It works!</body></html>")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_non_epmm_host_routed_fob_is_never_flagged(monkeypatch):
    """A non-EPMM host whose /mifs/c/...fob/ happens to 200 must NOT flag — the
    EPMM fingerprint gates everything, so routing alone never flags."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        # Every path 200s with a non-EPMM body — looks "open" but is not EPMM.
        return _resp(200, "<html><body>generic app</body></html>")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


# --- the RCE is NEVER triggered ---------------------------------------------


def test_probe_never_posts_and_sends_no_payload(monkeypatch):
    """The probe must only GET public paths and never POST / smuggle a command."""
    module = load_plugin(PLUGIN)
    contacted: list[str] = []

    def fake_get(url, *args, **kwargs):
        parsed = urlparse(url)
        contacted.append(parsed.path)
        # No request must carry a query string / command payload.
        assert parsed.query == ""
        path = parsed.path
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN)
        if path == _APPSTORE_FOB:
            return _resp(200, "")
        return _resp(404)

    def fake_post(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("probe must never POST")

    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.httpx, "post", fake_post, raising=False)

    module.probe(_target())

    # Only the declared benign fingerprint + feature-reachability paths may ever
    # be contacted — nothing else, and never with a payload.
    allowed = {
        _ADMIN_PATH,
        "/mifs/",
        "/mifs/c/windows/admin",
        "/",
        _APPSTORE_FOB,
        _AFTSTORE_FOB,
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
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN)
        if path == _APPSTORE_FOB:
            return _resp(200, "")
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
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN)
        if path == _APPSTORE_FOB:
            return _resp(200, "")
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert any(u.startswith("https://10.0.0.91:443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to the default port list."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.92"))  # no ports key → default_ports

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
        if path == _ADMIN_PATH:
            return _resp(200, _EPMM_LOGIN)
        if path == _APPSTORE_FOB:
            return _resp(200, "")
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2026-1340"
    assert findings[0].confidence == "high"
