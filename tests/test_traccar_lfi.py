"""Tests for the Traccar unauthenticated LFI probe (CVE-2025-61666).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (see tests/test_fortiweb.py and
tests/test_tomcat_rewrite.py).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2025_61666"

# --- canned bodies ----------------------------------------------------------

# A realistic Traccar /api/server JSON body — the unauthenticated fingerprint.
_SERVER_INFO = (
    '{"id":1,"registration":true,"readonly":false,"deviceReadonly":false,'
    '"map":"locationIqStreets","bingKey":"","mapUrl":"","poiLayer":"",'
    '"version":"6.7","attributes":{}}'
)

# A realistic conf/traccar.xml — a Java properties XML carrying DB credentials.
_TRACCAR_CONFIG = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n'
    "<properties>\n"
    '  <entry key="config.default">./conf/default.xml</entry>\n'
    '  <entry key="database.driver">org.h2.Driver</entry>\n'
    '  <entry key="database.url">jdbc:h2:./data/database</entry>\n'
    '  <entry key="database.user">sa</entry>\n'
    '  <entry key="database.password">s3cr3t-db-pass</entry>\n'
    "</properties>\n"
)

# A non-secret config (no password/secret/database.user keys) → still HIGH (the
# LFI is confirmed) but secret_keys_present is False.
_TRACCAR_CONFIG_NO_SECRETS = (
    "<properties>\n"
    '  <entry key="config.default">./conf/default.xml</entry>\n'
    '  <entry key="web.port">8082</entry>\n'
    "</properties>\n"
)

# An SPA index.html the server returns for every unknown path — must NOT flag.
_SPA_INDEX = "<!DOCTYPE html><html><body>traccar web app</body></html>"


def _resp(status: int, text: str = "", headers=None):
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        text=text,
        headers=headers or {},
        request=request,
    )


def _make_fake_get(path_map: dict[str, httpx.Response], record: list | None = None):
    """Return a fake httpx.get that replies per-URL-path; unknown paths → 404."""

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path = urlparse(url).path
        return path_map.get(path, _resp(404))

    return fake_get


def _target() -> Target:
    """A single open Traccar web port keeps the probe surface deterministic."""
    return Target(host="10.0.0.50", ports={8082: {"state": "open", "name": "http"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2025-61666"
    assert module.metadata["name"].startswith("Traccar")
    assert 8082 in module.metadata["port_hint"]
    assert "http" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- confirmed LFI (HIGH) ---------------------------------------------------


def test_confirmed_lfi_returns_high(monkeypatch):
    """Config leaked via traversal while the direct path refuses → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO, {"content-type": "application/json"})
        # The direct config path is not web-servable on a sane install.
        if path == "/conf/traccar.xml":
            return _resp(404)
        # ...but a traversal shape leaks the config through the override servlet.
        if path.startswith("/override/") or path.startswith("/web/override/"):
            return _resp(200, _TRACCAR_CONFIG)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2025-61666"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.50"
    assert finding.evidence["direct_status"] == 404
    assert finding.evidence["traversal_status"] == 200
    assert finding.evidence["leaked_file"] == "conf/traccar.xml"
    assert finding.evidence["secret_keys_present"] is True
    # Key NAMES recorded; secret VALUES never persisted.
    assert "database.password" in finding.evidence["config_key_names"]
    assert "database.user" in finding.evidence["config_key_names"]


def test_high_finding_never_persists_secret_values(monkeypatch):
    """The leaked password VALUE must never appear anywhere in the evidence."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(403)
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    serialized = repr(finding.to_dict())
    assert "s3cr3t-db-pass" not in serialized


def test_config_without_secret_keys_is_still_high(monkeypatch):
    """A served config with no secret keys still confirms the LFI (HIGH)."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(404)
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG_NO_SECRETS)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["secret_keys_present"] is False


def test_fingerprint_via_root_body_when_api_server_missing(monkeypatch):
    """Fingerprint can fall back to the root page Traccar marker."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(404)  # patched/blocked server-info endpoint
        if path == "/":
            return _resp(200, "<html><title>Traccar</title></html>")
        if path == "/conf/traccar.xml":
            return _resp(404)
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"


# --- MEDIUM (fingerprinted, LFI not confirmed) ------------------------------


def test_fingerprinted_but_unconfirmed_returns_medium(monkeypatch):
    """Traccar fingerprints, a traversal answers oddly but not config → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(404)
        # Traversal returns 200 but a generic page, not the config XML.
        if "override" in path:
            return _resp(200, _SPA_INDEX)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert "note" in finding.evidence


def test_high_wins_over_medium_across_paths(monkeypatch):
    """An earlier odd 200 sets MEDIUM, a later real config still escalates HIGH."""
    module = load_plugin(PLUGIN)
    traversals = module._TRAVERSAL_PATHS

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(404)
        # First traversal shape → odd page (MEDIUM candidate); a later shape →
        # real config (HIGH wins).
        if path == traversals[0]:
            return _resp(200, _SPA_INDEX)
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"


# --- false-positive guards --------------------------------------------------


def test_non_traccar_host_is_never_flagged(monkeypatch):
    """A non-Traccar host that leaks an XML-ish body must NOT be flagged."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        # No Traccar markers anywhere; even the "config" leaks via traversal.
        if path == "/api/server":
            return _resp(200, '{"app":"something-else"}')
        if path == "/":
            return _resp(200, "<html>nginx welcome</html>")
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG)  # would be config — but no fp!
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_direct_config_served_blocks_high(monkeypatch):
    """If the direct config path is 200 (plain misconfig), HIGH is not asserted.

    The traversal still returns config, but the control (direct path) did not
    refuse, so the servlet-LFI is not cleanly confirmed → MEDIUM, not HIGH.
    """
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(200, _TRACCAR_CONFIG)  # direct path NOT refusing
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"


def test_all_traversals_rejected_is_no_finding(monkeypatch):
    """Traccar fingerprints but every traversal is 404 → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(404)
        return _resp(404)  # all traversals correctly rejected

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_traversal_403_is_no_finding(monkeypatch):
    """Traversals correctly forbidden (403) → no finding."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if "override" in path:
            return _resp(403)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


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
    requested: list = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(404)
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    target = Target(host="10.0.0.51", ports={443: {"state": "open", "name": "https"}})
    finding = module.probe(target)

    assert finding is not None
    assert any(u.startswith("https://10.0.0.51:443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [8082, 80, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.52"))  # no ports key → default_ports

    assert 8082 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/api/server":
            return _resp(200, _SERVER_INFO)
        if path == "/conf/traccar.xml":
            return _resp(404)
        if "override" in path:
            return _resp(200, _TRACCAR_CONFIG)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2025-61666"
    assert findings[0].confidence == "high"
