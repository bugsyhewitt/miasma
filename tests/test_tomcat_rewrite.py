"""Tests for the Tomcat Rewrite Valve path-traversal probe (CVE-2025-55752).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path.
This mirrors the project's existing mock-at-the-seam testing convention
(see tests/test_actuator.py and tests/test_recon.py).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2025_55752"

# A minimal but realistic deployment descriptor body.
_WEB_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">\n'
    "  <display-name>secret-app</display-name>\n"
    "  <context-param>\n"
    "    <param-name>db.password</param-name>\n"
    "    <param-value>hunter2</param-value>\n"
    "  </context-param>\n"
    "</web-app>\n"
)

_TOMCAT_SERVER = "Apache-Coyote/1.1"


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
    """Return a fake httpx.get that replies per-URL-path.

    Any path not in ``path_map`` yields a 404. Optionally records called URLs.
    Note: keys are matched against the decoded ``urlparse`` path.
    """

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path = urlparse(url).path
        if path in path_map:
            return path_map[path]
        return _resp(404)

    return fake_get


# A single open HTTP-ish port keeps the probe surface small and deterministic.
def _target() -> Target:
    return Target(host="10.0.0.5", ports={8080: {"state": "open", "name": "http"}})


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2025-55752"
    assert callable(module.probe)


def test_confirmed_traversal_returns_high(monkeypatch):
    """A protected web.xml leaked via the simple traversal path → HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, "<h1>It works</h1>", headers={"server": _TOMCAT_SERVER}),
        "/WEB-INF/web.xml": _resp(200, _WEB_XML),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2025-55752"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.5"
    assert finding.evidence["traversal_path"] == "/WEB-INF/web.xml"
    assert finding.evidence["status_code"] == 200
    assert "coyote" in finding.evidence["server_header"].lower()


def test_confirmed_traversal_via_encoded_path(monkeypatch):
    """The simple path is blocked but an encoded traversal shape succeeds → HIGH."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            return _resp(200, "ok", headers={"server": _TOMCAT_SERVER})
        # The naive WEB-INF read is blocked...
        if path == "/WEB-INF/web.xml":
            return _resp(404)
        # ...but the encoded-traversal shapes carry %2e/%2f which urlparse keeps
        # raw in the path; any of them returning the descriptor confirms it.
        if "web.xml" in url.lower():
            return _resp(200, _WEB_XML)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    # The winning path must be one of the encoded traversal shapes, not the
    # plain /WEB-INF/web.xml (which was 404'd here).
    assert finding.evidence["traversal_path"] != "/WEB-INF/web.xml"
    assert "web.xml" in finding.evidence["traversal_path"].lower()


def test_tomcat_but_protected_returns_none(monkeypatch):
    """Tomcat fingerprinted but every protected path correctly 403/404 → none."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            return _resp(200, "ok", headers={"server": _TOMCAT_SERVER})
        # Every traversal attempt is correctly blocked.
        return _resp(403)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is None


def test_tomcat_with_suspicious_200_is_medium(monkeypatch):
    """Tomcat host returns a non-descriptor 200 on a protected path → MEDIUM."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            return _resp(200, "ok", headers={"server": _TOMCAT_SERVER})
        # A 200 that does NOT look like a deployment descriptor — suspicious but
        # not a confirmed read.
        return _resp(200, "<html>generic landing page</html>")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["status_code"] == 200
    assert "note" in finding.evidence


def test_non_tomcat_host_returns_none(monkeypatch):
    """A non-Tomcat host with odd 200s must not be flagged (no false positive)."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        path = urlparse(url).path
        if path == "/":
            return _resp(200, "ok", headers={"server": "nginx/1.25.0"})
        # Even a 200 here must not flag — not Tomcat, no descriptor body.
        return _resp(200, "<html>not a descriptor</html>")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(_target())

    assert finding is None


def test_high_wins_over_medium_across_ports(monkeypatch):
    """A MEDIUM hint on one port must not mask a confirmed HIGH on another."""
    module = load_plugin(PLUGIN)
    target = Target(
        host="h",
        ports={
            8080: {"state": "open", "name": "http"},
            8443: {"state": "open", "name": "https"},
        },
    )

    def fake_get(url, *args, **kwargs):
        parsed = urlparse(url)
        path = parsed.path
        port = parsed.port
        if path == "/":
            return _resp(200, "ok", headers={"server": _TOMCAT_SERVER})
        # Port 8080: suspicious 200 (would be MEDIUM on its own).
        if port == 8080:
            return _resp(200, "<html>landing</html>")
        # Port 8443: confirmed descriptor leak (HIGH).
        if port == 8443 and "web.xml" in url.lower():
            return _resp(200, _WEB_XML)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(target)

    assert finding is not None
    assert finding.confidence == "high"
    assert ":8443" in finding.evidence["base_url"]


def test_network_error_is_tolerated(monkeypatch):
    """Connection errors are swallowed; the probe returns None, never raises."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    assert module.probe(_target()) is None


def test_default_ports_used_when_no_recon(monkeypatch):
    """With no open ports from recon, the probe falls back to default ports."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []
    path_map = {
        "/": _resp(200, "ok", headers={"server": _TOMCAT_SERVER}),
        "/WEB-INF/web.xml": _resp(200, _WEB_XML),
    }
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    finding = module.probe(Target(host="10.0.0.9"))  # no ports → defaults

    assert finding is not None
    assert finding.confidence == "high"
    # The first default port (8080) should have been probed.
    assert any(":8080/" in u for u in requested)
    assert 8080 in module.metadata["default_ports"]


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/": _resp(200, "ok", headers={"server": _TOMCAT_SERVER}),
        "/WEB-INF/web.xml": _resp(200, _WEB_XML),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2025-55752"
    assert findings[0].confidence == "high"


@pytest.mark.parametrize(
    "port,expected_scheme",
    [(8080, "http"), (443, "https"), (8443, "https"), (80, "http")],
)
def test_scheme_selection_per_port(monkeypatch, port, expected_scheme):
    """https is used for 443/8443; http otherwise."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        return _resp(404)

    monkeypatch.setattr(module.httpx, "get", fake_get)
    module.probe(Target(host="h", ports={port: {"state": "open", "name": "http"}}))

    assert any(u.startswith(f"{expected_scheme}://h:{port}/") for u in requested)
