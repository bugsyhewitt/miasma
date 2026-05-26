"""Tests for the Spring Boot Actuator exposure probe (MIASMA-ACTUATOR-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path.
This mirrors the project's existing mock-at-the-seam testing convention
(see tests/test_recon.py, which mocks the nmap-wrapper seam).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_actuator_001"


def _resp(status: int, json_body=None, headers=None):
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        json=json_body if json_body is not None else {},
        headers=headers or {},
        request=request,
    )


def _make_fake_get(path_map: dict[str, httpx.Response], record: list | None = None):
    """Return a fake httpx.get that replies per-URL-path.

    Any path not in ``path_map`` yields a 404. Optionally records called URLs.
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
    assert module.metadata["vuln_id"] == "MIASMA-ACTUATOR-001"
    assert callable(module.probe)


def test_full_exposure_env_with_secrets_is_high(monkeypatch):
    """/actuator/env returns 200 with secret-bearing keys → HIGH."""
    module = load_plugin(PLUGIN)
    env_body = {
        "propertySources": [
            {
                "name": "systemEnvironment",
                "properties": {
                    "DB_PASSWORD": {"value": "******"},
                    "spring.datasource.username": {"value": "admin"},
                    "API_TOKEN": {"value": "abc123"},
                },
            }
        ]
    }
    path_map = {
        "/actuator/health": _resp(200, {"status": "UP"}),
        "/actuator": _resp(200, {"_links": {"env": {"href": "..."}}}),
        "/actuator/env": _resp(200, env_body),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-ACTUATOR-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.5"
    # Evidence names the leaked-secret keys so a human can confirm by hand.
    leaked = finding.evidence.get("secret_keys", [])
    assert any("password" in k.lower() for k in leaked)
    assert any("token" in k.lower() for k in leaked)


def test_partial_exposure_actuator_open_env_forbidden_is_medium(monkeypatch):
    """/actuator reachable but /actuator/env 403 → MEDIUM."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/actuator/health": _resp(200, {"status": "UP"}),
        "/actuator": _resp(200, {"_links": {"health": {"href": "..."}}}),
        "/actuator/env": _resp(403),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["actuator_status"] == 200
    assert finding.evidence["env_status"] == 403


def test_generic_spring_app_health_only_is_medium(monkeypatch):
    """/actuator/health 200 but env reachable with no secrets → MEDIUM."""
    module = load_plugin(PLUGIN)
    env_body = {
        "propertySources": [
            {
                "name": "systemProperties",
                "properties": {
                    "java.version": {"value": "21"},
                    "user.timezone": {"value": "UTC"},
                },
            }
        ]
    }
    path_map = {
        "/actuator/health": _resp(200, {"status": "UP"}),
        "/actuator": _resp(200, {"_links": {}}),
        "/actuator/env": _resp(200, env_body),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    # env is reachable (exposure) but leaks no recognised secrets → MEDIUM.
    assert finding.confidence == "medium"
    assert finding.evidence.get("secret_keys", []) == []


def test_no_exposure_all_404_is_no_finding(monkeypatch):
    """Nothing under /actuator responds 200 → no finding."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(module.httpx, "get", _make_fake_get({}))

    finding = module.probe(_target())

    assert finding is None


def test_heapdump_is_checked_not_downloaded(monkeypatch):
    """When env leaks secrets, heapdump is probed via header-only check."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []
    env_body = {
        "propertySources": [
            {"name": "env", "properties": {"SECRET_KEY": {"value": "x"}}}
        ]
    }
    path_map = {
        "/actuator/health": _resp(200, {"status": "UP"}),
        "/actuator": _resp(200, {}),
        "/actuator/env": _resp(200, env_body),
        "/actuator/heapdump": _resp(
            200,
            headers={
                "content-type": "application/octet-stream",
                "content-length": "52428800",
            },
        ),
    }
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    # heapdump must have been probed...
    assert any(u.endswith("/actuator/heapdump") for u in requested)
    # ...and reported via headers, never by reading the body.
    assert finding.evidence["heapdump"]["available"] is True
    assert finding.evidence["heapdump"]["content_length"] == "52428800"


def test_heapdump_probe_uses_no_stream_download(monkeypatch):
    """The heapdump check must not pull the body (header-only)."""
    module = load_plugin(PLUGIN)
    env_body = {
        "propertySources": [
            {"name": "env", "properties": {"PASSWORD": {"value": "x"}}}
        ]
    }
    seen_kwargs: list[dict] = []

    def fake_get(url, *args, **kwargs):
        seen_kwargs.append(kwargs)
        path = urlparse(url).path
        mapping = {
            "/actuator/health": _resp(200, {"status": "UP"}),
            "/actuator": _resp(200, {}),
            "/actuator/env": _resp(200, env_body),
            "/actuator/heapdump": _resp(
                200, headers={"content-type": "application/octet-stream"}
            ),
        }
        return mapping.get(path, _resp(404))

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(_target())

    # No call should request streaming/body download of the heapdump.
    for kw in seen_kwargs:
        assert kw.get("stream") in (None, False)


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    env_body = {
        "propertySources": [
            {"name": "env", "properties": {"DB_SECRET": {"value": "x"}}}
        ]
    }
    path_map = {
        "/actuator/health": _resp(200, {"status": "UP"}),
        "/actuator": _resp(200, {}),
        "/actuator/env": _resp(200, env_body),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-ACTUATOR-001"
    assert findings[0].confidence == "high"


def test_default_ports_used_when_no_recon(monkeypatch):
    """With no open ports from recon, probe falls back to default ports."""
    module = load_plugin(PLUGIN)
    requested: list[str] = []
    env_body = {
        "propertySources": [
            {"name": "env", "properties": {"TOKEN": {"value": "x"}}}
        ]
    }

    def fake_get(url, *args, **kwargs):
        requested.append(url)
        path = urlparse(url).path
        mapping = {
            "/actuator/health": _resp(200, {"status": "UP"}),
            "/actuator": _resp(200, {}),
            "/actuator/env": _resp(200, env_body),
        }
        return mapping.get(path, _resp(404))

    monkeypatch.setattr(module.httpx, "get", fake_get)

    finding = module.probe(Target(host="10.0.0.9"))  # no ports → defaults

    assert finding is not None
    # With no recon data the probe falls back to the default management ports
    # and tries the first one (80). It short-circuits on the first reachable
    # vulnerable port, so only that port need have been probed.
    assert any(":80/" in u for u in requested)
    assert metadata_default_ports_contains_8080(module)


def metadata_default_ports_contains_8080(module) -> bool:
    """Guard: 8080 remains a declared default management port."""
    return 8080 in module.metadata["default_ports"]


def test_network_error_on_one_port_is_tolerated(monkeypatch):
    """A connection error on a port is swallowed; probing continues."""
    module = load_plugin(PLUGIN)

    def fake_get(url, *args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    # Must not raise — returns None when nothing is reachable.
    assert module.probe(_target()) is None


@pytest.mark.parametrize(
    "port,expected_scheme",
    [(8080, "http"), (443, "https"), (8443, "https"), (8090, "http")],
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
