"""Tests for the exposed .env file probe (MIASMA-ENV-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the plugin
module and route each request to a canned response keyed by URL path. This
mirrors the project's mock-at-the-seam convention (tests/test_git_exposure.py).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_env_001"

# --- helpers ----------------------------------------------------------------

_ENV_WITH_SECRETS = (
    "APP_NAME=Acme\n"
    "APP_ENV=production\n"
    "# database\n"
    "DB_PASSWORD=s3cr3tpass\n"
    "AWS_SECRET_ACCESS_KEY=AKIAEXAMPLEKEY/deadbeef\n"
    "DATABASE_URL=postgres://app:hunter2@db.internal:5432/acme\n"
    "\n"
    "JWT_TOKEN=eyJhbGciOiJIUzI1NiJ9.payload.sig\n"
)
_ENV_CONFIG_ONLY = (
    "APP_NAME=Acme\n"
    "APP_ENV=production\n"
    "APP_DEBUG=false\n"
    "LOG_LEVEL=info\n"
)
_ENV_WITH_EXPORT = "export STRIPE_SECRET=sk_live_deadbeef\n"
_SPA_INDEX = "<!DOCTYPE html><html><body>app</body></html>"
_EMPTY = ""


def _resp(status: int, body: str = "", headers: dict | None = None) -> httpx.Response:
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers=headers or {},
        request=request,
    )


def _make_fake_get(path_map: dict[str, httpx.Response], record: list | None = None):
    """Return a fake httpx.get routing by URL path. Unknown paths yield 404."""

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append(url)
        path = urlparse(url).path or "/"
        return path_map.get(path, _resp(404))

    return fake_get


def _target() -> Target:
    """Single open web port keeps the probe surface small and deterministic."""
    return Target(host="10.0.0.30", ports={80: {"state": "open", "name": "http"}})


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-ENV-001"
    assert module.metadata["name"] == "Exposed .env File"
    assert 80 in module.metadata["port_hint"]
    assert 443 in module.metadata["port_hint"]
    assert callable(module.probe)


# --- exposed .env with secrets (HIGH) ---------------------------------------


def test_exposed_env_with_secrets_returns_high_finding(monkeypatch):
    """/.env returns dotenv content with secret-bearing keys => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {"/.env": _resp(200, _ENV_WITH_SECRETS)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-ENV-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.30"
    assert finding.evidence["path"] == "/.env"
    assert finding.evidence["url"] == "http://10.0.0.30:80/.env"
    # Secret-bearing keys are flagged...
    secret_keys = finding.evidence["secret_keys"]
    assert "DB_PASSWORD" in secret_keys
    assert "AWS_SECRET_ACCESS_KEY" in secret_keys
    assert "DATABASE_URL" in secret_keys
    assert "JWT_TOKEN" in secret_keys
    # ...non-secret keys are still recorded in the full key list.
    assert "APP_NAME" in finding.evidence["exposed_keys"]


def test_secret_values_are_never_persisted(monkeypatch):
    """The leaked secret VALUES must not appear in evidence or description."""
    module = load_plugin(PLUGIN)
    path_map = {"/.env": _resp(200, _ENV_WITH_SECRETS)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    blob = repr(finding.to_dict())
    assert "s3cr3tpass" not in blob
    assert "hunter2" not in blob
    assert "AKIAEXAMPLEKEY" not in blob
    assert "eyJhbGciOiJIUzI1NiJ9" not in blob


def test_export_prefixed_secret_key_is_detected(monkeypatch):
    """`export STRIPE_SECRET=...` is dotenv-shaped and secret-bearing => HIGH."""
    module = load_plugin(PLUGIN)
    path_map = {"/.env": _resp(200, _ENV_WITH_EXPORT)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert "STRIPE_SECRET" in finding.evidence["secret_keys"]


# --- config-only .env (MEDIUM) ----------------------------------------------


def test_config_only_env_returns_medium_finding(monkeypatch):
    """A served .env with no secret-bearing keys => MEDIUM (still disclosure)."""
    module = load_plugin(PLUGIN)
    path_map = {"/.env": _resp(200, _ENV_CONFIG_ONLY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["secret_keys"] == []
    assert finding.evidence["key_count"] == 4


# --- variant paths ----------------------------------------------------------


def test_env_production_variant_is_probed(monkeypatch):
    """When /.env is absent, /.env.production is still checked and flagged."""
    module = load_plugin(PLUGIN)
    path_map = {
        "/.env": _resp(404),
        "/.env.production": _resp(200, _ENV_WITH_SECRETS),
    }
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["path"] == "/.env.production"


# --- false-positive guards --------------------------------------------------


def test_spa_index_html_is_not_flagged(monkeypatch):
    """A server returning index.html (200) for every path must NOT be flagged."""
    module = load_plugin(PLUGIN)
    path_map = {"/.env": _resp(200, _SPA_INDEX)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_empty_200_body_is_not_flagged(monkeypatch):
    """A 200 with an empty body is not dotenv-shaped => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {"/.env": _resp(200, _EMPTY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


def test_env_404_is_no_finding(monkeypatch):
    """/.env (and variants) 404 => not exposed => no finding."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(module.httpx, "get", _make_fake_get({}))  # all 404

    assert module.probe(_target()) is None


def test_env_403_is_no_finding(monkeypatch):
    """/.env 403 (denied) => not exposed => no finding."""
    module = load_plugin(PLUGIN)
    path_map = {p: _resp(403) for p in module._CANDIDATE_PATHS}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    assert module.probe(_target()) is None


# --- connection / timeout errors --------------------------------------------


def test_connection_error_is_no_finding(monkeypatch):
    """A socket error on every candidate port => no finding, no exception."""
    module = load_plugin(PLUGIN)

    def boom(url, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(module.httpx, "get", boom)

    assert module.probe(_target()) is None


def test_timeout_is_no_finding(monkeypatch):
    """A timeout on every candidate port => no finding, no exception raised."""
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
    path_map = {"/.env": _resp(200, _ENV_WITH_SECRETS)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(path_map, record=requested)
    )

    target = Target(host="10.0.0.31", ports={443: {"state": "open", "name": "https"}})
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 443
    assert any(u.startswith("https://10.0.0.31:443/") for u in requested)


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [80, 443, 8080, 8443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split(":")[2].split("/")[0])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.32"))  # no ports key → default_ports

    assert 80 in contacted_ports
    assert 443 in contacted_ports
    assert 8080 in contacted_ports
    assert 8443 in contacted_ports


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    path_map = {"/.env": _resp(200, _ENV_WITH_SECRETS)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(path_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-ENV-001"
    assert findings[0].confidence == "high"
