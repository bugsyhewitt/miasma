"""Tests for the RabbitMQ Management API unauthenticated / default-credential
probe (MIASMA-RABBITMQ-001).

All HTTP is mocked — no live network. We monkeypatch ``httpx.get`` on the
plugin module and route each request to a canned response keyed by URL path
and whether the request carried HTTP Basic auth. This mirrors the project's
mock-at-the-seam convention established in tests/test_grafana.py and
tests/test_elastic.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "miasma_rabbitmq_001"

# --- canned response bodies -------------------------------------------------

# A realistic /api/overview body trimmed to the keys the probe parses.
_OVERVIEW_BODY = (
    '{"rabbitmq_version":"3.13.0",'
    '"management_version":"3.13.0",'
    '"erlang_version":"26.2.1",'
    '"cluster_name":"rabbit@host"}'
)

# A JSON 200 that is NOT RabbitMQ (missing the rabbitmq_version /
# management_version top-level keys). The probe must not be fooled by a
# coincidental 200 JSON object.
_NOT_RABBITMQ_BODY = '{"status":"ok","service":"other"}'

# The WWW-Authenticate header RabbitMQ's management plugin returns on a 401.
_RABBITMQ_CHALLENGE_HEADERS = {
    "www-authenticate": 'Basic realm="RabbitMQ Management"'
}

# A generic 401 challenge from some unrelated service — must NOT be treated
# as a RabbitMQ fingerprint, so the probe must NOT then attempt guest:guest.
_GENERIC_CHALLENGE_HEADERS = {
    "www-authenticate": 'Basic realm="Restricted"'
}


def _resp(
    status: int, body: str = "", headers: dict | None = None
) -> httpx.Response:
    """Build a real httpx.Response (no network) for a canned reply."""
    request = httpx.Request("GET", "http://example.test")
    return httpx.Response(
        status_code=status,
        content=body.encode(),
        headers=headers or {},
        request=request,
    )


def _make_fake_get(
    anon_map: dict[str, httpx.Response],
    auth_map: dict[str, httpx.Response] | None = None,
    record: list | None = None,
):
    """Return a fake httpx.get routing by URL path AND auth presence.

    ``anon_map`` maps URL path -> response for requests with no auth.
    ``auth_map`` maps URL path -> response for requests carrying any auth.
    """
    auth_map = auth_map or {}

    def fake_get(url, *args, **kwargs):
        if record is not None:
            record.append((url, kwargs.get("auth")))
        path = urlparse(url).path or "/"
        if kwargs.get("auth") is not None:
            return auth_map.get(path, _resp(404))
        return anon_map.get(path, _resp(404))

    return fake_get


def _target() -> Target:
    """Single open RabbitMQ management port keeps the probe surface deterministic."""
    return Target(
        host="10.0.0.30", ports={15672: {"state": "open", "name": "rabbitmq"}}
    )


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "MIASMA-RABBITMQ-001"
    assert (
        module.metadata["name"]
        == "RabbitMQ Management API Unauthenticated / Default-Credential Access"
    )
    assert 15672 in module.metadata["port_hint"]
    assert 15671 in module.metadata["port_hint"]
    assert 15672 in module.metadata["default_ports"]
    assert "rabbitmq" in module.metadata["service_hint"]
    assert "amqp" in module.metadata["service_hint"]
    assert callable(module.probe)


# --- anonymous access (HIGH) ------------------------------------------------


def test_anonymous_overview_is_high(monkeypatch):
    """/api/overview returns 200 with RabbitMQ body and no auth => HIGH."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(200, _OVERVIEW_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(anon_map))

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "MIASMA-RABBITMQ-001"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.30"
    assert finding.evidence["anonymous_access"] is True
    assert finding.evidence["rabbitmq_version"] == "3.13.0"
    assert finding.evidence["management_version"] == "3.13.0"
    assert finding.evidence["erlang_version"] == "26.2.1"
    assert finding.evidence["port"] == 15672
    # On the anonymous-access path we MUST NOT have set default_creds.
    assert "default_creds" not in finding.evidence


def test_anonymous_path_does_not_attempt_credentials(monkeypatch):
    """If /api/overview answers anonymously the probe must NOT then try guest:guest.

    The anonymous read already confirms the finding (HIGH); a follow-up
    guest:guest attempt would be wasted work and would muddy the evidence
    (anonymous_access vs default_creds).
    """
    module = load_plugin(PLUGIN)
    contacted: list = []
    anon_map = {"/api/overview": _resp(200, _OVERVIEW_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(anon_map, record=contacted)
    )

    module.probe(_target())

    auth_requests = [auth for _, auth in contacted if auth is not None]
    assert auth_requests == []


# --- default credentials (CRITICAL) -----------------------------------------


def test_default_creds_guest_guest_is_critical(monkeypatch):
    """401 challenge anonymously + 200 overview with guest:guest => CRITICAL."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(401, headers=_RABBITMQ_CHALLENGE_HEADERS)}
    auth_map = {"/api/overview": _resp(200, _OVERVIEW_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(anon_map, auth_map)
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "critical"
    assert finding.evidence["default_creds"] is True
    assert finding.evidence["matched_user"] == "guest"
    assert finding.evidence["rabbitmq_version"] == "3.13.0"
    assert finding.evidence["management_version"] == "3.13.0"
    assert finding.evidence["erlang_version"] == "26.2.1"
    assert finding.evidence["port"] == 15672
    # The default-creds path is mutually exclusive with anonymous_access.
    assert "anonymous_access" not in finding.evidence


def test_default_creds_uses_only_the_factory_pair(monkeypatch):
    """The single attempted login uses guest:guest only — no brute force."""
    module = load_plugin(PLUGIN)
    contacted: list = []
    anon_map = {"/api/overview": _resp(401, headers=_RABBITMQ_CHALLENGE_HEADERS)}
    auth_map = {"/api/overview": _resp(200, _OVERVIEW_BODY)}
    monkeypatch.setattr(
        module.httpx,
        "get",
        _make_fake_get(anon_map, auth_map, record=contacted),
    )

    module.probe(_target())

    auth_pairs = [auth for _, auth in contacted if auth is not None]
    assert auth_pairs == [("guest", "guest")]


# --- auth enforced / not vulnerable -----------------------------------------


def test_auth_enforced_guest_rejected_is_no_finding(monkeypatch):
    """RabbitMQ fingerprinted but guest:guest also 401 => no finding."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(401, headers=_RABBITMQ_CHALLENGE_HEADERS)}
    auth_map = {"/api/overview": _resp(401, headers=_RABBITMQ_CHALLENGE_HEADERS)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(anon_map, auth_map)
    )

    assert module.probe(_target()) is None


def test_guest_forbidden_is_no_finding(monkeypatch):
    """guest:guest returns 403 (guest restricted properly) => no finding."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(401, headers=_RABBITMQ_CHALLENGE_HEADERS)}
    auth_map = {"/api/overview": _resp(403)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(anon_map, auth_map)
    )

    assert module.probe(_target()) is None


# --- false-positive guards --------------------------------------------------


def test_non_rabbitmq_200_is_no_finding(monkeypatch):
    """A 200 JSON without rabbitmq_version / management_version keys => None."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(200, _NOT_RABBITMQ_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(anon_map))

    assert module.probe(_target()) is None


def test_non_rabbitmq_200_does_not_attempt_credentials(monkeypatch):
    """A non-RabbitMQ 200 must NOT trigger a guest:guest follow-up.

    Submitting guest:guest against an unrelated service would be probing
    arbitrary 200-returning endpoints with credentials, which violates the
    benign-probe contract.
    """
    module = load_plugin(PLUGIN)
    contacted: list = []
    anon_map = {"/api/overview": _resp(200, _NOT_RABBITMQ_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(anon_map, record=contacted)
    )

    module.probe(_target())

    auth_requests = [auth for _, auth in contacted if auth is not None]
    assert auth_requests == []


def test_generic_401_does_not_attempt_credentials(monkeypatch):
    """A 401 from an unrelated service (no RabbitMQ realm) must NOT trigger guest:guest.

    Without the RabbitMQ WWW-Authenticate fingerprint we have no positive
    confirmation that the service is RabbitMQ, so attempting the default
    credential would be credential-spraying against arbitrary 401-returning
    services.
    """
    module = load_plugin(PLUGIN)
    contacted: list = []
    anon_map = {"/api/overview": _resp(401, headers=_GENERIC_CHALLENGE_HEADERS)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(anon_map, record=contacted)
    )

    finding = module.probe(_target())

    assert finding is None
    auth_requests = [auth for _, auth in contacted if auth is not None]
    assert auth_requests == []


def test_html_200_is_no_finding(monkeypatch):
    """A 200 with non-JSON HTML body (a default SPA) => not RabbitMQ => None."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(200, "<html><body>hello</body></html>")}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(anon_map))

    assert module.probe(_target()) is None


def test_json_array_at_overview_is_no_finding(monkeypatch):
    """A 200 returning a JSON array (not an object) => not RabbitMQ => None."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(200, '[]')}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(anon_map))

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


# --- port fallback / scheme -------------------------------------------------


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to [15672, 15671, 80, 443]."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        # parse port from URL like https://host:443/path or http://host:80/path
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.31"))  # no ports → default_ports

    assert 15672 in contacted_ports
    assert 15671 in contacted_ports
    assert 80 in contacted_ports
    assert 443 in contacted_ports


def test_https_scheme_used_for_tls_ports(monkeypatch):
    """Ports 15671 and 443 are contacted over HTTPS; 15672 / 80 over HTTP."""
    module = load_plugin(PLUGIN)
    urls: list[str] = []

    def fake_get(url, *args, **kwargs):
        urls.append(url)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="10.0.0.32"))  # no recon → default ports

    assert any(u.startswith("https://10.0.0.32:15671/") for u in urls)
    assert any(u.startswith("https://10.0.0.32:443/") for u in urls)
    assert any(u.startswith("http://10.0.0.32:15672/") for u in urls)
    assert any(u.startswith("http://10.0.0.32:80/") for u in urls)


def test_default_port_15672_used_first(monkeypatch):
    """15672 must be the first candidate port the probe contacts."""
    module = load_plugin(PLUGIN)
    contacted_ports: list[int] = []

    def fake_get(url, *args, **kwargs):
        port = int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])
        contacted_ports.append(port)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "get", fake_get)

    module.probe(Target(host="h"))

    assert contacted_ports[0] == 15672


def test_recon_service_name_matches_rabbitmq(monkeypatch):
    """A non-default port marked as a rabbitmq service in recon is probed."""
    module = load_plugin(PLUGIN)
    contacted: list = []
    anon_map = {"/api/overview": _resp(200, _OVERVIEW_BODY)}
    monkeypatch.setattr(
        module.httpx, "get", _make_fake_get(anon_map, record=contacted)
    )

    # RabbitMQ on a non-default port; recon labels it rabbitmq.
    target = Target(
        host="10.0.0.33",
        ports={28080: {"state": "open", "name": "rabbitmq"}},
    )
    finding = module.probe(target)

    assert finding is not None
    assert finding.evidence["port"] == 28080
    assert contacted[0][0].startswith("http://10.0.0.33:28080/")


# --- evidence redaction -----------------------------------------------------


def test_finding_evidence_never_contains_broker_inventory(monkeypatch):
    """The finding evidence must not carry queues / exchanges / connections.

    The probe reads /api/overview which contains broker statistics, but the
    finding evidence should only record host/port/version markers — never the
    enumerated topology, which could leak operator-chosen queue/exchange
    names. Mirrors the existing redaction convention used by miasma_env_001
    and miasma_git_001.
    """
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(200, _OVERVIEW_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(anon_map))

    finding = module.probe(_target())

    assert finding is not None
    allowed_keys = {
        "host",
        "port",
        "anonymous_access",
        "default_creds",
        "matched_user",
        "rabbitmq_version",
        "management_version",
        "erlang_version",
    }
    assert set(finding.evidence.keys()).issubset(allowed_keys)


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    anon_map = {"/api/overview": _resp(200, _OVERVIEW_BODY)}
    monkeypatch.setattr(module.httpx, "get", _make_fake_get(anon_map))

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-RABBITMQ-001"
    assert findings[0].confidence == "high"
