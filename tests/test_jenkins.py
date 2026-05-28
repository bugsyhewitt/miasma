"""Tests for the Jenkins CVE-2024-23897 file-read probe (cve_2024_23897).

All HTTP is mocked — no live network. The plugin uses ``httpx.Client`` (not the
module-level ``httpx.get`` the elastic plugin uses), so we monkeypatch
``module.httpx.Client`` with a fake client whose ``.get`` / ``.post`` route by
URL path and request ``Side`` header to canned responses. This mirrors the
project's mock-at-the-seam convention from tests/test_elastic.py.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import pytest

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins

PLUGIN = "cve_2024_23897"

# --- canned bodies ----------------------------------------------------------

# /etc/passwd first lines as echoed back by the args4j expansion in the CLI
# error. The "root:" marker is what the probe keys on.
_PASSWD_LEAK = (
    "ERROR: No such command: root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)
_NO_LEAK_REPLY = "ERROR: No such command: who-am-i\n"


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


class _FakeClient:
    """Stand-in for ``httpx.Client`` used as a context manager.

    ``login`` is the response for ``GET /login``. ``upload`` / ``download`` are
    the responses for the two ``POST /cli`` sides, selected via the ``Side``
    header. A handler that is ``None`` raises ``httpx.ConnectError`` to simulate
    an unreachable endpoint. ``record`` collects (method, path, side) tuples.
    """

    def __init__(
        self,
        login: httpx.Response | Exception | None = None,
        upload: httpx.Response | Exception | None = None,
        download: httpx.Response | Exception | None = None,
        record: list | None = None,
    ):
        self._login = login
        self._upload = upload
        self._download = download
        self._record = record

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _resolve(self, handler):
        if isinstance(handler, Exception):
            raise handler
        if handler is None:
            raise httpx.ConnectError("refused")
        return handler

    def get(self, url, *args, **kwargs):
        if self._record is not None:
            self._record.append(("GET", urlparse(url).path, None))
        return self._resolve(self._login)

    def post(self, url, *args, headers=None, **kwargs):
        side = (headers or {}).get("Side")
        if self._record is not None:
            self._record.append(("POST", urlparse(url).path, side))
        handler = self._upload if side == "upload" else self._download
        return self._resolve(handler)


def _client_factory(**kw):
    """Return a callable usable as ``httpx.Client(...)`` that yields a fake."""

    def factory(*args, **kwargs):
        return _FakeClient(**kw)

    return factory


def _target() -> Target:
    """Single open Jenkins port keeps the probe surface deterministic."""
    return Target(
        host="10.0.0.20",
        ports={8080: {"state": "open", "name": "http", "product": "Jenkins"}},
    )


# --- discoverability --------------------------------------------------------


def test_plugin_is_discoverable_and_valid():
    assert PLUGIN in available_plugins()
    module = load_plugin(PLUGIN)
    assert module.metadata["vuln_id"] == "CVE-2024-23897"
    assert module.metadata["name"].startswith("Jenkins")
    assert 8080 in module.metadata["default_ports"]
    assert 8080 in module.metadata["port_hint"]
    assert callable(module.probe)


# --- version classification (unit) ------------------------------------------


@pytest.mark.parametrize(
    "version,expected",
    [
        ("2.441", True),  # last vulnerable weekly
        ("2.440", True),
        ("2.442", False),  # patched weekly
        ("2.426.2", True),  # last vulnerable LTS
        ("2.426.1", True),
        ("2.426.3", False),  # patched LTS
        ("2.427", True),  # weekly <= 2.441 is still in scope
        ("not-a-version", False),
    ],
)
def test_version_classification(version, expected):
    module = load_plugin(PLUGIN)
    assert module._is_vulnerable_version(version) is expected


# --- HIGH: confirmed file read ----------------------------------------------


def test_file_read_confirmed_is_high(monkeypatch):
    """CLI download reply leaks /etc/passwd (root:) => HIGH, confirmed."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins": "2.440"}),
            upload=_resp(200, ""),
            download=_resp(200, _PASSWD_LEAK),
        ),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.vuln_id == "CVE-2024-23897"
    assert finding.confidence == "high"
    assert finding.host == "10.0.0.20"
    assert finding.evidence["file_read_confirmed"] is True
    assert finding.evidence["port"] == 8080
    assert "root:" in finding.evidence["leak_excerpt"]


def test_file_read_confirmed_via_upload_reply_is_high(monkeypatch):
    """Leak echoed in the upload reply (not download) is still detected."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins": "2.426.1"}),
            upload=_resp(200, _PASSWD_LEAK),
            download=_resp(200, ""),
        ),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    assert finding.evidence["file_read_confirmed"] is True


def test_high_wins_even_on_patched_version(monkeypatch):
    """An actual leak overrides version classification (defence in depth)."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins": "2.500"}),  # "patched"
            upload=_resp(200, ""),
            download=_resp(200, _PASSWD_LEAK),
        ),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"


# --- MEDIUM: vulnerable version, read not confirmed -------------------------


def test_vulnerable_version_no_leak_is_medium(monkeypatch):
    """In-scope version but the CLI read produced no leak => MEDIUM."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins": "2.426.2"}),
            upload=_resp(200, _NO_LEAK_REPLY),
            download=_resp(200, _NO_LEAK_REPLY),
        ),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version_in_scope"] is True
    assert finding.evidence["file_read_confirmed"] is False
    assert finding.evidence["jenkins_version"] == "2.426.2"


def test_vulnerable_version_cli_unreachable_is_medium(monkeypatch):
    """In-scope version with the CLI endpoint unreachable still flags MEDIUM."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins": "2.441"}),
            upload=None,  # ConnectError
            download=None,
        ),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "medium"
    assert finding.evidence["version_in_scope"] is True


# --- none: patched / not jenkins --------------------------------------------


def test_patched_version_no_leak_is_no_finding(monkeypatch):
    """Patched Jenkins with no leak => no finding."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins": "2.426.3"}),
            upload=_resp(200, _NO_LEAK_REPLY),
            download=_resp(200, _NO_LEAK_REPLY),
        ),
    )

    assert module.probe(_target()) is None


def test_not_jenkins_is_no_finding(monkeypatch):
    """No X-Jenkins header and no Jenkins markers => not Jenkins => None."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(login=_resp(200, "<html>just nginx</html>")),
    )

    assert module.probe(_target()) is None


def test_login_connection_error_is_no_finding(monkeypatch):
    """A socket error on /login for every candidate port => no finding."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx, "Client", _client_factory(login=None)  # ConnectError
    )

    assert module.probe(_target()) is None


# --- fingerprint fallback (no X-Jenkins header) -----------------------------


def test_jenkins_marker_without_version_header(monkeypatch):
    """Jenkins identified via X-Jenkins-Session header; leak still => HIGH."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins-Session": "abc"}),
            upload=_resp(200, ""),
            download=_resp(200, _PASSWD_LEAK),
        ),
    )

    finding = module.probe(_target())

    assert finding is not None
    assert finding.confidence == "high"
    # No version header → no jenkins_version evidence key.
    assert "jenkins_version" not in finding.evidence


def test_marker_only_no_leak_is_no_finding(monkeypatch):
    """Jenkins marker present, no version, no leak => not enough to flag."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins-Session": "abc"}),
            upload=_resp(200, _NO_LEAK_REPLY),
            download=_resp(200, _NO_LEAK_REPLY),
        ),
    )

    assert module.probe(_target()) is None


# --- command framing (unit) -------------------------------------------------


def test_cli_command_frames_passwd_arg():
    """The framed command includes the who-am-i op and the @/etc/passwd arg."""
    module = load_plugin(PLUGIN)
    framed = module._build_cli_command()
    assert b"who-am-i" in framed
    assert b"@/etc/passwd" in framed
    # Ends with the zero-length Start frame (4 zero bytes + op 3).
    assert framed.endswith(b"\x00\x00\x00\x00\x03")


# --- port fallback ----------------------------------------------------------


def test_default_ports_probed_when_no_recon(monkeypatch):
    """With no recon data the probe falls back to the port hints."""
    module = load_plugin(PLUGIN)
    contacted: list[int] = []

    class _Recorder(_FakeClient):
        def get(self, url, *args, **kwargs):
            contacted.append(int(urlparse(url).netloc.split(":")[1]))
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(module.httpx, "Client", lambda *a, **k: _Recorder())

    module.probe(Target(host="10.0.0.21"))  # no ports → port_hint

    for port in module.metadata["port_hint"]:
        assert port in contacted


# --- runner integration -----------------------------------------------------


def test_run_through_runner_collects_finding(monkeypatch):
    """End-to-end via run_plugins: the finding flows out of the runner."""
    module = load_plugin(PLUGIN)
    monkeypatch.setattr(
        module.httpx,
        "Client",
        _client_factory(
            login=_resp(200, "<html>", {"X-Jenkins": "2.440"}),
            upload=_resp(200, ""),
            download=_resp(200, _PASSWD_LEAK),
        ),
    )

    findings = run_plugins(_target(), [PLUGIN])

    assert len(findings) == 1
    assert findings[0].vuln_id == "CVE-2024-23897"
    assert findings[0].confidence == "high"
