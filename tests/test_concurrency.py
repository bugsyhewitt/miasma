"""Tests for concurrent plugin execution in the runner.

``run_plugins(..., concurrency=N)`` runs up to N I/O-bound plugin probes in
parallel through a ThreadPoolExecutor. The contract the runner must hold no
matter how many threads run:

* findings come back in the **requested plugin order** (concurrency changes
  timing, never output);
* error isolation is preserved — one raising plugin becomes an
  ``"error"`` finding, the rest still run;
* inapplicable plugins are filtered out *before* any worker slot is used;
* probes genuinely overlap when ``concurrency > 1`` (the speed-up is real);
* ``concurrency=1`` reproduces the original sequential behaviour exactly;
* invalid concurrency values are rejected.
"""

import sys
import threading
import time
from types import ModuleType, SimpleNamespace

import pytest

from miasma.core import Finding, Target
from miasma.runner import run_plugins


def _register_plugin(monkeypatch, name, probe, metadata=None):
    """Register a fake plugin module so ``load_plugin(name)`` resolves it.

    ``load_plugin`` does ``importlib.import_module("miasma.plugins.<name>")``;
    seeding ``sys.modules`` short-circuits the import to our stub.
    """
    module = ModuleType(f"miasma.plugins.{name}")
    module.metadata = metadata if metadata is not None else {"vuln_id": name}
    module.probe = probe
    monkeypatch.setitem(sys.modules, f"miasma.plugins.{name}", module)
    return module


def _finding(vuln_id, host="10.0.0.1"):
    return Finding(vuln_id=vuln_id, host=host, confidence="high")


# ---------------------------------------------------------------------------
# ordering + correctness
# ---------------------------------------------------------------------------


def test_concurrent_findings_preserve_input_order(monkeypatch):
    # Plugin "a" sleeps the longest so it would finish LAST under concurrency.
    # The result must still list a, b, c in requested order.
    delays = {"a": 0.05, "b": 0.02, "c": 0.0}

    def make(name):
        def probe(target):
            time.sleep(delays[name])
            return _finding(name)

        return probe

    for name in ("a", "b", "c"):
        _register_plugin(monkeypatch, name, make(name))

    target = Target(host="10.0.0.1")
    findings = run_plugins(target, ["a", "b", "c"], concurrency=3)

    assert [f.vuln_id for f in findings] == ["a", "b", "c"]


def test_concurrency_one_matches_sequential(monkeypatch):
    for name in ("a", "b", "c"):
        _register_plugin(monkeypatch, name, (lambda n: lambda t: _finding(n))(name))

    target = Target(host="10.0.0.1")
    seq = run_plugins(target, ["a", "b", "c"], concurrency=1)
    par = run_plugins(target, ["a", "b", "c"], concurrency=3)

    assert [f.vuln_id for f in seq] == [f.vuln_id for f in par] == ["a", "b", "c"]


def test_default_concurrency_is_sequential():
    # No concurrency argument => default 1 => original behaviour preserved.
    target = Target(host="127.0.0.1")
    findings = run_plugins(target, ["test_always_finds"])
    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-TEST-0001"


def test_none_returning_plugins_are_dropped_under_concurrency(monkeypatch):
    _register_plugin(monkeypatch, "hit", lambda t: _finding("hit"))
    _register_plugin(monkeypatch, "miss", lambda t: None)

    target = Target(host="10.0.0.1")
    findings = run_plugins(target, ["miss", "hit", "miss"], concurrency=4)

    assert [f.vuln_id for f in findings] == ["hit"]


# ---------------------------------------------------------------------------
# error isolation under concurrency
# ---------------------------------------------------------------------------


def test_raising_plugin_is_isolated_under_concurrency(monkeypatch):
    def boom(target):
        raise RuntimeError("kaboom")

    _register_plugin(monkeypatch, "ok1", lambda t: _finding("ok1"))
    _register_plugin(monkeypatch, "bad", boom, metadata={"vuln_id": "BAD-1"})
    _register_plugin(monkeypatch, "ok2", lambda t: _finding("ok2"))

    target = Target(host="10.0.0.1")
    findings = run_plugins(target, ["ok1", "bad", "ok2"], concurrency=3)

    assert [f.vuln_id for f in findings] == ["ok1", "BAD-1", "ok2"]
    err = findings[1]
    assert err.confidence == "error"
    assert "kaboom" in err.evidence["error"]


# ---------------------------------------------------------------------------
# inapplicable plugins never occupy a worker slot
# ---------------------------------------------------------------------------


def test_inapplicable_plugins_filtered_before_threads(monkeypatch):
    called = {"skipped": False}

    def skipped_probe(target):
        called["skipped"] = True
        return _finding("skipped")

    # port_hint that the SSH-only target can't match -> must be skipped.
    _register_plugin(
        monkeypatch, "needs6379", skipped_probe, metadata={"port_hint": [6379]}
    )
    _register_plugin(monkeypatch, "runs", lambda t: _finding("runs"))

    target = Target(host="10.0.0.1", ports={22: {"state": "open", "name": "ssh"}})
    findings = run_plugins(target, ["needs6379", "runs"], concurrency=4)

    assert called["skipped"] is False
    assert [f.vuln_id for f in findings] == ["runs"]


# ---------------------------------------------------------------------------
# the parallelism is real
# ---------------------------------------------------------------------------


def test_probes_actually_overlap_under_concurrency(monkeypatch):
    # Three probes each block on a barrier. If they run sequentially the barrier
    # never trips (only one thread waits at a time) and the test times out via
    # the barrier's own timeout. If they run concurrently all three reach the
    # barrier and it releases. Proves probes genuinely overlap.
    barrier = threading.Barrier(3, timeout=2.0)

    def make(name):
        def probe(target):
            barrier.wait()
            return _finding(name)

        return probe

    for name in ("a", "b", "c"):
        _register_plugin(monkeypatch, name, make(name))

    target = Target(host="10.0.0.1")
    findings = run_plugins(target, ["a", "b", "c"], concurrency=3)

    assert [f.vuln_id for f in findings] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [0, -1, -10])
def test_concurrency_below_one_is_rejected(bad):
    target = Target(host="127.0.0.1")
    with pytest.raises(ValueError):
        run_plugins(target, ["test_always_finds"], concurrency=bad)


def test_single_applicable_plugin_takes_sequential_fast_path(monkeypatch):
    # With only one applicable plugin there's nothing to parallelise; the runner
    # should still produce the correct result regardless of the requested N.
    _register_plugin(monkeypatch, "solo", lambda t: _finding("solo"))
    target = Target(host="10.0.0.1")
    findings = run_plugins(target, ["solo"], concurrency=8)
    assert [f.vuln_id for f in findings] == ["solo"]


# ---------------------------------------------------------------------------
# CLI wiring of --concurrency
# ---------------------------------------------------------------------------


def _mock_scanner(monkeypatch):
    import nmap_wrapper.scanner as scanner_mod
    from nmap_wrapper.testing import FakeScanner, service_scan_result

    fake = FakeScanner(
        service_scan_result("127.0.0.1", [{"port": 8080, "name": "http-proxy"}])
    )
    monkeypatch.setattr(scanner_mod, "_new_scanner", lambda: fake)


def test_cli_passes_concurrency_to_runner(monkeypatch):
    import json

    from miasma import cli

    _mock_scanner(monkeypatch)
    seen = {}

    def fake_run_plugins(target, plugin_names, concurrency=1):
        seen["concurrency"] = concurrency
        return []

    monkeypatch.setattr(cli, "run_plugins", fake_run_plugins)

    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = cli.main(
            [
                "--target",
                "127.0.0.1",
                "--plugins",
                "test_always_finds",
                "--concurrency",
                "5",
            ]
        )
    assert exit_code == 0
    assert seen["concurrency"] == 5
    # The report still serialises cleanly.
    json.loads(buf.getvalue())


def test_cli_default_concurrency_is_one(monkeypatch):
    from miasma import cli

    _mock_scanner(monkeypatch)
    seen = {}

    def fake_run_plugins(target, plugin_names, concurrency=1):
        seen["concurrency"] = concurrency
        return []

    monkeypatch.setattr(cli, "run_plugins", fake_run_plugins)

    import io
    from contextlib import redirect_stdout

    with redirect_stdout(io.StringIO()):
        cli.main(["--target", "127.0.0.1", "--plugins", "test_always_finds"])
    assert seen["concurrency"] == 1


@pytest.mark.parametrize("bad", ["0", "-3"])
def test_cli_rejects_concurrency_below_one(monkeypatch, bad):
    from miasma import cli

    _mock_scanner(monkeypatch)
    with pytest.raises(SystemExit):
        cli.main(
            [
                "--target",
                "127.0.0.1",
                "--plugins",
                "test_always_finds",
                "--concurrency",
                bad,
            ]
        )
