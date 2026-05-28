"""Tests for the runner's port_hint/service_hint applicability filter.

The filter (``is_applicable`` + the skip in ``run_plugins``) lets the runner
skip plugins that obviously can't match a target's open ports/services, while
staying conservative enough never to drop a real finding:

* recon found nothing  -> never skip (nothing to filter on)
* plugin declares no hints -> never skip (opts out of filtering)
* otherwise skip only when no open port or service matches a declared hint
"""

from types import SimpleNamespace

from miasma.core import Finding, Target
from miasma.runner import is_applicable, load_plugin, run_plugins


def _fake_plugin(metadata, finding=None):
    """Build a minimal plugin-like module object with metadata + probe."""

    def probe(target):
        return finding

    return SimpleNamespace(metadata=metadata, probe=probe)


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------


def test_no_open_ports_is_always_applicable():
    # Recon found nothing; we can't filter, so the plugin must still run and
    # fall back to its own default-port ordering.
    plugin = _fake_plugin({"port_hint": [6379]})
    target = Target(host="10.0.0.1")  # no ports
    assert is_applicable(plugin, target) is True


def test_plugin_without_hints_is_always_applicable():
    plugin = _fake_plugin({"vuln_id": "MIASMA-TEST-0001"})
    target = Target(host="10.0.0.1", ports={6379: {"state": "open"}})
    assert is_applicable(plugin, target) is True


def test_port_hint_match_is_applicable():
    plugin = _fake_plugin({"port_hint": [6379, 6380]})
    target = Target(host="10.0.0.1", ports={6379: {"state": "open"}})
    assert is_applicable(plugin, target) is True


def test_port_hint_no_match_is_not_applicable():
    plugin = _fake_plugin({"port_hint": [6379, 6380]})
    target = Target(host="10.0.0.1", ports={22: {"state": "open"}})
    assert is_applicable(plugin, target) is False


def test_default_ports_used_as_alias_for_port_hint():
    # A pre-convention plugin that only declares default_ports is still filtered.
    plugin = _fake_plugin({"default_ports": [9200]})
    target = Target(host="10.0.0.1", ports={22: {"state": "open"}})
    assert is_applicable(plugin, target) is False

    target_match = Target(host="10.0.0.1", ports={9200: {"state": "open"}})
    assert is_applicable(plugin, target_match) is True


def test_service_hint_match_overrides_port_mismatch():
    # Redis on a non-standard port: port hint misses but the service name hits.
    plugin = _fake_plugin({"port_hint": [6379], "service_hint": ["redis"]})
    target = Target(
        host="10.0.0.1",
        ports={9999: {"state": "open", "name": "redis"}},
    )
    assert is_applicable(plugin, target) is True


def test_service_hint_is_case_insensitive_substring():
    plugin = _fake_plugin({"service_hint": ["http"]})
    target = Target(
        host="10.0.0.1",
        ports={12345: {"state": "open", "name": "HTTP-Proxy"}},
    )
    assert is_applicable(plugin, target) is True


def test_closed_ports_do_not_count_as_matches():
    plugin = _fake_plugin({"port_hint": [6379]})
    target = Target(host="10.0.0.1", ports={6379: {"state": "closed"}})
    # open_ports() returns nothing -> no-open-ports branch -> applicable.
    assert is_applicable(plugin, target) is True


# ---------------------------------------------------------------------------
# run_plugins integration
# ---------------------------------------------------------------------------


def test_run_plugins_skips_irrelevant_real_plugin(monkeypatch):
    # Redis plugin against an SSH-only host should be skipped — and crucially,
    # its probe() must never be called (no wasted network round-trip).
    module = load_plugin("miasma_redis_001")
    called = {"probe": False}

    def tracking_probe(target):
        called["probe"] = True
        return None

    monkeypatch.setattr(module, "probe", tracking_probe)

    target = Target(host="10.0.0.1", ports={22: {"state": "open", "name": "ssh"}})
    findings = run_plugins(target, ["miasma_redis_001"])

    assert findings == []
    assert called["probe"] is False


def test_run_plugins_runs_relevant_real_plugin(monkeypatch):
    # Same plugin, but now port 6379 is open -> it must run.
    module = load_plugin("miasma_redis_001")
    sentinel = Finding(
        vuln_id="MIASMA-REDIS-001",
        host="10.0.0.1",
        confidence="high",
    )
    called = {"probe": False}

    def tracking_probe(target):
        called["probe"] = True
        return sentinel

    monkeypatch.setattr(module, "probe", tracking_probe)

    target = Target(
        host="10.0.0.1",
        ports={6379: {"state": "open", "name": "redis"}},
    )
    findings = run_plugins(target, ["miasma_redis_001"])

    assert called["probe"] is True
    assert findings == [sentinel]


def test_run_plugins_never_skips_when_no_open_ports(monkeypatch):
    # No recon data -> plugin must still get a chance to run its own fallback.
    module = load_plugin("miasma_redis_001")
    called = {"probe": False}

    def tracking_probe(target):
        called["probe"] = True
        return None

    monkeypatch.setattr(module, "probe", tracking_probe)

    target = Target(host="10.0.0.1")  # no ports
    run_plugins(target, ["miasma_redis_001"])

    assert called["probe"] is True


def test_run_plugins_runs_hintless_plugin_against_any_target():
    # test_always_finds declares no hints -> always runs.
    target = Target(host="10.0.0.1", ports={22: {"state": "open", "name": "ssh"}})
    findings = run_plugins(target, ["test_always_finds"])
    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-TEST-0001"


def test_all_shipped_real_plugins_declare_hints():
    # Guard the convention: every shipped CVE/misconfig plugin should declare a
    # port_hint (or default_ports alias). test_always_finds is exempt by design.
    from miasma.runner import _hint_ports, available_plugins

    for name in available_plugins():
        if name == "test_always_finds":
            continue
        module = load_plugin(name)
        assert _hint_ports(module.metadata), (
            f"plugin '{name}' should declare a port_hint/default_ports"
        )
