"""Tests for plugin discovery and execution."""

from miasma.core import Target
from miasma.runner import available_plugins, load_plugin, run_plugins


def test_available_plugins_includes_shipped_plugins():
    plugins = available_plugins()
    assert "test_always_finds" in plugins
    assert "cve_2009_3548" in plugins


def test_load_plugin_validates_interface():
    module = load_plugin("test_always_finds")
    assert isinstance(module.metadata, dict)
    assert callable(module.probe)


def test_test_plugin_always_returns_a_finding():
    target = Target(host="127.0.0.1")
    findings = run_plugins(target, ["test_always_finds"])
    assert len(findings) == 1
    assert findings[0].vuln_id == "MIASMA-TEST-0001"
    assert findings[0].host == "127.0.0.1"
    assert findings[0].confidence == "high"


def test_plugin_exception_is_isolated_as_error_finding(monkeypatch):
    module = load_plugin("test_always_finds")

    def boom(target):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(module, "probe", boom)
    target = Target(host="127.0.0.1")
    findings = run_plugins(target, ["test_always_finds"])
    assert len(findings) == 1
    assert findings[0].confidence == "error"
    assert "kaboom" in findings[0].evidence["error"]
