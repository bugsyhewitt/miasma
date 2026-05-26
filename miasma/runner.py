"""Plugin discovery and probe execution.

A plugin is one Python module under :mod:`miasma.plugins` exposing a module-level
``metadata: dict`` and a ``probe(target: Target) -> Finding | None`` callable.

The runner loads requested plugins by their stem name (the file name without
``.py``), runs each ``probe`` against the target, and collects the non-None
:class:`~miasma.core.Finding` results.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType

import miasma.plugins as plugins_pkg
from miasma.core import Finding, Target


def available_plugins() -> list[str]:
    """Return the stem names of all plugin modules under miasma/plugins."""
    return sorted(
        name
        for _, name, ispkg in pkgutil.iter_modules(plugins_pkg.__path__)
        if not ispkg and not name.startswith("_")
    )


def load_plugin(name: str) -> ModuleType:
    """Import a plugin by stem name and validate its interface."""
    module = importlib.import_module(f"miasma.plugins.{name}")
    if not hasattr(module, "metadata") or not isinstance(module.metadata, dict):
        raise ValueError(f"plugin '{name}' is missing a 'metadata' dict")
    if not callable(getattr(module, "probe", None)):
        raise ValueError(f"plugin '{name}' is missing a 'probe' callable")
    return module


def run_plugins(target: Target, plugin_names: list[str]) -> list[Finding]:
    """Run each named plugin against ``target`` and collect findings.

    A plugin returning ``None`` means "not vulnerable / not applicable" and is
    simply skipped. A plugin raising an exception is isolated: its error is
    surfaced as a low-confidence Finding so one broken plugin can't abort a run.
    """
    findings: list[Finding] = []
    for name in plugin_names:
        module = load_plugin(name)
        try:
            result = module.probe(target)
        except Exception as exc:  # one plugin must not kill the whole run
            findings.append(
                Finding(
                    vuln_id=module.metadata.get("vuln_id", name),
                    host=target.host,
                    confidence="error",
                    evidence={"error": repr(exc)},
                    description=f"plugin '{name}' raised during probe",
                )
            )
            continue
        if result is not None:
            findings.append(result)
    return findings
