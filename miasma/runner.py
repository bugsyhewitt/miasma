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


def _hint_ports(metadata: dict) -> list[int]:
    """Return the plugin's declared port hints.

    The canonical field is ``port_hint``; ``default_ports`` is accepted as a
    backwards-compatible alias for plugins that predate the convention.
    """
    raw = metadata.get("port_hint")
    if raw is None:
        raw = metadata.get("default_ports")
    if not isinstance(raw, (list, tuple)):
        return []
    return [int(p) for p in raw]


def _hint_services(metadata: dict) -> list[str]:
    """Return the plugin's declared service-name hints, lowercased."""
    raw = metadata.get("service_hint")
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(s).lower() for s in raw]


def is_applicable(module: ModuleType, target: Target) -> bool:
    """Decide whether a plugin is worth running against ``target``.

    The check is deliberately conservative — a plugin is skipped *only* when we
    are confident it cannot match, so a port-hint typo or a missing service
    fingerprint never silently drops a real finding:

    * If recon found no open ports, never skip (we have nothing to filter on —
      the plugin's own fallback ordering decides what to probe).
    * If the plugin declares neither ``port_hint``/``default_ports`` nor
      ``service_hint``, never skip (it opts out of filtering).
    * Otherwise the plugin is applicable when at least one open port matches a
      declared port hint, OR an open port's nmap service name contains a
      declared service hint. Only when neither matches is it skipped.
    """
    open_ports = target.open_ports()
    if not open_ports:
        return True

    port_hints = _hint_ports(module.metadata)
    service_hints = _hint_services(module.metadata)
    if not port_hints and not service_hints:
        return True

    if any(port in port_hints for port in open_ports):
        return True

    if service_hints:
        for port in open_ports:
            service_name = target.service(port).get("name", "")
            if isinstance(service_name, str):
                name = service_name.lower()
                if any(hint in name for hint in service_hints):
                    return True

    return False


def run_plugins(target: Target, plugin_names: list[str]) -> list[Finding]:
    """Run each named plugin against ``target`` and collect findings.

    A plugin returning ``None`` means "not vulnerable / not applicable" and is
    simply skipped. A plugin raising an exception is isolated: its error is
    surfaced as a low-confidence Finding so one broken plugin can't abort a run.
    """
    findings: list[Finding] = []
    for name in plugin_names:
        module = load_plugin(name)
        if not is_applicable(module, target):
            # The target's open ports / services can't match this plugin's
            # hints. Skip the probe rather than waste a network round-trip.
            continue
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
