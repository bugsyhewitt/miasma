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
from concurrent.futures import ThreadPoolExecutor
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


def _probe_one(name: str, module: ModuleType, target: Target) -> Finding | None:
    """Run a single plugin's probe with error isolation.

    Returns the plugin's :class:`Finding`, ``None`` when the plugin reports
    nothing, or an ``"error"``-confidence Finding when the probe raised — one
    broken plugin must never abort the whole run, sequential or concurrent.
    """
    try:
        return module.probe(target)
    except Exception as exc:  # one plugin must not kill the whole run
        return Finding(
            vuln_id=module.metadata.get("vuln_id", name),
            host=target.host,
            confidence="error",
            evidence={"error": repr(exc)},
            description=f"plugin '{name}' raised during probe",
        )


def run_plugins(
    target: Target,
    plugin_names: list[str],
    concurrency: int = 1,
) -> list[Finding]:
    """Run each named plugin against ``target`` and collect findings.

    A plugin returning ``None`` means "not vulnerable / not applicable" and is
    simply skipped. A plugin raising an exception is isolated: its error is
    surfaced as an ``"error"``-confidence Finding so one broken plugin can't
    abort a run.

    ``concurrency`` caps how many plugins probe in parallel. The default of 1
    keeps the original sequential behaviour. Higher values run the I/O-bound
    probes through a :class:`ThreadPoolExecutor`, which dramatically cuts wall
    time when several plugins are requested (each probe is a network round-trip
    that mostly waits). Regardless of how many threads run, findings are always
    returned in the **input plugin order** — concurrency changes the timing,
    never the output. Inapplicable plugins are filtered before any thread is
    spawned, so a skipped plugin never occupies a worker slot.
    """
    if concurrency < 1:
        raise ValueError(f"concurrency must be >= 1, got {concurrency}")

    # Resolve and filter first, preserving the requested order. ``applicable``
    # holds (name, module) pairs in input order; index alignment lets us return
    # findings deterministically no matter which thread finishes first.
    applicable: list[tuple[str, ModuleType]] = []
    for name in plugin_names:
        module = load_plugin(name)
        if not is_applicable(module, target):
            # The target's open ports / services can't match this plugin's
            # hints. Skip the probe rather than waste a network round-trip.
            continue
        applicable.append((name, module))

    if not applicable:
        return []

    if concurrency == 1 or len(applicable) == 1:
        results = [_probe_one(name, module, target) for name, module in applicable]
    else:
        max_workers = min(concurrency, len(applicable))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            # ``map`` preserves input order in its output, so findings stay
            # deterministic even though probes complete out of order.
            results = list(
                pool.map(
                    lambda pair: _probe_one(pair[0], pair[1], target),
                    applicable,
                )
            )

    return [finding for finding in results if finding is not None]
