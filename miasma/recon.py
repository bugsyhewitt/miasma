"""Recon phase: fingerprint a host using the shared ``nmap-wrapper`` library.

The dependency on the ``nmap`` binary is owned by ``nmap-wrapper`` (the shared
necromancer scanner library); miasma no longer talks to python-nmap directly.
``nmap`` is NOT pip-installable; it is a documented system dependency (see both
this repo's README and nmap-wrapper's "System dependencies" section).

Tests mock the single nmap seam ``nmap_wrapper.scanner._new_scanner`` so the
suite stays green on machines without nmap installed.
"""

from __future__ import annotations

from nmap_wrapper import scan_host

from miasma.core import Target


def recon(host: str, port_range: str = "1-1000") -> Target:
    """Fingerprint ``host`` over ``port_range`` and return a populated Target.

    ``port_range`` is an nmap port spec such as "1-1000" or "22,80,443".
    Service/version detection (-sV) is performed by nmap-wrapper's ``scan_host``
    so plugins get product/version info.
    """
    result = scan_host(host, port_range)

    target = Target(host=host)
    for scanned_host in result.hosts:
        for svc in scanned_host.services:
            target.ports[svc.port] = {
                "state": svc.state,
                "name": svc.name,
                "product": svc.product,
                "version": svc.version,
                "cpe": svc.cpe,
            }
    return target
