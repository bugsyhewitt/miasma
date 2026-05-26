"""Recon phase: fingerprint a host with system ``nmap`` via python-nmap.

The dependency on the ``nmap`` binary is intentionally isolated here so the
rest of the codebase — and the test suite — can mock at the ``python-nmap``
boundary (the ``PortScanner`` object). ``nmap`` is NOT pip-installable; it is a
documented system dependency (see README "System dependencies").
"""

from __future__ import annotations

from typing import Any

from miasma.core import Target


def _new_scanner() -> Any:
    """Construct a python-nmap PortScanner.

    Isolated into its own function so tests can mock this single seam instead
    of needing a real ``nmap`` binary installed.
    """
    import nmap  # imported lazily so the package imports without nmap present

    return nmap.PortScanner()


def recon(host: str, port_range: str = "1-1000") -> Target:
    """Fingerprint ``host`` over ``port_range`` and return a populated Target.

    ``port_range`` is an nmap port spec such as "1-1000" or "22,80,443".
    Service/version detection (-sV) is enabled so plugins get product info.
    """
    scanner = _new_scanner()
    scanner.scan(hosts=host, ports=port_range, arguments="-sV")

    target = Target(host=host)
    for scanned_host in scanner.all_hosts():
        for proto in scanner[scanned_host].all_protocols():
            for port, info in scanner[scanned_host][proto].items():
                target.ports[int(port)] = dict(info)
    return target
