"""Core data types shared between the recon layer, the runner, and plugins.

A plugin is one Python file in ``miasma/plugins/<cve-id>.py`` exposing:

    metadata: dict
    def probe(target: Target) -> Finding | None: ...

``Target`` describes the host (plus the recon fingerprint, if available).
``Finding`` describes one verified vulnerability with evidence.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Target:
    """A host to probe, optionally enriched with nmap recon output.

    ``ports`` maps a port number to a dict of nmap-derived service info
    (state, name, product, version, ...). Empty until recon has run.
    """

    host: str
    ports: dict[int, dict[str, Any]] = field(default_factory=dict)

    def open_ports(self) -> list[int]:
        """Return the sorted list of ports nmap reported as open."""
        return sorted(
            port
            for port, info in self.ports.items()
            if info.get("state") == "open"
        )

    def service(self, port: int) -> dict[str, Any]:
        """Return the recon info dict for a port (empty dict if unknown)."""
        return self.ports.get(port, {})


@dataclass
class Finding:
    """A verified (or attempted) vulnerability finding for one target.

    ``confidence`` is a free-form label kept small on purpose:
    "high" | "medium" | "low". ``evidence`` carries reproduction detail
    (request sent, response observed) so a human can confirm by hand.
    """

    vuln_id: str
    host: str
    confidence: str
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)
