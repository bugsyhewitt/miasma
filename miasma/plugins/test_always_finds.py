"""Canonical test plugin: always returns a finding.

Exists so the pipeline (recon -> probe -> JSON output) can be exercised end to
end without depending on a real vulnerable service. Use it to verify that
plugin discovery, execution, and output serialization all work.
"""

from __future__ import annotations

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-TEST-0001",
    "name": "always-finds test plugin",
    "description": "Verification plugin that unconditionally reports a finding.",
    "confidence": "high",
    "references": [],
}


def probe(target: Target) -> Finding | None:
    return Finding(
        vuln_id=metadata["vuln_id"],
        host=target.host,
        confidence=metadata["confidence"],
        evidence={
            "note": "test plugin always reports a finding",
            "open_ports": target.open_ports(),
        },
        description=metadata["description"],
    )
