"""miasma — lightweight, plugin-driven verifier of high-confidence vulnerabilities.

Takes a fingerprinted host and runs benign verification probes for a specific
list of CVEs the user cares about. Each probe is a small Python module — easy to
author, easy to audit. Output is per-host JSON findings with vuln ID, confidence,
and reproduction evidence.
"""

from miasma.core import Finding, Target

__version__ = "0.1.0"

__all__ = ["Finding", "Target", "__version__"]
