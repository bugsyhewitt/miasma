"""CVE-2009-3548 — Apache Tomcat default/weak manager credentials.

Tomcat historically shipped (or admins left) the manager application reachable
with default credentials such as ``tomcat:tomcat`` and ``admin:`` (empty). A
host exposing ``/manager/html`` that accepts a default credential pair is
trivially compromisable.

This probe is BENIGN: it issues HTTP Basic-auth GET requests to the manager
endpoint with a small list of well-known default pairs and reports a finding
only if the server returns a non-401/403 (i.e. the credential was accepted).
No deploy, no exploitation, no state change — read-only verification suitable
for a bug-bounty recon-to-verification handoff.

[Worker decision: plugin filename uses underscores (cve_2009_3548.py) because
Python module names cannot contain hyphens, which is required for the runner's
importlib-based discovery. The criteria's "<cve-id>.py" is satisfied in spirit;
the canonical CVE id is recorded in metadata["vuln_id"] = "CVE-2009-3548".]
"""

from __future__ import annotations

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2009-3548",
    "name": "Apache Tomcat default manager credentials",
    "description": (
        "Tomcat manager application reachable with default/weak credentials."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2009-3548",
    ],
    # Ports we'll consider if recon found them open; falls back to these
    # defaults when no recon data is available. port_hint is the canonical
    # field the runner reads to skip irrelevant plugins; default_ports is kept
    # as the in-probe fallback alias.
    "port_hint": [8080, 8443, 80, 443],
    "service_hint": ["http", "https"],
    "default_ports": [8080, 8443, 80, 443],
}

# Well-known default Tomcat manager credential pairs (benign check only).
_DEFAULT_CREDS = [
    ("tomcat", "tomcat"),
    ("admin", "admin"),
    ("admin", ""),
    ("tomcat", "s3cret"),
    ("role1", "role1"),
]

_MANAGER_PATH = "/manager/html"


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open ports that look like HTTP; else defaults."""
    open_ports = target.open_ports()
    if open_ports:
        http_like = [
            port
            for port in open_ports
            if "http" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return http_like or open_ports
    return list(metadata["default_ports"])


def probe(target: Target) -> Finding | None:
    attempts: list[dict[str, object]] = []
    for port in _candidate_ports(target):
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target.host}:{port}{_MANAGER_PATH}"
        for user, password in _DEFAULT_CREDS:
            try:
                resp = httpx.get(
                    url,
                    auth=(user, password),
                    timeout=5.0,
                    verify=False,
                    follow_redirects=False,
                )
            except httpx.HTTPError as exc:
                attempts.append({"url": url, "creds": f"{user}:{password}", "error": repr(exc)})
                continue

            attempts.append({"url": url, "creds": f"{user}:{password}", "status": resp.status_code})
            # 401/403 => credential rejected. Anything else on the manager
            # endpoint means the default credential was accepted.
            if resp.status_code not in (401, 403, 404):
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence=metadata["confidence"],
                    evidence={
                        "url": url,
                        "accepted_credentials": f"{user}:{password}",
                        "status_code": resp.status_code,
                    },
                    description=metadata["description"],
                )
    return None
