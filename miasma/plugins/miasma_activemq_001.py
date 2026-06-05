"""MIASMA-ACTIVEMQ-001 — Apache ActiveMQ default-credential / unauthenticated admin console.

Apache ActiveMQ is the most widely deployed open-source Java message broker.
The embedded Jetty HTTP admin console ships enabled by default on port 8161 with
the factory credential ``admin:admin``. Two recurring misconfigurations turn a
reachable ActiveMQ console into a P1/critical finding:

    1. **Default credentials — admin:admin.** The factory password is never
       rotated in a very large fraction of deployments. Authenticating with
       ``admin:admin`` grants full broker control via the web UI: queue
       management, consumer inspection, connection listing, broker configuration
       reads, and (via the Hawtio plugin present in >= 5.15) JMX/JNDI
       invocation. In combination with CVE-2023-46604 (CVSS 10.0, pre-auth RCE
       via ClassPathXmlApplicationContext, fixed in 5.15.16 / 5.16.7 / 5.17.6 /
       5.18.3 and later) an exposed, default-credential console is routinely
       the first step in a full host compromise.

    2. **Unauthenticated console access.** Some deployments disable HTTP Basic
       authentication on the admin console entirely. A ``GET /`` that returns 200
       with ``"ActiveMQ"`` in the body without any authentication challenge
       confirms the console is open.

    3. **Unauthenticated Jolokia API.** The REST/JSON API used by the Hawtio
       console is mounted at ``/api/jolokia/`` and occasionally left open without
       authentication. A 200 response to a broker-attribute read exposes queue
       topology and the broker name / version.

This probe is BENIGN and read-only:

    1. ``GET /`` with no credentials — fingerprints ActiveMQ. A genuine admin
       console reply contains the string ``"ActiveMQ"`` (case-insensitive) in
       the response body. A 200 without an auth challenge is a HIGH finding. A
       401 triggers the default-credential attempt.
    2. ``GET /`` with HTTP Basic ``admin:admin`` — if step 1 returned 401, this
       confirms the factory credential (CRITICAL if accepted).
    3. ``GET /api/jolokia/read/org.apache.activemq:type=Broker/BrokerName`` with
       no credentials — a 200 JSON body carrying a ``value`` key with a non-empty
       string confirms the Jolokia API is open (MEDIUM).

No queue is created/deleted, no message is published/consumed, no configuration
is changed, and no second credential pair is tried.

Severity / confidence matrix:
    * ``critical`` — ActiveMQ fingerprinted AND ``admin:admin`` accepted.
    * ``high``     — ActiveMQ fingerprinted AND console returns 200 without auth.
    * ``medium``   — ActiveMQ fingerprinted AND Jolokia API open without auth.
    * none         — ActiveMQ fingerprinted but auth enforced, or not ActiveMQ.

Candidate ports: 8161 (primary Jetty HTTP), 80, 443, 8080 (reverse-proxy fronts).

Note: port 61616 (AMQP/OpenWire) is a message-protocol endpoint and is NOT
probed here; we only probe the HTTP admin surface.

[Worker decision: plugin filename miasma_activemq_001.py (underscores) because
the runner discovers plugins via importlib and module names cannot contain
hyphens. The canonical id MIASMA-ACTIVEMQ-001 lives in metadata["vuln_id"],
matching the miasma_grafana_001.py / miasma_couchdb_001.py convention.]
"""

from __future__ import annotations

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-ACTIVEMQ-001",
    "name": "Apache ActiveMQ Default-Credential / Unauthenticated Admin Console",
    "description": (
        "Apache ActiveMQ admin console reachable with the factory admin:admin "
        "credential or without authentication, or Jolokia REST API open without "
        "auth — exposing broker management, queue topology, connection inventory, "
        "and (where Hawtio is present) a path to JMX/JNDI invocation."
    ),
    "confidence": "high",
    "references": [
        "https://activemq.apache.org/components/classic/documentation/security",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
        "https://www.rapid7.com/blog/post/2023/11/01/etr-suspected-exploitation-of-apache-activemq-cve-2023-46604/",
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ],
    "port_hint": [8161, 80, 443, 8080],
    "service_hint": ["activemq", "http", "https"],
    "default_ports": [8161, 80, 443, 8080],
}

# The single factory credential pair ActiveMQ ships with.
_DEFAULT_USER = "admin"
_DEFAULT_PASS = "admin"

_TIMEOUT = 5.0

# Marker present in every ActiveMQ admin console response body.
_FINGERPRINT_MARKER = "activemq"

# Jolokia read-attribute path: smallest read that works on all 5.x and 6.x.
_JOLOKIA_PATH = "/api/jolokia/read/org.apache.activemq:type=Broker/BrokerName"


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered ActiveMQ-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        activemq_like = [
            port
            for port in open_ports
            if "activemq" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return activemq_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS only for the canonical TLS port; everything else plain HTTP."""
    return "https" if port == 443 else "http"


def _get(url: str, auth: tuple[str, str] | None = None) -> httpx.Response | None:
    """Benign GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common on
    internal ActiveMQ deployments behind a reverse proxy.
    """
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,  # noqa: S501
            follow_redirects=False,
            auth=auth,
        )
    except httpx.HTTPError:
        return None


def _is_activemq_body(resp: httpx.Response) -> bool:
    """Return True if the response body contains the ActiveMQ fingerprint marker."""
    try:
        return _FINGERPRINT_MARKER in resp.text.lower()
    except Exception:
        return False


def probe(target: Target) -> Finding | None:
    """Run the ActiveMQ admin-console and Jolokia checks against candidate ports.

    Returns the first (highest-severity) finding, or None if the target is not
    a vulnerable ActiveMQ instance on any candidate port.
    """
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # --- Step 1: probe root console path ---
        resp = _get(base + "/")
        if resp is None:
            continue

        if resp.status_code == 200 and _is_activemq_body(resp):
            # Console open without authentication (HIGH).
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "host": target.host,
                    "port": port,
                    "url": base + "/",
                    "auth_required": False,
                },
                description=(
                    metadata["description"]
                    + f" Admin console at {base}/ returns 200 without any "
                    "authentication challenge — unauthenticated broker access."
                ),
            )

        if resp.status_code == 401:
            # ActiveMQ fingerprinted via 401; try the factory default credential.
            auth_resp = _get(base + "/", auth=(_DEFAULT_USER, _DEFAULT_PASS))
            if (
                auth_resp is not None
                and auth_resp.status_code == 200
                and _is_activemq_body(auth_resp)
            ):
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="critical",
                    evidence={
                        "host": target.host,
                        "port": port,
                        "url": base + "/",
                        "auth_required": True,
                        "default_creds": True,
                        "matched_user": _DEFAULT_USER,
                    },
                    description=(
                        metadata["description"]
                        + f" Admin console at {base}/ accepts the factory "
                        f"{_DEFAULT_USER}:{_DEFAULT_PASS} credential — full "
                        "broker control, including queue management and Hawtio "
                        "JMX access, is possible."
                    ),
                )
            # Auth enforced and default creds rejected; fall through to Jolokia check.

        # --- Step 2: Jolokia API (MEDIUM) ---
        # Only checked when the console did not already yield a finding.
        jolokia_resp = _get(base + _JOLOKIA_PATH)
        if jolokia_resp is not None and jolokia_resp.status_code == 200:
            try:
                body = jolokia_resp.json()
            except Exception:
                body = None
            if isinstance(body, dict) and body.get("value"):
                broker_name = str(body["value"])[:64]
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="medium",
                    evidence={
                        "host": target.host,
                        "port": port,
                        "url": base + _JOLOKIA_PATH,
                        "jolokia_open": True,
                        "broker_name": broker_name,
                    },
                    description=(
                        metadata["description"]
                        + f" Jolokia REST API at {base}{_JOLOKIA_PATH} answers "
                        "200 without authentication, leaking broker name and "
                        "topology metadata."
                    ),
                )

    return None
