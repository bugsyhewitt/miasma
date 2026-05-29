"""MIASMA-RABBITMQ-001 — RabbitMQ Management API unauthenticated / default-credential access.

RabbitMQ is the dominant open-source AMQP message broker. Application traffic
flowing through it — payment events, password-reset jobs, password hashes en
route to a hashing worker, audit logs, internal RPC payloads — is some of the
most sensitive in-flight data in any system. Two recurring misconfigurations
turn that exposure into a P1/critical finding:

    1. **Default credentials.** A fresh RabbitMQ broker ships with the
       ``guest:guest`` administrator account. In versions ``>= 3.3`` the guest
       account is restricted to ``loopback_users = [guest]`` (localhost only),
       but operators routinely re-enable remote guest access for "convenience"
       (``loopback_users = none`` in ``rabbitmq.conf``), and many proxied /
       containerised deployments expose ``15672`` to the LAN or internet with
       the loopback restriction effectively bypassed by the reverse proxy. A
       single ``guest:guest`` login against ``/api/overview`` confirms the
       account is reachable and has administrator rights.

    2. **Anonymous management API.** Some operators front the management UI
       with their own SSO/auth at a reverse proxy and configure RabbitMQ to
       accept unauthenticated calls from the proxy's network (or disable the
       management auth plugin entirely). A ``GET /api/overview`` answering
       ``200`` with the broker's overview JSON and **no** ``WWW-Authenticate``
       header means anonymous read of the broker is enabled — the queue
       inventory, exchange topology, connected client list, and broker / OS /
       Erlang version fingerprint are readable without credentials.

Either path lets an unauthenticated peer read the full broker topology and,
through the same API, publish/consume on any vhost, declare/delete queues and
exchanges, reset users, and ship the management cluster into an attacker-
controlled state. RabbitMQ management exposure is a recurring P1 on bug-bounty
programs in messaging-heavy estates (payments, fintech, logistics).

This probe is BENIGN and read-only. It fingerprints the broker first, then
runs the two minimal checks a human would run by hand to confirm the finding:

    1. ``GET /api/overview`` — with no credentials.
       - 200 with a body carrying RabbitMQ's unique ``rabbitmq_version`` /
         ``management_version`` keys => anonymous read of the broker confirmed
         (HIGH; ``anonymous_access=True``).
       - 401 carrying a ``WWW-Authenticate: Basic realm="RabbitMQ Management"``
         header (or an equivalent RabbitMQ-flavoured challenge) => RabbitMQ
         fingerprinted, auth enforced; fall through to step 2.
       - Anything else (not RabbitMQ, or a non-management surface on this
         port) => skip this port; never flagged.

    2. ``GET /api/overview`` — with HTTP Basic ``guest:guest``.
       - 200 with the same ``rabbitmq_version`` / ``management_version`` keys
         => the factory ``guest:guest`` credential is accepted and reachable
         remotely (CRITICAL; ``default_creds=True``). The single documented
         factory pair is the only credential ever attempted — this is a
         misconfiguration check, not a brute force.
       - 401 / 403 => the guest account is correctly restricted; not
         vulnerable on this port.

No queue is declared or deleted, no message is published or consumed, no
binding is mutated, no user is reset, and no admin endpoint
(``/api/users/*``, ``/api/policies/*``, ``/api/vhosts/*``) is touched. Evidence
records only the host, port, broker version, RabbitMQ Erlang version, and
which of the two paths (anonymous vs. default-creds) confirmed the finding —
never the queue inventory, exchange list, or any message content.

Severity matrix:
    * CRITICAL — RabbitMQ fingerprints AND a ``guest:guest`` Basic login
                 against ``/api/overview`` is accepted (200 with the broker
                 overview). The factory administrator account is reachable
                 remotely; full broker control is one HTTP request away.
    * HIGH     — RabbitMQ fingerprints AND ``/api/overview`` answers 200 with
                 no auth challenge (anonymous_access). The full broker
                 topology is readable without credentials.
    * none     — Not RabbitMQ, or RabbitMQ with auth enforced and the guest
                 account correctly restricted.

Candidate ports: ``15672`` (HTTP management, the documented default),
``15671`` (HTTPS management; the standard TLS-terminated port), and the
common reverse-proxy fronts ``80`` / ``443`` (``443`` is contacted over
HTTPS; everything else over plain HTTP).

[Worker decision: plugin filename is miasma_rabbitmq_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-RABBITMQ-001 lives in
metadata["vuln_id"], matching the existing miasma_grafana_001.py /
miasma_redis_001.py / miasma_memcached_001.py convention. RabbitMQ was
named directly in the round's improvement spec as one of two candidate
next service-exposure plugins (the other was Cassandra). RabbitMQ was
selected: (1) the HTTP management API is a clean direct parallel to the
existing Grafana plugin (default-credential + anonymous-access matrix
over a JSON API) where a Cassandra probe would require constructing
binary native-protocol OP_STARTUP frames; (2) RabbitMQ is far more
commonly exposed than Cassandra in internet-facing estates, and
default-guest exposure is a recurring P1; (3) the broker overview is a
clean live-vs-empty fingerprint analogous to the Grafana org/health
checks. Cassandra unauthenticated access remains queued for a future
rotation.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-RABBITMQ-001",
    "name": "RabbitMQ Management API Unauthenticated / Default-Credential Access",
    "description": (
        "RabbitMQ management API reachable with the factory guest:guest "
        "credential or with anonymous read enabled, exposing the broker "
        "topology (queues, exchanges, connected clients) and the broker / "
        "Erlang version. The same API permits queue declare/delete, message "
        "publish/consume, and user management — full broker takeover is one "
        "HTTP request away."
    ),
    "confidence": "high",
    "references": [
        "https://www.rabbitmq.com/docs/access-control",
        "https://www.rabbitmq.com/docs/management",
        "https://www.rabbitmq.com/docs/management#http-api",
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [15672, 15671, 80, 443],
    "service_hint": ["rabbitmq", "amqp", "http", "https"],
    "default_ports": [15672, 15671, 80, 443],
}

# Keys present in a genuine RabbitMQ /api/overview JSON body. The overview
# endpoint answers with a large object whose top-level keys include
# "rabbitmq_version" and "management_version" on every supported broker
# release — those two together are unique to RabbitMQ's management API and
# distinguish it from any other JSON-200 service that happens to sit on the
# port.
_OVERVIEW_KEYS = ("rabbitmq_version", "management_version")

# The realm RabbitMQ's management plugin uses in its 401 challenge. We accept
# either the canonical "RabbitMQ Management" realm or a generic "RabbitMQ"
# marker in the WWW-Authenticate header — both have been observed across
# versions and reverse-proxy configurations.
_WWW_AUTH_MARKERS = ("rabbitmq",)

# The single factory credential pair RabbitMQ ships with. We only ever try
# the one documented default — this is a misconfiguration check, not a
# brute force.
_DEFAULT_USER = "guest"
_DEFAULT_PASS = "guest"

_TIMEOUT = 5.0

# Standard HTTPS-only management port and the canonical TLS port. Everything
# else is plain HTTP. 15671 is the documented TLS management port; 443 is the
# common reverse-proxy front.
_HTTPS_PORTS = (15671, 443)


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered RabbitMQ-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        rabbitmq_like = [
            port
            for port in open_ports
            if "rabbit" in target.service(port).get("name", "").lower()
            or "amqp" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return rabbitmq_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS for the canonical TLS management ports; everything else plain HTTP."""
    return "https" if port in _HTTPS_PORTS else "http"


def _get(
    url: str, auth: tuple[str, str] | None = None
) -> httpx.Response | None:
    """Benign GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common on
    internal RabbitMQ deployments behind a reverse proxy. Redirects are not
    followed: a redirect to a login page would mean the API surface is not
    actually unauthenticated and should not be flagged.
    """
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
            auth=auth,
        )
    except httpx.HTTPError:
        return None


def _is_rabbitmq_overview(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the parsed /api/overview body if it is genuinely RabbitMQ, else None.

    A genuine RabbitMQ overview is a JSON object carrying both
    ``rabbitmq_version`` and ``management_version`` at the top level. Anything
    else — a non-JSON 200, a JSON array, a JSON object missing those keys — is
    not RabbitMQ and is never flagged.
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    if all(key in body for key in _OVERVIEW_KEYS):
        return body
    return None


def _is_rabbitmq_challenge(resp: httpx.Response) -> bool:
    """True when a 401 response carries RabbitMQ's WWW-Authenticate marker.

    RabbitMQ's management plugin answers an unauthenticated request to
    ``/api/overview`` with a 401 whose ``WWW-Authenticate`` header references
    the RabbitMQ realm. This is the fingerprint that distinguishes a
    RabbitMQ-with-auth-enforced port from any other 401-returning service.
    """
    if resp.status_code != 401:
        return False
    challenge = resp.headers.get("www-authenticate", "").lower()
    return any(marker in challenge for marker in _WWW_AUTH_MARKERS)


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"
        overview_url = f"{base}/api/overview"

        # 1. Anonymous read of /api/overview.
        anon_resp = _get(overview_url)
        if anon_resp is None:
            # Transport error on this port — try the next candidate.
            continue

        anon_overview = _is_rabbitmq_overview(anon_resp)

        if anon_overview is not None:
            # 200 with the RabbitMQ overview body and no auth challenge =>
            # anonymous read of the broker is enabled. HIGH.
            evidence: dict[str, Any] = {
                "host": target.host,
                "port": port,
                "anonymous_access": True,
                "rabbitmq_version": anon_overview.get("rabbitmq_version"),
                "management_version": anon_overview.get("management_version"),
            }
            erlang = anon_overview.get("erlang_version")
            if erlang:
                evidence["erlang_version"] = erlang
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence=evidence,
                description=(
                    metadata["description"]
                    + " Anonymous read of /api/overview is enabled — the "
                    "broker topology (queues, exchanges, connected clients) "
                    "and version are readable without credentials."
                ),
            )

        # Not an anonymous overview. To proceed with the default-credential
        # check we require a positive RabbitMQ fingerprint — either the 401
        # carries the RabbitMQ WWW-Authenticate marker, or some other request
        # to this port has already identified it as RabbitMQ. Without the
        # fingerprint we MUST NOT attempt guest:guest against an arbitrary
        # 401-returning service: that would be probing unrelated systems.
        if not _is_rabbitmq_challenge(anon_resp):
            continue

        # 2. Default credentials: a single guest:guest GET of /api/overview.
        auth_resp = _get(overview_url, auth=(_DEFAULT_USER, _DEFAULT_PASS))
        if auth_resp is None:
            continue

        auth_overview = _is_rabbitmq_overview(auth_resp)
        if auth_overview is None:
            # 401/403 with guest:guest => the guest account is correctly
            # restricted; not vulnerable on this port.
            continue

        evidence = {
            "host": target.host,
            "port": port,
            "default_creds": True,
            "matched_user": _DEFAULT_USER,
            "rabbitmq_version": auth_overview.get("rabbitmq_version"),
            "management_version": auth_overview.get("management_version"),
        }
        erlang = auth_overview.get("erlang_version")
        if erlang:
            evidence["erlang_version"] = erlang
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="critical",
            evidence=evidence,
            description=(
                metadata["description"]
                + " The factory guest:guest administrator credential is "
                "accepted on the management API — full broker control "
                "(queue declare/delete, publish/consume, user management) "
                "is reachable without further authentication."
            ),
        )

    return None
