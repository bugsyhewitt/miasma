"""MIASMA-CONSUL-001 — HashiCorp Consul unauthenticated HTTP API access.

HashiCorp Consul ships with its **ACL system disabled by default**. Until an
operator explicitly bootstraps ACLs (``acl { enabled = true, default_policy =
"deny" }``), the full HTTP API on the default port 8500 answers every request
with no token and no authentication. An instance reachable on 8500 therefore
exposes the entire service mesh control plane to any client that can reach it.
The most valuable leaks are:

    * /v1/catalog/services — every registered service across the datacenter.
                             Like Prometheus' /api/v1/targets this is a live,
                             authoritative inventory of the internal estate
                             (service names → tags), discovered by Consul itself.
    * /v1/kv/?recurse=true — the recursive Key/Value store. Teams routinely keep
                             application configuration, database DSNs, API keys,
                             and other secrets in Consul KV; with ACLs off the
                             whole tree is readable (and writable). The values
                             are base64-encoded in the JSON response.
    * /v1/agent/self       — the agent's own configuration and member info;
                             carries the Consul ``Config``/``Member`` objects
                             that uniquely fingerprint a Consul agent and reveal
                             the running version and datacenter name.

Bug-bounty programs routinely rate an internet-exposed, ACL-disabled Consul as
P1/CRITICAL: the KV store frequently leaks credentials outright, and the catalog
hands an attacker a map of the internal network. Even with an empty KV store the
unauthenticated catalog inventory is a solid P2/HIGH.

This probe is BENIGN and read-only. It runs the three minimal GET requests a
human would run by hand to confirm the finding:

    1. GET /v1/agent/self — fingerprints Consul; a genuine reply is a JSON object
       carrying the ``Config`` and ``Member`` keys unique to the Consul agent
       API. The running version is read from ``Config.Version`` (older agents)
       or ``Member.Tags.build`` (newer agents) when present.
    2. GET /v1/catalog/services — confirms the service catalog is readable
       without a token and captures the registered-service count.
    3. GET /v1/kv/?recurse=true — confirms the KV store is readable without a
       token; the key names and the decoded values are scanned in-memory (never
       stored) for credential markers to raise severity.

No key is written, no service is deregistered, and no admin/operator endpoint
(``/v1/acl/bootstrap``, ``/v1/operator/*``) is touched. Only the read endpoints
are contacted — exactly the handshake used to confirm the finding by hand.

Severity matrix:
    * HIGH   — agent/self confirms Consul AND the KV store is readable without a
               token and contains credential markers (password/token/secret/...).
    * HIGH   — /v1/catalog/services enumerates one or more registered services
               without authentication (internal inventory leak).
    * MEDIUM — agent/self confirms Consul and at least one read endpoint answers
               without a token, but no services and no KV credentials were
               observed (still an unauthenticated API surface worth reporting).
    * none   — Consul not fingerprinted, or the API requires an ACL token.

Candidate ports: 8500 (primary HTTP API), 80, 443, 8501 (HTTPS API front).

[Worker decision: plugin filename is miasma_consul_001.py (underscores) because
the runner discovers plugins via importlib and module names cannot contain
hyphens. The canonical id MIASMA-CONSUL-001 lives in metadata["vuln_id"],
matching the existing miasma_prometheus_001.py / miasma_solr_001.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-CONSUL-001",
    "name": "Consul Unauthenticated HTTP API Access",
    "description": (
        "HashiCorp Consul HTTP API reachable without an ACL token, exposing the "
        "service catalog (every registered service across the datacenter), the "
        "recursive Key/Value store (which routinely holds application secrets and "
        "credentials), and the agent configuration. Consul ships with its ACL "
        "system disabled by default, so until an operator bootstraps ACLs the "
        "full read/write API on port 8500 answers every request unauthenticated."
    ),
    "confidence": "high",
    "references": [
        "https://developer.hashicorp.com/consul/docs/security/acl",
        "https://developer.hashicorp.com/consul/api-docs",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [8500, 80, 443, 8501],
    "service_hint": ["consul", "http", "https"],
    "default_ports": [8500, 80, 443, 8501],
}

# Keys present in a genuine /v1/agent/self object. The Consul agent API answers
# this endpoint with a top-level object carrying these keys on every supported
# build; their joint presence is the fingerprint.
_AGENT_SELF_KEYS = ("Config", "Member")

# Markers that, if present in a KV key name or its decoded value, indicate the
# unauthenticated KV store is leaking secrets — escalates the finding. Matched
# case-insensitively against both the key path and the decoded value text.
_CREDENTIAL_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "aws_access",
)

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Consul-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        consul_like = [
            port
            for port in open_ports
            if "consul" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return consul_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS for the canonical TLS ports; everything else plain HTTP."""
    return "https" if port in (443, 8501) else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign unauthenticated GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common on
    internal Consul deployments fronted by a reverse proxy or Consul's own TLS.
    """
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _agent_self(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the agent/self object if genuinely Consul, else None."""
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    if all(key in body for key in _AGENT_SELF_KEYS):
        return body
    return None


def _parse_version(agent: dict[str, Any]) -> str | None:
    """Pull the Consul version from an agent/self object (None if absent).

    Newer agents put the version under ``Config.Version``; older builds expose
    it via ``Member.Tags.build`` (e.g. ``"1.18.1:abc1234"``). We try both.
    """
    config = agent.get("Config")
    if isinstance(config, dict):
        value = config.get("Version")
        if isinstance(value, str) and value:
            return value

    member = agent.get("Member")
    if isinstance(member, dict):
        tags = member.get("Tags")
        if isinstance(tags, dict):
            build = tags.get("build")
            if isinstance(build, str) and build:
                # Tags.build is "<version>:<revision>" — keep just the version.
                return build.split(":", 1)[0]
    return None


def _count_catalog_services(base: str) -> int | None:
    """GET /v1/catalog/services and return the registered-service count.

    Returns ``None`` when the request fails or the endpoint requires a token; an
    int (possibly 0) when the endpoint answered with a parseable services map.
    Consul answers this endpoint with a JSON object mapping service name → tags,
    e.g. ``{"consul": [], "web": ["v1"], "db": []}``.
    """
    resp = _get(f"{base}/v1/catalog/services")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    return len(body)


def _kv_leaks_credentials(base: str) -> bool | None:
    """GET /v1/kv/?recurse=true and report whether it leaks credentials.

    Returns ``None`` when the KV endpoint is unreachable/token-gated (Consul
    answers 403 ``Permission denied`` when ACLs deny the read, and 404 when the
    store is genuinely empty — both mean "no credential leak observed here"),
    ``True`` when a key name or decoded value contains a credential marker, and
    ``False`` when the store is readable but no markers were found.

    The recursive KV listing is Consul's standard JSON form: a list of objects
    each carrying ``Key`` and a base64 ``Value``. Both the key path and the
    decoded value text are scanned in-memory only — neither is ever stored in
    the finding.
    """
    resp = _get(f"{base}/v1/kv/?recurse=true")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, list):
        return None

    import base64

    for entry in body:
        if not isinstance(entry, dict):
            continue
        key = entry.get("Key")
        if isinstance(key, str) and any(
            marker in key.lower() for marker in _CREDENTIAL_MARKERS
        ):
            return True
        value = entry.get("Value")
        if isinstance(value, str) and value:
            try:
                decoded = base64.b64decode(value).decode("utf-8", "replace")
            except Exception:
                continue
            lowered = decoded.lower()
            if any(marker in lowered for marker in _CREDENTIAL_MARKERS):
                return True
    return False


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        agent_resp = _get(f"{base}/v1/agent/self")
        if agent_resp is None:
            continue

        agent = _agent_self(agent_resp)
        if agent is None:
            # Not Consul on this port (or agent/self token-gated) — try next.
            continue

        version = _parse_version(agent)

        # Two supplementary unauthenticated reads, both benign.
        service_count = _count_catalog_services(base)
        kv_creds = _kv_leaks_credentials(base)

        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "version": version,
            "api_unauthenticated": True,
        }

        # --- Path A: KV store leaks credentials => HIGH ---
        if kv_creds is True:
            evidence["kv_readable"] = True
            evidence["kv_leaks_credentials"] = True
            if service_count is not None:
                evidence["services_exposed"] = True
                evidence["service_count"] = service_count
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence=evidence,
                description=(
                    metadata["description"]
                    + " The /v1/kv/?recurse=true endpoint returned the recursive "
                    "Key/Value store without a token, and a key name or decoded "
                    "value contains credential markers "
                    "(password/token/secret/...)."
                ),
            )

        # --- Path B: service catalog readable => HIGH ---
        if service_count is not None:
            evidence["services_exposed"] = True
            evidence["service_count"] = service_count
            if kv_creds is False:
                evidence["kv_readable"] = True
                evidence["kv_leaks_credentials"] = False
            if service_count > 0:
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence=evidence,
                    description=(
                        metadata["description"]
                        + " The /v1/catalog/services endpoint enumerated "
                        f"{service_count} registered service(s) without a token — "
                        "the internal service inventory is exposed."
                    ),
                )
            # catalog readable but empty — still unauthenticated.
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="medium",
                evidence=evidence,
                description=(
                    metadata["description"]
                    + " The catalog API answered without a token; the service "
                    "list was readable but empty."
                ),
            )

        # --- Path C: only agent/self (and maybe KV w/o creds) readable ---
        if kv_creds is False:
            evidence["kv_readable"] = True
            evidence["kv_leaks_credentials"] = False
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence=evidence,
            description=(
                metadata["description"]
                + " The /v1/agent/self endpoint answered without a token "
                "(agent configuration and version exposed); the service catalog "
                "was not reachable on this port."
            ),
        )

    return None
