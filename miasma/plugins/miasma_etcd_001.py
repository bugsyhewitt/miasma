"""MIASMA-ETCD-001 — etcd unauthenticated client API access.

etcd, the distributed key/value store that backs Kubernetes (and many service
meshes, feature-flag systems, and lock services), ships with **authentication
disabled by default**. Until an operator explicitly enables RBAC
(``etcdctl auth enable`` and a configured root user) — or terminates the client
endpoint behind mutual-TLS client certs — the etcd v3 client API on the default
port 2379 answers every request with no credential. etcd v3 exposes that API
both as gRPC and, via the built-in gRPC-gateway, as a plain JSON-over-HTTP
surface on the same port; the JSON gateway is what this probe speaks.

An etcd reachable on 2379 with auth off is among the highest-impact
misconfigurations on an internal network. When the cluster is the Kubernetes
control-plane store it holds *every* Kubernetes Secret in the cluster — service
account tokens, TLS private keys, registry pull credentials — in (by default)
plaintext. Even a non-Kubernetes etcd routinely holds application config, DSNs,
and feature secrets in its keyspace. Bug-bounty programs rate an internet- or
broadly-internal-reachable unauthenticated etcd as P1/CRITICAL because a single
range read dumps the entire keyspace.

This probe is BENIGN and read-only. It runs the minimal requests a human would
run by hand to confirm the finding, and never writes, deletes, compacts, or
touches any auth/maintenance-mutation endpoint:

    1. GET /version — the gRPC-gateway version endpoint. A genuine reply is a
       JSON object carrying the ``etcdserver`` and ``etcdcluster`` keys unique
       to etcd; ``etcdserver`` is the running server version. This fingerprints
       etcd but is NOT sufficient on its own — /version answers even when the
       v3 KV API requires authentication.
    2. POST /v3/maintenance/status — confirms the v3 client API answers without
       a credential and returns the cluster status (leader id, raft term, and
       the on-disk database size ``dbSize``). A successful status read is the
       authoritative "the API is unauthenticated" signal: when auth is enabled
       this returns HTTP 401 with ``etcdserver: user name is empty``.
    3. POST /v3/kv/range — a single bounded range read to confirm the keyspace
       itself is readable and to size it. etcd's gateway expects base64 ``key``
       and ``range_end``; the all-keys range is key ``"\\0"`` (b64 ``AA==``) with
       range_end ``"\\0"`` (the documented "all keys from \\0" convention). The
       request sets ``count_only: true`` and ``keys_only: true`` so the server
       returns only the COUNT and the key names — never the secret values — and
       the response payload stays tiny. The returned key NAMES are scanned
       in-memory (never stored) for Kubernetes-secret and credential markers to
       raise severity. No value bytes are ever requested, decoded, or stored.

Severity matrix:
    * HIGH   — /v3/maintenance/status answers without a credential AND the
               keyspace range read confirms the store is readable without auth
               (the entire keyspace — secrets included — is exfiltratable). Also
               HIGH when the key names reveal Kubernetes secrets / credential
               markers.
    * MEDIUM — /version fingerprints etcd and the v3 API answers without a
               credential, but the keyspace read was empty or could not be
               sized (still an unauthenticated control-plane API worth
               reporting).
    * none   — etcd not fingerprinted, or the v3 client API returns 401
               (authentication enabled / mutual-TLS required).

Candidate ports: 2379 (primary client API), 4001 (legacy v2 client port),
2380 (peer API — usually mTLS, probed last), 80, 443.

[Worker decision: plugin filename is miasma_etcd_001.py (underscores) because
the runner discovers plugins via importlib and module names cannot contain
hyphens. The canonical id MIASMA-ETCD-001 lives in metadata["vuln_id"],
matching the existing miasma_consul_001.py / miasma_prometheus_001.py
convention. etcd was not in POST_V01.md's ranked roadmap, but it is the natural
next service-exposure plugin in the same family as Consul/Prometheus and is the
control-plane store behind Kubernetes (already covered for the API server by
miasma_k8s_001) — closing the etcd gap completes that exposure surface.]
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-ETCD-001",
    "name": "etcd Unauthenticated Client API Access",
    "description": (
        "etcd client API reachable without a credential, exposing the entire "
        "key/value keyspace and the cluster maintenance API. etcd ships with "
        "authentication disabled by default, so until an operator enables RBAC "
        "(or fronts the client port with mutual-TLS) the v3 client API on port "
        "2379 answers every request unauthenticated. When etcd is the Kubernetes "
        "control-plane store this exposes every cluster Secret (service-account "
        "tokens, TLS keys, registry credentials) in plaintext."
    ),
    "confidence": "high",
    "references": [
        "https://etcd.io/docs/latest/op-guide/authentication/rbac/",
        "https://etcd.io/docs/latest/dev-guide/api_grpc_gateway/",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [2379, 4001, 2380, 80, 443],
    "service_hint": ["etcd", "etcd-client", "http", "https"],
    "default_ports": [2379, 4001, 2380, 80, 443],
}

# Keys present in a genuine /version reply. The gRPC-gateway answers this with a
# top-level object carrying both keys on every etcd v3 build; their joint
# presence is the fingerprint.
_VERSION_KEYS = ("etcdserver", "etcdcluster")

# The all-keys range, per etcd's documented convention: key "\0" with
# range_end "\0" selects every key from \0 onward (the whole keyspace). The
# gRPC-gateway expects both base64-encoded.
_ALL_KEYS_B64 = base64.b64encode(b"\x00").decode()  # "AA=="

# Markers that, if present in a returned KEY NAME, indicate the unauthenticated
# keyspace is leaking Kubernetes secrets or credentials — escalates the finding.
# Matched case-insensitively against the decoded key path only. Value bytes are
# never requested, so only key names are ever scanned.
_CREDENTIAL_MARKERS = (
    "/secrets/",
    "secret",
    "password",
    "passwd",
    "token",
    "serviceaccount",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "tls.key",
)

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered etcd-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        etcd_like = [
            port
            for port in open_ports
            if "etcd" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return etcd_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS for the canonical TLS port; everything else plain HTTP.

    etcd is frequently fronted with TLS even on 2379, but the gRPC-gateway also
    routinely runs plaintext on 2379 in misconfigured deployments. We treat 443
    as HTTPS and probe 2379/4001/2380/80 over plain HTTP; the per-request error
    handling means a TLS-only port simply yields no response and the probe moves
    on, so we never wrongly claim a finding against a port we couldn't speak to.
    """
    return "https" if port == 443 else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign unauthenticated GET; returns None on any transport error.

    TLS verification is disabled because self-signed / internal-CA certificates
    are the norm on etcd deployments.
    """
    try:
        return httpx.get(url, timeout=_TIMEOUT, verify=False, follow_redirects=False)
    except httpx.HTTPError:
        return None


def _post(url: str, json: dict[str, Any]) -> httpx.Response | None:
    """Benign unauthenticated POST to a read-only v3 endpoint.

    The only endpoints this probe POSTs to are /v3/maintenance/status (a pure
    read of cluster status) and /v3/kv/range with count_only/keys_only set (a
    pure read that returns no values). Neither mutates state.
    """
    try:
        return httpx.post(
            url,
            json=json,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _fingerprint_version(resp: httpx.Response | None) -> str | None:
    """Return the etcd server version from a /version reply, else None.

    A genuine etcd /version reply is a JSON object with both ``etcdserver`` and
    ``etcdcluster`` keys. Returns the ``etcdserver`` string when the body is a
    genuine etcd fingerprint; ``None`` when the port is not etcd.
    """
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    if not all(key in body for key in _VERSION_KEYS):
        return None
    version = body.get("etcdserver")
    return version if isinstance(version, str) and version else ""


def _status_unauthenticated(base: str) -> dict[str, Any] | None:
    """POST /v3/maintenance/status; return status dict if API is open, else None.

    etcd answers a successful status read with a JSON object carrying a
    ``header`` (cluster/member ids, raft term) and fields like ``version``,
    ``dbSize``, and ``leader``. When authentication is enabled the gateway
    returns HTTP 401 / a gRPC ``Unauthenticated`` error instead — in which case
    we return None ("the v3 API is NOT open").
    """
    resp = _post(f"{base}/v3/maintenance/status", json={})
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict) or "header" not in body:
        return None
    return body


def _range_keyspace(base: str) -> dict[str, Any] | None:
    """POST a count/keys-only all-keys range; return {'count', 'cred_leak'}.

    Returns ``None`` when the range read fails or is auth-gated. Otherwise
    returns a dict with the integer key ``count`` (the number of keys in the
    store, possibly 0) and the boolean ``cred_leak`` (whether any returned key
    NAME matches a credential / Kubernetes-secret marker).

    The request sets ``count_only`` and ``keys_only`` so the server returns only
    the count and the (already-public) key names — never any secret value bytes.
    We still cap the request with ``keys_only`` defensively and only ever read
    the decoded key NAMES in-memory; nothing is stored in the finding.
    """
    payload = {
        "key": _ALL_KEYS_B64,
        "range_end": _ALL_KEYS_B64,
        "count_only": True,
    }
    resp = _post(f"{base}/v3/kv/range", json=payload)
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None

    count_raw = body.get("count")
    try:
        count = int(count_raw) if count_raw is not None else 0
    except (TypeError, ValueError):
        count = 0

    # count_only responses carry no kvs; do a second keys_only read (bounded by
    # the server, still value-free) to scan key names for credential markers.
    cred_leak = _keys_leak_credentials(base)

    return {"count": count, "cred_leak": cred_leak}


def _keys_leak_credentials(base: str) -> bool:
    """POST a keys_only all-keys range and scan key NAMES for cred markers.

    Returns ``True`` when any returned key name matches a credential / k8s-secret
    marker, else ``False``. ``keys_only`` guarantees the server returns key names
    with empty value fields, so no secret value is ever transmitted, decoded, or
    stored. On any failure we conservatively return ``False`` (no leak observed).
    """
    payload = {
        "key": _ALL_KEYS_B64,
        "range_end": _ALL_KEYS_B64,
        "keys_only": True,
    }
    resp = _post(f"{base}/v3/kv/range", json=payload)
    if resp is None or resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    if not isinstance(body, dict):
        return False
    kvs = body.get("kvs")
    if not isinstance(kvs, list):
        return False
    for entry in kvs:
        if not isinstance(entry, dict):
            continue
        key_b64 = entry.get("key")
        if not isinstance(key_b64, str) or not key_b64:
            continue
        try:
            key_name = base64.b64decode(key_b64).decode("utf-8", "replace")
        except Exception:
            continue
        lowered = key_name.lower()
        if any(marker in lowered for marker in _CREDENTIAL_MARKERS):
            return True
    return False


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        version = _fingerprint_version(_get(f"{base}/version"))
        if version is None:
            # Not etcd on this port (or /version not the gateway) — try next.
            continue

        # Confirm the v3 client API answers without a credential.
        status = _status_unauthenticated(base)
        if status is None:
            # etcd fingerprinted, but the v3 API is auth-gated (401) on this
            # port — not an unauthenticated-access finding. Try the next port.
            continue

        db_size = status.get("dbSize")

        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "version": version or None,
            "api_unauthenticated": True,
        }
        if isinstance(db_size, (int, str)):
            evidence["db_size"] = db_size

        # Confirm the keyspace itself is readable without auth.
        keyspace = _range_keyspace(base)

        if keyspace is not None:
            key_count = keyspace["count"]
            cred_leak = keyspace["cred_leak"]
            evidence["keyspace_readable"] = True
            evidence["key_count"] = key_count
            evidence["key_names_leak_credentials"] = cred_leak

            if cred_leak:
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence=evidence,
                    description=(
                        metadata["description"]
                        + " The /v3/kv/range endpoint returned the keyspace "
                        "without a credential and a key name matches a "
                        "Kubernetes-secret / credential marker "
                        "(secrets/token/password/...)."
                    ),
                )
            if key_count > 0:
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence=evidence,
                    description=(
                        metadata["description"]
                        + f" The /v3/kv/range endpoint reported {key_count} key(s) "
                        "readable without a credential — the entire keyspace is "
                        "exfiltratable."
                    ),
                )
            # keyspace readable but empty — still unauthenticated.
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="medium",
                evidence=evidence,
                description=(
                    metadata["description"]
                    + " The v3 client API answered without a credential; the "
                    "keyspace was readable but empty."
                ),
            )

        # status answered unauthenticated but the keyspace read failed/gated.
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence=evidence,
            description=(
                metadata["description"]
                + " The /v3/maintenance/status endpoint answered without a "
                "credential (cluster status and version exposed); the keyspace "
                "range read was not reachable on this port."
            ),
        )

    return None
