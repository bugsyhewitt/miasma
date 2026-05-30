"""MIASMA-COUCHDB-001 — Apache CouchDB unauthenticated HTTP API exposure.

Apache CouchDB is a document database whose HTTP API is the only API surface;
every operation (create database, read document, replicate, run a view, edit
the cluster admin set) is one HTTP request. Two recurring misconfigurations
turn an internet- or broadly-internal-reachable CouchDB into a P1/critical
finding:

    1. **"Admin party" — no server admin configured.** CouchDB 1.x shipped in
       this state out of the box; 2.x/3.x require an admin to be set during
       cluster setup but a node started without completing setup, or a node
       whose ``_users`` / local.ini admin section was cleared, falls back to
       admin party. In admin party EVERY peer is a server admin. An
       unauthenticated peer can create databases, read/write/delete any
       document, replicate the entire dataset to an attacker-controlled
       endpoint, and on builds before the CVE-2022-24706 hardening edit the
       cluster admin set / install a design document that runs arbitrary
       JavaScript in the query server. The probe confirms via the documented
       admin-only endpoint ``GET /_all_dbs``: a 200 carrying the JSON array
       of database names without an authentication challenge is the
       definitive admin-party positive.

    2. **CVE-2017-12635 / CVE-2017-12636 era exposure.** Pre-2.1.1 builds
       answered ``GET /_config`` unauthenticated on the per-node loopback
       binding and shipped the Erlang ``query_server`` config writable,
       which chains to RCE. We do not probe ``/_config`` (it is gone from
       the cluster API in 3.x and the 1.x/early-2.x loopback variant is a
       different surface), but the version banner from ``GET /`` is
       captured so an operator can flag in-scope builds.

This probe is BENIGN and read-only. It runs the minimal GET requests a human
would run by hand to confirm the exposure and then stops:

    1. ``GET /`` — fingerprints CouchDB. A genuine reply is a JSON object
       whose ``couchdb`` field equals (case-insensitive) ``"Welcome"`` and
       whose ``version`` field is a parseable semver string. Both markers
       must be present; neither field is shipped by any other product.
    2. ``GET /_all_dbs`` — confirms admin-party exposure. A 200 carrying a
       JSON array is the positive (even an empty ``[]`` array is a
       positive: the endpoint is admin-only, so a 200 reply without
       authentication is the definitive misconfiguration regardless of
       whether the cluster has yet created its first user database). A
       401/403 reply means an admin is configured and authentication is
       enforced — clean negative.

A non-CouchDB host (a coincidental JSON 200 on ``/`` without both the
``couchdb`` and ``version`` markers, or a 200 on ``/_all_dbs`` whose body is
not a JSON array) is NEVER flagged. Redirects are not followed.

Evidence records only the host, port, CouchDB version string, the database
count, the CouchDB-reported ``vendor`` name when present, and (when the
``/`` reply included it) the ``git_sha`` / ``uuid`` fields the server itself
publishes. Database NAMES are NEVER read or stored; only the count.
Document bodies are NEVER read.

Severity matrix:
    * HIGH — CouchDB fingerprints AND ``/_all_dbs`` returns 200 with a JSON
             array. The cluster is in admin party; every database is
             readable, writable, and replicable to any peer.
    * none  — Not CouchDB, or ``/_all_dbs`` refused with 401/403 (an admin
              is configured), or any other non-array reply shape.

Candidate ports: ``5984`` (the documented default for the per-node clustered
port), ``6984`` (the documented TLS variant of 5984), ``80`` and ``443``
(common reverse-proxy fronts; ``443`` and ``6984`` are contacted over HTTPS,
everything else over plain HTTP).

[Worker decision: filename is miasma_couchdb_001.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain
hyphens; canonical id MIASMA-COUCHDB-001 lives in metadata["vuln_id"],
matching the existing miasma_*_001.py convention. The spec named
MIASMA-REDIS-001 and MIASMA-PROMETHEUS-001 as candidates but verification
against the codebase showed both were already shipped (R32-equivalent and
R26 respectively); per the spec's "verify against the actual codebase
before implementing" clause this rotation pivots to MIASMA-COUCHDB-001, the
next gap in the unauthenticated-datastore family (already-shipped peers:
mongodb, redis, elastic, cassandra, influxdb, memcached, zookeeper, etcd —
CouchDB is the remaining mainstream document store). The probe avoids
``GET /_config`` (gone from the cluster API in 3.x, different surface in
1.x/early-2.x) and never PUTs to ``/_node/.../`` to add an admin or
``/_users`` to create a user; admin party is confirmed exclusively via the
read-only ``/_all_dbs`` admin-only endpoint, which is the same one-step
check a human operator runs by hand.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-COUCHDB-001",
    "name": "CouchDB Unauthenticated HTTP API Exposure",
    "description": (
        "Apache CouchDB reachable without authentication on its HTTP API. "
        "CouchDB in 'admin party' mode (no server admin configured, or a "
        "node started without completing cluster setup) treats every peer "
        "as a server admin: any peer can create databases, read/write/delete "
        "any document, replicate the entire dataset to an attacker-controlled "
        "endpoint, and on builds before the CVE-2022-24706 hardening edit "
        "the cluster admin set or install a design document that runs "
        "arbitrary JavaScript in the query server. The admin-only "
        "/_all_dbs endpoint answering 200 without authentication is the "
        "definitive misconfiguration marker."
    ),
    "confidence": "high",
    "references": [
        "https://docs.couchdb.org/en/stable/intro/security.html",
        "https://docs.couchdb.org/en/stable/setup/cluster.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-24706",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-12635",
        "https://owasp.org/www-community/Broken_Access_Control",
    ],
    "port_hint": [5984, 6984, 80, 443],
    "service_hint": ["couchdb", "couch", "http", "https"],
    "default_ports": [5984, 6984, 80, 443],
}

_TIMEOUT = 5.0

# Ports contacted over TLS. 6984 is CouchDB's documented HTTPS variant of 5984;
# 443 is the reverse-proxy front.
_HTTPS_PORTS = (443, 6984)

# Required top-level value of the ``couchdb`` field on the welcome banner.
# CouchDB has answered the literal string "Welcome" since 0.x and no other
# product ships this exact field/value pair.
_COUCHDB_WELCOME_MARKER = "welcome"


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered CouchDB-ish open ports; else the port hints."""
    open_ports = target.open_ports()
    if open_ports:
        couch_like = [
            port
            for port in open_ports
            if "couch" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return couch_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


def _get(url: str) -> httpx.Response | None:
    try:
        return httpx.get(
            url,
            timeout=_TIMEOUT,
            verify=False,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return None


def _parse_welcome(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the parsed ``/`` body if it identifies as CouchDB.

    Genuine CouchDB ``/`` has:
      * status_code == 200
      * a JSON object body
      * a ``couchdb`` field whose value is the string "Welcome"
        (case-insensitive)
      * a ``version`` field that is a non-empty string
    Both markers must be present; either alone is not enough.
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    couchdb_field = body.get("couchdb")
    if not isinstance(couchdb_field, str):
        return None
    if couchdb_field.strip().lower() != _COUCHDB_WELCOME_MARKER:
        return None
    version_field = body.get("version")
    if not isinstance(version_field, str) or not version_field:
        return None
    return body


def _parse_all_dbs(resp: httpx.Response) -> int | None:
    """Return the database count from ``/_all_dbs``, or None.

    The admin-only ``/_all_dbs`` endpoint answers a JSON array of database
    names. A 200 carrying any JSON array — including an empty one — is the
    definitive admin-party positive: the endpoint is admin-restricted, so a
    200 reply without authentication confirms no admin is configured
    regardless of whether the cluster has yet created its first user
    database. A 401/403 / non-JSON / non-array reply is not flagged.
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, list):
        return None
    return len(body)


def _probe_port(target: Target, port: int) -> Finding | None:
    base = f"{_scheme(port)}://{target.host}:{port}"

    welcome_resp = _get(f"{base}/")
    if welcome_resp is None:
        return None
    welcome_body = _parse_welcome(welcome_resp)
    if welcome_body is None:
        return None

    all_dbs_resp = _get(f"{base}/_all_dbs")
    if all_dbs_resp is None:
        return None
    db_count = _parse_all_dbs(all_dbs_resp)
    if db_count is None:
        return None

    evidence: dict[str, Any] = {
        "host": target.host,
        "port": port,
        "couchdb_version": welcome_body["version"],
        "database_count": db_count,
    }
    # Optional welcome-banner fields the server itself publishes. Vendor /
    # git_sha / uuid help an operator distinguish a vanilla Apache build
    # from a downstream distribution (IBM Cloudant, Bitnami, etc.) without
    # touching any document or database name.
    vendor = welcome_body.get("vendor")
    if isinstance(vendor, dict):
        vendor_name = vendor.get("name")
        if isinstance(vendor_name, str) and vendor_name:
            evidence["vendor"] = vendor_name
    git_sha = welcome_body.get("git_sha")
    if isinstance(git_sha, str) and git_sha:
        evidence["git_sha"] = git_sha
    uuid = welcome_body.get("uuid")
    if isinstance(uuid, str) and uuid:
        evidence["uuid"] = uuid

    return Finding(
        vuln_id=metadata["vuln_id"],
        host=target.host,
        confidence="high",
        evidence=evidence,
        description=(
            metadata["description"]
            + " /_all_dbs answers 200 with a JSON array and no "
            "authentication challenge — the cluster is in admin party and "
            "every database is readable, writable, and replicable to any "
            "peer."
        ),
    )


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        finding = _probe_port(target, port)
        if finding is not None:
            return finding
    return None
