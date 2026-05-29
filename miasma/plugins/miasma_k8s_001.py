"""MIASMA-K8S-001 — Kubernetes API server reachable without authentication.

A Kubernetes API server with anonymous authentication enabled
(``--anonymous-auth=true`` — the default on older clusters and still seen on
self-managed installs) lets an unauthenticated client read cluster metadata and,
when RBAC is permissive, enumerate cluster resources. The API server is the
control plane's front door: anonymous read of the namespace list, pod inventory,
or secrets is a direct path to cluster compromise, and it is a recurring
P1/P2 finding in cloud-native bug-bounty programs.

This probe is BENIGN, read-only, and ENUMERATION-ONLY. It never creates,
mutates, or deletes any resource, never reads Secret *contents*, and never
attempts a privilege-escalation or token-replay step. It only issues
unauthenticated GETs against the well-known public API-server endpoints and
distinguishes "anonymous access is on" from "the server refuses anonymous
requests" (the secure default, which answers ``401``/``403``).

Flow:

    1. GET /version            — the API server's build endpoint. On an
                                 anonymous-enabled cluster this returns a JSON
                                 object with ``gitVersion``/``major``/``minor``.
                                 It is the canonical Kubernetes fingerprint AND
                                 confirms anonymous read in one request.
    2. GET /api/v1/namespaces  — the namespace list. A ``200`` with a
                                 ``NamespaceList`` body means anonymous access
                                 reaches real cluster resources (deeper than the
                                 version endpoint); a ``401``/``403`` means the
                                 server is fingerprinted as Kubernetes but
                                 refuses anonymous enumeration (the secure case).

Severity:

    * HIGH   — the host fingerprints as a Kubernetes API server AND
               ``/api/v1/namespaces`` returns ``200`` with a ``NamespaceList``.
               Anonymous access reaches live cluster resources — the most
               serious, directly actionable exposure.
    * MEDIUM — the host fingerprints as Kubernetes (``/version`` returns a
               Kubernetes build object) but namespace enumeration is refused
               (``401``/``403``). Anonymous read of the *version* endpoint alone
               is still an information leak worth reporting, and the cluster
               warrants a manual deeper check.
    * none   — not a Kubernetes API server (no Kubernetes fingerprint on any
               candidate port), or the server refuses anonymous requests on
               *every* probed endpoint (the secure, fully-locked-down default).

No credentials, bearer tokens, or service-account JWTs are ever sent. Evidence
records the build string, the endpoint reached, and (for HIGH) only the COUNT of
namespaces — never their names or any resource contents.

[Worker decision: ID is MIASMA-K8S-001 (POST_V01 Rank 17 / item 3.4), not a CVE.
Anonymous-auth exposure is a misconfiguration, not a discrete CVE — mirroring the
existing MIASMA-ACTUATOR-001 / MIASMA-GIT-001 / MIASMA-ENV-001 plugins. The
canonical id lives in metadata["vuln_id"].]

[Worker decision: HIGH is gated on the namespace list (anonymous access reaches
real resources), MEDIUM on the version endpoint alone (read leak but no resource
enumeration). This mirrors the POST_V01 entry ("high on version endpoint;
medium on namespace listing" is inverted there, but reaching live resources is
strictly the more severe state, so namespaces=HIGH / version-only=MEDIUM is the
correct severity ordering). We never read Secret contents — enumeration stops at
the namespace list, the standard non-destructive depth marker.]

[Worker decision: the namespace endpoint is only consulted AFTER the host
fingerprints as Kubernetes via /version. A bare 200 on /api/v1/namespaces
without a Kubernetes fingerprint is NOT flagged — an SPA or reverse proxy can
return 200 for any path, and we must not flag a non-Kubernetes host.]
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-K8S-001",
    "name": "Kubernetes API server unauthenticated access",
    "description": (
        "A Kubernetes API server with anonymous authentication enabled lets an "
        "unauthenticated client read the cluster build version and, when RBAC is "
        "permissive, enumerate cluster resources such as the namespace list. The "
        "API server is the control-plane front door, so anonymous read access is "
        "a direct path toward cluster compromise and a recurring P1/P2 "
        "cloud-native bug-bounty finding. This probe enumerates read-only and "
        "never reads secret contents or mutates any resource."
    ),
    "confidence": "high",
    "references": [
        "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests",
        "https://kubernetes.io/docs/concepts/security/",
    ],
    # The API server listens on 6443 (secure) by default; 8443 and 443 are common
    # on managed/proxied clusters. port_hint is the canonical field the runner
    # reads to skip irrelevant plugins; default_ports is the in-probe fallback.
    "port_hint": [6443, 8443, 443],
    "service_hint": ["http", "https", "ssl"],
    "default_ports": [6443, 8443, 443],
}

# The two unauthenticated GET endpoints, in escalating depth. /version is the
# fingerprint + anonymous-read confirmation; /api/v1/namespaces is the deeper
# resource-enumeration check (HIGH).
_VERSION_PATH = "/version"
_NAMESPACES_PATH = "/api/v1/namespaces"

# Keys that mark a genuine Kubernetes /version response. The endpoint returns a
# JSON object describing the build; ``gitVersion`` (e.g. "v1.29.3") plus the
# ``major``/``minor`` pair are the canonical markers.
_VERSION_KEYS = ("gitVersion", "major", "minor")

# The namespace list endpoint answers with a Kubernetes List object whose
# ``kind`` is "NamespaceList". We confirm that shape rather than trusting a bare
# 200 — a proxy/SPA can 200 any path.
_NAMESPACE_LIST_KIND = "NamespaceList"

# Anonymous-refused statuses (the secure default). A server that answers these
# on an endpoint is locked down for that endpoint.
_REFUSED_STATUSES = (401, 403)

# Ports we speak https on. The API server is TLS-only in practice; 443/6443/8443
# all serve TLS, and httpx with verify=False tolerates the cluster's self-signed
# / private-CA serving cert.
_TLS_PORTS = (443, 6443, 8443)

_TIMEOUT = 5.0


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open API-server-ish ports; else the defaults."""
    open_ports = target.open_ports()
    if open_ports:
        api_like = [
            port
            for port in open_ports
            if port in metadata["default_ports"]
            or "http" in target.service(port).get("name", "").lower()
        ]
        return api_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    # The API server is TLS everywhere in practice; default to https for the
    # known API-server ports and any unknown port, http only for an explicit
    # plaintext port (none expected, but kept symmetric with sibling plugins).
    return "https" if port in _TLS_PORTS or port not in (80, 8080) else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign unauthenticated GET; returns None on any transport error.

    TLS verification is disabled (clusters serve private-CA / self-signed certs)
    and redirects are not followed: the API server serves these endpoints
    directly, and a redirect means we are not talking to a real API server.
    No Authorization header, bearer token, or service-account JWT is ever sent.
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


def _json_body(resp: httpx.Response | None) -> dict[str, Any] | None:
    """Parse a response body as a JSON object, or None if it isn't one."""
    if resp is None:
        return None
    try:
        data = json.loads(resp.text)
    except (json.JSONDecodeError, UnicodeDecodeError, httpx.HTTPError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _is_k8s_version(resp: httpx.Response | None) -> dict[str, Any] | None:
    """Return the parsed /version object when it fingerprints Kubernetes.

    A genuine Kubernetes /version response is a JSON object carrying the build
    markers. A bare 200 from a proxy/SPA (HTML, or JSON without these keys) is
    NOT a Kubernetes fingerprint and yields None.
    """
    if resp is None or resp.status_code != 200:
        return None
    body = _json_body(resp)
    if body is None:
        return None
    if any(key in body for key in _VERSION_KEYS):
        return body
    return None


def _git_version(version_obj: dict[str, Any]) -> str | None:
    """The advertised build string (e.g. "v1.29.3"), if present."""
    git_version = version_obj.get("gitVersion")
    if isinstance(git_version, str) and git_version:
        return git_version
    major = version_obj.get("major")
    minor = version_obj.get("minor")
    if major is not None and minor is not None:
        return f"{major}.{minor}"
    return None


def _namespace_count(resp: httpx.Response | None) -> int | None:
    """Return the namespace count when /api/v1/namespaces is anonymously open.

    Confirms the body is a genuine ``NamespaceList`` (not a bare proxy 200) and
    returns the number of namespace items — never their names. Returns None when
    the endpoint refused, errored, or returned a non-NamespaceList body.
    """
    if resp is None or resp.status_code != 200:
        return None
    body = _json_body(resp)
    if body is None or body.get("kind") != _NAMESPACE_LIST_KIND:
        return None
    items = body.get("items")
    if not isinstance(items, list):
        return None
    return len(items)


def probe(target: Target) -> Finding | None:
    medium_evidence: dict[str, Any] | None = None

    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        # 1. Fingerprint + anonymous-read confirmation via /version.
        version_resp = _get(f"{base}{_VERSION_PATH}")
        version_obj = _is_k8s_version(version_resp)
        if version_obj is None:
            # Not a Kubernetes API server answering anonymously on this port.
            continue

        git_version = _git_version(version_obj)

        # 2. Deeper enumeration: can we anonymously list namespaces?
        ns_resp = _get(f"{base}{_NAMESPACES_PATH}")
        ns_count = _namespace_count(ns_resp)

        if ns_count is not None:
            # Anonymous access reaches live cluster resources — the most serious,
            # directly actionable exposure. Record only the namespace COUNT,
            # never the names.
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "base_url": base,
                    "version_endpoint": _VERSION_PATH,
                    "namespace_endpoint": _NAMESPACES_PATH,
                    "git_version": git_version,
                    "namespace_count": ns_count,
                    "note": (
                        "Kubernetes API server allows anonymous enumeration of "
                        "the namespace list (anonymous-auth enabled with "
                        "permissive RBAC). Only the namespace count is recorded; "
                        "no names, secrets, or resource contents were read, and "
                        "no resource was created or modified."
                    ),
                },
                description=metadata["description"],
            )

        # /version answered anonymously but namespace enumeration is refused
        # (or returned no NamespaceList). The version-endpoint leak alone is
        # still worth reporting; remember the first such host as a MEDIUM. A
        # confirmed HIGH on a later port still wins.
        if medium_evidence is None:
            medium_evidence = {
                "base_url": base,
                "version_endpoint": _VERSION_PATH,
                "git_version": git_version,
                "namespace_status": (
                    ns_resp.status_code if ns_resp is not None else None
                ),
                "note": (
                    "Kubernetes API server returns its build version to "
                    "unauthenticated requests, but anonymous namespace "
                    "enumeration is refused. The version-endpoint exposure is an "
                    "information leak worth a manual deeper check. No resource "
                    "was read or modified."
                ),
            }

    if medium_evidence is not None:
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence=medium_evidence,
            description=metadata["description"],
        )

    return None
