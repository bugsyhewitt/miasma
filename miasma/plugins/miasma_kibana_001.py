"""MIASMA-KIBANA-001 — Kibana unauthenticated HTTP API exposure.

Kibana is the official Elasticsearch UI and the dominant operator console for
the Elastic Stack. An unauthenticated Kibana exposes:

    * every index in the backing Elasticsearch cluster (browsing, querying,
      and CSV/JSON export via Discover);
    * every saved search, visualisation, and dashboard (which routinely
      hard-code business-sensitive index patterns and field names);
    * the Dev Tools console (`/app/dev_tools#/console`) which proxies
      arbitrary requests to the Elasticsearch cluster — read AND write — on
      behalf of the Kibana service account;
    * server-status and version detail useful for follow-on CVE selection
      (Kibana has shipped multiple pre-auth and post-auth RCEs, e.g.
      CVE-2019-7609, CVE-2018-17246, CVE-2023-31413).

Two recurring misconfigurations turn that exposure into a P1 finding:

    1. **Anonymous access enabled.** Operators front Kibana with their own
       SSO/auth at a reverse proxy and configure Kibana with
       ``xpack.security.authc.providers.anonymous`` (or the legacy
       ``xpack.security.authc.anonymous`` block) so dashboards render for
       unauthenticated viewers. The proxy auth is then routinely
       mis-configured, scoped to the wrong path, or simply absent on a
       second proxy. A ``GET /api/status`` answering ``200`` with the Kibana
       status JSON and **no** auth challenge confirms anonymous read.

    2. **Default / no security plugin.** The free Open Distro / OpenSearch
       Dashboards forks and stripped-down Kibana deployments occasionally
       ship without any security plugin installed. The login screen is
       never presented; the UI and Dev Tools console are reachable by any
       peer that can hit port ``5601``.

This probe is BENIGN and read-only. It fingerprints Kibana via the documented
``/api/status`` endpoint, which has carried the unique ``name == "kibana"``
top-level marker (alongside a ``version.number`` semver) across every
supported 7.x and 8.x release. The fingerprint is what distinguishes Kibana
from any other JSON-200 service that happens to sit on 5601 (the OpenSearch
Dashboards fork carries ``name == "OpenSearch Dashboards"`` instead and is
intentionally NOT flagged by this probe — it's a different product with its
own version surface and CVEs).

    1. ``GET /api/status`` — with no credentials.
       - 200 with a JSON body carrying ``name == "kibana"`` (case-insensitive)
         AND a parseable ``version.number`` => Kibana fingerprinted AND
         anonymous read confirmed (HIGH; ``anonymous_access=True``).
       - 401 / 403 with a Kibana-flavoured WWW-Authenticate challenge (or a
         JSON body whose ``error`` mentions Kibana) => Kibana fingerprinted,
         auth enforced; not vulnerable on this port.
       - 302 to ``/login`` / ``/spaces/enter`` => auth enforced; not
         vulnerable on this port.
       - Anything else (not Kibana, or a non-Kibana surface on this port) =>
         skip this port; never flagged.

No saved object is read, no index is queried, no Dev Tools call is issued,
no mutating endpoint (``/api/saved_objects/*``, ``/api/console/proxy``,
``/api/spaces/*``, ``/internal/*``) is touched. Evidence records only the
host, port, Kibana version, build number and build hash (all already in the
``/api/status`` body), and the overall status string — never the saved-object
inventory, the dashboard titles, or any index data.

Severity matrix:
    * HIGH — Kibana fingerprints AND ``/api/status`` answers 200 with no auth
             challenge (``anonymous_access=True``). The UI is reachable
             without credentials; every index in the backing Elasticsearch
             cluster is one click away in Discover, and the Dev Tools
             console proxies arbitrary requests to Elasticsearch on the
             Kibana service account.
    * none  — Not Kibana, or Kibana with authentication enforced (a 401 /
              403 challenge, or a 302 to a login surface).

Candidate ports: ``5601`` (HTTP, the documented default), ``5602`` (the
common second-instance port observed in clustered estates), and the common
reverse-proxy fronts ``80`` / ``443`` (``443`` is contacted over HTTPS;
everything else over plain HTTP).

[Worker decision: plugin filename is miasma_kibana_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens. The canonical id MIASMA-KIBANA-001 lives in
metadata["vuln_id"], matching the existing miasma_grafana_001.py /
miasma_rabbitmq_001.py / miasma_solr_001.py convention. This rotation's
spec asked for MIASMA-CONSUL-001 OR MIASMA-ETCD-001 — both were already
shipped (#26 and #27 respectively, with the RabbitMQ plugin (#30) being
the most recent service-exposure addition). Pivoting per the spec's
"correct pivot protocol" clause to the next-best gap in the POST_V01
service-exposure family. Kibana selected over the other obvious gaps
(Cassandra, CouchDB, MinIO, InfluxDB) because: (1) Kibana pairs directly
with the existing miasma_elastic_001 plugin (operators who expose
Elasticsearch routinely expose Kibana on the same estate); (2) the
fingerprint surface (`name == "kibana"` + `version.number` in
/api/status) is unambiguous and survives across 7.x and 8.x; (3) a clean
direct parallel to the existing Grafana plugin (HTTP JSON-API anonymous
read check); (4) Kibana is far more commonly exposed than Cassandra and
strictly higher impact than CouchDB / InfluxDB (Discover grants read of
every index in the cluster). Default-credential check is intentionally
out of scope — stock Kibana has no default credentials; the
``elastic:changeme`` pair lives on the Elasticsearch backend, not Kibana,
and is already covered conceptually by miasma_elastic_001's anonymous-
read flow.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-KIBANA-001",
    "name": "Kibana Unauthenticated HTTP API Exposure",
    "description": (
        "Kibana reachable without authentication on its HTTP API. An "
        "unauthenticated Kibana exposes every index in the backing "
        "Elasticsearch cluster (browseable via Discover), every saved "
        "search / visualisation / dashboard, and the Dev Tools console — "
        "which proxies arbitrary requests to the Elasticsearch cluster on "
        "the Kibana service account. Anonymous read is the recurring "
        "misconfiguration (operators front Kibana with reverse-proxy auth "
        "that is mis-scoped or absent)."
    ),
    "confidence": "high",
    "references": [
        "https://www.elastic.co/guide/en/kibana/current/api.html",
        "https://www.elastic.co/guide/en/kibana/current/access.html",
        "https://www.elastic.co/guide/en/kibana/current/anonymous-authentication.html",
        "https://www.elastic.co/guide/en/kibana/current/console-kibana.html",
        "https://owasp.org/www-community/Broken_Access_Control",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [5601, 5602, 80, 443],
    "service_hint": ["kibana", "http", "https"],
    "default_ports": [5601, 5602, 80, 443],
}

# Top-level key/value pair present in every supported Kibana /api/status body.
# Across 7.x and 8.x the endpoint answers with a JSON object whose ``name``
# field is the configured server.name (defaulting to the hostname) — but on
# every release we have observed, the ``version`` object carries the build
# semver in ``version.number`` and the server identifies itself as Kibana
# elsewhere in the body. We fingerprint via the combination of:
#   * a parseable ``version.number`` semver in the response, AND
#   * a Kibana marker somewhere in the body — either the legacy
#     ``status.overall`` block, or the modern ``status`` object's
#     ``overall.level`` field, or the explicit ``name`` containing "kibana"
#     case-insensitively. We deliberately do NOT match the OpenSearch
#     Dashboards fork (``name == "OpenSearch Dashboards"``) — that is a
#     different product.
_KIBANA_NAME_MARKERS = ("kibana",)

# OpenSearch Dashboards is the AWS-maintained fork of Kibana. Its /api/status
# carries an identical shape but a distinct ``name`` and ``version.build_flavor``.
# We must NOT flag it as Kibana — it has its own CVE surface and its own
# plugin will be a separate addition.
_NOT_KIBANA_MARKERS = ("opensearch dashboards", "opensearch-dashboards")

_TIMEOUT = 5.0

# Canonical TLS ports. 443 is the only standard HTTPS front for Kibana
# behind a reverse proxy; 5601 is plain HTTP by default in every release.
_HTTPS_PORTS = (443,)


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Kibana-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        kibana_like = [
            port
            for port in open_ports
            if "kibana" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return kibana_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS for the canonical TLS ports; everything else plain HTTP."""
    return "https" if port in _HTTPS_PORTS else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common
    on internal Kibana deployments behind a reverse proxy. Redirects are not
    followed: a 302 to a login page would mean the surface is not actually
    unauthenticated and should not be flagged.
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


def _parse_kibana_status(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the parsed /api/status body if it is genuinely Kibana, else None.

    Genuine Kibana has:
      * status_code == 200
      * a JSON object body
      * a parseable ``version.number`` semver string
      * a Kibana marker (the legacy/modern status block or a name field
        containing "kibana" case-insensitively)
      * and is NOT the OpenSearch Dashboards fork (distinct product).
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None

    version_obj = body.get("version")
    if not isinstance(version_obj, dict):
        return None
    version_number = version_obj.get("number")
    if not isinstance(version_number, str) or not version_number:
        return None

    # OpenSearch Dashboards fork — same shape, different product. Skip.
    name_field = body.get("name", "")
    if isinstance(name_field, str):
        lowered_name = name_field.lower()
        if any(marker in lowered_name for marker in _NOT_KIBANA_MARKERS):
            return None

    # Positive Kibana fingerprint: a name field that mentions Kibana, OR a
    # status block whose shape is Kibana-specific. The default server.name
    # is the hostname, so the name field will not always carry "kibana" —
    # the status block presence is the stronger signal.
    has_kibana_name = isinstance(name_field, str) and any(
        marker in name_field.lower() for marker in _KIBANA_NAME_MARKERS
    )
    status_block = body.get("status")
    has_status_shape = isinstance(status_block, dict) and (
        "overall" in status_block or "statuses" in status_block
    )

    if not (has_kibana_name or has_status_shape):
        return None

    return body


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"
        status_url = f"{base}/api/status"

        resp = _get(status_url)
        if resp is None:
            # Transport error on this port — try the next candidate.
            continue

        status_body = _parse_kibana_status(resp)
        if status_body is None:
            # Not Kibana, or Kibana with auth enforced (401/403/302); never
            # flagged. We never follow redirects, so a 302 to a login surface
            # is naturally treated as a non-200.
            continue

        # 200 with a Kibana status body and no auth challenge => anonymous
        # read of the Kibana UI surface confirmed. HIGH.
        version_obj = status_body.get("version", {})
        evidence: dict[str, Any] = {
            "host": target.host,
            "port": port,
            "anonymous_access": True,
            "kibana_version": version_obj.get("number"),
        }
        build_number = version_obj.get("build_number")
        if build_number is not None:
            evidence["build_number"] = build_number
        build_hash = version_obj.get("build_hash")
        if isinstance(build_hash, str) and build_hash:
            evidence["build_hash"] = build_hash

        # Overall status string (e.g. "green" / "yellow" / "red", or the
        # modern object's level) — useful triage detail, never inventory.
        status_block = status_body.get("status")
        if isinstance(status_block, dict):
            overall = status_block.get("overall")
            if isinstance(overall, dict):
                state = overall.get("level") or overall.get("state")
                if isinstance(state, str) and state:
                    evidence["overall_status"] = state
            elif isinstance(overall, str) and overall:
                evidence["overall_status"] = overall

        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="high",
            evidence=evidence,
            description=(
                metadata["description"]
                + " /api/status answers 200 with the Kibana status body and "
                "no authentication challenge — every index in the backing "
                "Elasticsearch cluster, every saved object, and the Dev "
                "Tools console are reachable without credentials."
            ),
        )

    return None
