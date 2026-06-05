"""MIASMA-JUPYTER-001 — Jupyter Notebook/Lab unauthenticated code-execution exposure.

A Jupyter Notebook or JupyterLab instance reachable without a token or password
is a **direct remote-code-execution vector** — not an information-disclosure
finding.  Any client that can reach the API can:

    * ``POST /api/kernels``       — spawn a Python (or R, Julia, …) kernel
    * WebSocket kernel channel    — send ``execute_request`` messages to execute
                                    arbitrary code in that kernel
    * ``GET  /api/contents/``     — browse and read files accessible to the
                                    Jupyter process (often the entire home dir
                                    or repository root)

This exposure is consistently rated CRITICAL / P1 on bug-bounty programmes:
public-cloud Jupyter deployments, data-science workstations, and Jupyter-as-a-
service platforms have all shipped critical vulnerabilities through this path.
Unauthenticated Jupyter instances are trivially exploited with a five-line
Python script using the stock ``requests`` library.

This probe is BENIGN and read-only.  It sends exactly three unauthenticated
GET requests to confirm the finding:

    1. ``GET /api``           — fingerprints Jupyter; a genuine reply is
                                ``{"version": "X.Y.Z"}`` with the ``version``
                                key (present since Notebook 4.x / JupyterLab
                                1.x).  A 200 without an auth challenge is the
                                primary signal.
    2. ``GET /api/kernels``   — confirms the kernel-management endpoint is
                                accessible without a token.  Returns a JSON
                                array (``[]`` when no kernels are running, or
                                a list of kernel objects for running kernels).
                                Kernel access = code execution.
    3. ``GET /api/kernelspecs`` — lists available kernelspecs (Python 3, R,
                                Julia, …).  Reading this endpoint without auth
                                confirms the execution surface.

No kernel is created, no code is executed, no file is read, no configuration
is changed — exactly the three read-only discovery requests a human tester
would run to confirm the finding by hand.

Severity matrix:
    * ``critical`` — ``GET /api`` fingerprints Jupyter AND ``GET /api/kernels``
                     returns 200 (kernel management accessible without auth →
                     RCE possible via POST /api/kernels + WebSocket
                     execute_request).
    * ``high``     — ``GET /api`` fingerprints Jupyter AND
                     ``GET /api/kernelspecs`` returns 200 (execution surface
                     enumerable; kernel management may be behind a different
                     auth check — confirm manually).
    * ``medium``   — ``GET /api`` fingerprints Jupyter without an auth
                     challenge but both kernel/kernelspecs endpoints return
                     non-200 (API surface confirmed; exact execution scope
                     unclear).
    * none         — Jupyter not fingerprinted, or all endpoints are
                     authenticated.

Candidate ports: 8888 (primary), 8889, 8890, 8080, 10000 (common alternates),
80, 443 (reverse-proxy fronts).

[Worker decision: plugin filename is miasma_jupyter_001.py (underscores)
because the runner discovers plugins via importlib and module names cannot
contain hyphens.  The canonical id MIASMA-JUPYTER-001 lives in
metadata["vuln_id"], matching the existing miasma_grafana_001.py /
miasma_prometheus_001.py / miasma_activemq_001.py convention.]
"""

from __future__ import annotations

from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "MIASMA-JUPYTER-001",
    "name": "Jupyter Notebook/Lab Unauthenticated Code-Execution Exposure",
    "description": (
        "Jupyter Notebook or JupyterLab API reachable without authentication, "
        "exposing kernel management (direct remote code execution), notebook "
        "file contents, and the kernelspec inventory.  Rated CRITICAL / P1 on "
        "bug-bounty programmes because unauthenticated kernel access enables "
        "arbitrary code execution via POST /api/kernels + WebSocket."
    ),
    "confidence": "high",
    "references": [
        "https://jupyter-notebook.readthedocs.io/en/stable/security.html",
        "https://jupyterlab.readthedocs.io/en/stable/user/security.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-21699",
        "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference",
    ],
    # port_hint is the canonical field the runner reads to skip irrelevant
    # plugins; default_ports is kept as the in-probe fallback alias.
    "port_hint": [8888, 8889, 8890, 8080, 10000, 80, 443],
    "service_hint": ["jupyter", "notebook", "jupyterlab", "http", "https"],
    "default_ports": [8888, 8889, 8890, 8080, 10000, 80, 443],
}

_TIMEOUT = 5.0

# The /api response must carry this key to count as a genuine Jupyter instance
# (present since Notebook 4.x / JupyterLab 1.x on every server build).
_API_VERSION_KEY = "version"


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered Jupyter-ish open ports; else the default list."""
    open_ports = target.open_ports()
    if open_ports:
        jupyter_like = [
            port
            for port in open_ports
            if "jupyter" in target.service(port).get("name", "").lower()
            or "notebook" in target.service(port).get("name", "").lower()
            or port in metadata["default_ports"]
        ]
        return jupyter_like or open_ports
    return list(metadata["default_ports"])


def _scheme(port: int) -> str:
    """HTTPS only for the canonical TLS port; everything else plain HTTP."""
    return "https" if port == 443 else "http"


def _get(url: str) -> httpx.Response | None:
    """Benign unauthenticated GET; returns None on any transport error.

    TLS verification is disabled because self-signed certificates are common
    on internal Jupyter deployments.
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


def _fingerprint_jupyter(resp: httpx.Response) -> str | None:
    """Return the Jupyter version string if this is a genuine unauthenticated
    Jupyter API endpoint, else None.

    A 200 response from ``GET /api`` carrying a JSON object with the
    ``version`` key is the Jupyter fingerprint.  A 401/403 means auth is
    enforced; any redirect or non-JSON body is not Jupyter.
    """
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    version = body.get(_API_VERSION_KEY)
    if isinstance(version, str) and version:
        return version
    return None


def _kernels_accessible(base: str) -> bool:
    """Return True if ``GET /api/kernels`` answers 200 without authentication.

    A 200 response — whether an empty list ``[]`` or a list of running kernels —
    means the kernel-management endpoint is accessible without a token.
    Kernel management access implies the ability to spawn a new kernel and
    submit ``execute_request`` messages over its WebSocket channel (RCE).
    """
    resp = _get(f"{base}/api/kernels")
    if resp is None:
        return False
    return resp.status_code == 200


def _kernelspecs_accessible(base: str) -> bool:
    """Return True if ``GET /api/kernelspecs`` answers 200 without authentication.

    A 200 response means the available kernelspecs (Python 3, R, Julia, …) are
    enumerable without a token, confirming the execution-surface scope.
    """
    resp = _get(f"{base}/api/kernelspecs")
    if resp is None:
        return False
    return resp.status_code == 200


def probe(target: Target) -> Finding | None:
    """Run the Jupyter unauthenticated-access probe against *target*.

    Tries each candidate port in turn, returning the first (most severe)
    finding or None when Jupyter is not reachable or is properly secured.
    Three read-only GET requests at most per port; no kernel created, no code
    executed, no files read.
    """
    for port in _candidate_ports(target):
        scheme = _scheme(port)
        base = f"{scheme}://{target.host}:{port}"

        # Step 1: fingerprint Jupyter via GET /api.
        resp = _get(f"{base}/api")
        if resp is None:
            continue
        version = _fingerprint_jupyter(resp)
        if version is None:
            # Not Jupyter or auth required at the /api level.
            continue

        # Step 2: check kernel management access (direct RCE surface).
        kernels_open = _kernels_accessible(base)
        if kernels_open:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="critical",
                evidence={
                    "host": target.host,
                    "port": port,
                    "scheme": scheme,
                    "version": version,
                    "kernels_accessible": True,
                    "kernelspecs_accessible": False,
                    "rce_path": (
                        f"POST {base}/api/kernels to spawn a kernel, "
                        f"then execute code via WebSocket execute_request"
                    ),
                },
                description=(
                    f"Jupyter {version}: GET /api/kernels returned 200 "
                    "without authentication — RCE possible"
                ),
            )

        # Step 3: check kernelspecs access (execution surface enumerable).
        kernelspecs_open = _kernelspecs_accessible(base)
        if kernelspecs_open:
            return Finding(
                vuln_id=metadata["vuln_id"],
                host=target.host,
                confidence="high",
                evidence={
                    "host": target.host,
                    "port": port,
                    "scheme": scheme,
                    "version": version,
                    "kernels_accessible": False,
                    "kernelspecs_accessible": True,
                },
                description=(
                    f"Jupyter {version}: GET /api/kernelspecs returned 200 "
                    "without authentication — execution surface enumerable"
                ),
            )

        # Jupyter fingerprinted but kernel/kernelspecs gated — MEDIUM.
        return Finding(
            vuln_id=metadata["vuln_id"],
            host=target.host,
            confidence="medium",
            evidence={
                "host": target.host,
                "port": port,
                "scheme": scheme,
                "version": version,
                "kernels_accessible": False,
                "kernelspecs_accessible": False,
            },
            description=(
                f"Jupyter {version}: GET /api returned 200 without "
                "authentication (API surface reachable); confirm kernel/execution scope manually"
            ),
        )

    return None
