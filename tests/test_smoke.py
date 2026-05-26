"""End-to-end smoke test with the nmap layer mocked.

Runs the real CLI (recon -> probe -> JSON output) against a fake scanner so the
suite is green even on systems without ``nmap`` installed. miasma fingerprints
via the shared ``nmap-wrapper`` library, so we mock that library's single nmap
seam (``nmap_wrapper.scanner._new_scanner``) with its shipped ``FakeScanner`` +
canned-data builder.
"""

import json

import nmap_wrapper.scanner as scanner_mod
from nmap_wrapper.testing import FakeScanner, service_scan_result

from miasma.cli import main


def test_end_to_end_test_plugin_produces_json_finding(monkeypatch, capsys):
    fake = FakeScanner(
        service_scan_result(
            "127.0.0.1",
            [
                {"port": 8080, "name": "http-proxy"},
                {"port": 22, "name": "ssh"},
            ],
        )
    )
    monkeypatch.setattr(scanner_mod, "_new_scanner", lambda: fake)

    exit_code = main(
        [
            "--target",
            "127.0.0.1",
            "--plugins",
            "test_always_finds",
            "--port-range",
            "1-10000",
            "--format",
            "json",
        ]
    )
    assert exit_code == 0

    out = capsys.readouterr().out
    report = json.loads(out)

    assert report["target"] == "127.0.0.1"
    assert report["port_range"] == "1-10000"
    assert report["open_ports"] == [22, 8080]
    assert report["plugins"] == ["test_always_finds"]
    assert len(report["findings"]) == 1

    finding = report["findings"][0]
    assert finding["vuln_id"] == "MIASMA-TEST-0001"
    assert finding["host"] == "127.0.0.1"
    assert finding["confidence"] == "high"
    assert finding["evidence"]["open_ports"] == [22, 8080]
