"""Tests for the ``--output-file`` CLI flag.

The flag writes the JSON report to a file instead of stdout, enabling piping
into downstream tooling. The nmap layer is mocked at the shared
``nmap-wrapper`` seam so the suite is green without ``nmap`` installed.
"""

import json

import nmap_wrapper.scanner as scanner_mod
from nmap_wrapper.testing import FakeScanner, service_scan_result

from miasma.cli import main


def _mock_scanner(monkeypatch):
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


def test_output_file_writes_report_and_keeps_stdout_clean(
    monkeypatch, capsys, tmp_path
):
    _mock_scanner(monkeypatch)
    out_path = tmp_path / "findings.json"

    exit_code = main(
        [
            "--target",
            "127.0.0.1",
            "--plugins",
            "test_always_finds",
            "--output-file",
            str(out_path),
        ]
    )
    assert exit_code == 0

    # Nothing went to stdout — the report landed in the file instead.
    assert capsys.readouterr().out == ""
    assert out_path.exists()

    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["target"] == "127.0.0.1"
    assert report["open_ports"] == [22, 8080]
    assert report["plugins"] == ["test_always_finds"]
    assert len(report["findings"]) == 1
    assert report["findings"][0]["vuln_id"] == "MIASMA-TEST-0001"


def test_output_file_dash_writes_to_stdout(monkeypatch, capsys, tmp_path):
    _mock_scanner(monkeypatch)

    exit_code = main(
        [
            "--target",
            "127.0.0.1",
            "--plugins",
            "test_always_finds",
            "--output-file",
            "-",
        ]
    )
    assert exit_code == 0

    report = json.loads(capsys.readouterr().out)
    assert report["target"] == "127.0.0.1"
    assert report["findings"][0]["vuln_id"] == "MIASMA-TEST-0001"


def test_default_still_writes_to_stdout(monkeypatch, capsys):
    _mock_scanner(monkeypatch)

    exit_code = main(
        [
            "--target",
            "127.0.0.1",
            "--plugins",
            "test_always_finds",
        ]
    )
    assert exit_code == 0

    report = json.loads(capsys.readouterr().out)
    assert report["target"] == "127.0.0.1"


def test_output_file_content_matches_stdout_byte_for_byte(
    monkeypatch, capsys, tmp_path
):
    _mock_scanner(monkeypatch)
    main(["--target", "127.0.0.1", "--plugins", "test_always_finds"])
    stdout_text = capsys.readouterr().out

    out_path = tmp_path / "findings.json"
    main(
        [
            "--target",
            "127.0.0.1",
            "--plugins",
            "test_always_finds",
            "--output-file",
            str(out_path),
        ]
    )
    assert out_path.read_text(encoding="utf-8") == stdout_text
