"""End-to-end smoke test with the nmap layer mocked.

Runs the real CLI (recon -> probe -> JSON output) against a fake scanner so the
suite is green even on systems without ``nmap`` installed (mocked at the
python-nmap boundary, ``miasma.recon._new_scanner``).
"""

import json

import miasma.recon as recon_mod
from miasma.cli import main


class _FakeHost:
    def __init__(self, protos):
        self._protos = protos

    def all_protocols(self):
        return list(self._protos.keys())

    def __getitem__(self, proto):
        return self._protos[proto]


class FakeScanner:
    def __init__(self, data):
        self._data = data

    def scan(self, hosts, ports, arguments):  # matches python-nmap signature
        self.scanned = (hosts, ports, arguments)

    def all_hosts(self):
        return list(self._data.keys())

    def __getitem__(self, host):
        return _FakeHost(self._data[host])


def test_end_to_end_test_plugin_produces_json_finding(monkeypatch, capsys):
    fake = FakeScanner(
        {
            "127.0.0.1": {
                "tcp": {
                    8080: {"state": "open", "name": "http-proxy"},
                    22: {"state": "open", "name": "ssh"},
                }
            }
        }
    )
    monkeypatch.setattr(recon_mod, "_new_scanner", lambda: fake)

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
