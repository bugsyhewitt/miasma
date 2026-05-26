"""Recon tests with the python-nmap boundary mocked.

These tests never invoke the real ``nmap`` binary — they mock the PortScanner
seam (``miasma.recon._new_scanner``) so the suite is green on systems without
nmap installed.
"""

from unittest.mock import MagicMock

import miasma.recon as recon_mod
from miasma.recon import recon


class FakeScanner:
    """Minimal stand-in for python-nmap's PortScanner."""

    def __init__(self, data):
        self._data = data
        self.scan = MagicMock()

    def all_hosts(self):
        return list(self._data.keys())

    def __getitem__(self, host):
        return _FakeHost(self._data[host])


class _FakeHost:
    def __init__(self, protos):
        self._protos = protos

    def all_protocols(self):
        return list(self._protos.keys())

    def __getitem__(self, proto):
        return self._protos[proto]


def test_recon_populates_target_from_scanner(monkeypatch):
    fake = FakeScanner(
        {
            "127.0.0.1": {
                "tcp": {
                    80: {"state": "open", "name": "http", "product": "nginx"},
                    22: {"state": "open", "name": "ssh"},
                    81: {"state": "closed", "name": "hosts2-ns"},
                }
            }
        }
    )
    monkeypatch.setattr(recon_mod, "_new_scanner", lambda: fake)

    target = recon("127.0.0.1", "1-1000")

    assert target.host == "127.0.0.1"
    assert target.open_ports() == [22, 80]
    assert target.service(80)["product"] == "nginx"
    fake.scan.assert_called_once()
