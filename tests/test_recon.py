"""Recon tests with the shared nmap seam mocked.

These tests never invoke the real ``nmap`` binary. miasma now fingerprints via
the shared ``nmap-wrapper`` library, so we mock that library's single nmap seam
(``nmap_wrapper.scanner._new_scanner``) using its shipped ``FakeScanner`` +
canned-data builder. The suite stays green on systems without nmap installed.
"""

import nmap_wrapper.scanner as scanner_mod
from nmap_wrapper.testing import FakeScanner, service_scan_result

from miasma.recon import recon


def test_recon_populates_target_from_scanner(monkeypatch):
    fake = FakeScanner(
        service_scan_result(
            "127.0.0.1",
            [
                {"port": 80, "name": "http", "product": "nginx"},
                {"port": 22, "name": "ssh"},
                {"port": 81, "name": "hosts2-ns", "state": "closed"},
            ],
        )
    )
    monkeypatch.setattr(scanner_mod, "_new_scanner", lambda: fake)

    target = recon("127.0.0.1", "1-1000")

    assert target.host == "127.0.0.1"
    assert target.open_ports() == [22, 80]
    assert target.service(80)["product"] == "nginx"
    fake.scan.assert_called_once()
