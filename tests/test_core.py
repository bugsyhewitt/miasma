"""Tests for the core data types."""

from miasma.core import Finding, Target


def test_target_open_ports_filters_and_sorts():
    target = Target(
        host="127.0.0.1",
        ports={
            80: {"state": "open", "name": "http"},
            22: {"state": "open", "name": "ssh"},
            443: {"state": "closed", "name": "https"},
        },
    )
    assert target.open_ports() == [22, 80]


def test_target_service_returns_empty_for_unknown_port():
    target = Target(host="127.0.0.1")
    assert target.service(9999) == {}


def test_finding_to_dict_roundtrips():
    finding = Finding(
        vuln_id="CVE-0000-0000",
        host="127.0.0.1",
        confidence="high",
        evidence={"request": "GET /", "response": "200"},
        description="demo",
    )
    d = finding.to_dict()
    assert d["vuln_id"] == "CVE-0000-0000"
    assert d["host"] == "127.0.0.1"
    assert d["confidence"] == "high"
    assert d["evidence"]["response"] == "200"
    assert d["description"] == "demo"
