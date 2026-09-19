"""Tests for the optional Nmap -sV bridge: XML parsing, availability, and merge."""

import subprocess

from scanner import nmap_probe

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssl" servicefp="huh" method="table">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed" reason="reset" reason_ttl="0"/>
        <service name="telnet" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_extracts_open_services():
    ports = nmap_probe.parse_nmap_xml(_SAMPLE_XML)
    assert set(ports) == {22, 443}
    assert ports[22]["product"] == "OpenSSH"
    assert ports[22]["version"] == "8.9p1"
    assert ports[22]["cpe"] == "cpe:/a:openbsd:openssh:8.9p1"
    # closed ports are dropped
    assert 23 not in ports
    # cpe pulls the version when Nmap omitted it
    assert ports[443]["version"] == "1.18.0"
    assert ports[443]["cpe"] == "cpe:/a:nginx:nginx:1.18.0"


def test_parse_nmap_xml_corrupt_is_graceful():
    assert nmap_probe.parse_nmap_xml("<not xml") == {}


def test_nmap_available_false_for_bogus_binary():
    assert nmap_probe.nmap_available("definitely-not-a-real-nmap-binary-xyz") is False
    assert nmap_probe.nmap_available("") is False


def test_run_nmap_sv_parses_subprocess_output(monkeypatch):
    executed = {}

    def fake_run(command, **kwargs):
        executed["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout=_SAMPLE_XML, stderr="")

    monkeypatch.setattr(nmap_probe.subprocess, "run", fake_run)
    result = nmap_probe.run_nmap_sv("nmap", "127.0.0.1", [22, 443], timeout=30)
    assert set(result) == {22, 443}
    assert "-oX" in executed["command"]
    assert executed["command"][-1] == "127.0.0.1"


def test_run_nmap_sv_empty_ports_returns_empty():
    assert nmap_probe.run_nmap_sv("nmap", "127.0.0.1", []) == {}


def test_run_nmap_sv_failure_returns_empty(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=10)

    monkeypatch.setattr(nmap_probe.subprocess, "run", fake_run)
    assert nmap_probe.run_nmap_sv("nmap", "127.0.0.1", [22], timeout=1) == {}


def test_merge_nmap_results_enriches_and_adds():
    services = [
        {"port": 22, "name": "ssh", "product": None, "version": None, "banner": None},
    ]
    nmap = {22: {"name": "ssh", "product": "OpenSSH", "version": "8.9p1", "cpe": None},
            443: {"name": "https", "product": "nginx", "version": "1.18.0", "cpe": None}}
    merged = nmap_probe.merge_nmap_results(services, nmap)
    assert [s["port"] for s in merged] == [22, 443]
    ssh = merged[0]
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.9p1"
    assert merged[1]["name"] == "https"