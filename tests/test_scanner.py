"""Tests for the asynchronous port scanner."""

import asyncio

from scanner import scanner


class FakeReader:
    def __init__(self, data: bytes = b""):
        self.data = data

    async def read(self, _n: int):
        return self.data


class FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def _fake_connection_factory(reader, error=None):
    async def fake_open_connection(*args, **kwargs):
        if error:
            raise error
        return reader, FakeWriter()

    return fake_open_connection


async def test_scan_host_returns_open_port_with_banner(monkeypatch):
    monkeypatch.setattr(
        scanner.asyncio, "open_connection", _fake_connection_factory(FakeReader(b"hello\r\n"))
    )
    result = await scanner.scan_host("192.0.2.1", [22], timeout=0.5)
    assert len(result) == 1
    assert result[0]["port"] == 22
    assert result[0]["state"] == "open"
    assert result[0]["banner"] == "hello"


async def test_scan_host_drops_closed_ports(monkeypatch):
    async def refused(*args, **kwargs):
        raise ConnectionRefusedError()

    monkeypatch.setattr(scanner.asyncio, "open_connection", refused)
    result = await scanner.scan_host("192.0.2.1", [22, 80, 443], timeout=0.5)
    assert result == []


async def test_scan_host_handles_timeout(monkeypatch):
    async def no_connection(*args, **kwargs):
        raise TimeoutError()

    monkeypatch.setattr(scanner.asyncio, "open_connection", no_connection)
    result = await scanner.scan_host("192.0.2.1", [22], timeout=0.5)
    assert result == []


async def test_banner_read_timeout_still_marks_open(monkeypatch):
    class SlowReader(FakeReader):
        async def read(self, _n):
            raise TimeoutError()

    monkeypatch.setattr(
        scanner.asyncio,
        "open_connection",
        _fake_connection_factory(SlowReader(b"")),
    )
    result = await scanner.scan_host("192.0.2.1", [80], timeout=0.5)
    assert len(result) == 1
    assert result[0]["state"] == "open"
    assert result[0]["banner"] == ""


async def test_scan_host_concurrency_bounded(monkeypatch):
    calls = 0

    async def counting_connection(*args, **kwargs):
        nonlocal calls
        calls += 1
        return FakeReader(b""), FakeWriter()

    monkeypatch.setattr(scanner.asyncio, "open_connection", counting_connection)
    result = await scanner.scan_host("192.0.2.1", range(5), concurrency=2, timeout=0.5)
    assert calls == 5
    assert len(result) == 5


def test_default_scan_ports_are_unique_tcp_ports():
    ports = scanner.default_scan_ports()
    assert len(ports) == len(set(ports))
    assert all(isinstance(p, int) and 0 < p < 65536 for p in ports)
    assert 22 in ports and 443 in ports and 3306 in ports


def test_scan_host_with_services_returns_detected_service(monkeypatch):
    async def ssh_connection(*args, **kwargs):
        return FakeReader(b"SSH-2.0-OpenSSH_8.9p1\r\n"), FakeWriter()

    monkeypatch.setattr(scanner.asyncio, "open_connection", ssh_connection)
    services = asyncio.run(
        scanner.scan_host_with_services("192.0.2.1", [22], timeout=0.5)
    )
    assert services[0]["port"] == 22
    assert services[0]["name"] == "ssh"
    assert services[0]["product"] == "openssh"