"""Asynchronous TCP port scanner with banner grabbing.

Uses ``asyncio.open_connection`` with configurable timeouts and a semaphore to
bound concurrency. No root/sudo privileges or external binaries are required,
which keeps the core scanner dependency-free and easy to test.
"""

import asyncio
import socket
from typing import Iterable, List

from .service_detect import detect_service

DEFAULT_TIMEOUT = 1.0
DEFAULT_BANNER_TIMEOUT = 0.5
DEFAULT_CONCURRENCY = 50


async def _probe(
    host: str,
    port: int,
    protocol: str = "tcp",
    timeout: float = DEFAULT_TIMEOUT,
    banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> dict:
    """Attempt a connection to ``host:port`` and grab a banner if it opens."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, family=socket.AF_UNSPEC),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, TimeoutError, OSError):
        return {"port": port, "protocol": protocol, "state": "closed", "banner": None}

    banner = ""
    try:
        if protocol == "tcp":
            data = await asyncio.wait_for(reader.read(1024), timeout=banner_timeout)
            banner = data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, TimeoutError, OSError):
        banner = ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # pragma: no cover - best-effort close
            pass

    return {"port": port, "protocol": protocol, "state": "open", "banner": banner}


async def scan_host(
    host: str,
    ports: Iterable[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> List[dict]:
    """Scan ``ports`` on ``host``; return open ports as ``{port, protocol, state, banner}``.

    All ports are probed concurrently (bounded by ``concurrency``) and closed
    ports are silently dropped from the result.
    """
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _wrapped(port: int) -> dict:
        async with semaphore:
            return await _probe(host, port, "tcp", timeout, banner_timeout)

    results = await asyncio.gather(*(_wrapped(port) for port in ports))
    return [r for r in results if r["state"] == "open"]


async def scan_host_with_services(
    host: str,
    ports: Iterable[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> List[dict]:
    """Scan ``host`` and run lightweight service detection on open ports.

    Returns one dict per open port: ``{port, name, product, version, banner}``.
    """
    open_ports = await scan_host(host, ports, timeout, concurrency, banner_timeout)
    services: List[dict] = []
    for item in open_ports:
        svc = detect_service(item["port"], item["banner"])
        svc["port"] = item["port"]
        services.append(svc)
    return services


def default_scan_ports() -> List[int]:
    """Return a sensible default set of TCP ports for discovery scans."""
    return [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993,
        995, 1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 4000, 5000, 5432,
        5601, 5900, 6379, 7001, 8000, 8080, 8443, 8888, 9090, 9200, 10000,
        11211, 27017, 28080, 50070,
    ]