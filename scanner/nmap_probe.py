"""Optional Nmap ``-sV`` fingerprinting bridge.

The built-in scanner is passive (banner-only), so TLS/SMB and other
bannerless services stay un-fingerprinted. When Nmap is installed and
``USE_NMAP`` is enabled, ``run_nmap_sv`` runs active version detection on the
open ports already discovered by the fast connect scan and parses Nmap's XML
report with the standard library only (no ``python-nmap`` dependency).

Everything degrades gracefully: if Nmap is missing or times out, scans simply
keep whatever the passive scanner found.
"""

import logging
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("network_mapper.nmap_probe")

_DEFAULT_BINARY = "nmap"
_DEFAULT_TIMEOUT = 180.0

# Extract the CPE version from an Nmap cpe entry like ``cpe:/a:openbsd:openssh:8.9p1``.
_CPE_VERSION_RE = re.compile(r"cpe:/a:[^:]+:[^:]+:([^:]+)")


def nmap_available(binary: str = _DEFAULT_BINARY) -> bool:
    """Whether the Nmap binary can be located on this machine."""
    if not binary:
        return False
    if os.path.sep in binary or binary.lower().endswith(".exe"):
        return Path(binary).is_file()
    return shutil.which(binary) is not None


def _service_from_element(service_el) -> Dict[str, Optional[str]]:
    """Extract name/product/version/CPE from an Nmap ``<service>`` element."""
    info: Dict[str, Optional[str]] = {
        "name": service_el.get("name"),
        "product": service_el.get("product"),
        "version": service_el.get("version"),
        "cpe": None,
    }
    for cpe_el in service_el.findall("cpe"):
        raw = (cpe_el.text or "").strip()
        if not raw:
            continue
        info["cpe"] = raw
        if not info["version"]:
            match = _CPE_VERSION_RE.search(raw)
            if match:
                info["version"] = match.group(1)
        break
    return info


def parse_nmap_xml(xml_report: str) -> Dict[int, Dict[str, Optional[str]]]:
    """Parse an Nmap XML report into {port: service info} for open ports.

    Only ports whose state is ``open`` are returned; closed/filtered ports are
    ignored. When Nmap names the protocol ``ssl`` and wraps the underlying
    service, the inner service name/product are used instead.
    """
    result: Dict[int, Dict[str, Optional[str]]] = {}
    try:
        root = ET.fromstring(xml_report)
    except ET.ParseError:
        logger.warning("Nmap produced unparseable XML")
        return result

    for port_el in root.findall(".//ports/port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        try:
            port = int(port_el.get("portid", 0))
        except (TypeError, ValueError):
            continue
        if port <= 0:
            continue

        protocol = port_el.get("protocol", "tcp")
        service_el = port_el.find("service")
        if service_el is None:
            result[port] = {"name": None, "product": None, "version": None, "cpe": None}
            continue

        info = _service_from_element(service_el)
        # Nmap TLS ports report the protocol as "ssl" with the real service
        # (e.g. http, smtp) as the name. Promote that to the service name.
        if info["name"] in ("ssl",):
            inner = service_el.get("servicefp")
            info["name"] = inner if inner else None
        result[port] = {**info, "protocol": protocol}
    return result


def run_nmap_sv(
    binary: str = _DEFAULT_BINARY,
    host: str = "",
    ports: Optional[List[int]] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> Dict[int, Dict[str, Optional[str]]]:
    """Run ``nmap -sV`` against ``host:ports`` and return parsed open services.

    ``-Pn`` skips host discovery (targets are explicitly authorized), ``-sV``
    enables version detection, ``-oX -`` streams XML to stdout for parsing.
    Returns an empty dict on any failure so callers can fall back gracefully.
    """
    ports = [int(p) for p in (ports or []) if p > 0]
    if not host or not ports:
        return {}

    command = [
        binary,
        "-Pn",
        "-sV",
        "--version-intensity",
        "5",
        "--open",
        "-oX",
        "-",
        "-p",
        ",".join(str(p) for p in ports),
        host,
    ]
    logger.info("Running %s on %s ports=%s", binary, host, ports)
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Nmap failed/expired for %s: %s", host, exc)
        return {}
    if proc.returncode != 0 and "Nmap" not in proc.stdout:
        logger.warning("Nmap exited %s for %s: %s", proc.returncode, host, proc.stderr.strip()[:300])
        return {}
    if not proc.stdout:
        return {}
    return parse_nmap_xml(proc.stdout)


def merge_nmap_results(
    services: List[dict], nmap_results: Dict[int, Dict[str, Optional[str]]]
) -> List[dict]:
    """Enrich detected services with Nmap data and add Nmap-only open ports.

    Existing services keep their banner/port hint but adopt name/product/
    version when Nmap fingerprinting produced more detail. Nmap ports our
    scanner missed are appended as new open services.
    """
    merged: List[dict] = []
    seen: set[int] = set()
    for svc in services:
        port = svc.get("port")
        if port in nmap_results:
            seen.add(port)
            n = nmap_results[port]
            # Prefer real fingerprints; never drop a banner we already have.
            enriched = dict(svc)
            if n.get("name") and (not enriched.get("name") or enriched.get("name") == "unknown"):
                enriched["name"] = n["name"]
            if n.get("product"):
                enriched["product"] = n["product"]
            if n.get("version"):
                enriched["version"] = n["version"]
            if n.get("cpe") and not enriched.get("cpe"):
                enriched["cpe"] = n["cpe"]
            merged.append(enriched)
        else:
            merged.append(svc)

    for port, info in nmap_results.items():
        if port in seen or port in {s.get("port") for s in merged}:
            continue
        merged.append(
            {
                "port": port,
                "name": info.get("name") or "unknown",
                "product": info.get("product"),
                "version": info.get("version"),
                "banner": None,
                "cpe": info.get("cpe"),
            }
        )
    merged.sort(key=lambda s: s.get("port", 0))
    return merged