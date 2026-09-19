"""Scan export to JSON, CSV and STIX 2.1 bundles.

``to_json`` is a full dump of a scan; ``to_csv`` is a flat table of findings
suitable for spreadsheets; ``to_stix`` emits a STIX 2.1 bundle with one IPv4
indicator per host plus a vulnerability object per CVE (interoperable with
threat-intelligence platforms / SIEMs).
"""

import csv
import io
import json
import uuid
from typing import Any, Dict, List

_CSV_FIELDS = [
    "scan_id",
    "target_ip",
    "target_hostname",
    "port",
    "service",
    "product",
    "version",
    "cve_id",
    "severity",
    "cvss_score",
    "cvss_vector",
    "epss_score",
    "kev",
    "confidence",
    "risk_score",
    "description",
    "remediation",
]


def _finding_rows(scan, findings: List[Any]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for finding in findings:
        service = finding.service
        port = service.port if service is not None else None
        rows.append(
            {
                "scan_id": scan.id,
                "target_ip": scan.target.ip,
                "target_hostname": scan.target.hostname or "",
                "port": port.port if port else "",
                "service": service.name if service else "",
                "product": service.product or "" if service else "",
                "version": service.version or "" if service else "",
                "cve_id": finding.cve_id,
                "severity": finding.severity,
                "cvss_score": finding.cvss_score if finding.cvss_score is not None else "",
                "cvss_vector": finding.cvss_vector or "",
                "epss_score": finding.epss_score if finding.epss_score is not None else "",
                "kev": "yes" if finding.kev else "no",
                "confidence": finding.confidence,
                "risk_score": finding.risk_score if finding.risk_score is not None else "",
                "description": (finding.description or "").strip(),
                "remediation": (finding.remediation or "").strip(),
            }
        )
    return rows


def to_json(scan, findings: List[Any]) -> str:
    """Full scan dump as pretty JSON."""
    payload = {
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
            "error": scan.error,
            "target": {
                "ip": scan.target.ip,
                "hostname": scan.target.hostname,
                "authorized": scan.target.authorized,
            },
        },
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": {
                    "name": p.service.name if p.service else None,
                    "product": p.service.product if p.service else None,
                    "version": p.service.version if p.service else None,
                    "cpe": p.service.cpe if p.service else None,
                },
            }
            for p in sorted(scan.ports, key=lambda x: x.port)
        ],
        "findings": _finding_rows(scan, findings),
        "exported_by": "network-mapper",
        "exported_at": _iso(None),
    }
    return json.dumps(payload, indent=2)


def to_csv(scan, findings: List[Any]) -> str:
    """Findings as a CSV table (UTF-8 with BOM for Excel compatibility)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    for row in _finding_rows(scan, findings):
        writer.writerow(row)
    return buffer.getvalue()


def to_stix(scan, findings: List[Any]) -> str:
    """A minimal STIX 2.1 bundle (indicators + vulnerability objects)."""
    now = _iso(None)
    objects: List[Dict[str, object]] = []

    # One IPv4 indicator for the scanned host.
    objects.append(
        {
            "type": "indicator",
            "id": _stix_id("indicator"),
            "created": now,
            "modified": now,
            "name": f"Network Mapper scan #{scan.id} indicator",
            "pattern": "[ipv4-addr:value = '{}']".format(scan.target.ip),
            "valid_from": _iso(scan.started_at),
            "indicator_types": ["malicious-activity"],
            "labels": ["network-mapper"],
        }
    )

    # One vulnerability object per CVE matched on the host.
    seen: set[str] = set()
    for finding in findings:
        if finding.cve_id in seen:
            continue
        seen.add(finding.cve_id)
        objects.append(
            {
                "type": "vulnerability",
                "id": _stix_id("vulnerability"),
                "created": now,
                "modified": now,
                "name": finding.cve_id,
                "description": (finding.description or "").strip()[:1000],
                "external_references": [
                    {
                        "source_name": "nvd",
                        "external_id": finding.cve_id,
                        "url": f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}",
                    }
                ],
            }
        )

    return json.dumps(
        {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "spec_version": "2.1",
            "objects": objects,
        },
        indent=2,
    )


def _stix_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4().hex}"


def _iso(value) -> str:
    """ISO-8601 timestamp; defaults to UTC now for naive datetimes."""
    from datetime import datetime, timezone

    if value is None:
        value = datetime.now(timezone.utc)
    if not value.tzinfo:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")