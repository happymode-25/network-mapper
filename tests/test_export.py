"""Tests for scan export (JSON / CSV / STIX 2.1)."""

import json

import pytest
from sqlalchemy import select

from backend.app import exporters, models
from backend.app.database import SessionLocal
from backend.app.scan_service import execute_scan

ALLOWED_IP = "127.0.0.1"


def _fake_services(host):
    return [
        {
            "port": 22,
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "banner": f"SSH-2.0-OpenSSH_8.9p1 from {host}",
        },
        {
            "port": 80,
            "name": "http",
            "product": "nginx",
            "version": "1.18.0",
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
        },
    ]


@pytest.fixture()
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def completed_scan(db, monkeypatch):
    """A scan with two findings persisted through the real pipeline."""
    target = models.Target(ip=ALLOWED_IP, hostname="local", authorized=True)
    db.add(target)
    db.commit()
    scan = models.Scan(target_id=target.id, status="queued")
    db.add(scan)
    db.commit()

    async def fake_scan(host, ports, **kwargs):
        return _fake_services(host)

    monkeypatch.setattr("scanner.scanner.scan_host_with_services", fake_scan)
    result = execute_scan(db, scan.id)
    assert result.status == "completed"
    findings = db.scalars(select(models.Finding)).all()
    assert len(findings) >= 2
    return result


def _load_findings(db):
    return list(db.scalars(select(models.Finding).order_by(models.Finding.cve_id)))


def test_to_json_is_valid_and_contains_key_data(db, completed_scan):
    payload = json.loads(exporters.to_json(completed_scan, _load_findings(db)))
    assert payload["scan"]["id"] == completed_scan.id
    assert payload["scan"]["target"]["ip"] == ALLOWED_IP
    assert payload["findings"]
    cve_ids = {row["cve_id"] for row in payload["findings"]}
    assert "CVE-2024-6387" in cve_ids
    ports = {p["port"] for p in payload["ports"]}
    assert ports == {22, 80}


def test_to_csv_header_and_rows(db, completed_scan):
    csv_text = exporters.to_csv(completed_scan, _load_findings(db))
    lines = csv_text.splitlines()
    assert lines[0] == ",".join(exporters._CSV_FIELDS)
    assert len(lines) >= 3
    assert "CVE-2024-6387" in csv_text
    assert ALLOWED_IP in csv_text


def test_to_stix_bundle_structure(db, completed_scan):
    bundle = json.loads(exporters.to_stix(completed_scan, _load_findings(db)))
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    types = {obj["type"] for obj in bundle["objects"]}
    assert "indicator" in types and "vulnerability" in types
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert "[ipv4-addr:value = '127.0.0.1']" in indicator["pattern"]
    vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    ext_ids = {ref["external_id"] for v in vulns for ref in v["external_references"]}
    assert "CVE-2024-6387" in ext_ids


def test_export_endpoint_formats(db, client, auth_headers, completed_scan):
    scan_id = completed_scan.id

    resp = client.get(f"/api/scans/{scan_id}/export?format=json", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["scan"]["id"] == scan_id

    resp = client.get(f"/api/scans/{scan_id}/export?format=csv", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "cve_id" in resp.text.splitlines()[0]

    resp = client.get(f"/api/scans/{scan_id}/export?format=stix", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["type"] == "bundle"

    bad = client.get(f"/api/scans/{scan_id}/export?format=pdf", headers=auth_headers)
    assert bad.status_code == 422