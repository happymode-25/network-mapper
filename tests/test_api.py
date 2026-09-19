"""Tests for security helpers, the API and the end-to-end scan service."""

import pytest
from sqlalchemy import select

from backend.app import models
from backend.app.database import SessionLocal
from backend.app.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    is_allowed,
    verify_password,
)

ALLOWED_IP = "127.0.0.1"
DISALLOWED_IP = "198.51.100.7"  # TEST-NET-2, not on the test allowlist
CLOUD_METADATA_IP = "169.254.169.254"


class TestAllowlist:
    def test_loopback_allowed_when_listed(self):
        assert is_allowed(ALLOWED_IP)

    def test_rfc1918_allowed(self):
        assert is_allowed("10.1.2.3")
        assert is_allowed("192.168.50.10")

    def test_testnet_blocked(self):
        assert not is_allowed(DISALLOWED_IP)

    def test_cloud_metadata_always_blocked(self):
        assert not is_allowed(CLOUD_METADATA_IP)

    def test_invalid_ip_rejected(self):
        assert not is_allowed("not-an-ip")
        assert not is_allowed("999.999.999.999")


class TestTokens:
    def test_create_and_decode(self):
        token = create_access_token("admin")
        assert decode_access_token(token) == "admin"

    def test_decode_garbage(self):
        assert decode_access_token("nope.invalid.token") is None

    def test_password_hashing(self):
        hashed = hash_password("secret")
        assert verify_password("secret", hashed)
        assert not verify_password("wrong", hashed)


class TestAPI:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_protected_route_requires_auth(self, client):
        resp = client.get("/api/targets")
        assert resp.status_code == 401

    def test_login_and_me(self, client):
        resp = client.post("/api/token", data={"username": "admin", "password": "admin"})
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        me = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert me.json()["username"] == "admin"

    def test_login_rejects_bad_credentials(self, client):
        resp = client.post("/api/token", data={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_create_allowed_target(self, client, auth_headers):
        resp = client.post("/api/targets", json={"ip": ALLOWED_IP, "hostname": "local"}, headers=auth_headers)
        assert resp.status_code == 201
        assert resp.json()["authorized"] is True
        assert resp.json()["ip"] == ALLOWED_IP

    def test_create_disallowed_target_rejected(self, client, auth_headers):
        resp = client.post("/api/targets", json={"ip": DISALLOWED_IP}, headers=auth_headers)
        assert resp.status_code == 400
        assert "not on the allowed targets list" in resp.json()["detail"]

    def test_create_invalid_ip_rejected(self, client, auth_headers):
        resp = client.post("/api/targets", json={"ip": "banana"}, headers=auth_headers)
        assert resp.status_code == 422

    def test_list_targets_paginated(self, client, auth_headers):
        client.post("/api/targets", json={"ip": ALLOWED_IP}, headers=auth_headers)
        resp = client.get("/api/targets?page=1&size=5", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
        assert len(resp.json()["items"]) >= 1

    def test_create_scan_and_get_details(self, client, auth_headers):
        target = client.post("/api/targets", json={"ip": ALLOWED_IP}, headers=auth_headers).json()
        scan = client.post("/api/scans", json={"target_id": target["id"]}, headers=auth_headers)
        assert scan.status_code == 201
        scan_id = scan.json()["id"]
        detail = client.get(f"/api/scans/{scan_id}", headers=auth_headers)
        assert detail.status_code == 200
        assert detail.json()["status"] in ("queued", "running", "completed")
        assert detail.json()["target"]["ip"] == ALLOWED_IP

    def test_create_scan_with_requested_ports(self, client, auth_headers):
        target = client.post("/api/targets", json={"ip": ALLOWED_IP}, headers=auth_headers).json()
        scan = client.post(
            "/api/scans",
            json={"target_id": target["id"], "ports_to_scan": "22, 80-82,443"},
            headers=auth_headers,
        )
        assert scan.status_code == 201
        body = scan.json()
        assert body["requested_ports"] == "22,80,81,82,443"
        detail = client.get(f"/api/scans/{body['id']}", headers=auth_headers).json()
        assert detail["requested_ports"] == "22,80,81,82,443"

    def test_create_scan_rejects_invalid_ports(self, client, auth_headers):
        target = client.post("/api/targets", json={"ip": ALLOWED_IP}, headers=auth_headers).json()
        for bad in ("99999", "22,abc", "80-5", "0,80", "22-20000"):
            resp = client.post(
                "/api/scans",
                json={"target_id": target["id"], "ports_to_scan": bad},
                headers=auth_headers,
            )
            assert resp.status_code == 422, bad

    def test_scan_for_unauthorized_target_rejected(self, client, auth_headers):
        target = client.post(
            "/api/targets", json={"ip": DISALLOWED_IP}, headers=auth_headers
        )
        assert target.status_code == 400

    def test_get_missing_scan_404(self, client, auth_headers):
        assert client.get("/api/scans/9999", headers=auth_headers).status_code == 404

    def test_assets_crud(self, client, auth_headers):
        created = client.post(
            "/api/assets",
            json={"ip": ALLOWED_IP, "hostname": "box", "importance": "high"},
            headers=auth_headers,
        )
        assert created.status_code == 201
        updated = client.put(
            f"/api/assets/{created.json()['id']}",
            json={"importance": "critical"},
            headers=auth_headers,
        )
        assert updated.json()["importance"] == "critical"


def _fake_services(target_ip):
    return [
        {
            "port": 22,
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "banner": f"SSH-2.0-OpenSSH_8.9p1 from {target_ip}",
        },
        {
            "port": 80,
            "name": "http",
            "product": "nginx",
            "version": "1.18.0",
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
        },
    ]


class TestScanService:
    @pytest.fixture()
    def db(self):
        db = SessionLocal()
        yield db
        db.close()

    def test_execute_scan_completes_and_persists(self, db, monkeypatch):
        from backend.app.scan_service import execute_scan

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
        assert [p.port for p in db.scalars(select(models.Port)).all()] == [22, 80]
        findings = db.scalars(select(models.Finding)).all()
        ids = {f.cve_id for f in findings}
        assert "CVE-2024-6387" in ids  # regreSSHion affects OpenSSH 8.5.1-9.7.1
        assert any(f.severity == "critical" for f in findings)
        # nginx/CVE-2021-23017 should also match
        assert any("CVE-2021-23017" in f.cve_id for f in findings)

    def test_execute_scan_uses_requested_ports(self, db, monkeypatch):
        from backend.app.scan_service import execute_scan

        target = models.Target(ip=ALLOWED_IP, hostname="local", authorized=True)
        db.add(target)
        db.commit()
        scan = models.Scan(target_id=target.id, status="queued", requested_ports="22,443,80")
        db.add(scan)
        db.commit()

        captured: dict = {}

        async def fake_scan(host, ports, **kwargs):
            captured["ports"] = list(ports)
            return _fake_services(host)

        monkeypatch.setattr("scanner.scanner.scan_host_with_services", fake_scan)
        execute_scan(db, scan.id)
        assert captured["ports"] == [22, 80, 443]  # deduplicated, sorted

    def test_execute_scan_disallowed_target_fails(self, db):
        from backend.app.scan_service import execute_scan

        target = models.Target(ip=DISALLOWED_IP, hostname="evil", authorized=False)
        db.add(target)
        db.commit()
        scan = models.Scan(target_id=target.id, status="queued")
        db.add(scan)
        db.commit()
        result = execute_scan(db, scan.id)
        assert result.status == "failed"
        assert "not on the allowed" in (result.error or "")

    def test_execute_scan_missing_scan_raises(self, db):
        from backend.app.scan_service import execute_scan

        with pytest.raises(ValueError):
            execute_scan(db, 987654)

    def test_findings_endpoint_reports_scan_results(self, db, client, auth_headers, monkeypatch):
        import backend.app.scan_service as svc

        target = models.Target(ip=ALLOWED_IP, hostname="local", authorized=True)
        db.add(target)
        db.commit()
        scan = models.Scan(target_id=target.id, status="queued")
        db.add(scan)
        db.commit()

        async def fake_scan(host, ports, **kwargs):
            return _fake_services(host)

        monkeypatch.setattr("scanner.scanner.scan_host_with_services", fake_scan)
        svc.execute_scan(db, scan.id)

        resp = client.get(f"/api/scans/{scan.id}/findings", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
        first = resp.json()["items"][0]
        for key in ("cve_id", "severity", "cvss_score", "epss_score", "kev", "confidence", "risk_score"):
            assert key in first