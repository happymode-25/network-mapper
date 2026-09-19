"""Shared fixtures. Env vars are set before any app import so settings use them."""

import os
import sys
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./test_network_mapper.db"
os.environ["USE_SAMPLE_CVES"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["ALLOWED_TARGETS"] = (
    "127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, 203.0.113.0/24"
)
os.environ["RATE_LIMIT_SCANS_PER_MINUTE"] = "1000"
os.environ["AUDIT_LOG_FILE"] = "test_audit.log"
os.environ["FINGERPRINT_PROBE"] = "false"
os.environ["USE_NMAP"] = "false"

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.app import models  # noqa: E402,F401 - register tables on Base
from backend.app.database import Base, engine  # noqa: E402
from backend.app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_database():
    """Isolate every test with a clean schema."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture()
def client(monkeypatch):
    """FastAPI TestClient with the Celery enqueue call stubbed out."""
    monkeypatch.setattr(
        "backend.app.api.scans.enqueue_scan", lambda scan_id: None
    )
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def auth_headers(client):
    """Authenticate as the default admin and return bearer headers."""
    resp = client.post(
        "/api/token",
        data={"username": "admin", "password": "admin"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}