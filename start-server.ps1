# Start the Network Mapper API locally (no Docker / no Redis).
# Scans run inline; SQLite is used. Edit ALLOWED_TARGETS to match YOUR network.

$env:DATABASE_URL   = "sqlite:///./local.db"
$env:INLINE_SCANS   = "true"
$env:USE_SAMPLE_CVES = "true"
$env:SECRET_KEY     = "dev-key"
$env:ALLOWED_TARGETS = "127.0.0.1, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8"

Write-Host "Starting Network Mapper at http://127.0.0.1:8000/docs (Ctrl+C to stop)"
& .\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload