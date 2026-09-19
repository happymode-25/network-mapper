# Network Mapper

Automated network service discovery and vulnerability assessment platform.

Scans **authorized** network targets, detects services and versions, correlates
them with vulnerability intelligence (NVD, CISA KEV, EPSS), computes
risk-based findings and presents everything in a web dashboard.

> **Authorisation boundary.** This tool is designed for scanning targets you own
> or are explicitly permitted to test. Target IPs are enforced against an
> allowlist (`ALLOWED_TARGETS`), and loopback / cloud-metadata addresses are
> blocked. Scanning systems you do not own may be illegal in your jurisdiction.

---

## Overview

| Layer | Stack |
| --- | --- |
| Scanner | Pure-`asyncio` TCP scanner + banner grabber (no root required) |
| Matcher | NVD API 2.0, CISA KEV feed, FIRST EPSS API, `packaging` version comparer |
| Backend | Python 3.11, FastAPI, SQLAlchemy 2, Alembic, Celery, Redis, PostgreSQL |
| Frontend | React 18, Vite, React Query, Axios, React Router, Tailwind CSS |
| Deployment | Docker Compose, Nginx, GitHub Actions |

The core value is the **correlation engine**: version normalization, CPE
mapping, confidence modelling and a composite risk score that fuses CVSS + EPSS
+ KEV + asset importance.

### Fingerprinting strategy

Detection happens in three layers:

1. **Passive banners** (built-in, unsigned/privilege-free): SSH, HTTP, FTP,
   SMTP banners parsed from the service greeting.
2. **Active TLS/HTTP probes** (built-in): for bannerless web services the
   scanner sends one minimal `GET /` (plain or TLS) and fingerprints the
   `Server` header, and handshakes TLS to record the certificate CN / TLS
   version. Fully dependency-free.
3. **Nmap `-sV`** (optional, opt-in): when `USE_NMAP=true` and the `nmap`
   binary is installed, Nmap performs deep version detection on the open ports
   (handles TLS, SMB, RDP and routers); output is parsed from Nmap's XML with
   the standard library only.

---

## Architecture

```
                 ┌───────────────────────┐
                 │   NVD / KEV / EPSS    │   external intelligence feeds
                 └──────────┬────────────┘
                            │
  ┌────────────┐   scan     ┌▼──────────────┐   queued    ┌─────────────┐
  │  Frontend  │ ─────────► │    FastAPI    │ ──────────► │   Celery    │
  │  React SPA │ ◄───────── │ backend:8000  │             │   worker    │
  └─────┬──────┘    JSON    └───────┬───────┘             └──────┬──────┘
        │  :3000 (nginx)            │                             │
        │                           ├──────────┐   asyncio.run   ▼
        │                     ┌─────▼──────┐    │  ┌───────────────────────┐
        └────────────────────►│ PostgreSQL │    └─►│ scanner (asyncio TCP) │
                              └─────┬──────┘       │ service detection     │
                                    │              │ version normalization  │
                              ┌─────▼──────┐       └───────────┬───────────┘
                              │   Redis    │                   │
                              └────────────┘     ┌────────▼──────────┐
                                                 │ matcher (CPE / CVE │
                                                 │ / risk scoring)    │
                                                 └────────────────────┘
```

Flow per scan: queue → validate allowlist → port scan + banner grab →
service detection → version normalization → CPE mapping → CVE correlation
(sample data or NVD) → EPSS/KEV enrichment → risk scoring → persist findings.

---

## Quick Start (Docker)

```bash
cp .env.example .env          # adjust ALLOWED_TARGETS / credentials first
docker compose up --build
docker compose exec backend python -m backend.app.seed
```

- Dashboard: http://localhost:3000
- API / OpenAPI docs: http://localhost:8000/docs
- Default login: `admin` / `admin` (set `DEFAULT_ADMIN_USERNAME`/`DEFAULT_ADMIN_PASSWORD` in `.env`)

The backend container runs `alembic upgrade head` on startup, so migrations are
applied automatically.

> **No Docker installed?** Use the zero-dependency quick start below — the
> whole stack runs on your machine with plain Python, no Redis/PostgreSQL.

## Quick Start (no Docker — local demo)

Works with a plain Python 3.11+ install. Uses SQLite and runs scan tasks
inline, so there is no Redis or Celery worker to start.

```bash
cd network-mapper
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

# PowerShell:
$env:DATABASE_URL="sqlite:///./local.db"; $env:INLINE_SCANS="true"; $env:USE_SAMPLE_CVES="true"
$env:SECRET_KEY="dev-key"; $env:ALLOWED_TARGETS="127.0.0.1, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8"
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Then open http://127.0.0.1:8000/docs, log in (`admin` / `admin`), add a target
in your allowlist, and run a scan — it executes synchronously and results are
saved immediately. Point `ALLOWED_TARGETS` at your LAN subnet to see real
findings.

## Manual Setup (no Docker)

Requires Python 3.11+, Node 18+, and local PostgreSQL + Redis.

```bash
# 1. Python dependencies
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

# 2. Database
createdb network_mapper
alembic -c backend/alembic.ini upgrade head

# 3. Environment
cp .env.example .env
#   set DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/network_mapper
#   set CELERY_BROKER_URL=redis://localhost:6379/0        (and result backend /1)

# 4. API + worker (two terminals)
uvicorn backend.app.main:app --reload --port 8000
celery -A backend.app.tasks worker --loglevel=info

# 5. Frontend
cd frontend && npm install && npm run dev           # http://localhost:5173

# 6. Seed a localhost scan
python -m backend.app.seed
```

## Real vs Sample Data

`USE_SAMPLE_CVES=true` (default) uses the bundled
`matcher/data/sample_cves.json` — 16 realistic CVEs covering OpenSSH, Apache
HTTPd, nginx, vsftpd, Postfix, ProFTPd and IIS — with baked-in KEV/EPSS flags.
This makes the whole pipeline run fully offline and deterministically, ideal
for demos and CI.

Set `USE_SAMPLE_CVES=false` (and optionally `NVD_API_KEY`) to query the live
NIST NVD API 2.0 for each detected service, enrich with the live CISA KEV feed
and FIRST EPSS API, and cache results in the `cves` table. Note NVD rate limits
(5 req/30s without a key) slow live scans down by design.

---

## Security

- **Allowlist** (`ALLOWED_TARGETS`): comma-separated IPs/CIDRs. Targets outside
  it are rejected at creation *and* re-checked inside the worker.
- **Blocklist**: `169.254.169.254`, `0.0.0.0/8`, CGNAT, multicast, reserved
  ranges are always denied — SSRF-style protection against internal metadata.
- **Auth**: JWT (`python-jose`), OAuth2 password flow at `/api/token`;
  all routes except `/health` and `/api/token` require a bearer token.
- **Rate limiting**: per-user sliding window on scan creation
  (`RATE_LIMIT_SCANS_PER_MINUTE`).
- **Audit logging**: every target/scan action is written to the `audit_logs`
  table and a JSONL file.
- **Input validation**: IP and port inputs validated with `ipaddress`; malformed
  input is rejected with 422.

## Testing

```bash
pip install -r backend/requirements.txt
pytest -q        # 74 tests: scanner, service detection, version normalizer,
                 # CPE mapper, matcher/risk scoring, NVD/KEV/EPSS clients,
                 # API/auth/allowlist, and end-to-end scan service flow
```

CI (`.github/workflows/main.yml`) runs `ruff` on `backend/ scanner/ matcher/`,
`pytest`, and a production frontend build on every push/PR.

## API Overview

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/token` | Login → JWT |
| POST | `/api/targets` | Add an allowed target |
| GET | `/api/targets` | List targets (paged) |
| POST | `/api/scans` | Queue a scan |
| GET | `/api/scans` | List scans (paged) |
| GET | `/api/scans/{id}` | Scan detail (ports/services/findings) |
| GET | `/api/scans/{id}/findings` | Findings (paged, filter by severity) |
| GET | `/api/scans/{id}/export?format=json\|csv\|stix` | Export findings (JSON dump, CSV table, STIX 2.1 bundle) |
| GET | `/api/compare?scan_a=A&scan_b=B` | Diff two scans (added/removed/changed) |
| GET/POST/PUT | `/api/assets` | Assets & importance |

## Risk Scoring

```
risk = (cvss * 0.5) + (epss * 10 * 0.3) + (kev ? 2 : 0) + asset_importance_weight
```
| risk | severity |
| --- | --- |
| 0 | none |
| 0.1 – 3.9 | low |
| 4.0 – 6.9 | medium |
| 7.0 – 8.9 | high |
| 9.0 – 10.0 | critical |

Confidence: `high` for exact version match, `medium` for version-range match,
`low` for product-only match.

## Limitations

- Banner-grabbing is passive and single-request; services that require active
  protocol negotiation may show incomplete product/version info — enable
  `USE_NMAP` for deep fingerprints, or use heartbeat `FINGERPRINT_PROBE=false`
  to skip the active TLS/HTTP probes entirely.
- No UDP scanning; TCP-only by default (add Nmap `-sV` integration for deeper
  fingerprinting).
- `python-nmap` is intentionally **not** required — the built-in scanner and
  Nmap bridge are dependency-free (a local `nmap` binary does the heavy
  lifting when enabled).
- NVD `configurations` with complex AND/OR trees use the last-seen version
  window; range inference is heuristic.
- Matches can produce false positives where banners lie about versions.
- `epss`/`kev` values in sample mode are illustrative, not live.

## Future Work

- Nmap NSE script scanning and gameplay-focused `-sC` defaults
- UDP scans, ICMP host discovery, ARP sweep (Scapy); LAN discovery UI
- Topology graph (Cytoscape.js) with asset relationships
- Scan scheduling (Celery Beat) and email/Slack alerts
- Multitenant users & RBAC (user table + roles)
- `versionEndExcluding` fine-grained tree parsing for NVD configs
- PDF report export alongside the current JSON/CSV/STIX options

## License

MIT — see [LICENSE](LICENSE). Use responsibly and only on systems you own or
have explicit authorization to test.