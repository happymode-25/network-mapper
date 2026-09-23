# Network Mapper

## Automated Network Service Discovery and Vulnerability Assessment Platform

**Course / Subject:** Networking and Cybersecurity Project
**Student Name:** _________________________________
**Student ID:** _________________________________
**Date of Submission:** _________________________________

---

## Abstract

The **Network Mapper** project is a full-stack security tool that performs automated
network service discovery and vulnerability assessment. It scans authorized network
targets, detects running services and their versions, correlates the results with
vulnerability intelligence feeds (NVD, CISA KEV, and FIRST EPSS), and produces risk
scored, severity-rated findings that can be viewed in a web dashboard or exported as
JSON, CSV, or STIX 2.1 threat-intelligence bundles.

Unlike conventional scanning tools that require elevated privileges, the core scanner
is a dependency-free, pure-`asyncio` TCP scanner with banner grabbing. An optional
Nmap `-sV` integration provides deeper version detection when the binary is installed.
The main contribution is the **correlation engine**, which turns raw scan data into
actionable, prioritized security findings by fusing CVSS severity, EPSS exploit
likelihood, CISA KEV known-exploitation status, and asset importance into a single
composite risk score.

---

## 1. Introduction

### 1.1 Background

Every organization relies on networked services. Attackers routinely scan the
internet for exposed and out-of-date services, so defenders need the same visibility
to identify weak points first. Manually fingerprinting hundreds of hosts and port
results and then looking up each product version against public vulnerability
databases is slow, error-prone, and impossible to scale. This project automates that
entire workflow.

### 1.2 Problem Statement

Security teams face three problems:

1. **Discovery** — finding which ports are open and which services run on them,
   accurately and without needing root privileges.
2. **Correlation** — matching each detected product/version against a database of
   known vulnerabilities (CVEs) to know which exposures actually matter.
3. **Prioritization** — deciding *which* vulnerability to fix first, when there are
   hundreds of them.

### 1.3 Objectives

- Build an automated tool that **discovers** open ports and identifies services and
  product versions.
- **Correlate** detected software against vulnerability intelligence (NVD, CISA KEV,
  EPSS).
- **Score and rank** findings so the most dangerous exposures surface first.
- Provide a **web dashboard** and machine-readable **exports** (JSON, CSV, STIX 2.1).
- Respect an **authorize-only** policy: scans are restricted to an allowlist and
  dangerous/reserved address ranges are blocked by default.

### 1.4 Scope and Ethical Boundary

This tool is designed for testing systems the user owns or is explicitly permitted to
test. Targets are enforced against an allowlist (`ALLOWED_TARGETS`), and loopback,
cloud-metadata, CGNAT, multicast, and reserved ranges are always blocked. Scanning
systems you do not own may be illegal in some jurisdictions. The tool is educational
in intent and strictly defensive.

---

## 2. Technologies Used

| Layer         | Stack                                                              |
| ------------- | ------------------------------------------------------------------ |
| Scanner       | Pure-`asyncio` TCP scanner + banner grabber (no root required)      |
| Matcher       | NVD API 2.0, CISA KEV feed, FIRST EPSS API, `packaging` version     |
| Backend       | Python 3.11, FastAPI, SQLAlchemy 2, Alembic, Celery, Redis, PgSQL   |
| Frontend      | React 18, Vite, React Query, Axios, React Router, Tailwind CSS      |
| Deployment    | Docker Compose (PostgreSQL 15, Redis 7, Nginx), GitHub Actions CI   |
| Testing       | pytest, pytest-asyncio, respx (HTTP mocking), ruff (linting)        |

Key libraries: `fastapi`, `sqlalchemy`, `alembic`, `celery`, `pydantic-settings`,
`httpx`, `python-jose` (JWT), `passlib[bcrypt]`, `packaging`, `asyncio`, and `ipaddress`
(full list in `backend/requirements.txt`).

---

## 3. System Architecture

The platform is split into five collaborating components:

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

### 3.1 Data Flow

1. A user adds an authorized **Target** (validated against the allowlist).
2. A **Scan** is queued; the Celery worker executes the pipeline.
3. The **scanner** asynchronously probes TCP ports and grabs banners.
4. **Service detection** identifies product and version from banners.
5. **Version normalization** converts messy version strings to canonical form.
6. The **CPE mapper** converts product names into CPE 2.3 identifiers.
7. The **matcher** correlates with CVEs (bundled sample data or live NVD), enriches
   with KEV/EPSS, and computes composite risk scores.
8. **Findings** are persisted and served to the React dashboard or exported.

### 3.2 Scanner (three-layer fingerprinting strategy)

1. **Passive banners** (built-in, no privileges): parses SSH, HTTP, FTP, and SMTP
   greeting banners.
2. **Active TLS/HTTP probes** (built-in): for bannerless web services, sends one
   minimal `GET /` (plain or TLS) and fingerprints the `Server` / `X-Powered-By`
   headers; TLS handshakes record the certificate CN and TLS version. Fully
   dependency-free.
3. **Nmap `-sV`** (optional, opt-in): when `USE_NMAP=true` and the `nmap` binary is
   installed, performs deep version detection on open ports; the XML report is parsed
   with the standard library only.

### 3.3 Version Normalization

Real-world banners contain messy versions such as `8.9p1`, `1.2.3-rc1`, or `v12.0.3`.
The normalizer converts them to canonical dotted-numeric form (e.g. `8.9p1` →
`8.9.1`, `v12.0.3` → `12.0.3`) so they can be compared reliably against CVE version
ranges using `packaging.version`.

### 3.4 Correlation Engine (the core contribution)

The matcher filters candidate CVEs to those affecting the detected product (by CPE
product key and version window), assigns a **confidence** label, and computes a
composite risk score:

```
risk = (cvss * 0.5) + (epss * 10 * 0.3) + (kev ? 2 : 0) + asset_importance_weight
```

| Risk score | Severity |
| ---------- | -------- |
| 0          | none     |
| 0.1 – 3.9  | low      |
| 4.0 – 6.9  | medium   |
| 7.0 – 8.9  | high     |
| 9.0 – 10.0 | critical |

Confidence: **high** for an exact version match, **medium** for a version-range
match, **low** for a product-only match. Asset importance weights (none/low/medium/
high/critical) let organizations prioritize critical servers over test machines.

### 3.5 Sample vs Live Vulnerability Data

- `USE_SAMPLE_CVES=true` (default) uses the bundled `matcher/data/sample_cves.json` —
  16 realistic CVEs covering OpenSSH, Apache HTTPd, nginx, vsftpd, Postfix, ProFTPd,
  and IIS with baked-in KEV/EPSS flags. The pipeline then runs fully offline and
  deterministically, which is ideal for demos and CI.
- `USE_SAMPLE_CVES=false` queries the live NIST NVD API 2.0, enriches with the live
  CISA KEV feed and FIRST EPSS API, and caches results in the `cves` table. NVD rate
  limits (5 requests/30 s without an API key) are respected with automatic pacing.

---

## 4. Implementation Details

### 4.1 Database Model

Entity relationships (as required by the build specification):

```
Target ── 1:N ── Scan ── 1:N ── Port ── 1:1 ── Service ── 1:N ── Finding
   │                                    1:N
   └── Asset (importance)          CVE (cached intelligence)
AuditLog (every target/scan action)
```

### 4.2 REST API

| Method | Path                          | Description                                    |
| ------ | ----------------------------- | ---------------------------------------------- |
| POST   | `/api/token`                  | Login → JWT                                    |
| POST   | `/api/targets`                | Add an allowed target                          |
| GET    | `/api/targets`                | List targets (paged)                           |
| POST   | `/api/scans`                  | Queue a scan (supports `ports_to_scan`)        |
| GET    | `/api/scans`                  | List scans (paged)                             |
| GET    | `/api/scans/{id}`             | Scan detail (ports/services/findings)          |
| GET    | `/api/scans/{id}/findings`    | Findings (paged, filter by severity)           |
| GET    | `/api/scans/{id}/export`      | Export JSON / CSV / STIX 2.1 bundle            |
| GET    | `/api/compare`                | Diff two scans (added/removed/changed)         |
| GET/POST/PUT | `/api/assets`            | Assets & importance                            |

### 4.3 Security Features

- **Allowlist** — targets outside `ALLOWED_TARGETS` are rejected at creation and
  re-checked inside the worker.
- **Blocklist** — `169.254.169.254` (cloud metadata), `0.0.0.0/8`, CGNAT, multicast,
  and reserved ranges are always denied (SSRF-style protection).
- **Authentication** — JWT (HMAC-SHA256 via `python-jose`) issued at `/api/token`;
  all routes except `/health` and `/api/token` require a bearer token. Passwords are
  hashed with bcrypt.
- **Rate limiting** — per-user sliding window on scan creation.
- **Audit logging** — every target/scan action is recorded in the `audit_logs` table
  and an append-only JSONL file.
- **Input validation** — IP and port inputs validated with `ipaddress`; malformed
  input is rejected with HTTP 422.

### 4.4 Frontend

The React single-page application provides a dashboard with live statistics, a
severity summary and service list for the latest scan, pages to manage targets and
assets, a scan history, a scan detail view, scan comparison, and a findings table
with severity filtering. It uses React Query for data fetching, Axios for the API
client, and Tailwind CSS for a responsive dark-theme UI.

### 4.5 Deployment

- **Docker Compose** — PostgreSQL 15, Redis 7, backend (Uvicorn), Celery worker, and
  a frontend served by Nginx; Alembic migrations run automatically on startup.
- **Local demo (no Docker)** — SQLite with inline scans runs the entire platform with
  plain Python and no Redis/PostgreSQL (`start-server.ps1` for Windows).
- **CI** — GitHub Actions runs `ruff`, `pytest`, and a production frontend build on
  every push/PR.

---

## 5. Testing

The project is covered by 85 test functions across eight modules:

| Module                | Focus                                              |
| --------------------- | -------------------------------------------------- |
| `test_scanner`        | Async port scanning / banner grabbing              |
| `test_service_detect` | Banner parsing (SSH, HTTP, FTP, SMTP)              |
| `test_fingerprint`    | TLS/HTTP active probes, header parsing             |
| `test_nmap_probe`     | Nmap XML parsing and result merging                |
| `test_matcher`        | CVE matching, confidence, risk scoring             |
| `test_clients`        | NVD / KEV / EPSS client behavior (mocked HTTP via respx) |
| `test_export`         | JSON / CSV / STIX export generation                |
| `test_api`            | API, auth, allowlist, rate limiting, E2E scan flow |

Run with:

```bash
pip install -r backend/requirements.txt
pytest -q          # or: pytest --cov to see coverage
```

---

## 6. Results

After running a scan against a target on the allowlist, the platform reports:

- the open ports with service family, product, and normalized version;
- a CPE identifier for each detected product;
- matched CVEs with CVSS vector, EPSS score, KEV status, confidence, and composite
  risk score and severity;
- remediation guidance for each finding (from the sample data or CWE reference);
- exports in JSON (full dump), CSV (flat findings table), or STIX 2.1 (interoperable
  with threat-intelligence platforms / SIEMs);
- a two-scan comparison showing added / removed / changed findings, useful for
  tracking remediation progress or verifying a patch fixed an exposure.

---

## 7. Limitations

- Banner grabbing is passive and single-request; services requiring active protocol
  negotiation may show incomplete product/version info (Nmap `-sV` mitigates this).
- TCP-only scanning by default; no UDP or ICMP host discovery yet.
- NVD `configurations` with complex AND/OR trees use the last-seen version window;
  range inference is heuristic, and banners that lie about versions can cause false
  positives.
- `epss`/`kev` values in sample mode are illustrative, not live.
- Single-admin authentication (no multi-user / RBAC yet).

---

## 8. Future Work

- Nmap NSE script scanning and `-sC` defaults.
- UDP scans, ICMP host discovery, and ARP sweeps (Scapy); LAN discovery UI.
- Topology graph (Cytoscape.js) with asset relationships.
- Scan scheduling (Celery Beat) plus email/Slack alerts.
- Multitenant users and roles (RBAC).
- Fine-grained `versionEndExcluding` tree parsing for NVD configurations.
- PDF report export alongside JSON/CSV/STIX options.

---

## 9. Conclusion

The Network Mapper project delivers a complete, working, and ethically scoped
network discovery and vulnerability assessment platform. The combination of a
fast dependency-free scanner, a real correlation engine, a composite risk score, a
usable web dashboard, and open threat-intelligence exports makes it useful both as a
learning tool for networking/security concepts and as a practical defensive utility.
It demonstrates the full software engineering cycle: design, implementation, testing,
containerized deployment, and continuous integration. All scanning is restricted to
authorized targets, and the code is released under the MIT license.

---

## Appendix A — How to Run (Local, No Docker)

```bash
cd network-mapper
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r backend/requirements.txt

# PowerShell (or edit .env):
$env:DATABASE_URL="sqlite:///./local.db"
$env:INLINE_SCANS="true"
$env:USE_SAMPLE_CVES="true"
$env:SECRET_KEY="dev-key"
$env:ALLOWED_TARGETS="127.0.0.1, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8"
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/docs, log in with `admin` / `admin`, add a target from
the allowlist, and run a scan. Results are saved immediately.

## Appendix B — How to Run (Docker)

```bash
cp .env.example .env       # edit ALLOWED_TARGETS / credentials first
docker compose up --build
docker compose exec backend python -m backend.app.seed
```

- Dashboard: http://localhost:3000
- API docs: http://localhost:8000/docs

## Appendix C — Sample Risk Score Calculation

For a critical server (importance = **critical**, +4.0) running OpenSSH 9.5 and
CVE-2024-6387 (CVSS 8.1, EPSS 0.9751, in KEV):

```
risk = (8.1 × 0.5) + (0.9751 × 10 × 0.3) + 2.0 + 4.0
     = 4.05 + 2.93 + 2.0 + 4.0
     = 12.98  →  clamped to 10.0  →  severity = critical
```