# SecureQA Sentinel

A self-hosted, AI-powered web vulnerability scanning dashboard. SecureQA Sentinel wraps [OWASP ZAP](https://www.zaproxy.org/) in a full-stack application that automates scanning, explains findings in plain language using local or cloud LLMs, and maintains a tamper-evident audit trail of everything it does.

Built as a final-year B.Tech CSE internship project (cybersecurity specialization).

---

## Table of contents

- [Why self-hosted](#why-self-hosted)
- [Features](#features)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Usage](#usage)
- [API reference](#api-reference)
- [Project structure](#project-structure)
- [CI/CD](#cicd)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why self-hosted

Most AI-powered security tools route scan data through third-party cloud APIs by default. For a tool whose entire job is surfacing vulnerability findings, that's a problem: you'd be sending a live map of your application's weaknesses to an external service.

SecureQA Sentinel is architected the other way around. The scanner (ZAP), the database (SQLite), and one of the two AI backends (Ollama) all run entirely on your own machine, with no data leaving your network unless you explicitly opt into the cloud AI backend (Groq) for a given request. Self-hosting here isn't a deployment detail — it's a deliberate response to what this specific tool does.

---

## Features

- **Automated scanning pipeline** — triggers OWASP ZAP spider, passive, and active scans against a target and tracks progress in real time via a two-phase progress bar (`POST /api/scan` returns immediately with a job ID; the frontend polls actual ZAP progress, not a fake timer).
- **Dual-backend AI reports** — every scan's findings can be summarized into a plain-language report by either a local Ollama model or the Groq cloud API, selectable per request, with independent caching so switching backends never returns stale results from the other one.
- **Chatbot Q&A panel** — ask follow-up questions about a specific scan's findings; the AI backend is given that scan's data as context and maintains conversation history.
- **Tamper-evident audit trail** — every scan action is logged with a SHA-256 hash chained to the previous entry. Editing or deleting a row anywhere in the chain breaks every hash after it, and `GET /api/audit/verify` proves whether the log is intact.
- **PDF export** — generate a shareable PDF report of any scan via ReportLab.
- **Scan comparison / diffing** — compare two scans to see findings added, removed, or persisting between runs. Findings are matched by `(name, CWE)` pair rather than URL, since scan targets with dynamic state (like OWASP Juice Shop) don't produce stable URLs across runs.
- **CSP hardening demo** — a companion nginx reverse proxy (`csp-proxy`) injects a hardened Content-Security-Policy header in front of the scan target, producing a clean before/after finding-count comparison.
- **Fully containerized** — one `docker compose up` brings up the scanner, backend, and frontend together.

---

## Architecture

```
Target app (e.g. OWASP Juice Shop)
        │
        ▼
OWASP ZAP  ──spider──▶ passive scan ──▶ active scan
        │
        ▼
Flask backend  (orchestrates ZAP via its REST API, polls progress,
        │        normalizes findings)
        ▼
SQLite  (scans, findings, reports, hash-chained audit log)
        │
        ▼
AI report layer  (Ollama local  /  Groq cloud — selectable, cached per backend)
        │
        ▼
React dashboard  (progress bar, findings table, chatbot, PDF export,
                   scan comparison view)
```

**Request flow for a scan:**

1. Frontend calls `POST /api/scan` with a target URL and AI backend choice.
2. Flask starts the scan asynchronously against the `zap` container's REST API and returns `202 Accepted` with a job ID immediately — the client never blocks on a long-running scan.
3. Flask polls ZAP's own spider and active-scan progress endpoints in the background.
4. The frontend polls the backend for progress, driving a two-phase bar (spider %, then active scan %).
5. On completion, findings are pulled from ZAP, normalized, and written to SQLite, with a new hash-chained entry added to the audit log.
6. The frontend requests an AI-generated report for the completed scan; the backend checks the per-backend cache first, otherwise generates and stores a new one.

---

## Tech stack

| Layer | Technology |
|---|---|
| Scanner | OWASP ZAP 2.17.0 (Docker) |
| Backend | Flask 3.1.3, Flask-CORS, SQLAlchemy |
| Database | SQLite |
| AI (local) | Ollama, running as a host process (outside Docker, for RAM reasons — see [Known limitations](#known-limitations)) |
| AI (cloud) | Groq API |
| PDF generation | ReportLab |
| Frontend | React + Vite |
| Web server (compose) | nginx (serves the built frontend; also used standalone for the CSP demo) |
| Containerization | Docker, Docker Compose |
| CI/CD | GitHub Actions |

---

## Getting started

### Prerequisites

- Docker Desktop
- Node.js (only needed for local frontend dev outside Docker)
- Python 3.x + `venv` (only needed for local backend dev outside Docker)
- [Ollama](https://ollama.com/) installed on the host if you want local AI reports
- A Groq API key if you want cloud AI reports (optional)
- A local instance of [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (or another **authorized** scan target — see the warning below)

> **Only scan targets you own or have explicit written permission to test.** Active scanning sends attack-style traffic (SQL injection payloads, XSS probes, fuzzing) and is unauthorized access under laws like the CFAA, the UK Computer Misuse Act, or India's IT Act regardless of intent. OWASP Juice Shop exists specifically so this kind of tool can be exercised legally. Do not point this at production systems, third-party sites, or anything you don't have clear authorization to test.

### Setup

```bash
# Clone the repo
git clone https://github.com/NamrataDhingra654/SecureQA_Sentinel.git
cd SecureQA_Sentinel

# Start Juice Shop (or your authorized scan target) separately, e.g.:
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Set required environment variables
setx GROQ_API_KEY "your-key-here"     # Windows, optional — for cloud AI backend
# (open a new terminal after setx for the variable to take effect)

# Bring up the full stack
docker compose up -d --build
```

Once running:

| Service | URL |
|---|---|
| Dashboard | `http://localhost:8081` |
| Flask API | `http://localhost:5000` |
| ZAP | `http://localhost:8080` |

### Windows-specific setup notes

- A local Apache service (`httpd.exe`) commonly conflicts with ZAP on port 8080. Kill it before starting, from an **Administrator** command prompt:
  ```
  taskkill /F /IM httpd.exe
  ```
- PowerShell aliases `curl` to `Invoke-WebRequest`, which does not behave like real curl. Use `curl.exe` explicitly when testing endpoints from PowerShell.
- Ollama must be reachable from inside the backend container via `host.docker.internal`, since it runs as a host process rather than a compose service (RAM constraints — see below).

---

## Usage

1. Open the dashboard and enter your scan target's URL.
2. Choose an AI backend (Ollama or Groq) for the report that will be generated.
3. Start the scan and watch the two-phase progress bar (spidering, then active scan).
4. Once complete, review findings, read the AI-generated report, or ask the chatbot follow-up questions about specific findings.
5. Export a PDF report, or run a second scan later and use the comparison view to see what changed.
6. Use `GET /api/audit/verify` at any time to confirm the audit log hasn't been tampered with.

---

## API reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan` | `POST` | Start a new scan against a target URL. Returns `202` with a job ID. |
| `/api/scan/<id>` | `GET` | Get scan status/progress and results. |
| `/api/scan/<id>/chat` | `POST` | Ask a question about a scan's findings; maintains conversation history. |
| `/api/scan/<id>/export/pdf` | `GET` | Download a PDF report for a scan. |
| `/api/scans/compare?a=<id>&b=<id>` | `GET` | Diff findings between two scans, matched by `(name, CWE)`. |
| `/api/audit/verify` | `GET` | Verify the SHA-256 hash chain of the audit log. |

---

## Project structure

```
secureqa-sentinel/
├── .github/
│   └── workflows/
│       └── ci.yml              # 3-job pipeline: backend, frontend, docker build
├── .gitignore
├── Dockerfile                   # Backend image
├── docker-compose.yml           # zap + backend + frontend services
├── requirements.txt
├── scanner.py                   # ZAP orchestration (reads ZAP_API_URL from env)
├── app.py                       # Flask routes
├── models.py                    # SQLAlchemy models (Scan, Finding, Report, AuditLog)
├── demo_light_scan.py           # RAM-safe passive-only scan, for demo data
└── frontend/
    ├── Dockerfile                # Multi-stage Vite build, served via nginx
    ├── nginx.frontend.conf
    └── src/
        └── App.jsx
```

---

## CI/CD

GitHub Actions runs on every push and pull request, across three jobs:

1. **backend-lint-build** — installs dependencies, runs flake8 (hard-fails only on real errors like syntax errors or undefined names), byte-compiles all Python files, runs `pytest` if a test suite exists.
2. **frontend-lint-build** — `npm ci` + `npm run build`, plus `npm run lint` if configured.
3. **docker-build-validation** — builds both the backend and frontend Docker images (build-only, no push), gated on the first two jobs passing, with layer caching for faster reruns.

---

## Known limitations

These are documented deliberately, not accidental gaps — a self-hosted student project has a different risk profile than a production tool, and the tradeoffs below are made consciously:

- **No authentication layer.** Any client that can reach the Flask API can trigger scans or read results. This mirrors the same "local dev convenience over production hardening" tradeoff already present in the ZAP container's own config (`api.disablekey=true`, permissive address allowlisting). Acceptable for a local, single-user demo environment; would need to be addressed before any multi-user or internet-facing deployment.
- **Full active scans are RAM-intensive.** Scanning a stateful app like Juice Shop with ZAP's active scan can exhaust RAM on constrained machines and crash Docker Desktop. `demo_light_scan.py` (spider + passive scan only) is provided as a lighter-weight alternative for generating demo data without the crash risk.
- **Ollama runs outside Docker Compose**, as a host process, specifically to avoid adding another RAM-heavy container to the stack. The backend reaches it via `host.docker.internal`.
- **ZAP's crawl of stateful targets is non-deterministic by URL** — the same target scanned twice won't necessarily produce identical URLs for the same underlying pages, which is why scan comparison matches findings by `(name, CWE)` instead.
- **`scans.db` exists in early git history** (committed before `.gitignore` was set up) even though it's excluded going forward — harmless, but visible if you inspect the full git log.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| ZAP won't bind to port 8080 | `httpd.exe` (Apache) already using it | `taskkill /F /IM httpd.exe` from an Admin prompt |
| `docker compose up` fails with a port conflict | A leftover container (e.g. an old `zap-scanner`) still holds the port | `docker compose down` then restart; `docker rm -f <name>` for orphaned containers |
| New backend routes return a stock HTML 404 instead of a JSON error | Flask's `debug=True` auto-reloader failed silently | Full manual restart — `docker compose up -d --build backend` under compose, don't rely on auto-reload |
| Frontend requests blocked by CORS | Frontend origin not in the backend's allowed origins list | Confirm the frontend's port is included in the Flask-CORS config |
| Docker Desktop crashes mid-scan | RAM exhaustion from a full active scan | Restart Docker Desktop and the target container (`docker restart juice-shop`) before clearing accumulated state; consider `demo_light_scan.py` for demo purposes |
| `curl` commands behave oddly on Windows | PowerShell aliases `curl` to `Invoke-WebRequest` | Use `curl.exe` explicitly |
| Timestamps display with a `+5:30` offset | UTC timestamp missing explicit `Z` suffix | Append `Z` to UTC timestamps before display |

---

## Roadmap

- [x] Core async scan pipeline with real progress tracking
- [x] SHA-256 tamper-evident audit trail
- [x] Dual-backend AI report generation with per-backend caching
- [x] Chatbot Q&A panel
- [x] PDF export
- [x] Scan comparison/diffing
- [x] CSP hardening demo
- [x] Docker Compose packaging
- [x] CI/CD via GitHub Actions
- [ ] Authentication layer (deliberately out of scope for this project — see [Known limitations](#known-limitations))

---