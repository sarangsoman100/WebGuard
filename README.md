<div align="center">

# 🛡️ WebGuard

**A self-hosted web application vulnerability scanner, built from scratch in Python & Flask.**

Crawl a target, run a full battery of active/passive security checks, score the risk, and walk away with a client-ready PDF report — all from your own dashboard, on your own infrastructure.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](#)
[![SQLite](https://img.shields.io/badge/Database-SQLite-07405E?style=flat-square&logo=sqlite&logoColor=white)](#)
[![Status](https://img.shields.io/badge/status-active--development-yellow?style=flat-square)](#)
[![Made for authorized testing](https://img.shields.io/badge/use-authorized%20testing%20only-critical?style=flat-square)](#-responsible-use)

</div>

---

## Why WebGuard?

Most "toy" vulnerability scanners either stop at a header check or require standing up Burp/ZAP with a mountain of config. WebGuard sits in between: a lightweight Flask app with a real crawler, a modular check engine covering the classes of bugs that actually show up in bug bounty and pentest reports, background job processing so scans don't block the UI, and scan history you can diff over time to prove regressions got fixed.

It's built to be read, not just run — every check lives in its own file under `scanner/`, so adding a new detector is a matter of writing one function and registering it.

---

## Table of Contents

- [Features](#-features)
- [How a Scan Works](#-how-a-scan-works)
- [Scan Modes](#-scan-modes)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Configuration](#-configuration)
- [API Overview](#-api-overview)
- [Roadmap](#-roadmap)
- [Responsible Use](#-responsible-use)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🔍 Detection Engine
A dedicated module per vulnerability class, all feeding into a shared findings/risk pipeline:

| Category | Checks |
|---|---|
| **Injection** | SQL Injection, XML External Entity (XXE) |
| **Cross-Site Scripting** | Reflected XSS |
| **Access & Trust** | CORS misconfiguration, CSRF protection, Open Redirect, SSRF |
| **Transport & Config** | Missing/weak security headers, cookie flags (`Secure`, `HttpOnly`, `SameSite`), insecure HTTP methods, TLS/transport checks |
| **Recon & Disclosure** | Information disclosure (server banners, stack traces), sensitive file exposure (`.env`, `.git`, backups), endpoint exposure via `robots.txt` / sitemaps |
| **Auth Surface** | Login form and authentication security checks |

### 🕷️ Smart Crawling
A bounded, same-origin crawler discovers pages and parameters up to a configurable depth and page limit before the scanner touches a single endpoint.

### ⚙️ Configurable Scan Modes
Choose **Passive**, **Standard**, or **Active** scanning — trading crawl depth and probe aggressiveness for speed and safety. See [Scan Modes](#-scan-modes).

### 🧵 Background Job Queue
Scans run on a thread-pool worker, not the request thread. Kick off a scan, get a `job_id` immediately, and poll (or refresh the page) for live progress — nothing times out on a slow target.

### 📊 Risk Scoring
Findings are deduplicated and rolled into a single explainable **Security Score** (0–100) and risk level, so you can track "is this app actually getting safer" instead of just counting raw alerts.

### 📈 History, Diffing & Reporting
- Every scan is persisted to SQLite with its full finding set.
- The **Compare** view diffs two scans: what got fixed, what's new, what changed severity.
- One click exports a professional, multi-page **PDF security assessment** (cover page, executive summary, severity breakdown, per-finding evidence and remediation) via ReportLab.

### 🖥️ Built-in Dashboard
A dark, security-console-styled UI (no JS framework, no build step) for launching scans, watching live progress, browsing history, and reading reports — served straight from Flask templates.

---

## 🔄 How a Scan Works

```
   POST /api/scan
        │
        ▼
 ┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
 │   Crawler   │────▶│  Vulnerability│────▶│   Dedup + Risk    │
 │ (discovery) │     │    Modules    │     │     Engine        │
 └─────────────┘     └──────────────┘     └──────────────────┘
        │                                          │
        ▼                                          ▼
  endpoints found                          security_score, risk_level
                                                     │
                                                     ▼
                                          saved to SQLite → dashboard,
                                          history, compare, PDF export
```

1. You submit a target URL and a scan mode.
2. The request returns instantly with a `job_id` — the scan itself runs in the background.
3. The crawler discovers endpoints (bounded by mode-specific max pages / depth).
4. Every discovered endpoint is run through the full check suite.
5. Findings are deduplicated, scored, and written to the database.
6. The dashboard polls job status and renders results the moment the scan completes.

---

## ⚙️ Scan Modes

| Mode | Max Pages | Timeout | Crawl Depth | Best for |
|---|---:|---:|---:|---|
| `passive` | 10 | 5s | 1 | Quick, low-impact reconnaissance |
| `standard` | 20 | 10s | 2 | Default — balanced coverage and speed |
| `active` | 50 | 15s | 3 | Deep, authorized assessments |

> The live, authoritative configuration for your instance is always available at `GET /api/scan/modes`.

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Scanning | `requests`, `BeautifulSoup4` |
| Background jobs | `concurrent.futures.ThreadPoolExecutor` |
| Storage | SQLite |
| Reporting | ReportLab (PDF generation) |
| Auth (scaffolded) | `python-jose` (JWT), `werkzeug.security` |
| Frontend | Vanilla HTML / CSS / JS — no framework, no build step |

---

## 📁 Project Structure

```
Webguard/
├── app.py                  # Flask routes, background scan orchestration, PDF export
├── auth.py                 # JWT/password-hash auth helpers
├── database.py              # SQLite schema + data access layer
├── jobs_module.py           # Thread-pool background job runner
├── docs/
│   └── Api Documentation.md # Full REST API reference
├── scanner/
│   ├── scanner.py            # Scan orchestration, modes, config
│   ├── crawler.py            # Bounded same-origin crawler
│   ├── risk.py                # Scoring / risk engine
│   ├── dedup.py               # Finding deduplication
│   ├── sqli.py, xss.py, csrf.py, cors.py, ssrf.py, xxe.py
│   ├── headers.py, cookies.py, transport.py, methods.py
│   ├── disclosure.py, sensitive.py, endpoint_exposure.py
│   ├── redirect.py, parameters.py, auth.py
├── templates/                # Dashboard, history, reports, compare, scan detail pages
├── static/
│   ├── css/style.css
│   └── js/app.js
└── webguard.db               # SQLite database (created on first run)
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip

### 1. Clone & enter the project
```bash
git clone https://github.com/<your-username>/webguard.git
cd webguard
```

### 2. Create a virtual environment
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
Create a `requirements.txt` (not yet included) with:
```
flask
requests
beautifulsoup4
python-dotenv
python-jose[cryptography]
reportlab
```
then:
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
See [Configuration](#-configuration) below, then run:
```bash
python app.py
```

### 5. Open the dashboard
Visit **http://127.0.0.1:5000**, drop in a target URL you're authorized to test, pick a scan mode, and hit scan.

---

## 🔧 Configuration

WebGuard reads its settings from a `.env` file in the project root:

```env
JWT_SECRET=replace-with-a-long-random-secret
ACCESS_TOKEN_EXPIRE_MINUTES=60
```

> ⚠️ **Never commit your real `.env` file.** Add it to `.gitignore` and generate a fresh, random `JWT_SECRET` for every environment (e.g. `python -c "import secrets; print(secrets.token_urlsafe(48))"`).

---

## 🔌 API Overview

WebGuard is fully API-driven — the dashboard is just a client of it. Full request/response schemas live in [`docs/Api Documentation.md`](docs/Api%20Documentation.md).

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Queue a new background scan (returns a `job_id`) |
| `GET` | `/api/scan/jobs/<job_id>` | Poll job status / progress |
| `GET` | `/api/scan/jobs` | List active (queued/running) jobs |
| `GET` | `/api/scan/modes` | Get available scan modes and their configuration |
| `GET` | `/api/history` | List all past scans |
| `GET` | `/api/history/<scan_id>` | Full detail for one scan |
| `GET` | `/api/compare?baseline=<id>&current=<id>` | Diff two scans |
| `GET` | `/api/reports/<scan_id>/pdf` | Download a PDF security report |

Quick example:
```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:5001", "mode": "standard"}'
```

---

## 🗺️ Roadmap

- [ ] Wire up the JWT authentication layer (`auth.py`) to protect scan/report routes
- [ ] Multi-user support with per-user scan history
- [ ] Authenticated / session-based scanning (crawl behind a login)
- [ ] Rate limiting and scan scheduling
- [ ] CI-friendly CLI mode for pipeline security gates
- [ ] `requirements.txt` + Docker Compose for one-command setup

---

## 🛡️ Responsible Use

WebGuard performs **active security testing**, including requests designed to trigger and confirm vulnerabilities. Only run it against:

- Applications you own, or
- Targets you have **explicit, documented authorization** to test.

Scanning systems without permission may be illegal in your jurisdiction. The maintainers assume no liability for misuse.

---

## 🤝 Contributing

Contributions, new detector modules, and bug reports are welcome.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Commit your changes
4. Open a pull request

A new vulnerability check is typically just a new file in `scanner/` exposing a `check_*()` function, registered in `scanner/scanner.py`.

---

## 📄 License

No license has been set for this repository yet. Until one is added, all rights are reserved by the author — consider adding an [MIT](https://choosealicense.com/licenses/mit/) or similar open-source license if you intend for others to use or contribute to this project.

---

<div align="center">

Built as a hands-on exploration of how web vulnerability scanners actually work, end to end.

</div>
