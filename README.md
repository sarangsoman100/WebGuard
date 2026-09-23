# WebGuard

<p align="center">
  <strong>Web Application Vulnerability Scanner</strong><br>
  <sub>Crawl · Discover · Test · Analyze · Score · Report</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Security-Application%20Testing-8B5CF6?style=flat-square" alt="Security Testing">
  <img src="https://img.shields.io/badge/Status-Active-22C55E?style=flat-square" alt="Status">
</p>

---

## What is WebGuard?

**WebGuard** is a Python/Flask-based web application vulnerability scanner designed to help security testers discover, analyze, and document common web security issues in authorized testing environments.

Instead of treating a scan as a simple list of URLs and alerts, WebGuard follows a security-assessment workflow:

```text
Target
  │
  ▼
Crawler
  │
  ▼
Endpoint Discovery
  │
  ▼
Security Tests
  │
  ▼
Finding Normalization & Deduplication
  │
  ▼
Risk Analysis
  │
  ├── Security Score
  ├── Risk Level
  ├── Finding Breakdown
  └── Top Risks
  │
  ▼
History / Comparison / Report
```

The project was developed as an **MCA cybersecurity project** with a focus on practical web application security testing and a usable security-assessment workflow.

---

## Why WebGuard?

Security scanners can produce a large amount of raw information. WebGuard is designed to turn that information into something easier to understand:

- Discover application endpoints automatically.
- Run multiple categories of security checks.
- Separate confirmed findings from potential issues and misconfigurations.
- Deduplicate repeated findings.
- Calculate an overall security score and risk level.
- Keep historical scan results.
- Compare scans for regression testing.
- Run scans as background jobs with progress tracking.
- Generate professional PDF security reports.

The goal is not simply:

> **"Something looks vulnerable."**

It is:

> **"Here is what was tested, what was found, how significant it is, where it occurs, and what should be reviewed next."**

---

# ✨ Features

## 🔎 Web Application Scanning

WebGuard includes checks for common web application security weaknesses and security configuration issues.

### Vulnerability & Security Checks

| Category | Capability |
|---|---|
| SQL Injection | Detects SQL injection indicators and database errors |
| Reflected XSS | Tests parameters for reflected script injection |
| CSRF | Checks for missing anti-CSRF protections |
| SSRF | Tests controlled server-side request behavior |
| XXE | Checks XML entity processing behavior |
| Open Redirect | Detects potentially unsafe redirects |
| Security Headers | Reviews important HTTP security headers |
| Cookie Security | Checks cookie security attributes |
| CORS | Reviews cross-origin configuration |
| HTTP Methods | Checks exposed/unsafe HTTP methods |
| Sensitive Files | Looks for commonly exposed sensitive resources |
| Endpoint Exposure | Identifies potentially exposed application functionality |
| Information Disclosure | Detects useful information unintentionally exposed by the application |
| Transport Security | Reviews HTTPS/security-related transport configuration |

> WebGuard is intended for **authorized security testing only**.

---

# 🎯 Scan Modes

WebGuard provides three scan profiles:

| Mode | Max Pages | Timeout | Crawl Depth | Intended Use |
|---|---:|---:|---:|---|
| `passive` | 10 | 5s | 1 | Lower-impact inspection |
| `standard` | 20 | 10s | 2 | Normal security assessment |
| `active` | 50 | 15s | 3 | Deeper controlled testing |

The application exposes the currently configured profiles through:

```http
GET /api/scan/modes
```

The server-side configuration remains the source of truth.

---

# 🧠 Risk Engine

One of WebGuard's core components is its risk-analysis layer.

Findings are not treated equally. The risk engine considers factors such as:

- Severity
- Finding category
- Confidence
- Exploitability
- Repeated findings affecting the same endpoint
- Vulnerability type

The engine produces information including:

```text
Risk Points
Security Score
Overall Risk Level
Finding Breakdown
Top Risks
Confidence Counts
```

### Security Score

WebGuard represents the security score on a:

```text
0 ─────────────────────────────── 100
```

scale, where a higher score represents a stronger security posture.

The scanner also distinguishes between classifications such as:

```text
Confirmed Vulnerability
Potential Vulnerability
Security Misconfiguration
Informational
```

This helps avoid treating every scanner observation as a confirmed exploitable vulnerability.

---

# ⚙️ Background Scanning

Longer scans are handled through a lightweight background job system.

Instead of keeping the browser request waiting for the complete scan:

```text
POST /api/scan
       │
       ▼
   Create Job
       │
       ▼
   Background Worker
       │
       ├── Discovery
       ├── Crawling
       ├── Scanning
       ├── Analysis
       ├── Risk Calculation
       └── Database Storage
       │
       ▼
   Completed Scan
```

Jobs expose progress information such as:

```text
Queued
Discovery
Scanning
Analysis
Risk Analysis
Saving
Completed
```

The frontend can reconnect to an active job after a browser refresh using the stored job identifier.

### Important

The current implementation uses an in-process worker pool. It is designed for the project's local/single-instance use case and is **not a distributed task queue**.

---

# 🗂️ Scan History

Completed assessments are stored in SQLite.

The history system allows you to review:

- Target
- Scan mode
- Number of endpoints
- Findings
- Risk level
- Security score
- Scan details

This makes WebGuard useful for repeated testing rather than only one-off scans.

---

# 🔁 Scan Comparison

WebGuard includes scan-to-scan comparison.

You can compare a baseline scan with a newer scan and identify:

```text
Fixed Findings
New Findings
Severity Changes
Unchanged Findings
Added Endpoints
Removed Endpoints
Score Changes
Risk Changes
```

This makes the scanner useful for basic **security regression testing**.

Example:

```text
Baseline Scan
     │
     ▼
Fix Application
     │
     ▼
Run New Scan
     │
     ▼
Compare
     │
     ├── Fixed
     ├── New
     ├── Severity Changed
     └── Unchanged
```

---

# 📄 Security Reports

WebGuard can generate a professional PDF report for a completed scan.

The report can contain:

- WebGuard branding
- Target information
- Scan metadata
- Security score
- Overall risk level
- Finding counts
- High/Critical counts
- Severity distribution
- Finding classifications
- Endpoint inventory
- Detailed findings
- CWE mappings
- OWASP mappings
- Confidence
- Verification status
- Affected endpoint
- Parameter
- HTTP method
- Test mode
- Evidence/detection details
- Impact
- Remediation recommendations
- Page numbers and report footer

API endpoint:

```http
GET /api/reports/{scan_id}/pdf
```

---

# 🌐 REST API

WebGuard exposes a REST API for integrating the scanner with other applications.

### Main Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Queue a security scan |
| `GET` | `/api/scan/modes` | Get scan modes/configuration |
| `GET` | `/api/scan/jobs/{job_id}` | Get scan-job status |
| `GET` | `/api/scan/jobs` | Get active jobs |
| `GET` | `/api/history` | Get scan history |
| `GET` | `/api/history/{scan_id}` | Get scan details |
| `GET` | `/api/compare` | Compare two scans |
| `GET` | `/api/reports/{scan_id}/pdf` | Generate PDF report |

Interactive API documentation is available when enabled:

```text
/api/docs
/api/redoc
/api/openapi.json
```

---

# 🧪 Example API Workflow

```text
GET /api/scan/modes
        │
        ▼
POST /api/scan
        │
        ▼
Receive job_id
        │
        ▼
GET /api/scan/jobs/{job_id}
        │
        ▼
Poll until completed
        │
        ▼
Receive scan_id
        │
        ▼
GET /api/history/{scan_id}
        │
        ├───────────────┐
        ▼               ▼
Review Findings     Generate PDF
        │
        ▼
Compare With Future Scan
```

---

# 🏗️ Architecture

At a high level, WebGuard is organized into several layers:

```text
┌─────────────────────────────────────────────┐
│                 Web Interface               │
│       Dashboard / History / Reports         │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│                  Flask API                  │
│     Scan / Jobs / History / Compare / PDF  │
└──────────────────────┬──────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌───────────────────┐     ┌───────────────────┐
│  Background Jobs  │     │      Crawler      │
└─────────┬─────────┘     └─────────┬─────────┘
          │                         │
          └────────────┬────────────┘
                       ▼
              ┌──────────────────┐
              │ Security Scanner │
              │ Modules / Tests  │
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │ Finding Pipeline │
              │ Normalize/Dedup  │
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │   Risk Engine    │
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │      SQLite      │
              │ History / Jobs   │
              └──────────────────┘
```

---

# 📁 Project Structure

A simplified view of the project:

```text
WebGuard/
│
├── app.py
├── database.py
├── jobs_module.py
├── requirements.txt
│
├── scanner/
│   ├── scanner.py
│   ├── crawler.py
│   ├── parameters.py
│   ├── dedup.py
│   ├── risk.py
│   └── ...
│
├── templates/
│   ├── index.html
│   ├── history.html
│   ├── reports.html
│   ├── compare.html
│   └── scan_details.html
│
├── static/
│   ├── style.css
│   └── app.js
│
└── webguard.db
```

> The exact file list can evolve as the project develops.

---

# 🛠️ Tech Stack

### Backend

- **Python**
- **Flask**

### Security Engine

- Custom Python vulnerability checks
- Web crawler
- Parameter discovery
- Finding normalization
- Finding deduplication
- Risk calculation

### Database

- **SQLite**

### Frontend

- HTML
- CSS
- JavaScript

### Reporting

- PDF report generation

### Development / Testing

- Burp Suite
- Local vulnerable applications
- Controlled security-testing environments

---

# 🚀 Getting Started

## 1. Clone the repository

```bash
git clone https://github.com/<your-username>/WebGuard.git
cd WebGuard
```

## 2. Create a virtual environment

### Windows

```powershell
python -m venv venv
```

Activate it:

```powershell
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Start WebGuard

```bash
python app.py
```

The default local address is:

```text
http://127.0.0.1:5000
```

Open it in your browser.

---

# 🧪 Testing WebGuard

For development and demonstration, use a deliberately vulnerable application or another application that you own/have explicit authorization to test.

A local test target can be run separately, for example:

```text
http://127.0.0.1:5001
```

Then enter the target into WebGuard:

```text
http://127.0.0.1:5001
```

Select:

```text
Passive
Standard
Active
```

and start the scan.

---

# 🔐 Security & Responsible Use

WebGuard is a **security testing tool**.

Only scan:

- Applications you own
- Applications where you have explicit authorization
- Dedicated security-testing environments
- Intentionally vulnerable labs

Do **not** use WebGuard to scan third-party systems without permission.

The scanner's results should also be treated as assessment evidence rather than absolute proof. Security findings should be manually validated where appropriate.

---

# ⚠️ GitHub Security Hygiene

Do **not** commit local/generated files such as:

```text
venv/
.venv/
__pycache__/
*.pyc
.env
webguard.db
*.log
```

A recommended `.gitignore`:

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class

# Virtual environments
venv/
.venv/
env/

# Environment / secrets
.env
.env.*

# Local database
webguard.db
*.db
*.sqlite
*.sqlite3

# Logs
*.log

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
```

Never commit passwords, API keys, JWT secrets, database credentials, or other private configuration.

---

# 🗺️ Roadmap

The project is being developed toward a more complete security-assessment platform.

### Current / Completed Areas

- [x] Web vulnerability scanning
- [x] Security header analysis
- [x] Cookie security checks
- [x] CORS analysis
- [x] SQL injection checks
- [x] Reflected XSS checks
- [x] CSRF checks
- [x] SSRF checks
- [x] XXE checks
- [x] Open redirect checks
- [x] Sensitive file / endpoint checks
- [x] Crawler
- [x] Parameter discovery
- [x] Finding deduplication
- [x] Risk engine
- [x] Security scoring
- [x] Passive / Standard / Active modes
- [x] Scan configuration
- [x] Scan history
- [x] Background scan jobs
- [x] Scan comparison
- [x] Security report generation
- [x] PDF report export
- [x] REST API
- [x] API documentation

### Planned / Future

- [ ] Finding-level retest/rescan
- [ ] Advanced target validation and scope control
- [ ] Further UI/UX refinement
- [ ] Expanded test coverage
- [ ] More robust deployment architecture
- [ ] Docker / Docker Compose deployment
- [ ] Scheduled scans
- [ ] API authentication and authorization
- [ ] Rate limiting
- [ ] Webhook notifications

---

# 📸 Screenshots

Add your project screenshots here once you have the final UI captures.

Suggested screenshots:

```text
Dashboard
Scan in Progress
Scan Results
Finding Details
Scan History
Scan Comparison
Security Report
API Documentation
```

Example Markdown:

```markdown
![WebGuard Dashboard](screenshots/dashboard.png)
```

---

# 🎓 Project Context

**WebGuard** was developed as an **MCA cybersecurity project** to explore practical web application security testing.

The project combines concepts from:

- Web application security
- Vulnerability assessment
- Ethical hacking
- Web crawling
- Security automation
- Risk analysis
- Secure software development
- REST API development
- Security reporting

Rather than implementing a single vulnerability check, the project brings these components together into one assessment workflow.

---

# 👨‍💻 Author

**Sarang Soman**

MCA | Cybersecurity

Interested in:

```text
Cybersecurity
Ethical Hacking
Web Application Security
Security Automation
Python
```

---

# 📜 License

Add your preferred license before publishing the repository.

For example:

```text
MIT License
```

---

<p align="center">
  <strong>WebGuard</strong><br>
  <sub>Find it. Understand it. Fix it.</sub>
</p>
