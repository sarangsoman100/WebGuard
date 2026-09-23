# WebGuard API Documentation

**Version:** 2.0  
**Project:** WebGuard – Web Application Vulnerability Scanner  
**API Base URL:** `http://127.0.0.1:5000`

---

## 1. Overview

WebGuard provides a REST API for queueing background security scans, tracking scan progress, retrieving scan history and scan details, viewing supported scan modes, comparing scan results, and exporting security reports as PDF.

The API is intended for authorized security testing and controlled environments.

### API Conventions

- **Protocol:** HTTP
- **Data format:** JSON
- **Content-Type:** `application/json` for JSON request bodies
- **Authentication:** Not currently required
- **Default local host:** `127.0.0.1:5000`

> **Security note:** Only scan applications that you own or have explicit permission to test.

---

# 2. Start a Security Scan

## `POST /api/scan`

Starts a WebGuard security scan against the supplied target URL.

### Request Headers

```http
Content-Type: application/json
```

### Request Body

```json
{
  "url": "http://127.0.0.1:5001",
  "mode": "standard"
}
```

### Parameters

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `url` | string | Yes | Target web application URL |
| `mode` | string | No | Scan mode: `passive`, `standard`, or `active` |

If `mode` is omitted, the application uses the default scan mode.

### Scan Modes

| Mode | Typical Max Pages | Timeout | Crawl Depth | Purpose |
|---|---:|---:|---:|---|
| `passive` | 10 | 5 sec | 1 | Low-impact security inspection |
| `standard` | 20 | 10 sec | 2 | Balanced scan for normal use |
| `active` | 50 | 15 sec | 3 | Deeper testing with controlled probes |

The exact configuration returned by your running server should be treated as authoritative through `GET /api/scan/modes`.

### Example using cURL

```bash
curl -X POST http://127.0.0.1:5000/api/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\":\"http://127.0.0.1:5001\",\"mode\":\"standard\"}"
```

### Successful Response

The current API starts scans as background jobs. A successful request returns `202 Accepted` with a `job_id`.

```json
{
  "success": true,
  "job_id": 73,
  "target": "http://127.0.0.1:5001",
  "mode": "standard",
  "status": "queued"
}
```

The scan continues in the background. Retrieve progress through `GET /api/scan/jobs/{job_id}`. When complete, the job response contains the stored `scan_id`, which can then be used with the scan-history and report endpoints.

### Response Fields

| Field | Type | Description |
|---|---|---|
| `success` | boolean | Indicates that the scan job was accepted |
| `job_id` | integer | Background scan-job identifier |
| `target` | string | Target URL |
| `mode` | string | Scan mode used |
| `status` | string | Initial job state, normally `queued` |

### Background Job States

```text
queued → running → completed
                 ↘ failed
```

Progress information is exposed through `GET /api/scan/jobs/{job_id}`.

---

# 3. Get Available Scan Modes

## `GET /api/scan/modes`

Returns the scan modes supported by WebGuard and, in the current configuration, their associated scanning profiles.

### Request

```http
GET /api/scan/modes
```

### Example

```bash
curl http://127.0.0.1:5000/api/scan/modes
```

### Example Response

```json
{
  "passive": {
    "max_pages": 10,
    "timeout": 5,
    "max_depth": 1
  },
  "standard": {
    "max_pages": 20,
    "timeout": 10,
    "max_depth": 2
  },
  "active": {
    "max_pages": 50,
    "timeout": 15,
    "max_depth": 3
  }
}
```

> The response structure may vary slightly depending on the currently installed WebGuard configuration. The endpoint itself is the source of truth for supported modes.

---

# 4. Get Background Scan Job Status

## `GET /api/scan/jobs/{job_id}`

Returns the current state and progress of a background scan job.

### Path Parameter

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `job_id` | integer | Yes | Background scan-job ID returned by `POST /api/scan` |

### Example

```bash
curl http://127.0.0.1:5000/api/scan/jobs/73
```

### Example Response

```json
{
  "id": 73,
  "target": "http://127.0.0.1:5001",
  "mode": "standard",
  "status": "running",
  "progress": 72,
  "stage": "Analysis",
  "message": "Analyzing scan results.",
  "scan_id": null,
  "error": null
}
```

When the job completes, `status` becomes `completed` and `scan_id` contains the stored scan ID.

### Job Response Fields

| Field | Type | Description |
|---|---|---|
| `id` | integer | Job identifier |
| `target` | string | Scan target |
| `mode` | string | Scan mode |
| `status` | string | `queued`, `running`, `completed`, or `failed` |
| `progress` | integer | Approximate progress from 0 to 100 |
| `stage` | string | Current scan stage |
| `message` | string | Human-readable progress message |
| `scan_id` | integer/null | Completed scan ID, when available |
| `error` | string/null | Error message if the job failed |

---

# 5. Get Active Scan Jobs

## `GET /api/scan/jobs`

Returns currently queued or running background scan jobs.

### Example

```bash
curl http://127.0.0.1:5000/api/scan/jobs
```

### Example Response

```json
{
  "jobs": [
    {
      "id": 73,
      "target": "http://127.0.0.1:5001",
      "mode": "standard",
      "status": "running",
      "progress": 40,
      "stage": "Scanning",
      "message": "Running vulnerability checks."
    }
  ]
}
```

---

# 4. Get Scan History

## `GET /api/history`

Returns previously stored scans.

### Request

```http
GET /api/history
```

### Example

```bash
curl http://127.0.0.1:5000/api/history
```

### Example Response

```json
[
  {
    "id": 12,
    "target": "http://127.0.0.1:5001",
    "mode": "standard",
    "risk_level": "High",
    "security_score": 65
  }
]
```

The returned records represent scans stored in WebGuard's SQLite database.

---

# 7. Get Scan Details

## `GET /api/history/{scan_id}`

Returns the details of one previously completed scan.

### Path Parameter

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `scan_id` | integer | Yes | ID of the stored scan |

### Example

```bash
curl http://127.0.0.1:5000/api/history/12
```

### Typical Response

```json
{
  "id": 12,
  "target": "http://127.0.0.1:5001",
  "mode": "standard",
  "findings": [
    {
      "type": "SQL Injection",
      "severity": "High",
      "confidence": "High",
      "url": "http://127.0.0.1:5001/user?id=1"
    }
  ],
  "risk": {
    "security_score": 65,
    "risk_level": "High"
  }
}
```

The finding list depends on the scan.

---

# 8. Compare Two Scans

## `GET /api/compare`

Compares a baseline scan with a newer scan.

### Query Parameters

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `baseline` | integer | Yes | ID of the older/baseline scan |
| `current` | integer | Yes | ID of the newer scan |

### Example

```bash
curl "http://127.0.0.1:5000/api/compare?baseline=10&current=12"
```

### Example Response

```json
{
  "baseline_scan": 10,
  "current_scan": 12,
  "score_delta": 15,
  "risk_changed": true,
  "fixed": [],
  "new": [],
  "severity_changed": [],
  "unchanged": [],
  "endpoint_changes": {
    "added": [],
    "removed": []
  }
}
```

### Comparison Categories

- **Fixed:** Finding existed in the baseline but is no longer detected.
- **New:** Finding appears in the current scan but was not present in the baseline.
- **Severity Changed:** Same finding exists but its severity changed.
- **Unchanged:** Finding remains materially unchanged.
- **Endpoint Changes:** Tracks discovered endpoint additions and removals.

This makes the comparison API useful for security regression testing.

---

# 9. Finding Structure

A WebGuard finding can contain information such as:

```json
{
  "type": "SQL Injection",
  "name": "SQL Injection",
  "category": "Vulnerability",
  "severity": "High",
  "confidence": "High",
  "url": "http://127.0.0.1:5001/user?id=1",
  "parameter": "id",
  "cwe": "CWE-89",
  "owasp": "A03:2021 – Injection",
  "description": "Potential SQL injection vulnerability detected."
}
```

### Common Categories

| Category | Meaning |
|---|---|
| `Vulnerability` | A security issue identified by WebGuard |
| `Potential Vulnerability` | Evidence suggests a vulnerability but confirmation is limited |
| `Security Misconfiguration` | Unsafe or missing security configuration |
| `Informational` | Useful security information that is not necessarily a vulnerability |

### Severity Levels

- `Critical`
- `High`
- `Medium`
- `Low`
- `Informational`

### Confidence Levels

- `High`
- `Medium`
- `Low`

---

# 10. Risk Response

The risk engine evaluates findings and produces an overall security assessment.

A risk response can contain information such as:

```json
{
  "risk_points": 8.05,
  "security_score": 92,
  "risk_level": "High",
  "finding_breakdown": [],
  "top_risks": [],
  "confidence_counts": {
    "High": 1,
    "Medium": 0,
    "Low": 0
  }
}
```

### Security Score

The security score is represented on a 0–100 scale, where a higher score indicates a stronger security posture.

The risk engine considers factors including:

- Severity
- Finding category
- Confidence
- Exploitability
- Repeated findings affecting the same endpoint
- Vulnerability type

---

# 11. Error Handling

The API may return an error response when a request is invalid or cannot be processed.

### Example

```json
{
  "error": "Invalid target URL"
}
```

### Common HTTP Status Codes

| Status | Meaning |
|---:|---|
| `200` | Request completed successfully |
| `400` | Invalid request or missing/invalid parameters |
| `404` | Requested scan/resource does not exist |
| `500` | Internal server error |

Clients should check the HTTP status code before processing a response as a successful result.

---

# 12. JavaScript Integration Example

A frontend application can start a scan using `fetch()`:

```javascript
async function startWebGuardScan(targetUrl) {
    const response = await fetch("http://127.0.0.1:5000/api/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            url: targetUrl,
            mode: "standard"
        })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Scan failed");
    }

    return data;
}
```

---

# 13. Python Integration Example

WebGuard can also be consumed by Python applications.

```python
import requests

payload = {
    "url": "http://127.0.0.1:5001",
    "mode": "standard"
}

response = requests.post(
    "http://127.0.0.1:5000/api/scan",
    json=payload
)

response.raise_for_status()

data = response.json()

print("Scan ID:", data["scan_id"])
print("Risk:", data["risk"])
```

---

# 14. Recommended API Workflow

A typical client workflow is:

```text
1. GET /api/scan/modes
          ↓
2. POST /api/scan
          ↓
3. Receive job_id
          ↓
4. GET /api/scan/jobs/{job_id}
          ↓
5. Poll until completed
          ↓
6. Read scan_id from the job
          ↓
7. GET /api/history/{scan_id}
          ↓
8. Review findings and risk
          ↓
9. GET /api/reports/{scan_id}/pdf (optional)
          ↓
10. GET /api/compare?baseline=X&current=Y (optional)
```

This workflow supports both individual security assessments and repeated security regression testing.

---

# 15. Current API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Queue a background security scan |
| `GET` | `/api/scan/modes` | Get supported scan modes/configuration |
| `GET` | `/api/scan/jobs/{job_id}` | Get background scan-job status/progress |
| `GET` | `/api/scan/jobs` | Get active queued/running scan jobs |
| `GET` | `/api/history` | Get scan history |
| `GET` | `/api/history/{scan_id}` | Get completed scan details |
| `GET` | `/api/compare` | Compare two scans |
| `GET` | `/api/reports/{scan_id}/pdf` | Generate/download a PDF security report |

Interactive documentation is also available if enabled:

- `/api/docs` – Swagger/OpenAPI interface
- `/api/redoc` – ReDoc interface
- `/api/openapi.json` – OpenAPI specification

---

# 16. Security Considerations

WebGuard is designed for authorized security testing.

Before scanning:

1. Confirm that you own the target or have explicit authorization.
2. Prefer a dedicated test environment for active scanning.
3. Avoid scanning third-party systems without permission.
4. Use passive or standard mode when lower-impact testing is appropriate.
5. Treat scan results as security assessment evidence that should be manually validated.

The current API does **not** provide authentication. API authentication and access control are planned as a future security enhancement.

---

# 17. Export Security Report as PDF

## `GET /api/reports/{scan_id}/pdf`

Generates a server-side PDF security report for a completed scan.

### Path Parameter

| Parameter | Type | Required | Description |
|---|---|---:|---|
| `scan_id` | integer | Yes | ID of the completed scan |

### Example

```bash
curl -o webguard-report.pdf http://127.0.0.1:5000/api/reports/73/pdf
```

The generated report includes, where available:

- WebGuard branding and report metadata
- Target and scan ID
- Scan timestamp
- Overall risk level and security score
- Endpoint and finding counts
- High/Critical finding counts
- Finding classification
- Severity distribution
- Endpoint inventory
- Detailed security findings
- CWE and OWASP mappings
- Confidence and verification information
- Affected endpoint, parameter, HTTP method, and test mode
- Evidence/detection details
- Impact and remediation recommendations
- Page numbering and report footer

---

# 18. Future API Enhancements

Potential future improvements include:

- API authentication and authorization
- API keys or JWT-based access control
- Background scan jobs
- Scan status endpoints
- Scheduled scans
- Exporting reports through API
- Pagination for large scan histories
- Rate limiting
- Webhook notifications
- Docker-based API deployment

---

## Project

**WebGuard – Web Application Vulnerability Scanner**

Built as an MCA cybersecurity project using a Python/Flask backend, crawler, vulnerability detection modules, risk engine, and SQLite scan history.
