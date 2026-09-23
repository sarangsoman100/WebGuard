# WebGuard API Documentation

**Version:** 1.0  
**Project:** WebGuard – Web Application Vulnerability Scanner  
**API Base URL:** `http://127.0.0.1:5000`

---

## 1. Overview

WebGuard provides a REST API for starting security scans, retrieving scan history and scan details, viewing supported scan modes, and comparing two scan results.

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

```json
{
  "success": true,
  "scan_id": 12,
  "target": "http://127.0.0.1:5001",
  "mode": "standard",
  "discovered_endpoints": [
    "http://127.0.0.1:5001/",
    "http://127.0.0.1:5001/search"
  ],
  "results": [],
  "findings": [],
  "risk": {}
}
```

The exact `results`, `findings`, and `risk` contents depend on the target application and detected issues.

### Response Fields

| Field | Type | Description |
|---|---|---|
| `success` | boolean | Indicates whether the scan request completed successfully |
| `scan_id` | integer | Database identifier for the scan |
| `target` | string | Target URL |
| `mode` | string | Scan mode used |
| `discovered_endpoints` | array | Endpoints discovered by the crawler |
| `results` | array | Raw/structured scanner results |
| `findings` | array | Deduplicated security findings |
| `risk` | object | Overall risk and security-score information |

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

# 5. Get Scan Details

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

# 6. Compare Two Scans

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

# 7. Finding Structure

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

# 8. Risk Response

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

# 9. Error Handling

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

# 10. JavaScript Integration Example

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

# 11. Python Integration Example

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

# 12. Recommended API Workflow

A typical client workflow is:

```text
1. GET /api/scan/modes
          ↓
2. POST /api/scan
          ↓
3. Receive scan_id
          ↓
4. GET /api/history/{scan_id}
          ↓
5. Review findings and risk
          ↓
6. Run a later scan
          ↓
7. GET /api/compare?baseline=X&current=Y
```

This workflow supports both individual security assessments and repeated security regression testing.

---

# 13. Current API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Start a security scan |
| `GET` | `/api/scan/modes` | Get supported scan modes/configuration |
| `GET` | `/api/history` | Get scan history |
| `GET` | `/api/history/{scan_id}` | Get scan details |
| `GET` | `/api/compare` | Compare two scans |

Interactive documentation is also available if enabled:

- `/api/docs` – Swagger/OpenAPI interface
- `/api/redoc` – ReDoc interface
- `/api/openapi.json` – OpenAPI specification

---

# 14. Security Considerations

WebGuard is designed for authorized security testing.

Before scanning:

1. Confirm that you own the target or have explicit authorization.
2. Prefer a dedicated test environment for active scanning.
3. Avoid scanning third-party systems without permission.
4. Use passive or standard mode when lower-impact testing is appropriate.
5. Treat scan results as security assessment evidence that should be manually validated.

The current API does **not** provide authentication. API authentication and access control are planned as a future security enhancement.

---

# 15. Future API Enhancements

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
