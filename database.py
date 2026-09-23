import json
import sqlite3


DB_NAME = "webguard.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(cursor, table, column, definition):
    """
    Add a column if it does not already exist.
    """

    columns = {
        row["name"]
        for row in cursor.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }

    if column not in columns:
        cursor.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # ---------------------------------------------------------
    # Scans table
    # ---------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            endpoints_count INTEGER DEFAULT 0,
            vulnerability_count INTEGER DEFAULT 0,
            high_risk_count INTEGER DEFAULT 0,
            security_score INTEGER DEFAULT 0,
            risk_level TEXT,
            endpoints_json TEXT DEFAULT '[]'
        )
    """)

    # ---------------------------------------------------------
    # Findings table
    # ---------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,

            type TEXT,
            category TEXT,
            name TEXT,
            severity TEXT,
            confidence TEXT,

            description TEXT,
            recommendation TEXT,

            parameter TEXT,
            method TEXT,

            url TEXT,
            endpoint TEXT,

            detection TEXT,
            evidence TEXT,
            test_mode TEXT,

            affected_endpoints_json TEXT DEFAULT '[]',

            cwe TEXT,
            owasp TEXT,
            impact TEXT,
            verification_status TEXT,

            FOREIGN KEY (scan_id)
                REFERENCES scans(id)
        )
    """)

    # ---------------------------------------------------------
    # Database migrations
    # ---------------------------------------------------------

    _ensure_column(
        cursor,
        "scans",
        "endpoints_json",
        "TEXT DEFAULT '[]'"
    )

    _ensure_column(
        cursor,
        "findings",
        "category",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "confidence",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "method",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "endpoint",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "detection",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "evidence",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "test_mode",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "affected_endpoints_json",
        "TEXT DEFAULT '[]'"
    )

    # Finding intelligence metadata
    _ensure_column(
        cursor,
        "findings",
        "cwe",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "owasp",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "impact",
        "TEXT"
    )

    _ensure_column(
        cursor,
        "findings",
        "verification_status",
        "TEXT"
    )

    # ---------------------------------------------------------
    # Background scan jobs table
    # ---------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            mode TEXT DEFAULT 'standard',
            status TEXT DEFAULT 'queued',
            progress INTEGER DEFAULT 0,
            stage TEXT DEFAULT 'Queued',
            message TEXT DEFAULT 'Scan queued.',
            scan_id INTEGER,
            error TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()


def save_scan(
    target,
    endpoints_count,
    vulnerability_count,
    high_risk_count,
    security_score,
    risk_level,
    findings,
    endpoints=None
):
    """
    Save a complete scan and all findings.
    """

    conn = get_connection()
    cursor = conn.cursor()

    endpoints = (
        endpoints
        if isinstance(endpoints, list)
        else []
    )

    # ---------------------------------------------------------
    # Save scan
    # ---------------------------------------------------------

    cursor.execute("""
        INSERT INTO scans (
            target,
            endpoints_count,
            vulnerability_count,
            high_risk_count,
            security_score,
            risk_level,
            endpoints_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        target,
        endpoints_count,
        vulnerability_count,
        high_risk_count,
        security_score,
        risk_level,
        json.dumps(endpoints),
    ))

    scan_id = cursor.lastrowid

    # ---------------------------------------------------------
    # Save findings
    # ---------------------------------------------------------

    for finding in findings or []:

        if not isinstance(finding, dict):
            continue

        # Primary URL.
        affected = (
            finding.get("url")
            or finding.get("endpoint")
        )

        # Deduplicated findings may contain multiple
        # affected endpoints.
        affected_endpoints = finding.get(
            "affected_endpoints",
            []
        )

        if not isinstance(
            affected_endpoints,
            list
        ):
            affected_endpoints = []

        # If there is a URL but it isn't in the list,
        # include it.
        if (
            affected
            and affected not in affected_endpoints
        ):
            affected_endpoints.insert(
                0,
                affected
            )

        # Endpoint path.
        endpoint = finding.get("endpoint")

        if not endpoint and affected:
            try:
                from urllib.parse import urlparse

                endpoint = (
                    urlparse(affected).path
                    or "/"
                )

            except Exception:
                endpoint = None

        cursor.execute("""
            INSERT INTO findings (
                scan_id,
                type,
                category,
                name,
                severity,
                confidence,
                description,
                recommendation,
                parameter,
                method,
                url,
                endpoint,
                detection,
                evidence,
                test_mode,
                affected_endpoints_json,
                cwe,
                owasp,
                impact,
                verification_status
            )
            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?
            )
        """, (
            scan_id,

            finding.get("type"),

            finding.get("category"),

            finding.get("name"),

            finding.get("severity"),

            finding.get("confidence"),

            finding.get("description"),

            finding.get("recommendation"),

            finding.get("parameter"),

            finding.get("method"),

            affected,

            endpoint,

            finding.get("detection"),

            finding.get("evidence"),

            finding.get("test_mode"),

            json.dumps(
                affected_endpoints
            ),

            finding.get("cwe"),
            finding.get("owasp"),
            finding.get("impact"),
            finding.get("verification_status")
        ))

    conn.commit()
    conn.close()

    return scan_id


def get_scan_history():
    """
    Return scan history.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY scan_time DESC, id DESC
    """)

    scans = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    for scan in scans:

        try:
            scan["endpoints"] = json.loads(
                scan.get("endpoints_json")
                or "[]"
            )

        except (
            TypeError,
            json.JSONDecodeError
        ):
            scan["endpoints"] = []

        scan.pop(
            "endpoints_json",
            None
        )

    return scans


def get_scan(scan_id):
    """
    Return one complete scan including findings.
    """

    conn = get_connection()
    cursor = conn.cursor()

    # ---------------------------------------------------------
    # Scan
    # ---------------------------------------------------------

    cursor.execute("""
        SELECT *
        FROM scans
        WHERE id = ?
    """, (scan_id,))

    scan = cursor.fetchone()

    if not scan:
        conn.close()
        return None

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    cursor.execute("""
        SELECT *
        FROM findings
        WHERE scan_id = ?
        ORDER BY id ASC
    """, (scan_id,))

    findings = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    result = dict(scan)

    # ---------------------------------------------------------
    # Decode endpoints
    # ---------------------------------------------------------

    try:
        result["endpoints"] = json.loads(
            result.get("endpoints_json")
            or "[]"
        )

    except (
        TypeError,
        json.JSONDecodeError
    ):
        result["endpoints"] = []

    result.pop(
        "endpoints_json",
        None
    )

    # ---------------------------------------------------------
    # Decode affected endpoints
    # ---------------------------------------------------------

    for finding in findings:

        try:
            finding["affected_endpoints"] = json.loads(
                finding.get(
                    "affected_endpoints_json"
                )
                or "[]"
            )

        except (
            TypeError,
            json.JSONDecodeError
        ):
            finding["affected_endpoints"] = []

        finding.pop(
            "affected_endpoints_json",
            None
        )

    result["findings"] = findings

    return result


# =========================================================
# Background Scan Jobs
# =========================================================

def create_scan_job(target, mode="standard"):
    """Create a persistent background scan job and return its ID."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_jobs (
            target,
            mode,
            status,
            progress,
            stage,
            message
        )
        VALUES (?, ?, 'queued', 0, 'Queued', 'Scan queued.')
    """, (target, mode))

    job_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return job_id


def update_scan_job(
    job_id,
    status=None,
    progress=None,
    stage=None,
    message=None,
    scan_id=None,
    error=None,
    started=False,
    completed=False,
):
    """Update one or more persistent fields for a background scan job."""
    fields = []
    values = []

    if status is not None:
        fields.append("status = ?")
        values.append(status)

    if progress is not None:
        fields.append("progress = ?")
        values.append(max(0, min(100, int(progress))))

    if stage is not None:
        fields.append("stage = ?")
        values.append(stage)

    if message is not None:
        fields.append("message = ?")
        values.append(message)

    if scan_id is not None:
        fields.append("scan_id = ?")
        values.append(scan_id)

    if error is not None:
        fields.append("error = ?")
        values.append(error)

    if started:
        fields.append("started_at = CURRENT_TIMESTAMP")

    if completed:
        fields.append("completed_at = CURRENT_TIMESTAMP")

    if not fields:
        return

    values.append(job_id)

    conn = get_connection()
    conn.execute(
        f"UPDATE scan_jobs SET {', '.join(fields)} WHERE id = ?",
        values,
    )
    conn.commit()
    conn.close()


def get_scan_job(job_id):
    """Return a single background scan job."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM scan_jobs WHERE id = ?",
        (job_id,),
    ).fetchone()
    conn.close()

    return dict(row) if row else None


def get_active_scan_jobs():
    """Return queued/running jobs for dashboard recovery."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT *
        FROM scan_jobs
        WHERE status IN ('queued', 'running')
        ORDER BY id DESC
    """).fetchall()
    conn.close()

    return [dict(row) for row in rows]

