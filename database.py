import json
import sqlite3

DB_NAME = "webguard.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(cursor, table, column, definition):
    columns = {
        row["name"]
        for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()
    }

    if column not in columns:
        cursor.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            type TEXT,
            name TEXT,
            severity TEXT,
            description TEXT,
            recommendation TEXT,
            parameter TEXT,
            url TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # Migration for an existing webguard.db created by an older version.
    _ensure_column(cursor, "scans", "endpoints_json", "TEXT DEFAULT '[]'")

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
    conn = get_connection()
    cursor = conn.cursor()

    endpoints = endpoints if isinstance(endpoints, list) else []

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
        json.dumps(endpoints)
    ))

    scan_id = cursor.lastrowid

    for finding in findings or []:
        affected = finding.get("url")

        # deduplicate_findings stores all affected endpoints here.
        if not affected:
            affected_endpoints = finding.get("affected_endpoints", [])
            if affected_endpoints:
                affected = affected_endpoints[0]

        cursor.execute("""
            INSERT INTO findings (
                scan_id,
                type,
                name,
                severity,
                description,
                recommendation,
                parameter,
                url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            finding.get("type"),
            finding.get("name"),
            finding.get("severity"),
            finding.get("description"),
            finding.get("recommendation"),
            finding.get("parameter"),
            affected
        ))

    conn.commit()
    conn.close()

    return scan_id


def get_scan_history():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY scan_time DESC, id DESC
    """)

    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()

    for scan in scans:
        try:
            scan["endpoints"] = json.loads(
                scan.get("endpoints_json") or "[]"
            )
        except (TypeError, json.JSONDecodeError):
            scan["endpoints"] = []

        scan.pop("endpoints_json", None)

    return scans


def get_scan(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        WHERE id = ?
    """, (scan_id,))

    scan = cursor.fetchone()

    if not scan:
        conn.close()
        return None

    cursor.execute("""
        SELECT *
        FROM findings
        WHERE scan_id = ?
        ORDER BY id ASC
    """, (scan_id,))

    findings = [dict(row) for row in cursor.fetchall()]
    conn.close()

    result = dict(scan)

    try:
        result["endpoints"] = json.loads(
            result.get("endpoints_json") or "[]"
        )
    except (TypeError, json.JSONDecodeError):
        result["endpoints"] = []

    result.pop("endpoints_json", None)
    result["findings"] = findings

    return result
