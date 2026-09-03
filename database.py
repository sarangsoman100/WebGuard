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
        json.dumps(endpoints)
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
                affected_endpoints_json
            )
            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
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
            )
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