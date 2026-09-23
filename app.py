from flask import Flask, render_template, request, jsonify, abort, send_file
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

# pyrefly: ignore [missing-import]
from jobs_module import submit_scan_job

from database import (
    init_db,
    save_scan,
    get_scan_history,
    get_scan,
    get_scan_job,
    get_active_scan_jobs,
)

from scanner.scanner import (
    scan_multiple_targets,
    normalize_mode,
    SCAN_MODES,
    normalize_scan_config,
    DEFAULT_SCAN_CONFIG,
    ALLOWED_SCAN_CONFIG,
)

from scanner.crawler import crawl_target

from scanner.risk import calculate_risk

from scanner.dedup import deduplicate_findings

app = Flask(__name__)



# ============================================================
# Web Pages
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/reports")
def reports_page():
    return render_template("reports.html")


@app.route("/compare")
def compare_page():
    return render_template("compare.html")


@app.route("/scan/<int:scan_id>")
def scan_details_page(scan_id):

    if not get_scan(scan_id):
        abort(404)

    return render_template(
        "scan_details.html",
        scan_id=scan_id,
    )


# ============================================================
# Scan History API
# ============================================================

@app.route("/api/history", methods=["GET"])
def history():

    scans = get_scan_history()

    return jsonify({
        "success": True,
        "scans": scans,
    })


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def history_detail(scan_id):

    scan = get_scan(scan_id)

    if not scan:

        return jsonify({
            "success": False,
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "scan": scan,
    })


# ============================================================
# Scan Comparison
# ============================================================

def _normalize_endpoint(value):
    """Normalize an endpoint so query-string values do not affect identity."""
    if not value:
        return "/"

    try:
        from urllib.parse import urlsplit
        parsed = urlsplit(str(value))
        return parsed.path.rstrip("/") or "/"
    except Exception:
        return str(value).split("?", 1)[0].split("#", 1)[0] or "/"


def _finding_identity(finding):
    """
    Stable identity for comparing findings between scans.

    Endpoint-specific findings include the normalized endpoint and
    parameter. Global findings are matched by type/name/parameter.
    """
    finding_type = str(finding.get("type") or "").strip().lower()
    name = str(finding.get("name") or "").strip().lower()
    parameter = str(finding.get("parameter") or "").strip().lower()
    endpoint = _normalize_endpoint(
        finding.get("url") or finding.get("endpoint")
    ).lower()

    endpoint_specific_types = {
        "sql injection",
        "reflected xss",
        "stored xss",
        "dom xss",
        "ssrf",
        "open redirect",
        "xxe",
        "csrf protection",
    }

    if finding_type in endpoint_specific_types:
        return (finding_type, name, endpoint, parameter)

    return (finding_type, name, parameter)


def _finding_display(finding):
    return {
        "type": finding.get("type"),
        "name": finding.get("name"),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "confidence": finding.get("confidence"),
        "endpoint": (
            finding.get("endpoint")
            or _normalize_endpoint(finding.get("url"))
        ),
        "parameter": finding.get("parameter"),
        "cwe": finding.get("cwe"),
        "owasp": finding.get("owasp"),
    }


def _compare_findings(baseline_findings, current_findings):
    baseline_map = {
        _finding_identity(f): f
        for f in baseline_findings
        if isinstance(f, dict)
    }

    current_map = {
        _finding_identity(f): f
        for f in current_findings
        if isinstance(f, dict)
    }

    fixed = []
    new = []
    severity_changed = []
    unchanged = []

    for key, old in baseline_map.items():
        if key not in current_map:
            fixed.append(_finding_display(old))
            continue

        current = current_map[key]
        old_severity = str(old.get("severity") or "Unknown")
        new_severity = str(current.get("severity") or "Unknown")

        if old_severity.lower() != new_severity.lower():
            item = _finding_display(current)
            item["old_severity"] = old_severity
            item["new_severity"] = new_severity
            severity_changed.append(item)
        else:
            unchanged.append(_finding_display(current))

    for key, current in current_map.items():
        if key not in baseline_map:
            new.append(_finding_display(current))

    return {
        "fixed": fixed,
        "new": new,
        "severity_changed": severity_changed,
        "unchanged": unchanged,
    }


def _endpoint_set(scan):
    endpoints = set()

    raw_endpoints = (
        scan.get("endpoints", [])
        if isinstance(scan, dict)
        else []
    )

    for item in raw_endpoints:
        if isinstance(item, str):
            value = item
        elif isinstance(item, dict):
            value = item.get("url")
        else:
            value = None

        if value:
            endpoints.add(_normalize_endpoint(value))

    return endpoints


def _risk_change(old, new):
    old_value = str(old or "Unknown")
    new_value = str(new or "Unknown")

    if old_value.lower() == new_value.lower():
        return f"Unchanged: {new_value}"

    return f"{old_value} → {new_value}"


@app.route("/api/compare", methods=["GET"])
def compare_scans():
    baseline_id = request.args.get("baseline", type=int)
    current_id = request.args.get("current", type=int)

    if not baseline_id or not current_id:
        return jsonify({
            "success": False,
            "error": "Both baseline and current scan IDs are required.",
        }), 400

    if baseline_id == current_id:
        return jsonify({
            "success": False,
            "error": "Baseline and current scan must be different.",
        }), 400

    baseline = get_scan(baseline_id)
    current = get_scan(current_id)

    if not baseline:
        return jsonify({
            "success": False,
            "error": f"Baseline scan #{baseline_id} was not found.",
        }), 404

    if not current:
        return jsonify({
            "success": False,
            "error": f"Current scan #{current_id} was not found.",
        }), 404

    finding_comparison = _compare_findings(
        baseline.get("findings", []),
        current.get("findings", []),
    )

    baseline_endpoints = _endpoint_set(baseline)
    current_endpoints = _endpoint_set(current)

    added_endpoints = sorted(current_endpoints - baseline_endpoints)
    removed_endpoints = sorted(baseline_endpoints - current_endpoints)

    old_score = int(baseline.get("security_score") or 0)
    current_score = int(current.get("security_score") or 0)

    summary = {
        "fixed": len(finding_comparison["fixed"]),
        "new": len(finding_comparison["new"]),
        "severity_changed": len(finding_comparison["severity_changed"]),
        "unchanged": len(finding_comparison["unchanged"]),
        "score_delta": current_score - old_score,
        "risk_change": _risk_change(
            baseline.get("risk_level"),
            current.get("risk_level"),
        ),
        "baseline_score": old_score,
        "current_score": current_score,
        "baseline_findings": len(baseline.get("findings", [])),
        "current_findings": len(current.get("findings", [])),
        "baseline_endpoints": len(baseline_endpoints),
        "current_endpoints": len(current_endpoints),
        "endpoint_delta": len(current_endpoints) - len(baseline_endpoints),
        "endpoints_added": len(added_endpoints),
        "endpoints_removed": len(removed_endpoints),
    }

    return jsonify({
        "success": True,
        "comparison": {
            "baseline": {
                "id": baseline.get("id"),
                "target": baseline.get("target"),
                "scan_time": baseline.get("scan_time"),
                "security_score": old_score,
                "risk_level": baseline.get("risk_level"),
            },
            "current": {
                "id": current.get("id"),
                "target": current.get("target"),
                "scan_time": current.get("scan_time"),
                "security_score": current_score,
                "risk_level": current.get("risk_level"),
            },
            "summary": summary,
            "fixed": finding_comparison["fixed"],
            "new": finding_comparison["new"],
            "severity_changed": finding_comparison["severity_changed"],
            "unchanged": finding_comparison["unchanged"],
            "endpoint_changes": {
                "added": added_endpoints,
                "removed": removed_endpoints,
            },
        },
    })


# ============================================================
# Scan Modes API
# ============================================================

@app.route("/api/scan/modes", methods=["GET"])
def scan_modes():

    return jsonify({
        "success": True,
        "modes": SCAN_MODES,
        "scan_config": {
            "defaults": DEFAULT_SCAN_CONFIG,
            "allowed": {
                key: list(values)
                for key, values in ALLOWED_SCAN_CONFIG.items()
            },
        },
    })


# ============================================================
# Main Scan API
# ============================================================

# ============================================================
# Background Scan Jobs
# ============================================================

def _execute_scan(url, mode, progress_callback=None):
    """
    Execute the existing WebGuard scan pipeline in a background worker.

    The scanner logic itself is unchanged. This function only moves the
    existing synchronous scan workflow into a background job.
    """

    def progress(value, stage, message):
        if progress_callback:
            progress_callback(value, stage, message)

    scan_config = normalize_scan_config(mode)

    # ========================================================
    # Endpoint Discovery
    # ========================================================

    progress(
        10,
        "Discovery",
        "Crawling target endpoints..."
    )

    discovered = crawl_target(
        url,
        max_pages=scan_config["max_pages"],
    )

    # ========================================================
    # Apply Maximum Crawl Depth
    # ========================================================

    if scan_config["max_depth"] >= 1:

        from urllib.parse import urlparse

        parsed_root = urlparse(url)

        root_parts = (
            parsed_root.path.strip("/").split("/")
            if parsed_root.path.strip("/")
            else []
        )

        root_len = len(root_parts)

        filtered = []

        for item in discovered:

            if not isinstance(item, dict):
                continue

            if not item.get("url"):
                continue

            parsed_item = urlparse(item["url"])

            path_parts = (
                parsed_item.path.strip("/").split("/")
                if parsed_item.path.strip("/")
                else []
            )

            relative_depth = max(
                0,
                len(path_parts) - root_len
            )

            if relative_depth <= scan_config["max_depth"]:
                filtered.append(item)

        discovered = filtered

    progress(
        30,
        "Discovery",
        f"Discovered {len(discovered)} endpoint(s)."
    )

    # ========================================================
    # Extract URLs
    # ========================================================

    urls = [
        item["url"]
        for item in discovered
        if (
            isinstance(item, dict)
            and item.get("url")
        )
    ]

    if not urls:
        urls = [url]

    urls = list(
        dict.fromkeys(urls)
    )

    # ========================================================
    # Vulnerability Scanning
    # ========================================================

    progress(
        40,
        "Scanning",
        f"Scanning {len(urls)} target endpoint(s)..."
    )

    scan_results = scan_multiple_targets(
        urls,
        mode=mode,
        scan_config=scan_config,
    )

    # ========================================================
    # Combine Findings
    # ========================================================

    progress(
        72,
        "Analysis",
        "Combining scanner findings..."
    )

    all_findings = []

    for result in scan_results:

        if not isinstance(result, dict):
            continue

        result_findings = (
            result.get("findings", [])
            or []
        )

        for original_finding in result_findings:

            if not isinstance(
                original_finding,
                dict
            ):
                continue

            finding = dict(
                original_finding
            )

            finding["url"] = (
                finding.get("url")
                or result.get("target")
                or url
            )

            if not finding.get("endpoint"):

                from urllib.parse import urlparse

                parsed = urlparse(
                    finding["url"]
                )

                finding["endpoint"] = (
                    parsed.path or "/"
                )

            all_findings.append(
                finding
            )

    # ========================================================
    # Deduplicate Findings
    # ========================================================

    progress(
        80,
        "Analysis",
        "Deduplicating findings..."
    )

    unique_findings = (
        deduplicate_findings(
            all_findings
        )
    )

    # ========================================================
    # Risk Calculation
    # ========================================================

    progress(
        87,
        "Risk Analysis",
        "Calculating security risk..."
    )

    risk = calculate_risk(
        unique_findings
    )

    # ========================================================
    # Save Scan
    # ========================================================

    progress(
        94,
        "Saving",
        "Saving scan results to database..."
    )

    scan_id = save_scan(

        target=url,

        endpoints_count=len(
            discovered
        ),

        vulnerability_count=len(
            unique_findings
        ),

        high_risk_count=(
            risk.get("critical", 0)
            +
            risk.get("high", 0)
        ),

        security_score=risk.get(
            "security_score",
            0
        ),

        risk_level=risk.get(
            "risk_level",
            "Unknown"
        ),

        findings=unique_findings,

        endpoints=discovered,
    )

    progress(
        100,
        "Completed",
        "Scan completed successfully."
    )

    return scan_id


@app.route("/api/scan", methods=["POST"])
def scan():

    """
    Create a background scan job.

    The request returns immediately with a job ID.
    The actual scan is executed by jobs_module.py.
    """

    data = request.get_json(
        silent=True
    )

    # --------------------------------------------------------
    # Validate request
    # --------------------------------------------------------

    if not data or "url" not in data:

        return jsonify({
            "success": False,
            "error": "Target URL is required",
        }), 400

    url = str(
        data["url"]
    ).strip()

    if not url:

        return jsonify({
            "success": False,
            "error": "Target URL is required",
        }), 400

    if not (
        url.startswith("http://")
        or
        url.startswith("https://")
    ):

        return jsonify({
            "success": False,
            "error": (
                "URL must start with "
                "http:// or https://"
            ),
        }), 400

    # --------------------------------------------------------
    # Scan mode
    # --------------------------------------------------------

    mode = normalize_mode(
        data.get(
            "mode",
            "standard"
        )
    )

    # --------------------------------------------------------
    # Create background job
    # --------------------------------------------------------

    try:

        job_id = submit_scan_job(
            url,
            mode,
            _execute_scan,
        )

        return jsonify({

            "success": True,

            "job_id": job_id,

            "target": url,

            "mode": mode,

            "status": "queued",

        }), 202

    except Exception as exc:

        app.logger.exception(
            "Unable to create scan job"
        )

        return jsonify({

            "success": False,

            "error": (
                f"Unable to create scan job: {exc}"
            ),

        }), 500


# ============================================================
# Background Job Status
# ============================================================

@app.route(
    "/api/scan/jobs/<int:job_id>",
    methods=["GET"]
)
def scan_job_status(job_id):

    """
    Return the current state of a background scan.
    """

    job = get_scan_job(
        job_id
    )

    if not job:

        return jsonify({

            "success": False,

            "error": "Scan job not found",

        }), 404

    response = {

        "success": True,

        "job": job,

    }

    # --------------------------------------------------------
    # Attach completed scan results
    # --------------------------------------------------------

    if (
        job.get("status") == "completed"
        and
        job.get("scan_id")
    ):

        scan = get_scan(
            job["scan_id"]
        )

        if scan:

            response["scan"] = scan

            response["risk"] = (
                calculate_risk(
                    scan.get(
                        "findings",
                        []
                    )
                )
            )

    return jsonify(
        response
    )


@app.route(
    "/api/scan/jobs",
    methods=["GET"]
)
def active_scan_jobs():

    """
    Return queued/running jobs.

    Used by the frontend to recover a scan
    after a page refresh.
    """

    return jsonify({

        "success": True,

        "jobs": get_active_scan_jobs(),

    })
# ============================================================
# Exportable Security Reports
# ============================================================

def _pdf_text(value, default="Not specified"):
    """Safely convert scanner data into ReportLab-friendly text."""
    if value is None or value == "":
        value = default
    if isinstance(value, (list, tuple, set)):
        value = " • ".join(str(item) for item in value)
    return xml_escape(str(value)).replace("\n", "<br/>")


def _pdf_severity_color(severity):
    value = str(severity or "Low").lower()
    return {
        "critical": colors.HexColor("#7f1d1d"),
        "high": colors.HexColor("#b91c1c"),
        "medium": colors.HexColor("#b45309"),
        "low": colors.HexColor("#4d7c0f"),
    }.get(value, colors.HexColor("#526776"))


def _pdf_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(15 * mm, 9 * mm, "WebGuard Security Scanner")
    canvas.drawRightString(A4[0] - 15 * mm, 9 * mm,
                           f"Confidential • Page {doc.page}")
    canvas.restoreState()


def _build_security_report_pdf(scan):
    """Build a professional A4 PDF from a stored WebGuard scan."""
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"WebGuard Security Assessment - Scan #{scan.get('id', 'Unknown')}",
        author="WebGuard Security Scanner",
        subject="Security assessment report",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="WGTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=22, leading=27, textColor=colors.HexColor("#172b3a"),
        spaceAfter=8))
    styles.add(ParagraphStyle(
        name="WGSubtitle", parent=styles["Normal"], fontSize=9.5, leading=14,
        textColor=colors.HexColor("#617586"), spaceAfter=4))
    styles.add(ParagraphStyle(
        name="WGSection", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=16, textColor=colors.HexColor("#172b3a"),
        spaceBefore=6, spaceAfter=8))
    styles.add(ParagraphStyle(
        name="WGBody", parent=styles["BodyText"], fontSize=8.5, leading=12,
        textColor=colors.HexColor("#344754")))
    styles.add(ParagraphStyle(
        name="WGSmall", parent=styles["BodyText"], fontSize=7.5, leading=10,
        textColor=colors.HexColor("#526776")))
    styles.add(ParagraphStyle(
        name="WGFindingTitle", parent=styles["Heading3"],
        fontName="Helvetica-Bold", fontSize=10.5, leading=13,
        textColor=colors.HexColor("#172b3a"), spaceAfter=3))
    styles.add(ParagraphStyle(
        name="WGBadge", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=7.5, textColor=colors.white, alignment=TA_CENTER))

    findings = scan.get("findings", []) or []
    endpoints = scan.get("endpoints", []) or []

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    confirmed = potential = misconfig = informational = 0

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "Low").title()
        if severity in counts:
            counts[severity] += 1
        category = str(finding.get("category") or "").lower()
        if category == "vulnerability":
            confirmed += 1
        elif category == "potential vulnerability":
            potential += 1
        elif category == "security misconfiguration":
            misconfig += 1
        elif category == "informational":
            informational += 1

    story = []

    # Cover
    story += [
        Paragraph("WEBGUARD", styles["WGSubtitle"]),
        Spacer(1, 10 * mm),
        Paragraph("Security Assessment Report", styles["WGTitle"]),
        Paragraph(_pdf_text(scan.get("target"), "Unknown target"),
                  ParagraphStyle("Target", parent=styles["Heading1"],
                                 fontName="Helvetica-Bold", fontSize=15,
                                 leading=19, textColor=colors.HexColor("#243847"),
                                 spaceAfter=8)),
        Paragraph(
            f"Scan #{_pdf_text(scan.get('id'), '—')} • "
            f"Scan time: {_pdf_text(scan.get('scan_time'), 'Unknown')}",
            styles["WGSubtitle"]),
        Paragraph(
            "Report generated: "
            f"{__import__('datetime').datetime.now().astimezone().strftime('%d %b %Y, %I:%M %p %Z')}",
            styles["WGSubtitle"]),
        Spacer(1, 12 * mm),
    ]

    risk = str(scan.get("risk_level") or "Unknown")
    score = scan.get("security_score")
    cover_table = Table([
        ["Overall Risk", "Security Score", "Endpoints", "Total Findings"],
        [risk, f"{score}/100" if score is not None else "—",
         str(scan.get("endpoints_count", len(endpoints))),
         str(scan.get("vulnerability_count", len(findings)))],
    ], colWidths=[42 * mm] * 4)
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f4")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#617586")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 12),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#172b3a")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafb")),
        ("GRID", (0, 0), (-1, -1), .5, colors.HexColor("#cbd5da")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story += [
        cover_table, Spacer(1, 12 * mm),
        Paragraph(
            "This report contains the security findings, affected endpoints, "
            "technical evidence, classification, and remediation guidance "
            "recorded by the WebGuard scan.", styles["WGBody"]),
        PageBreak(),
    ]

    # Executive summary
    story.append(Paragraph("1. Executive Summary", styles["WGSection"]))
    summary_rows = [
        ["Metric", "Result"],
        ["Target", _pdf_text(scan.get("target"), "Unknown")],
        ["Scan ID", _pdf_text(scan.get("id"), "—")],
        ["Risk Level", _pdf_text(risk)],
        ["Security Score", f"{score}/100" if score is not None else "—"],
        ["Endpoints Discovered", str(scan.get("endpoints_count", len(endpoints)))],
        ["Total Findings", str(len(findings))],
        ["High/Critical Findings", str(counts["High"] + counts["Critical"])],
    ]
    summary_table = Table(summary_rows, colWidths=[55 * mm, 125 * mm], repeatRows=1)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172b3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#344754")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f8fafb"), colors.white]),
        ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#ccd4da")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [summary_table, Spacer(1, 8 * mm)]

    story.append(Paragraph("Finding Classification", styles["WGSection"]))
    class_table = Table([
        ["Confirmed Vulnerabilities", "Potential Vulnerabilities",
         "Security Misconfigurations", "Informational"],
        [str(confirmed), str(potential), str(misconfig), str(informational)],
    ], colWidths=[45 * mm] * 4)
    class_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f4")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#172b3a")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#ccd4da")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [class_table, Spacer(1, 8 * mm)]

    story.append(Paragraph("Severity Distribution", styles["WGSection"]))
    severity_rows = [["Severity", "Count", "Relative Bar"]]
    max_count = max(counts.values()) if counts else 1
    for severity in ["Critical", "High", "Medium", "Low"]:
        width = max(5, int((counts[severity] / max_count) * 90)) if max_count else 5
        bar = Table([[""]], colWidths=[width * mm], rowHeights=[3 * mm])
        bar.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _pdf_severity_color(severity))
        ]))
        severity_rows.append([severity, str(counts[severity]), bar])
    severity_table = Table(severity_rows,
                           colWidths=[35 * mm, 20 * mm, 105 * mm],
                           repeatRows=1)
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172b3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#d2d9de")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [severity_table, PageBreak()]

    # Endpoints
    story.append(Paragraph("2. Discovered Endpoints", styles["WGSection"]))
    if endpoints:
        rows = [["#", "Endpoint", "Status"]]
        for i, item in enumerate(endpoints, 1):
            if isinstance(item, str):
                endpoint, status = item, "OK"
            elif isinstance(item, dict):
                endpoint = item.get("url") or item.get("endpoint") or "Unknown endpoint"
                status = item.get("status_code") or "OK"
            else:
                endpoint, status = str(item), "OK"
            rows.append([str(i), Paragraph(_pdf_text(endpoint), styles["WGSmall"]),
                         str(status)])
        table = Table(rows, colWidths=[12 * mm, 145 * mm, 23 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172b3a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#344754")),
            ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#d2d9de")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No endpoint data stored.", styles["WGBody"]))

    story.append(PageBreak())
    story.append(Paragraph(f"3. Security Findings ({len(findings)})", styles["WGSection"]))

    if not findings:
        story.append(Paragraph("No security findings were recorded for this scan.",
                               styles["WGBody"]))
    else:
        for i, finding in enumerate(findings, 1):
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "Low")
            category = finding.get("category") or "Not classified"
            confidence = finding.get("confidence") or "Medium"
            verification = (
                finding.get("verification_status")
                or ("Reproduced" if finding.get("verification") == "reproduced"
                    else "Actively Tested" if finding.get("test_mode") == "active"
                    else "Observed")
            )
            affected = finding.get("affected_endpoints") or []
            affected_text = (" • ".join(str(x) for x in affected)
                             if isinstance(affected, (list, tuple)) else str(affected))

            badge = Table([[Paragraph(_pdf_text(severity), styles["WGBadge"])]],
                          colWidths=[22 * mm], rowHeights=[7 * mm])
            badge.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), _pdf_severity_color(severity)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            header = Table([[
                Paragraph(f"{i}. {_pdf_text(finding.get('name') or finding.get('type'), 'Security Finding')}",
                          styles["WGFindingTitle"]),
                badge
            ]], colWidths=[158 * mm, 22 * mm])
            header.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]))

            parts = [
                header,
                Paragraph(
                    f"<b>Type:</b> {_pdf_text(finding.get('type'), 'Security issue')}"
                    f" &nbsp;&nbsp; <b>Category:</b> {_pdf_text(category)}",
                    styles["WGSmall"]),
                Spacer(1, 2 * mm),
                Paragraph(_pdf_text(finding.get("description"),
                                    "No description available."), styles["WGBody"]),
                Spacer(1, 2 * mm),
            ]

            intel = Table([
                ["CWE", "OWASP", "Confidence", "Verification"],
                [_pdf_text(finding.get("cwe"), "Not mapped"),
                 _pdf_text(finding.get("owasp"), "Not mapped"),
                 _pdf_text(confidence), _pdf_text(verification)],
            ], colWidths=[45 * mm] * 4)
            intel.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f4")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafb")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#d2d9de")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            parts += [intel, Spacer(1, 2 * mm)]

            details = Table([
                ["Affected Endpoint", _pdf_text(finding.get("url") or finding.get("endpoint"))],
                ["Parameter", _pdf_text(finding.get("parameter"), "None")],
                ["Method", _pdf_text(finding.get("method"), "Not specified")],
                ["Test Mode", _pdf_text(finding.get("test_mode"), "Not specified")],
                ["Affected Endpoints", _pdf_text(affected_text, "Not specified")],
            ], colWidths=[42 * mm, 138 * mm])
            details.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#253b48")),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#465b68")),
                ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#dce1e5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            parts += [details, Spacer(1, 2 * mm)]

            blocks = [
                ("Evidence", finding.get("evidence"), "No additional evidence recorded."),
                ("Detection", finding.get("detection"), "Automated analysis."),
                ("Impact", finding.get("impact"), None),
                ("Recommendation", finding.get("recommendation"),
                 "Review and remediate the finding."),
            ]
            for label, value, default in blocks:
                if label == "Impact" and not value:
                    continue
                content = _pdf_text(value, default or "Not specified")
                block = Table([[Paragraph(f"<b>{label}</b><br/>{content}",
                                          styles["WGSmall"])]],
                              colWidths=[180 * mm])
                block.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1),
                     colors.HexColor("#f4f7f8") if label == "Recommendation"
                     else colors.HexColor("#f8fafb")),
                    ("BOX", (0, 0), (-1, -1), .4, colors.HexColor("#cbd5da")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]))
                parts += [block, Spacer(1, 2 * mm)]

            story += [KeepTogether(parts), Spacer(1, 4 * mm)]

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("End of report • WebGuard Security Scanner", styles["WGSmall"]))

    doc.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
    buffer.seek(0)
    return buffer


@app.route("/api/reports/<int:scan_id>/pdf", methods=["GET"])
def export_report_pdf(scan_id):
    """Generate and download a PDF security assessment for a completed scan."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    try:
        pdf_buffer = _build_security_report_pdf(scan)
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"WebGuard_Security_Report_Scan_{scan_id}.pdf",
        )
    except Exception as exc:
        app.logger.exception("Unable to generate PDF report for scan %s", scan_id)
        return jsonify({
            "success": False,
            "error": f"Unable to generate PDF report: {exc}",
        }), 500


# ============================================================
# Application Startup
# ============================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        port=5000,
    )