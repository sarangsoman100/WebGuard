from flask import Flask, render_template, request, jsonify, abort

from database import (
    init_db,
    save_scan,
    get_scan_history,
    get_scan,
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

@app.route("/api/scan", methods=["POST"])
def scan():

    data = request.get_json(silent=True)

    # --------------------------------------------------------
    # Validate request body
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

    # --------------------------------------------------------
    # Normalize scan mode
    # --------------------------------------------------------

    mode = normalize_mode(
        data.get(
            "mode",
            "standard",
        )
    )

    scan_config = normalize_scan_config(
        data.get("config")
    )

    try:

        # ====================================================
        # Endpoint Discovery
        # ====================================================

        discovered = crawl_target(
            url,
            max_pages=scan_config["max_pages"],
        )

        # The bundled crawler API currently exposes max_pages only. Apply the
        # requested depth as a conservative post-discovery bound based on URL
        # path depth, without changing the crawler module supplied by the user.
        if scan_config["max_depth"] >= 1:
            from urllib.parse import urlparse
            root_path = urlparse(url).path.strip("/").split("/") if urlparse(url).path.strip("/") else []
            root_len = len(root_path)
            filtered = []
            for item in discovered:
                if not isinstance(item, dict) or not item.get("url"):
                    continue
                path_parts = urlparse(item["url"]).path.strip("/").split("/") if urlparse(item["url"]).path.strip("/") else []
                relative_depth = max(0, len(path_parts) - root_len)
                if relative_depth <= scan_config["max_depth"]:
                    filtered.append(item)
            discovered = filtered

        # ----------------------------------------------------
        # Extract URLs
        # ----------------------------------------------------

        urls = [
            item["url"]
            for item in discovered
            if (
                isinstance(item, dict)
                and item.get("url")
            )
        ]

        # ----------------------------------------------------
        # Always scan the original target
        # ----------------------------------------------------

        if not urls:
            urls = [url]

        # ----------------------------------------------------
        # Remove duplicate URLs while preserving order
        # ----------------------------------------------------

        urls = list(
            dict.fromkeys(urls)
        )

        # ====================================================
        # Scan Discovered Targets
        # ====================================================

        scan_results = scan_multiple_targets(
            urls,
            mode=mode,
            scan_config=scan_config,
        )

        # ====================================================
        # Combine Findings
        # ====================================================

        all_findings = []

        for result in scan_results:

            if not isinstance(
                result,
                dict,
            ):
                continue

            result_findings = (
                result.get(
                    "findings",
                    [],
                )
                or []
            )

            for original_finding in result_findings:

                if not isinstance(
                    original_finding,
                    dict,
                ):
                    continue

                finding = dict(
                    original_finding
                )

                # ------------------------------------------------
                # Make sure every finding has a URL
                # ------------------------------------------------

                finding["url"] = (
                    finding.get("url")
                    or result.get("target")
                    or url
                )

                # ------------------------------------------------
                # Make sure endpoint is available
                # ------------------------------------------------

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

        # ====================================================
        # Deduplicate Findings
        # ====================================================

        unique_findings = (
            deduplicate_findings(
                all_findings
            )
        )

        # ====================================================
        # Overall Risk Calculation
        # ====================================================

        risk = calculate_risk(
            unique_findings
        )

        # ====================================================
        # Save Scan
        # ====================================================

        scan_id = save_scan(

            target=url,

            endpoints_count=len(
                discovered
            ),

            vulnerability_count=len(
                unique_findings
            ),

            high_risk_count=(
                risk.get(
                    "critical",
                    0,
                )
                +
                risk.get(
                    "high",
                    0,
                )
            ),

            security_score=risk.get(
                "security_score",
                0,
            ),

            risk_level=risk.get(
                "risk_level",
                "Unknown",
            ),

            findings=unique_findings,

            endpoints=discovered,
        )

        # ====================================================
        # API Response
        # ====================================================

        return jsonify({

            "success": True,

            "scan_id": scan_id,

            "target": url,

            "mode": mode,

            "discovered_endpoints": discovered,

            "results": scan_results,

            "findings": unique_findings,

            "risk": risk,
        })

    except Exception as exc:

        app.logger.exception(
            "Scan failed"
        )

        return jsonify({
            "success": False,
            "error": f"Scan failed: {exc}",
        }), 500


# ============================================================
# Application Entry Point
# ============================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        port=5000,
    )