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
# Scan Modes API
# ============================================================

@app.route("/api/scan/modes", methods=["GET"])
def scan_modes():

    return jsonify({
        "success": True,
        "modes": SCAN_MODES,
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

    try:

        # ====================================================
        # Endpoint Discovery
        # ====================================================

        discovered = crawl_target(
            url,
            max_pages=20,
        )

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