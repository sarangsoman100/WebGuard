import time
from urllib.parse import urlparse

import requests

from scanner.sqli import check_sql_injection
from scanner.headers import check_security_headers
from scanner.cookies import check_cookies
from scanner.methods import check_http_methods
from scanner.disclosure import check_information_disclosure
from scanner.parameters import discover_parameters
from scanner.xss import check_reflected_xss
from scanner.cors import check_cors
from scanner.sensitive import check_sensitive_exposure
from scanner.redirect import check_open_redirect
from scanner.transport import check_transport_security
from scanner.endpoint_exposure import check_endpoint_exposure
from scanner.csrf import check_csrf
from scanner.auth import check_authentication_security
from scanner.ssrf import check_ssrf

# ============================================================
# Scan Modesm
# ============================================================

SCAN_MODES = {
    "passive": {
        "label": "Passive",
        "description": (
            "Low-impact observation without active parameter probes."
        ),
    },
    "standard": {
        "label": "Standard",
        "description": (
            "Recommended balanced assessment with safe active checks."
        ),
    },
    "active": {
        "label": "Active",
        "description": (
            "Deeper authorized assessment with additional comparisons."
        ),
    },
}


def normalize_mode(mode):
    mode = str(mode or "standard").strip().lower()

    if mode in SCAN_MODES:
        return mode

    return "standard"


# ============================================================
# Finding Helper
# ============================================================

def _finding(
    *,
    type_,
    category,
    name,
    severity,
    confidence,
    description,
    recommendation,
    evidence=None,
    detection=None,
    parameter=None,
):
    return {
        "type": type_,
        "category": category,
        "name": name,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence,
        "detection": detection,
        "parameter": parameter,
    }


# ============================================================
# Single Target Scan
# ============================================================

def scan_target(url, mode="standard"):

    mode = normalize_mode(mode)

    result = {
        "target": url,
        "mode": mode,
        "status": "Unknown",
        "status_code": None,
        "response_time": None,
        "server": None,
        "https": False,
        "findings": [],
        "error": None,
    }

    try:

        # ----------------------------------------------------
        # Validate URL
        # ----------------------------------------------------

        parsed = urlparse(url)

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.netloc
        ):
            result["error"] = "Invalid URL"
            return result

        result["https"] = (
            parsed.scheme == "https"
        )

        # ----------------------------------------------------
        # Request target
        # ----------------------------------------------------

        start_time = time.perf_counter()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
        )

        elapsed = (
            time.perf_counter()
            - start_time
        )

        # ----------------------------------------------------
        # Basic response information
        # ----------------------------------------------------

        result["status_code"] = (
            response.status_code
        )

        result["status"] = (
            response.reason or "OK"
        )

        result["response_time"] = round(
            elapsed * 1000,
            2,
        )

        result["server"] = (
            response.headers.get("Server")
        )

        # ====================================================
        # Passive Security Analysis
        # ====================================================

        # Security headers
        result["findings"].extend(
            check_security_headers(
                response.headers
            ) or []
        )

        # Cookie security
        result["findings"].extend(
            check_cookies(
                response
            ) or []
        )

        # HTTP methods
        result["findings"].extend(
            check_http_methods(
                response
            ) or []
        )

        # Information disclosure
        result["findings"].extend(
            check_information_disclosure(
                response
            ) or []
        )

        # CORS
        #
        # check_cors() expects the response object.
        # Only call it once.
        result["findings"].extend(
            check_cors(
                response
            ) or []
        )
        # -------------------------------
        # Transport Security
        # -------------------------------

        if mode in ("standard", "active"):

            result["findings"].extend(
                check_transport_security(url) or []
            )
        
        # -------------------------------
        # Authentication Security
        # -------------------------------

        if mode in ("standard", "active"):

            result["findings"].extend(
                check_authentication_security(url) or []
            )

        # -------------------------------
        # CSRF Protection
        # -------------------------------

        if mode in ("standard", "active"):
            result["findings"].extend(
                check_csrf(url) or []
            )

        # -------------------------------
        # Robots.txt Endpoint Exposure
        # -------------------------------

        if mode in ("standard", "active"):

            result["findings"].extend(
                check_endpoint_exposure(url) or []
            )
        # ====================================================
        # Sensitive File Checks
        # ====================================================

        if mode in (
            "standard",
            "active",
        ):

            result["findings"].extend(
                check_sensitive_exposure(
                    url
                ) or []
            )

        return result

    except requests.exceptions.Timeout:

        result["error"] = (
            "Request timed out"
        )

    except requests.exceptions.ConnectionError:

        result["error"] = (
            "Could not connect to target"
        )

    except requests.exceptions.RequestException as error:

        result["error"] = str(error)

    return result


# ============================================================
# Multiple Target Scan
# ============================================================

def scan_multiple_targets(
    urls,
    mode="standard",
):

    mode = normalize_mode(mode)

    all_results = []

    if not urls:
        return all_results

    # ========================================================
    # Discover parameters from ALL supplied pages
    # ========================================================

    parameters = []

    if mode in (
        "standard",
        "active",
    ):

        for page_url in urls:

            try:

                page_parameters = (
                    discover_parameters(
                        page_url
                    )
                    or []
                )

            except Exception:

                page_parameters = []

            for parameter_info in page_parameters:

                if (
                    parameter_info
                    not in parameters
                ):

                    parameters.append(
                        parameter_info
                    )

    # ========================================================
    # Scan each URL
    # ========================================================

    for url in urls:

        result = scan_target(
            url,
            mode=mode,
        )

        # ----------------------------------------------------
        # If target could not be scanned
        # ----------------------------------------------------

        if result.get("error"):
            all_results.append(result)
            continue

        result["parameters"] = []

        # ====================================================
        # Parameter-based testing
        # ====================================================

        if mode in (
            "standard",
            "active",
        ):

            for parameter_info in parameters:

                if not isinstance(
                    parameter_info,
                    dict,
                ):
                    continue

                parameter_url = (
                    parameter_info.get("url")
                )

                if not parameter_url:
                    continue

                # --------------------------------------------
                # Normalize parameter endpoint
                # --------------------------------------------

                parameter_base_url = urlparse(
                    parameter_url
                )._replace(
                    query="",
                    fragment="",
                ).geturl().rstrip("/")

                # --------------------------------------------
                # Normalize target endpoint
                # --------------------------------------------

                target_base_url = urlparse(
                    url
                )._replace(
                    query="",
                    fragment="",
                ).geturl().rstrip("/")

                # --------------------------------------------
                # Make sure parameter belongs to endpoint
                # --------------------------------------------

                if (
                    parameter_base_url
                    != target_base_url
                ):
                    continue

                result["parameters"].append(
                    parameter_info
                )

                # --------------------------------------------
                # Only test GET parameters
                # --------------------------------------------

                if (
                    str(
                        parameter_info.get(
                            "method",
                            ""
                        )
                    ).upper()
                    != "GET"
                ):
                    continue

                parameter = (
                    parameter_info.get(
                        "parameter"
                    )
                )

                if not parameter:
                    continue

                # ============================================
                # Reflected XSS Detection
                # ============================================

                try:

                    xss_finding = (
                        check_reflected_xss(
                            parameter_url,
                            parameter,
                        )
                    )

                except Exception:

                    xss_finding = None

                if xss_finding:

                    xss_finding["url"] = (
                        parameter_url
                    )

                    result.setdefault(
                        "findings",
                        [],
                    ).append(
                        xss_finding
                    )

                # ============================================
                # SQL Injection Detection
                # ============================================

                try:

                    sqli_finding = (
                        check_sql_injection(
                            parameter_url,
                            parameter,
                        )
                    )

                except Exception:

                    sqli_finding = None

                if sqli_finding:

                    sqli_finding["url"] = (
                        parameter_url
                    )

                    result.setdefault(
                        "findings",
                        [],
                    ).append(
                        sqli_finding
                    )

                # ============================================
                # Open Redirect Detection
                # ============================================

                try:

                    redirect_finding = (
                        check_open_redirect(
                            parameter_url,
                            parameter,
                        )
                    )

                except Exception:

                    redirect_finding = None

                if redirect_finding:

                    redirect_finding["url"] = (
                        parameter_url
                    )

                    result.setdefault(
                        "findings",
                        [],
                    ).append(
                        redirect_finding
                    )
                # ============================================
                # SSRF Detection
                # ============================================

                try:

                    ssrf_finding = check_ssrf(
                        parameter_url,
                        parameter,
                    )

                except Exception:

                    ssrf_finding = None

                if ssrf_finding:

                    ssrf_finding["url"] = parameter_url

                    result.setdefault(
                        "findings",
                        [],
                    ).append(
                        ssrf_finding
                    )
        # ====================================================
        # Store completed result
        # ====================================================

        all_results.append(
            result
        )

    return all_results
