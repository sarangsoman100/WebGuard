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
from scanner.xxe  import check_xxe
from scanner.risk import (
    calculate_risk,
    calculate_overall_risk,
)

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
# Scan Configuration
# ============================================================

SCAN_CONFIG = {
    "passive": {
        "parameter_testing": False,
        "deep_testing": False,
    },
    "standard": {
        "parameter_testing": True,
        "deep_testing": False,
    },
    "active": {
        "parameter_testing": True,
        "deep_testing": True,
    },
}


def get_scan_config(mode):
    """Return the normalized configuration for the selected scan mode."""
    mode = normalize_mode(mode)
    return SCAN_CONFIG[mode]


# ============================================================
# Scan Configuration
# ============================================================

ALLOWED_SCAN_CONFIG = {
    "max_pages": (10, 20, 50),
    "timeout": (5, 10, 15),
    "max_depth": (1, 2, 3),
}

DEFAULT_SCAN_CONFIG = {
    "max_pages": 20,
    "timeout": 10,
    "max_depth": 3,
}

def normalize_scan_config(scan_config=None):
    """Normalize user scan settings to bounded, safe presets."""
    incoming = scan_config if isinstance(scan_config, dict) else {}
    normalized = dict(DEFAULT_SCAN_CONFIG)

    for key, allowed in ALLOWED_SCAN_CONFIG.items():
        try:
            value = int(incoming.get(key, DEFAULT_SCAN_CONFIG[key]))
        except (TypeError, ValueError):
            value = DEFAULT_SCAN_CONFIG[key]
        if value not in allowed:
            value = DEFAULT_SCAN_CONFIG[key]
        normalized[key] = value

    return normalized


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

def scan_target(url, mode="standard", timeout=10):

    mode = normalize_mode(mode)
    config = get_scan_config(mode)
    try:
        timeout = max(1, int(timeout))
    except (TypeError, ValueError):
        timeout = DEFAULT_SCAN_CONFIG["timeout"]

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
            timeout=timeout,
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

        if config["parameter_testing"]:

            result["findings"].extend(
                check_transport_security(url) or []
            )
        
        # ====================================================
        # XXE Detection
        # ====================================================

        xxe_finding = None
        if config["parameter_testing"]:

            try:

                xxe_finding = check_xxe(url)

            except Exception:   

                xxe_finding = None
        

        if xxe_finding:

            result.setdefault(
            "findings",
            [],
        ).append(
            xxe_finding
        )
        # -------------------------------
        # Authentication Security
        # -------------------------------

        if config["parameter_testing"]:

            result["findings"].extend(
                check_authentication_security(url) or []
            )

        # -------------------------------
        # CSRF Protection
        # -------------------------------

        if config["parameter_testing"]:
            result["findings"].extend(
                check_csrf(url) or []
            )

        # -------------------------------
        # Robots.txt Endpoint Exposure
        # -------------------------------

        if config["parameter_testing"]:

            result["findings"].extend(
                check_endpoint_exposure(url) or []
            )
        # ====================================================
        # Sensitive File Checks
        # ====================================================

        if config["parameter_testing"]:

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

def _deduplicate_findings(findings):
    """Deduplicate findings while keeping the strongest evidence."""
    unique = {}

    confidence_order = {"low": 1, "medium": 2, "high": 3}

    def key(f):
        return (
            str(f.get("type", "")).strip().lower(),
            str(f.get("category", "")).strip().lower(),
            str(f.get("parameter", "")).strip().lower(),
            str(f.get("url", "")).strip().lower(),
        )

    def strength(f):
        confidence = confidence_order.get(
            str(f.get("confidence", "")).strip().lower(), 0
        )
        verified = 1 if f.get("verification") == "reproduced" else 0
        active = 1 if f.get("test_mode") == "active" else 0
        evidence = 1 if f.get("evidence") else 0
        return (verified, confidence, active, evidence)

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        k = key(finding)
        if k not in unique:
            unique[k] = finding
            continue

        current = unique[k]
        if strength(finding) > strength(current):
            merged = dict(current)
            merged.update(finding)
            unique[k] = merged
        else:
            for field in ("evidence", "detection", "recommendation", "description"):
                if not current.get(field) and finding.get(field):
                    current[field] = finding[field]

    return list(unique.values())



# ============================================================
# Finding Intelligence Metadata
# ============================================================

FINDING_METADATA = {
    "SQL Injection": ("CWE-89", "A03:2021 – Injection",
                      "An attacker may influence database queries, potentially exposing, modifying, or deleting application data."),
    "Reflected XSS": ("CWE-79", "A03:2021 – Injection",
                      "Untrusted input reflected into a browser context may enable script execution or manipulation of a victim's session."),
    "Stored XSS": ("CWE-79", "A03:2021 – Injection",
                   "Persisted untrusted content may execute in browsers of users who view the affected page."),
    "DOM XSS": ("CWE-79", "A03:2021 – Injection",
                "Client-side processing of untrusted data may enable script execution in a victim's browser."),
    "SSRF": ("CWE-918", "A10:2021 – Server-Side Request Forgery",
             "A server-side URL fetch feature may be abused to reach resources that should not be accessible from the application."),
    "Open Redirect": ("CWE-601", "A01:2021 – Broken Access Control",
                      "Users may be redirected to attacker-controlled destinations, supporting phishing and trust abuse."),
    "XXE": ("CWE-611", "A05:2021 – Security Misconfiguration",
            "Unsafe XML entity processing can become dangerous when external entity resolution or unsafe DTDs are permitted."),
    "CSRF Protection": ("CWE-352", "A01:2021 – Broken Access Control",
                        "A missing anti-CSRF control may allow a victim's browser to submit unintended state-changing requests."),
    "Missing Security Header": ("CWE-693", "A05:2021 – Security Misconfiguration",
                                "Missing browser security controls can increase exposure to client-side attacks."),
    "Cookie Security": ("CWE-614 / CWE-1004", "A05:2021 – Security Misconfiguration",
                        "Weak cookie attributes can increase the risk of session exposure or unintended cross-site access."),
    "Information Disclosure": ("CWE-200", "A05:2021 – Security Misconfiguration",
                               "Exposed implementation details can provide useful information for reconnaissance."),
    "Transport Security": ("CWE-319", "A02:2021 – Cryptographic Failures",
                           "Unencrypted HTTP can expose transmitted data to interception or modification."),
    "HTTP Method Security": ("CWE-749", "A05:2021 – Security Misconfiguration",
                             "Unnecessary HTTP methods can expand the application's attack surface."),
    "CORS": ("CWE-942", "A05:2021 – Security Misconfiguration",
             "An overly permissive cross-origin policy can expose resources to unintended origins."),
    "Sensitive File Exposure": ("CWE-538", "A05:2021 – Security Misconfiguration",
                                "Accessible sensitive files can disclose configuration, source, credentials, or operational information."),
    "Endpoint Exposure": ("CWE-538", "A05:2021 – Security Misconfiguration",
                          "Exposed administrative, backup, or operational endpoints may increase attack surface."),
    "Authentication Security": ("CWE-287", "A07:2021 – Identification and Authentication Failures",
                                "Weak authentication controls can increase the likelihood of unauthorized account access."),
}


def _apply_finding_metadata(finding):
    """
    Attach standardized CWE/OWASP metadata.

    Detector implementations use slightly different finding types/names,
    so metadata is matched using both the normalized type and finding name.
    """

    finding_type = str(
        finding.get("type") or ""
    ).strip()

    finding_name = str(
        finding.get("name") or ""
    ).strip()

    # Exact match first.
    metadata = FINDING_METADATA.get(finding_type)

    if metadata is None:
        combined = (
            f"{finding_type} {finding_name}"
        ).lower()

        # Vulnerabilities
        if "sql injection" in combined:
            metadata = FINDING_METADATA["SQL Injection"]

        elif (
            "reflected xss" in combined
            or "potential reflected xss" in combined
        ):
            metadata = FINDING_METADATA["Reflected XSS"]

        elif "stored xss" in combined:
            metadata = FINDING_METADATA["Stored XSS"]

        elif "dom xss" in combined:
            metadata = FINDING_METADATA["DOM XSS"]

        elif "ssrf" in combined:
            metadata = FINDING_METADATA["SSRF"]

        elif "open redirect" in combined:
            metadata = FINDING_METADATA["Open Redirect"]

        elif (
            "xxe" in combined
            or "xml entity" in combined
            or "xml parser" in combined
        ):
            metadata = FINDING_METADATA["XXE"]

        elif "csrf" in combined:
            metadata = FINDING_METADATA["CSRF Protection"]

        # Security controls / misconfigurations
        elif (
            "content-security-policy" in combined
            or "security header" in combined
            or "missing security header" in combined
        ):
            metadata = FINDING_METADATA["Missing Security Header"]

        elif "cookie" in combined:
            metadata = FINDING_METADATA["Cookie Security"]

        elif (
            "information disclosure" in combined
            or "server information" in combined
        ):
            metadata = FINDING_METADATA["Information Disclosure"]

        elif (
            "unencrypted http" in combined
            or "transport security" in combined
            or "http transport" in combined
        ):
            metadata = FINDING_METADATA["Transport Security"]

        elif (
            "risky http method" in combined
            or "http method" in combined
            or "methods enabled" in combined
        ):
            metadata = FINDING_METADATA["HTTP Method Security"]

        elif "cors" in combined:
            metadata = FINDING_METADATA["CORS"]

        elif "sensitive file" in combined:
            metadata = FINDING_METADATA["Sensitive File Exposure"]

        elif "endpoint exposure" in combined:
            metadata = FINDING_METADATA["Endpoint Exposure"]

        elif "authentication" in combined:
            metadata = FINDING_METADATA["Authentication Security"]

    if metadata:
        cwe, owasp, impact = metadata
    else:
        cwe = None
        owasp = None
        impact = (
            "Review the affected behavior and assess its "
            "security impact."
        )

    finding["cwe"] = (
        finding.get("cwe")
        or cwe
    )

    finding["owasp"] = (
        finding.get("owasp")
        or owasp
    )

    finding["impact"] = (
        finding.get("impact")
        or impact
    )

    finding["verification_status"] = (
        "Reproduced"
        if finding.get("verification") == "reproduced"
        else (
            "Actively Tested"
            if finding.get("test_mode") == "active"
            else "Observed"
        )
    )

    return finding


def _normalize_finding(finding, target_url=None):
    """
    Normalize a scanner finding into a consistent structure.

    Confidence is preserved when supplied by the detector.
    When a detector does not provide confidence, a sensible
    fallback is assigned based on the finding type.
    """

    if not isinstance(finding, dict):
        return None

    normalized = dict(finding)

    # --------------------------------------------------------
    # Required fields
    # --------------------------------------------------------

    normalized["type"] = str(
        normalized.get("type") or "Unknown"
    ).strip()

    normalized["category"] = str(
        normalized.get("category") or "Informational"
    ).strip()

    normalized["name"] = str(
        normalized.get("name") or "Unnamed Finding"
    ).strip()

    normalized["severity"] = str(
        normalized.get("severity") or "Low"
    ).strip()

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = normalized.get("confidence")

    if confidence:
        confidence = str(
            confidence
        ).strip().title()

    else:

        # Directly observable passive findings.
        passive_high_confidence = {
            "Missing Security Header",
            "Cookie Security",
            "Information Disclosure",
            "Transport Security",
            "HTTP Method Security",
            "CORS",
            "Sensitive File Exposure",
            "Endpoint Exposure",
            "Authentication Security",
        }

        # Active checks where the scanner has detected
        # suspicious behavior but additional verification
        # may still be useful.
        active_medium_confidence = {
            "Reflected XSS",
            "SSRF",
            "XXE",
            "Open Redirect",
            "CSRF Protection",
            "SQL Injection",
        }

        finding_type = normalized["type"]

        if finding_type in passive_high_confidence:
            confidence = "High"

        elif finding_type in active_medium_confidence:
            confidence = "Medium"

        else:
            confidence = "Medium"

    # Only allow supported confidence levels.
    if confidence not in {
        "High",
        "Medium",
        "Low",
    }:
        confidence = "Medium"

    normalized["confidence"] = confidence

    # --------------------------------------------------------
    # Description / recommendation
    # --------------------------------------------------------

    normalized["description"] = str(
        normalized.get("description") or ""
    ).strip()

    normalized["recommendation"] = str(
        normalized.get("recommendation") or ""
    ).strip()

    # --------------------------------------------------------
    # Target / endpoint
    # --------------------------------------------------------

    if not normalized.get("url"):
        normalized["url"] = target_url

    finding_url = (
        normalized.get("url")
        or target_url
    )

    if finding_url:

        parsed = urlparse(
            finding_url
        )

        normalized["endpoint"] = (
            parsed.path or "/"
        )

    else:

        normalized["endpoint"] = None

    # --------------------------------------------------------
    # Optional fields
    # --------------------------------------------------------

    normalized.setdefault(
        "parameter",
        None,
    )

    normalized.setdefault(
        "method",
        None,
    )

    normalized.setdefault(
        "detection",
        None,
    )

    normalized.setdefault(
        "evidence",
        None,
    )

    normalized.setdefault(
        "verification",
        None,
    )

    # --------------------------------------------------------
    # Test mode
    # --------------------------------------------------------

    active_types = {
        "SQL Injection",
        "Reflected XSS",
        "Stored XSS",
        "DOM XSS",
        "Open Redirect",
        "SSRF",
        "XXE",
        "CSRF Protection",
    }

    finding_type = normalized["type"]

    if finding_type in active_types:
        normalized["test_mode"] = "active"

    else:
        normalized["test_mode"] = "passive"

    # --------------------------------------------------------
    # Finding intelligence metadata
    # --------------------------------------------------------
    # Apply this AFTER normalization/test-mode assignment so every
    # finding gets CWE/OWASP/impact data before it is persisted.
    normalized = _apply_finding_metadata(normalized)

    return normalized


def _normalize_findings(findings, target_url=None):
    """
    Normalize all findings while preserving their order.
    """

    normalized_findings = []

    for finding in findings or []:

        normalized = _normalize_finding(
            finding,
            target_url=target_url,
        )

        if normalized:
            normalized_findings.append(
                normalized
            )

    return normalized_findings
# ============================================================
# Active Deep Verification / Differential Probing
# ============================================================

ACTIVE_PROBE_CONFIG = {
    "sql": [
        "1",
        "1'",
        "1 AND 1=1",
        "1 AND 1=2",
    ],
    "xss": [
        "WebGuardXSSTest-A",
        "WebGuardXSSTest-B",
        "WebGuardXSSTest-C",
    ],
    "redirect": [
        "https://webguard-redirect-a.example/",
        "https://webguard-redirect-b.example/",
    ],
    "ssrf": [
        "http://127.0.0.1:5001/ssrf-marker",
        "http://127.0.0.1:5001/ssrf-status",
    ],
}


def _replace_get_parameter(url, parameter, value):
    """Return a URL with exactly one GET parameter replaced."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    rebuilt = []

    for key, current in query:
        if key == parameter and not replaced:
            rebuilt.append((key, value))
            replaced = True
        else:
            rebuilt.append((key, current))

    if not replaced:
        rebuilt.append((parameter, value))

    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(rebuilt), parts.fragment))


def _safe_request_profile(url, timeout=5):
    """Collect lightweight response characteristics for differential analysis."""
    try:
        response = requests.get(
            url,
            timeout=max(1, int(timeout)),
            allow_redirects=False,
            headers={"User-Agent": "WebGuard-ActiveScanner/1.0"},
        )
        body = response.text or ""
        return {
            "status": response.status_code,
            "length": len(body),
            "location": response.headers.get("Location", ""),
            "body_prefix": body[:300],
        }
    except requests.RequestException:
        return None


def _profiles_differ(profiles):
    usable = [p for p in profiles if p]
    if len(usable) < 2:
        return False
    return len({
        (p.get("status"), p.get("length"), p.get("location"))
        for p in usable
    }) > 1


def _active_probe_parameter(parameter_info, detector_type, timeout=5):
    """Run controlled GET probes and return differential evidence metadata."""
    if not isinstance(parameter_info, dict):
        return None

    base_url = parameter_info.get("url")
    parameter = parameter_info.get("parameter")
    method = str(parameter_info.get("method", "")).upper()
    if not base_url or not parameter or method != "GET":
        return None

    if detector_type == "SQL Injection":
        values = ACTIVE_PROBE_CONFIG["sql"]
    elif detector_type == "Reflected XSS":
        values = ACTIVE_PROBE_CONFIG["xss"]
    elif detector_type == "Open Redirect":
        values = ACTIVE_PROBE_CONFIG["redirect"]
    elif detector_type == "SSRF":
        values = ACTIVE_PROBE_CONFIG["ssrf"]
    else:
        return None

    profiles = []
    for value in values:
        probe_url = _replace_get_parameter(base_url, parameter, value)
        profile = _safe_request_profile(probe_url, timeout=timeout)
        if profile:
            profile["probe"] = value
            profiles.append(profile)

    if len(profiles) < 2:
        return None

    return {
        "probe_count": len(profiles),
        "differential_change": _profiles_differ(profiles),
        "profiles": profiles,
    }


def _active_deep_verify(parameter_info, timeout=5):
    """Perform multiple controlled probes and strengthen an existing finding.

    Active mode deliberately uses local/safe markers and example domains. The
    detector must already report the vulnerability; differential probing only
    supplies additional evidence and does not create a finding by itself.
    """
    if not isinstance(parameter_info, dict):
        return []

    parameter_url = parameter_info.get("url")
    parameter = parameter_info.get("parameter")
    method = str(parameter_info.get("method", "")).upper()

    if not parameter_url or not parameter or method != "GET":
        return []

    verified = []
    checks = (
        ("Reflected XSS", check_reflected_xss),
        ("SQL Injection", check_sql_injection),
        ("Open Redirect", check_open_redirect),
        ("SSRF", check_ssrf),
    )

    for finding_type, detector in checks:
        try:
            initial = detector(parameter_url, parameter)
            if not initial:
                continue

            probe_data = _active_probe_parameter(parameter_info, finding_type, timeout=timeout)
            if not probe_data:
                continue

            # Re-run the detector after the differential probe set. This keeps
            # the detector's own evidence authoritative while the probe set
            # supplies independent response characteristics.
            confirmation = detector(parameter_url, parameter)
            if not confirmation:
                continue

            finding = dict(initial)
            finding["confidence"] = "High"
            finding["test_mode"] = "active"
            finding["verification"] = "reproduced"
            finding["url"] = parameter_url
            finding["parameter"] = parameter
            finding["active_probe_count"] = probe_data["probe_count"]
            finding["differential_change"] = probe_data["differential_change"]
            finding["detection"] = (
                f"Active multi-probe verification reproduced {finding_type} "
                f"using {probe_data['probe_count']} controlled probes."
            )
            finding["evidence"] = (
                f"The detector reproduced the finding and Active mode collected "
                f"{probe_data['probe_count']} response profiles; differential "
                f"response change={probe_data['differential_change']}."
            )
            verified.append(finding)
        except Exception:
            continue

    return verified


def _active_verify_xxe(url):
    """Repeat XXE detection and record controlled verification evidence."""
    try:
        first = check_xxe(url)
        if not first:
            return None
        second = check_xxe(url)
        if not second:
            return None

        finding = dict(first)
        finding["confidence"] = "High"
        finding["test_mode"] = "active"
        finding["verification"] = "reproduced"
        finding["active_probe_count"] = 2
        finding["differential_change"] = True
        finding["url"] = url
        finding["detection"] = (
            "Active controlled XXE verification reproduced the XML behavior "
            "on independent requests."
        )
        finding["evidence"] = (
            "The XXE detector returned a matching controlled result on two "
            "active verification requests."
        )
        return finding
    except Exception:
        return None

# ============================================================
# Multiple Target Scan
# ============================================================

def scan_multiple_targets(
    urls,
    mode="standard",
    scan_config=None,
):

    mode = normalize_mode(mode)
    config = get_scan_config(mode)
    scan_config = normalize_scan_config(scan_config)

    all_results = []

    if not urls:
        return all_results

    # ========================================================
    # Discover parameters from ALL supplied pages
    # ========================================================

    parameters = []

    if config["parameter_testing"]:

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
            timeout=scan_config["timeout"],
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

        if config["parameter_testing"]:

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
            # Active-only deep verification
            # ====================================================
            if config["deep_testing"]:
                for parameter_info in result.get("parameters", []):
                    for deep_finding in _active_deep_verify(parameter_info, timeout=scan_config["timeout"]):
                        result.setdefault(
                            "findings",
                            [],
                        ).append(deep_finding)
        # ====================================================
        # Active-only XXE verification
        # ====================================================
        if config["deep_testing"]:
            xxe_verified = _active_verify_xxe(url)
            if xxe_verified:
                result.setdefault("findings", []).append(xxe_verified)

        # ====================================================
        # Store completed result
        # ====================================================

        result["findings"] = _deduplicate_findings(
            result.get("findings", [])
        )

        result["findings"] = _normalize_findings(
            result["findings"],
            target_url=url,
        )

        result["risk"] = calculate_risk(
            result["findings"]
        )

        all_results.append(
            result
        )

    overall_risk = calculate_overall_risk(
    all_results
)

    for result in all_results:

        if isinstance(result, dict):

            result.setdefault(
                "scan_summary",
            overall_risk
        )

    return all_results