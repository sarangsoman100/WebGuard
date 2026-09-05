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
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    config = get_scan_config(mode)

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


def _safe_request_profile(url):
    """Collect lightweight response characteristics for differential analysis."""
    try:
        response = requests.get(
            url,
            timeout=5,
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


def _active_probe_parameter(parameter_info, detector_type):
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
        profile = _safe_request_profile(probe_url)
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


def _active_deep_verify(parameter_info):
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

            probe_data = _active_probe_parameter(parameter_info, finding_type)
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


# ============================================================
# Phase 2B - Concurrent Target / Parameter Scanning
# ============================================================

# Conservative, mode-aware concurrency. These limits apply to WebGuard's
# own worker pool; individual detectors retain their existing request logic.
SCAN_WORKERS = {
    "passive": 6,
    "standard": 4,
    "active": 2,
}

PARAMETER_WORKERS = {
    "passive": 1,
    "standard": 6,
    "active": 3,
}


def _run_detector(detector, *args):
    """Run one detector without allowing one failure to abort a scan."""
    try:
        return detector(*args)
    except Exception:
        return None


def _base_endpoint(url):
    return (
        urlparse(url)
        ._replace(query="", fragment="")
        .geturl()
        .rstrip("/")
    )


def _parameter_belongs_to_target(parameter_info, target_url):
    if not isinstance(parameter_info, dict):
        return False

    parameter_url = parameter_info.get("url")
    if not parameter_url:
        return False

    return _base_endpoint(parameter_url) == _base_endpoint(target_url)


def _discover_parameters_for_url(url):
    try:
        return discover_parameters(url) or []
    except Exception:
        return []


def _test_parameter(parameter_info):
    """
    Run the four existing parameter detectors concurrently.

    The detectors themselves are unchanged. This function only coordinates
    them and returns their findings together with the parameter metadata.
    """
    if not isinstance(parameter_info, dict):
        return {
            "parameter": parameter_info,
            "findings": [],
        }

    parameter_url = parameter_info.get("url")
    parameter = parameter_info.get("parameter")
    method = str(
        parameter_info.get("method", "")
    ).upper()

    if not parameter_url or not parameter:
        return {
            "parameter": parameter_info,
            "findings": [],
        }

    # WebGuard currently performs GET parameter testing only.
    if method != "GET":
        return {
            "parameter": parameter_info,
            "findings": [],
        }

    detectors = (
        ("Reflected XSS", check_reflected_xss),
        ("SQL Injection", check_sql_injection),
        ("Open Redirect", check_open_redirect),
        ("SSRF", check_ssrf),
    )

    findings = []

    with ThreadPoolExecutor(
        max_workers=4
    ) as executor:
        futures = {
            executor.submit(
                _run_detector,
                detector,
                parameter_url,
                parameter,
            ): finding_type
            for finding_type, detector in detectors
        }

        for future in as_completed(futures):
            try:
                finding = future.result()
            except Exception:
                finding = None

            if finding:
                finding["url"] = parameter_url
                findings.append(finding)

    # Stable detector order for UI/report consistency.
    order = {
        "Reflected XSS": 1,
        "SQL Injection": 2,
        "Open Redirect": 3,
        "SSRF": 4,
    }

    findings.sort(
        key=lambda item: order.get(
            item.get("type"),
            99,
        )
    )

    return {
        "parameter": parameter_info,
        "findings": findings,
    }


def _active_verify_selected(
    parameter_info,
    finding_types,
):
    """
    Active verification optimized to verify only detector types that already
    produced a finding during the normal parameter pass.

    This preserves the existing safety rule in _active_deep_verify():
    differential probing supplies evidence but does not create findings.
    """
    if not isinstance(parameter_info, dict):
        return []

    parameter_url = parameter_info.get("url")
    parameter = parameter_info.get("parameter")
    method = str(
        parameter_info.get("method", "")
    ).upper()

    if (
        not parameter_url
        or not parameter
        or method != "GET"
    ):
        return []

    detector_map = {
        "Reflected XSS": check_reflected_xss,
        "SQL Injection": check_sql_injection,
        "Open Redirect": check_open_redirect,
        "SSRF": check_ssrf,
    }

    verified = []

    for finding_type in (
        "Reflected XSS",
        "SQL Injection",
        "Open Redirect",
        "SSRF",
    ):
        if finding_type not in finding_types:
            continue

        detector = detector_map[finding_type]

        try:
            initial = detector(
                parameter_url,
                parameter,
            )

            if not initial:
                continue

            probe_data = _active_probe_parameter(
                parameter_info,
                finding_type,
            )

            if not probe_data:
                continue

            confirmation = detector(
                parameter_url,
                parameter,
            )

            if not confirmation:
                continue

            finding = dict(initial)
            finding["confidence"] = "High"
            finding["test_mode"] = "active"
            finding["verification"] = "reproduced"
            finding["url"] = parameter_url
            finding["parameter"] = parameter
            finding["active_probe_count"] = (
                probe_data["probe_count"]
            )
            finding["differential_change"] = (
                probe_data["differential_change"]
            )
            finding["detection"] = (
                f"Active multi-probe verification reproduced "
                f"{finding_type} using "
                f"{probe_data['probe_count']} controlled probes."
            )
            finding["evidence"] = (
                f"The detector reproduced the finding and Active mode "
                f"collected {probe_data['probe_count']} response profiles; "
                f"differential response change="
                f"{probe_data['differential_change']}."
            )

            verified.append(finding)

        except Exception:
            continue

    return verified


def _active_verify_parameter_job(job):
    parameter_info, finding_types = job
    return _active_verify_selected(
        parameter_info,
        finding_types,
    )


def _scan_base_target(url, mode):
    return scan_target(
        url,
        mode=mode,
    )


def _stable_parameter_key(parameter_info):
    if not isinstance(parameter_info, dict):
        return None

    return (
        str(parameter_info.get("url", "")).strip().lower(),
        str(parameter_info.get("parameter", "")).strip().lower(),
        str(parameter_info.get("method", "")).strip().upper(),
    )


def scan_multiple_targets(
    urls,
    mode="standard",
):
    """
    Concurrent multi-target scanner.

    Phase 2B optimizations:
    - Base target scans run concurrently.
    - Parameter discovery runs concurrently.
    - Parameter detectors run concurrently.
    - Active verification only revisits parameter types that already
      produced findings.
    - Concurrency remains bounded and mode-aware.
    - Output order remains deterministic.
    """

    mode = normalize_mode(mode)
    config = get_scan_config(mode)

    if not urls:
        return []

    # ------------------------------------------------------------------
    # Normalize and deduplicate target URLs.
    # ------------------------------------------------------------------

    unique_urls = []
    seen_urls = set()

    for value in urls:
        if not value:
            continue

        value = str(value).strip()
        key = value.lower()

        if key in seen_urls:
            continue

        seen_urls.add(key)
        unique_urls.append(value)

    if not unique_urls:
        return []

    # ------------------------------------------------------------------
    # 1. Parameter discovery in parallel.
    # ------------------------------------------------------------------

    parameters_by_target = {
        url: []
        for url in unique_urls
    }

    if config["parameter_testing"]:
        discovery_workers = min(
            SCAN_WORKERS[mode],
            len(unique_urls),
        )

        with ThreadPoolExecutor(
            max_workers=max(
                1,
                discovery_workers,
            )
        ) as executor:
            futures = {
                executor.submit(
                    _discover_parameters_for_url,
                    url,
                ): url
                for url in unique_urls
            }

            for future in as_completed(futures):
                url = futures[future]

                try:
                    discovered = future.result()
                except Exception:
                    discovered = []

                unique_parameters = []
                parameter_seen = set()

                for parameter_info in discovered:
                    key = _stable_parameter_key(
                        parameter_info
                    )

                    if not key or key in parameter_seen:
                        continue

                    parameter_seen.add(key)
                    unique_parameters.append(
                        parameter_info
                    )

                parameters_by_target[url] = (
                    unique_parameters
                )

    # ------------------------------------------------------------------
    # 2. Base target scans in parallel.
    # ------------------------------------------------------------------

    target_workers = min(
        SCAN_WORKERS[mode],
        len(unique_urls),
    )

    base_results = {}

    with ThreadPoolExecutor(
        max_workers=max(
            1,
            target_workers,
        )
    ) as executor:
        futures = {
            executor.submit(
                _scan_base_target,
                url,
                mode,
            ): url
            for url in unique_urls
        }

        for future in as_completed(futures):
            url = futures[future]

            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "target": url,
                    "mode": mode,
                    "status": "Unknown",
                    "status_code": None,
                    "response_time": None,
                    "server": None,
                    "https": urlparse(url).scheme == "https",
                    "findings": [],
                    "error": str(exc),
                }

            base_results[url] = result

    # ------------------------------------------------------------------
    # 3. Parameter testing in parallel.
    # ------------------------------------------------------------------

    parameter_jobs = []

    if config["parameter_testing"]:
        for url in unique_urls:
            for parameter_info in parameters_by_target.get(
                url,
                [],
            ):
                if not _parameter_belongs_to_target(
                    parameter_info,
                    url,
                ):
                    continue

                parameter_jobs.append(
                    (
                        url,
                        parameter_info,
                    )
                )

    parameter_results_by_target = {
        url: []
        for url in unique_urls
    }

    if parameter_jobs:
        parameter_workers = min(
            PARAMETER_WORKERS[mode],
            len(parameter_jobs),
        )

        with ThreadPoolExecutor(
            max_workers=max(
                1,
                parameter_workers,
            )
        ) as executor:
            futures = {
                executor.submit(
                    _test_parameter,
                    parameter_info,
                ): url
                for url, parameter_info in parameter_jobs
            }

            for future in as_completed(futures):
                url = futures[future]

                try:
                    tested = future.result()
                except Exception:
                    continue

                parameter_results_by_target[
                    url
                ].append(tested)

    # ------------------------------------------------------------------
    # 4. Build results in the original URL order.
    # ------------------------------------------------------------------

    all_results = []

    for url in unique_urls:
        result = base_results.get(url)

        if not isinstance(result, dict):
            result = {
                "target": url,
                "mode": mode,
                "status": "Unknown",
                "status_code": None,
                "response_time": None,
                "server": None,
                "https": urlparse(url).scheme == "https",
                "findings": [],
                "error": "No scan result",
            }

        if result.get("error"):
            result["parameters"] = []
            result["findings"] = _normalize_findings(
                result.get("findings", []),
                target_url=url,
            )
            result["risk"] = calculate_risk(
                result["findings"]
            )
            all_results.append(result)
            continue

        result["parameters"] = []

        # --------------------------------------------------------------
        # Attach discovered parameters belonging to this target.
        # --------------------------------------------------------------

        for parameter_info in parameters_by_target.get(
            url,
            [],
        ):
            if _parameter_belongs_to_target(
                parameter_info,
                url,
            ):
                result["parameters"].append(
                    parameter_info
                )

        # --------------------------------------------------------------
        # Add parameter detector findings.
        # --------------------------------------------------------------

        active_jobs = []

        for tested in parameter_results_by_target.get(
            url,
            [],
        ):
            parameter_info = tested.get(
                "parameter"
            )

            findings = tested.get(
                "findings",
                [],
            ) or []

            for finding in findings:
                result.setdefault(
                    "findings",
                    [],
                ).append(finding)

            if config["deep_testing"] and findings:
                finding_types = {
                    finding.get("type")
                    for finding in findings
                    if finding.get("type")
                }

                active_jobs.append(
                    (
                        parameter_info,
                        finding_types,
                    )
                )

        # --------------------------------------------------------------
        # Active differential verification.
        # --------------------------------------------------------------

        if active_jobs:
            active_workers = min(
                PARAMETER_WORKERS["active"],
                len(active_jobs),
            )

            with ThreadPoolExecutor(
                max_workers=max(
                    1,
                    active_workers,
                )
            ) as executor:
                futures = [
                    executor.submit(
                        _active_verify_parameter_job,
                        job,
                    )
                    for job in active_jobs
                ]

                for future in as_completed(futures):
                    try:
                        verified = future.result()
                    except Exception:
                        verified = []

                    for finding in verified:
                        result.setdefault(
                            "findings",
                            [],
                        ).append(finding)

        # --------------------------------------------------------------
        # Active XXE verification.
        #
        # Keep the existing detector behavior, but run it once per target
        # in the normal target worker phase rather than multiplying it by
        # parameter count.
        # --------------------------------------------------------------

        if config["deep_testing"]:
            xxe_verified = _active_verify_xxe(url)

            if xxe_verified:
                result.setdefault(
                    "findings",
                    [],
                ).append(
                    xxe_verified
                )

        # --------------------------------------------------------------
        # Final per-target dedup / normalization / risk.
        # --------------------------------------------------------------

        result["findings"] = _deduplicate_findings(
            result.get(
                "findings",
                [],
            )
        )

        result["findings"] = _normalize_findings(
            result["findings"],
            target_url=url,
        )

        result["risk"] = calculate_risk(
            result["findings"]
        )

        all_results.append(result)

    # ------------------------------------------------------------------
    # Overall risk.
    # ------------------------------------------------------------------

    overall_risk = calculate_overall_risk(
        all_results
    )

    for result in all_results:
        if isinstance(result, dict):
            result.setdefault(
                "scan_summary",
                overall_risk,
            )

    return all_results
