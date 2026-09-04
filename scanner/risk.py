# scanner/risk.py
"""
WebGuard Phase 2 Risk Engine

Backward-compatible with the existing WebGuard finding structure while
adding confidence, exploitability, endpoint impact, and explainable scoring.

The engine is intentionally deterministic: the same findings produce the
same score, which makes scan reports and comparisons easier to understand.
"""

from collections import defaultdict


SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 1.0,
}

CATEGORY_MULTIPLIERS = {
    "Vulnerability": 1.00,
    "Potential Vulnerability": 0.70,
    "Security Misconfiguration": 0.35,
    "Informational": 0.00,
}

CONFIDENCE_MULTIPLIERS = {
    "High": 1.00,
    "Medium": 0.80,
    "Low": 0.60,
}

# Finding types that are generally more directly exploitable.
# Unknown types use the neutral value of 1.0.
EXPLOITABILITY_MULTIPLIERS = {
    "SQL Injection": 1.15,
    "SSRF": 1.15,
    "XXE": 1.10,
    "Command Injection": 1.20,
    "Remote Code Execution": 1.25,
    "Authentication Bypass": 1.20,
    "Path Traversal": 1.10,
    "Open Redirect": 0.90,
    "Stored XSS": 1.05,
    "Reflected XSS": 1.00,
    "DOM XSS": 1.00,
    "CSRF Protection": 0.90,
    "Sensitive File Exposure": 0.85,
    "Security Headers": 0.70,
    "Cookie Security": 0.70,
    "Information Disclosure": 0.45,
    "HTTP Method Security": 0.65,
    "CORS": 0.80,
    "Transport Security": 0.75,
}

# Multiple affected endpoints should increase risk, but not linearly.
# Otherwise one recurring issue across 100 pages would destroy the score.
ENDPOINT_IMPACT_CAP = 2.00


def _normalize_category(category):
    if not category:
        return "Informational"

    value = str(category).strip().lower()

    category_map = {
        "vulnerability": "Vulnerability",
        "potential vulnerability": "Potential Vulnerability",
        "security misconfiguration": "Security Misconfiguration",
        "misconfiguration": "Security Misconfiguration",
        "informational": "Informational",
        "information": "Informational",
    }

    return category_map.get(value, "Informational")


def _normalize_severity(severity):
    if not severity:
        return "Low"

    value = str(severity).strip().lower()

    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    return severity_map.get(value, "Low")


def _normalize_confidence(confidence):
    if not confidence:
        return "Medium"

    value = str(confidence).strip().lower()

    confidence_map = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    return confidence_map.get(value, "Medium")


def _normalize_type(finding_type):
    if not finding_type:
        return ""

    return str(finding_type).strip()


def _endpoint_count(finding):
    """
    Estimate how many distinct endpoints are affected.

    Supports the current WebGuard `affected_endpoints` field and also
    handles older findings containing only `url`/`endpoint`.
    """
    endpoints = finding.get("affected_endpoints")

    if isinstance(endpoints, (list, tuple, set)):
        cleaned = {
            str(item).strip()
            for item in endpoints
            if item
        }
        if cleaned:
            return len(cleaned)

    if endpoints:
        return 1

    if finding.get("url") or finding.get("endpoint"):
        return 1

    return 0


def _endpoint_multiplier(count):
    """
    Diminishing-return impact multiplier.

    1 endpoint  -> 1.00
    2 endpoints -> 1.20
    3 endpoints -> 1.35
    5 endpoints -> ~1.60
    10+         -> capped at 2.00
    """
    if count <= 1:
        return 1.00

    multiplier = 1.0 + (0.35 * (1.0 - (0.75 ** (count - 1))))

    return min(ENDPOINT_IMPACT_CAP, round(multiplier, 4))


def _exploitability_multiplier(finding_type):
    return EXPLOITABILITY_MULTIPLIERS.get(
        finding_type,
        1.00,
    )


def _finding_score(finding):
    """
    Calculate the explainable risk contribution of one finding.
    """
    severity = _normalize_severity(finding.get("severity"))
    category = _normalize_category(finding.get("category"))
    confidence = _normalize_confidence(finding.get("confidence"))
    finding_type = _normalize_type(finding.get("type"))

    base = SEVERITY_WEIGHTS.get(severity, 0.0)
    category_factor = CATEGORY_MULTIPLIERS.get(category, 0.0)
    confidence_factor = CONFIDENCE_MULTIPLIERS.get(confidence, 0.80)
    exploitability_factor = _exploitability_multiplier(finding_type)

    endpoint_count = _endpoint_count(finding)
    endpoint_factor = _endpoint_multiplier(endpoint_count)

    score = (
        base
        * category_factor
        * confidence_factor
        * exploitability_factor
        * endpoint_factor
    )

    return {
        "score": round(score, 2),
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "base_weight": base,
        "category_multiplier": category_factor,
        "confidence_multiplier": confidence_factor,
        "exploitability_multiplier": exploitability_factor,
        "endpoint_multiplier": endpoint_factor,
        "affected_endpoints": endpoint_count,
    }


def _risk_level(
    critical,
    high,
    medium,
    low,
    vulnerabilities,
    potential_vulnerabilities,
    security_score,
):
    """
    Determine the displayed overall risk.

    Confirmed critical/high vulnerabilities take priority. High-severity
    potential findings do not automatically become High risk.
    """
    if critical > 0:
        return "Critical"

    if vulnerabilities > 0 and high > 0:
        return "High"

    if vulnerabilities > 0 and medium > 0:
        return "High"

    if potential_vulnerabilities > 0 and high > 0:
        return "Medium"

    if high > 0:
        return "Medium"

    if medium > 0:
        return "Medium"

    if low > 0:
        return "Low"

    # Score-only fallback for future/custom finding types.
    if security_score < 40:
        return "High"

    if security_score < 70:
        return "Medium"

    if security_score < 90:
        return "Low"

    return "Secure"


def calculate_risk(findings):
    """
    Calculate risk for one target.

    Returns the original fields expected by WebGuard plus:
      - confidence counts
      - confirmed/potential counts
      - finding_breakdown
      - top_risks
    """
    findings = [
        finding
        for finding in (findings or [])
        if isinstance(finding, dict)
    ]

    total_findings = len(findings)

    critical = high = medium = low = 0
    vulnerabilities = 0
    potential_vulnerabilities = 0
    misconfigurations = 0
    informational = 0

    high_confidence = 0
    medium_confidence = 0
    low_confidence = 0

    risk_points = 0.0
    finding_breakdown = []

    for index, finding in enumerate(findings, start=1):
        severity = _normalize_severity(finding.get("severity"))
        category = _normalize_category(finding.get("category"))
        confidence = _normalize_confidence(finding.get("confidence"))
        finding_type = _normalize_type(finding.get("type"))

        if severity == "Critical":
            critical += 1
        elif severity == "High":
            high += 1
        elif severity == "Medium":
            medium += 1
        else:
            low += 1

        if category == "Vulnerability":
            vulnerabilities += 1
        elif category == "Potential Vulnerability":
            potential_vulnerabilities += 1
        elif category == "Security Misconfiguration":
            misconfigurations += 1
        else:
            informational += 1

        if confidence == "High":
            high_confidence += 1
        elif confidence == "Medium":
            medium_confidence += 1
        else:
            low_confidence += 1

        details = _finding_score(finding)
        risk_points += details["score"]

        finding_breakdown.append({
            "rank": index,
            "type": finding_type or "Unknown",
            "name": finding.get("name", "Unnamed Finding"),
            "severity": severity,
            "category": category,
            "confidence": confidence,
            "risk_points": details["score"],
            "affected_endpoints": details["affected_endpoints"],
            "exploitability": details["exploitability_multiplier"],
        })

    risk_points = round(risk_points, 2)

    security_score = round(
        max(
            0,
            min(
                100,
                100 - risk_points,
            ),
        )
    )

    risk_level = _risk_level(
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        vulnerabilities=vulnerabilities,
        potential_vulnerabilities=potential_vulnerabilities,
        security_score=security_score,
    )

    # Highest-impact findings first.
    finding_breakdown.sort(
        key=lambda item: item["risk_points"],
        reverse=True,
    )

    for rank, item in enumerate(finding_breakdown, start=1):
        item["rank"] = rank

    top_risks = finding_breakdown[:5]

    return {
        "total": total_findings,

        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,

        "vulnerabilities": vulnerabilities,
        "potential_vulnerabilities": potential_vulnerabilities,
        "misconfigurations": misconfigurations,
        "informational": informational,

        "high_confidence": high_confidence,
        "medium_confidence": medium_confidence,
        "low_confidence": low_confidence,

        "risk_points": risk_points,
        "security_score": security_score,
        "risk_level": risk_level,

        "finding_breakdown": finding_breakdown,
        "top_risks": top_risks,
    }


def calculate_overall_risk(results):
    """
    Calculate one overall risk summary for a complete multi-target scan.

    Each result may contain a `risk` dictionary generated by
    calculate_risk().
    """
    summary = {
        "targets": 0,
        "total": 0,

        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,

        "vulnerabilities": 0,
        "potential_vulnerabilities": 0,
        "misconfigurations": 0,
        "informational": 0,

        "high_confidence": 0,
        "medium_confidence": 0,
        "low_confidence": 0,

        "risk_points": 0.0,
        "security_score": 100,
        "risk_level": "Secure",

        "top_risks": [],
    }

    valid_results = []

    for result in results or []:
        if not isinstance(result, dict):
            continue

        risk = result.get("risk")

        if not isinstance(risk, dict):
            continue

        valid_results.append(risk)

    if not valid_results:
        return summary

    summary["targets"] = len(valid_results)

    for risk in valid_results:
        summary["total"] += int(risk.get("total", 0) or 0)

        summary["critical"] += int(risk.get("critical", 0) or 0)
        summary["high"] += int(risk.get("high", 0) or 0)
        summary["medium"] += int(risk.get("medium", 0) or 0)
        summary["low"] += int(risk.get("low", 0) or 0)

        summary["vulnerabilities"] += int(
            risk.get("vulnerabilities", 0) or 0
        )
        summary["potential_vulnerabilities"] += int(
            risk.get("potential_vulnerabilities", 0) or 0
        )
        summary["misconfigurations"] += int(
            risk.get("misconfigurations", 0) or 0
        )
        summary["informational"] += int(
            risk.get("informational", 0) or 0
        )

        summary["high_confidence"] += int(
            risk.get("high_confidence", 0) or 0
        )
        summary["medium_confidence"] += int(
            risk.get("medium_confidence", 0) or 0
        )
        summary["low_confidence"] += int(
            risk.get("low_confidence", 0) or 0
        )

        summary["risk_points"] += float(
            risk.get("risk_points", 0) or 0
        )

    summary["risk_points"] = round(
        summary["risk_points"],
        2,
    )

    summary["security_score"] = round(
        max(
            0,
            min(
                100,
                100 - summary["risk_points"],
            ),
        )
    )

    summary["risk_level"] = _risk_level(
        critical=summary["critical"],
        high=summary["high"],
        medium=summary["medium"],
        low=summary["low"],
        vulnerabilities=summary["vulnerabilities"],
        potential_vulnerabilities=summary["potential_vulnerabilities"],
        security_score=summary["security_score"],
    )

    # Collect the highest-risk findings from all targets.
    combined_top_risks = []

    for risk in valid_results:
        for item in risk.get("top_risks", []) or []:
            if isinstance(item, dict):
                combined_top_risks.append(dict(item))

    combined_top_risks.sort(
        key=lambda item: float(item.get("risk_points", 0) or 0),
        reverse=True,
    )

    summary["top_risks"] = combined_top_risks[:10]

    return summary
