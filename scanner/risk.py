# scanner/risk.py


SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1
}


# Category multipliers.
#
# Vulnerabilities have the greatest impact.
# Potential vulnerabilities have a slightly reduced impact because
# they require additional verification.
# Security misconfigurations affect the score, but less heavily.
# Informational findings do not reduce the security score.
CATEGORY_MULTIPLIERS = {
    "Vulnerability": 1.0,
    "Potential Vulnerability": 0.7,
    "Security Misconfiguration": 0.35,
    "Informational": 0.0
}


def _normalize_category(category):
    """
    Normalize finding categories so small capitalization differences
    do not break the risk calculation.
    """

    if not category:
        return "Informational"

    category = str(category).strip().lower()

    category_map = {
        "vulnerability": "Vulnerability",
        "potential vulnerability": "Potential Vulnerability",
        "security misconfiguration": "Security Misconfiguration",
        "misconfiguration": "Security Misconfiguration",
        "informational": "Informational",
        "information": "Informational"
    }

    return category_map.get(
        category,
        "Informational"
    )


def _normalize_severity(severity):
    """
    Normalize severity values.
    """

    if not severity:
        return "Low"

    value = str(severity).strip().lower()

    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low"
    }

    return severity_map.get(
        value,
        "Low"
    )


def calculate_risk(findings):

    findings = findings or []

    # -----------------------------------------
    # Basic counts
    # -----------------------------------------

    total_findings = len(findings)

    critical = 0
    high = 0
    medium = 0
    low = 0

    # -----------------------------------------
    # Category counts
    # -----------------------------------------

    vulnerabilities = 0
    potential_vulnerabilities = 0
    misconfigurations = 0
    informational = 0

    # -----------------------------------------
    # Risk calculation
    # -----------------------------------------

    risk_points = 0.0

    for finding in findings:

        severity = _normalize_severity(
            finding.get("severity")
        )

        category = _normalize_category(
            finding.get("category")
        )

        # Severity counts
        if severity == "Critical":
            critical += 1

        elif severity == "High":
            high += 1

        elif severity == "Medium":
            medium += 1

        elif severity == "Low":
            low += 1

        # Category counts
        if category == "Vulnerability":
            vulnerabilities += 1

        elif category == "Potential Vulnerability":
            potential_vulnerabilities += 1

        elif category == "Security Misconfiguration":
            misconfigurations += 1

        elif category == "Informational":
            informational += 1

        # Category-aware risk
        base_weight = SEVERITY_WEIGHTS.get(
            severity,
            0
        )

        multiplier = CATEGORY_MULTIPLIERS.get(
            category,
            0
        )

        risk_points += (
            base_weight *
            multiplier
        )

    # -----------------------------------------
    # Security score
    # -----------------------------------------

    security_score = round(
        max(
            0,
            min(
                100,
                100 - risk_points
            )
        )
    )

    # -----------------------------------------
    # Overall risk level
    # -----------------------------------------

    if critical > 0:

        risk_level = "Critical"

    elif high > 0:

        # A High-severity informational/configuration
        # finding should not automatically make the
        # entire application "High".
        if vulnerabilities > 0:
            risk_level = "High"
        elif potential_vulnerabilities > 0:
            risk_level = "Medium"
        else:
            risk_level = "Medium"

    elif medium > 0:

        risk_level = "Medium"

    elif low > 0:

        risk_level = "Low"

    else:

        risk_level = "Secure"

    # -----------------------------------------
    # Return complete risk information
    # -----------------------------------------

    return {
        "total": total_findings,

        # Severity counts
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,

        # Category counts
        "vulnerabilities": vulnerabilities,
        "potential_vulnerabilities": potential_vulnerabilities,
        "misconfigurations": misconfigurations,
        "informational": informational,

        # Risk
        "risk_points": round(
            risk_points,
            2
        ),

        "security_score": security_score,

        "risk_level": risk_level
    }