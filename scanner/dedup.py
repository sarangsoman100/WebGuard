# scanner/dedup.py

from collections import OrderedDict
from urllib.parse import urlparse


ENDPOINT_SPECIFIC_TYPES = {
    "SQL Injection",
    "Reflected XSS",
    "Stored XSS",
    "DOM XSS",
    "SSRF",
    "Open Redirect",
    "XXE",
    "CSRF Protection",
}


def _normalize(value):
    if value is None:
        return None

    return str(value).strip().lower()


def _is_endpoint_specific(finding):
    return finding.get("type") in ENDPOINT_SPECIFIC_TYPES


def _get_endpoint(finding):
    """
    Return the full URL associated with a finding.
    """

    return (
        finding.get("url")
        or finding.get("endpoint")
    )


def _get_endpoint_path(url):
    """
    Convert a full URL into its endpoint path.
    """

    if not url:
        return None

    try:
        return urlparse(url).path or "/"
    except Exception:
        return None


def _finding_key(finding):
    """
    Build a stable finding identity.

    Active vulnerability findings remain endpoint-specific.

    Passive findings are grouped by vulnerability identity.
    """

    finding_type = _normalize(
        finding.get("type")
    )

    name = _normalize(
        finding.get("name")
    )

    category = _normalize(
        finding.get("category")
    )

    parameter = _normalize(
        finding.get("parameter")
    )

    if _is_endpoint_specific(finding):

        endpoint = _normalize(
            _get_endpoint(finding)
        )

        return (
            "endpoint-specific",
            finding_type,
            category,
            name,
            parameter,
            endpoint,
        )

    return (
        "global",
        finding_type,
        category,
        name,
        parameter,
    )


def _merge_finding(existing, finding):
    """
    Merge useful information from a duplicate finding.
    """

    confidence_order = {
        "low": 1,
        "medium": 2,
        "high": 3,
    }

    existing_confidence = _normalize(
        existing.get("confidence")
    )

    new_confidence = _normalize(
        finding.get("confidence")
    )

    if (
        confidence_order.get(new_confidence, 0)
        > confidence_order.get(existing_confidence, 0)
    ):
        existing["confidence"] = finding.get(
            "confidence"
        )

    fields = [
        "description",
        "recommendation",
        "detection",
        "evidence",
        "method",
        "test_mode",
    ]

    for field in fields:

        if (
            not existing.get(field)
            and finding.get(field)
        ):
            existing[field] = finding.get(field)

    return existing


def deduplicate_findings(findings):
    """
    Deduplicate scanner findings.

    Passive/configuration findings are grouped together
    while retaining every affected endpoint.

    Active vulnerability findings remain endpoint-specific.
    """

    unique = OrderedDict()

    for finding in findings or []:

        if not isinstance(finding, dict):
            continue

        key = _finding_key(finding)

        endpoint_url = _get_endpoint(
            finding
        )

        endpoint_path = (
            finding.get("endpoint")
            or _get_endpoint_path(endpoint_url)
        )

        # -----------------------------------------------------
        # First occurrence
        # -----------------------------------------------------

        if key not in unique:

            item = {
                "type": finding.get(
                    "type",
                    "Unknown"
                ),

                "category": finding.get(
                    "category",
                    "Informational"
                ),

                "name": finding.get(
                    "name",
                    "Unnamed Finding"
                ),

                "severity": finding.get(
                    "severity",
                    "Low"
                ),

                "confidence": finding.get(
                    "confidence",
                    "Medium"
                ),

                "description": finding.get(
                    "description",
                    ""
                ),

                "recommendation": finding.get(
                    "recommendation",
                    ""
                ),

                "parameter": finding.get(
                    "parameter"
                ),

                "method": finding.get(
                    "method"
                ),

                "url": endpoint_url,

                "endpoint": endpoint_path,

                "detection": finding.get(
                    "detection"
                ),

                "evidence": finding.get(
                    "evidence"
                ),

                "test_mode": finding.get(
                    "test_mode"
                ),

                "affected_endpoints": [],
            }

            if endpoint_url:
                item["affected_endpoints"].append(
                    endpoint_url
                )

            unique[key] = item

        # -----------------------------------------------------
        # Duplicate occurrence
        # -----------------------------------------------------

        else:

            item = unique[key]

            item = _merge_finding(
                item,
                finding
            )

            if (
                endpoint_url
                and endpoint_url
                not in item["affected_endpoints"]
            ):
                item["affected_endpoints"].append(
                    endpoint_url
                )

            unique[key] = item

    return list(unique.values())