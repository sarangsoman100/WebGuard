import requests
from urllib.parse import urlparse, urljoin


# ============================================================
# Robots.txt Endpoint Exposure Detector
# ============================================================

def check_endpoint_exposure(url):
    """
    Read robots.txt and safely inspect the paths it discloses.

    This does NOT brute-force directories.
    It only checks paths explicitly disclosed by robots.txt.
    """

    findings = []

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return findings

    base_url = (
        f"{parsed.scheme}://{parsed.netloc}"
    )

    robots_url = urljoin(
        base_url,
        "/robots.txt"
    )

    try:

        response = requests.get(
            robots_url,
            timeout=5,
            allow_redirects=False,
        )

    except requests.RequestException:
        return findings

    if response.status_code != 200:
        return findings

    content = response.text

    if not content.strip():
        return findings

    # --------------------------------------------------------
    # Extract Disallow paths
    # --------------------------------------------------------

    paths = []

    for line in content.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if ":" not in line:
            continue

        directive, value = line.split(
            ":",
            1
        )

        directive = directive.strip().lower()
        value = value.strip()

        if directive != "disallow":
            continue

        if not value:
            continue

        if not value.startswith("/"):
            continue

        if value not in paths:
            paths.append(value)

    # --------------------------------------------------------
    # Nothing disclosed
    # --------------------------------------------------------

    if not paths:
        return findings

    # Limit requests so robots.txt cannot cause excessive
    # scanning.
    paths = paths[:20]

    # --------------------------------------------------------
    # Inspect disclosed endpoints
    # --------------------------------------------------------

    for path in paths:

        endpoint_url = urljoin(
            base_url,
            path
        )

        try:

            endpoint_response = requests.get(
                endpoint_url,
                timeout=5,
                allow_redirects=False,
            )

        except requests.RequestException:
            continue

        status = endpoint_response.status_code

        # ----------------------------------------------------
        # Ignore normal missing endpoints
        # ----------------------------------------------------

        if status in (
            404,
            410,
        ):
            continue

        # ----------------------------------------------------
        # Redirects are interesting, but not automatically
        # vulnerabilities.
        # ----------------------------------------------------

        if status in (
            301,
            302,
            303,
            307,
            308,
        ):

            findings.append({
                "type": "Endpoint Exposure",
                "category": "Informational",
                "name": (
                    f"Robots.txt Disclosed Endpoint: {path}"
                ),
                "severity": "Low",
                "confidence": "High",
                "description": (
                    f"The endpoint '{path}' is disclosed in "
                    "robots.txt and redirects the request."
                ),
                "recommendation": (
                    "Review whether the endpoint needs to be "
                    "publicly discoverable and whether the "
                    "robots.txt entry is necessary."
                ),
                "detection": (
                    "robots.txt endpoint validation"
                ),
                "evidence": (
                    f"robots.txt contains Disallow: {path}; "
                    f"the endpoint returned HTTP {status}."
                ),
                "url": endpoint_url,
            })

            continue

        # ----------------------------------------------------
        # Determine content characteristics
        # ----------------------------------------------------

        content_type = (
            endpoint_response.headers
            .get(
                "Content-Type",
                ""
            )
            .lower()
        )

        body = (
            endpoint_response.text[:5000]
            .lower()
        )

        # ----------------------------------------------------
        # Admin / management interfaces
        # ----------------------------------------------------

        admin_keywords = (
            "admin",
            "administrator",
            "dashboard",
            "control panel",
            "management",
            "login",
        )

        is_admin_endpoint = (
            any(
                keyword in path.lower()
                for keyword in admin_keywords
            )
            or any(
                keyword in body
                for keyword in admin_keywords
            )
        )

        # ----------------------------------------------------
        # Backup / sensitive resources
        # ----------------------------------------------------

        sensitive_keywords = (
            "backup",
            "database",
            "dump",
            "config",
            "private",
            "secret",
            ".sql",
            ".bak",
            ".zip",
        )

        is_sensitive_endpoint = (
            any(
                keyword in path.lower()
                for keyword in sensitive_keywords
            )
            or (
                "application/zip"
                in content_type
            )
            or (
                "application/sql"
                in content_type
            )
        )

        # ----------------------------------------------------
        # Sensitive resource
        # ----------------------------------------------------

        if is_sensitive_endpoint:

            findings.append({
                "type": "Endpoint Exposure",
                "category": "Vulnerability",
                "name": (
                    f"Potential Sensitive Endpoint Exposure: {path}"
                ),
                "severity": "High",
                "confidence": "Medium",
                "description": (
                    f"A potentially sensitive endpoint "
                    f"'{path}' was disclosed through "
                    "robots.txt and returned a successful "
                    f"HTTP {status} response."
                ),
                "recommendation": (
                    "Remove sensitive resources from the "
                    "public web root, restrict access using "
                    "authentication/authorization, and avoid "
                    "disclosing unnecessary sensitive paths "
                    "through robots.txt."
                ),
                "detection": (
                    "robots.txt endpoint validation"
                ),
                "evidence": (
                    f"robots.txt contains Disallow: {path}; "
                    f"the endpoint returned HTTP {status}."
                ),
                "url": endpoint_url,
            })

            continue

        # ----------------------------------------------------
        # Administrative interface
        # ----------------------------------------------------

        if is_admin_endpoint:

            findings.append({
                "type": "Administrative Interface Exposure",
                "category": "Security Misconfiguration",
                "name": (
                    f"Administrative Endpoint Disclosed: {path}"
                ),
                "severity": "Medium",
                "confidence": "Medium",
                "description": (
                    f"The endpoint '{path}' is disclosed "
                    "through robots.txt and appears to expose "
                    "an administrative or management interface."
                ),
                "recommendation": (
                    "Restrict administrative interfaces with "
                    "strong authentication and authorization. "
                    "Avoid relying on robots.txt as an access "
                    "control mechanism."
                ),
                "detection": (
                    "robots.txt endpoint validation"
                ),
                "evidence": (
                    f"robots.txt contains Disallow: {path}; "
                    f"the endpoint returned HTTP {status} and "
                    "appears administrative."
                ),
                "url": endpoint_url,
            })

            continue

        # ----------------------------------------------------
        # Generic accessible endpoint
        # ----------------------------------------------------

        if 200 <= status < 300:

            findings.append({
                "type": "Endpoint Exposure",
                "category": "Informational",
                "name": (
                    f"Robots.txt Disclosed Accessible Endpoint: {path}"
                ),
                "severity": "Low",
                "confidence": "High",
                "description": (
                    f"The endpoint '{path}' is explicitly "
                    "disclosed in robots.txt and is accessible."
                ),
                "recommendation": (
                    "Review whether the endpoint needs to be "
                    "listed in robots.txt. Remember that "
                    "robots.txt is not an access-control "
                    "mechanism."
                ),
                "detection": (
                    "robots.txt endpoint validation"
                ),
                "evidence": (
                    f"robots.txt contains Disallow: {path}; "
                    f"the endpoint returned HTTP {status}."
                ),
                "url": endpoint_url,
            })

    return findings