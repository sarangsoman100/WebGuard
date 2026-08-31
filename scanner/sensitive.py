import requests
from urllib.parse import urljoin, urlparse


SENSITIVE_RESOURCES = [
    {
        "path": "/.env",
        "name": "Exposed Environment File",
        "severity": "High",
        "description": (
            "An environment configuration file appears to be publicly "
            "accessible."
        ),
        "recommendation": (
            "Remove the file from the web root and ensure environment "
            "configuration files are never publicly accessible."
        ),
        "indicators": [
            "database_url=",
            "database_password=",
            "db_password=",
            "secret_key=",
            "api_key=",
            "app_secret=",
            "aws_access_key_id=",
        ],
    },
    {
        "path": "/.git/HEAD",
        "name": "Exposed Git Repository Metadata",
        "severity": "High",
        "description": (
            "Git repository metadata appears to be publicly accessible."
        ),
        "recommendation": (
            "Remove the .git directory from the web-accessible directory "
            "and block access to repository metadata."
        ),
        "indicators": [
            "ref: refs/",
            "ref: refs/heads/",
        ],
    },
    {
        "path": "/backup.zip",
        "name": "Exposed Backup Archive",
        "severity": "High",
        "description": (
            "A predictable backup archive appears to be publicly accessible."
        ),
        "recommendation": (
            "Remove backup archives from the web root and store backups "
            "outside publicly accessible directories."
        ),
        "binary": True,
    },
    {
        "path": "/backup.sql",
        "name": "Exposed Database Backup",
        "severity": "High",
        "description": (
            "A database backup file appears to be publicly accessible."
        ),
        "recommendation": (
            "Remove database dumps from the web root and store them "
            "outside publicly accessible directories."
        ),
        "indicators": [
            "create table",
            "insert into",
            "drop table",
            "-- mysql dump",
            "sqlite_sequence",
        ],
    },
    {
        "path": "/config.php.bak",
        "name": "Exposed Configuration Backup",
        "severity": "High",
        "description": (
            "A backup copy of a configuration file appears to be "
            "publicly accessible."
        ),
        "recommendation": (
            "Remove configuration backups from the web root and "
            "prevent backup files from being served."
        ),
        "indicators": [
            "<?php",
            "password",
            "database",
            "mysqli",
            "pdo",
        ],
    },
    {
        "path": "/.htaccess.bak",
        "name": "Exposed Web Server Configuration Backup",
        "severity": "Medium",
        "description": (
            "A backup copy of a web server configuration file "
            "appears to be publicly accessible."
        ),
        "recommendation": (
            "Remove configuration backups from the web root."
        ),
        "indicators": [
            "rewriteengine",
            "rewritecond",
            "rewriterule",
            "deny from",
            "allow from",
        ],
    },
    {
        "path": "/phpinfo.php",
        "name": "PHP Information Disclosure",
        "severity": "Medium",
        "description": (
            "A publicly accessible PHP information page may expose "
            "server and application configuration details."
        ),
        "recommendation": (
            "Remove phpinfo pages from production systems."
        ),
        "indicators": [
            "php version",
            "phpinfo()",
            "configuration",
            "loaded modules",
        ],
    },
]


def _looks_like_not_found(response):
    """
    Avoid reporting custom 404 pages as exposed resources.
    """

    if response.status_code in (404, 410):
        return True

    body = response.text[:5000].lower()

    not_found_markers = [
        "404 not found",
        "page not found",
        "file not found",
        "the requested url was not found",
    ]

    return any(
        marker in body
        for marker in not_found_markers
    )


def _contains_indicator(response, indicators):
    body = response.text[:20000].lower()

    return any(
        indicator.lower() in body
        for indicator in indicators
    )


def _is_zip(response):
    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    return (
        "zip" in content_type
        or response.content[:2] == b"PK"
    )


def _is_html(response):
    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    return "text/html" in content_type


def check_sensitive_exposure(base_url):
    """
    Check a conservative list of predictable sensitive resources.

    This detector does not perform broad directory brute forcing.
    A resource is reported only when its response matches expected
    content characteristics.
    """

    findings = []

    parsed = urlparse(base_url)

    root = (
        f"{parsed.scheme}://{parsed.netloc}"
    )

    for resource in SENSITIVE_RESOURCES:

        target = urljoin(
            root + "/",
            resource["path"].lstrip("/")
        )

        try:
            response = requests.get(
                target,
                timeout=5,
                allow_redirects=False,
            )

        except requests.RequestException:
            continue

        # -----------------------------------------------------
        # Ignore obvious missing resources
        # -----------------------------------------------------

        if _looks_like_not_found(response):
            continue

        # -----------------------------------------------------
        # Redirects are not exposure by themselves
        # -----------------------------------------------------

        if response.status_code in (
            301,
            302,
            303,
            307,
            308,
        ):
            continue

        # -----------------------------------------------------
        # We normally require successful retrieval
        # -----------------------------------------------------

        if response.status_code != 200:
            continue

        # -----------------------------------------------------
        # ZIP backup
        # -----------------------------------------------------

        if resource.get("binary"):

            if not _is_zip(response):
                continue

            findings.append({
                "type": "Sensitive File Exposure",
                "category": "Vulnerability",
                "name": resource["name"],
                "severity": resource["severity"],
                "confidence": "High",
                "description": resource["description"],
                "recommendation": resource["recommendation"],
                "detection": "Known sensitive-resource check",
                "evidence": (
                    f"HTTP 200 from {target} with ZIP content "
                    "signature detected."
                ),
                "url": target,
            })

            continue

        # -----------------------------------------------------
        # Content-based resources
        # -----------------------------------------------------

        indicators = resource.get(
            "indicators",
            []
        )

        if not indicators:
            continue

        if not _contains_indicator(
            response,
            indicators
        ):
            continue

        findings.append({
            "type": "Sensitive File Exposure",
            "category": "Vulnerability",
            "name": resource["name"],
            "severity": resource["severity"],
            "confidence": "High",
            "description": resource["description"],
            "recommendation": resource["recommendation"],
            "detection": "Known sensitive-resource check",
            "evidence": (
                f"HTTP 200 from {target}; response contained "
                "content indicators associated with the exposed "
                "resource."
            ),
            "url": target,
        })

    return findings