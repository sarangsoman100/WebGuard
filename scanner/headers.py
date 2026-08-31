SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Helps prevent XSS and other code-injection attacks."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Forces browsers to use HTTPS for the application."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Helps protect against clickjacking attacks."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Prevents browsers from MIME-sniffing responses."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information browsers send."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Controls access to browser features and APIs."
    }
}


def check_security_headers(response_headers):
    findings = []

    # Convert headers to lowercase for case-insensitive comparison
    existing_headers = {
        key.lower(): value
        for key, value in response_headers.items()
    }

    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in existing_headers:
            findings.append({
                "type": "Missing Security Header",
                "category": "Security Misconfiguration",
                "name": header,
                "severity": info["severity"],
                "confidence": "High",
                "description": info["description"],
                "recommendation": (
                    f"Configure the {header} HTTP response header."
                )
            })

    return findings