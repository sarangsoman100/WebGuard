def check_http_methods(response):

    findings = []

    allow_header = response.headers.get("Allow", "")

    if not allow_header:
        return findings

    methods = {
        method.strip().upper()
        for method in allow_header.split(",")
    }

    dangerous_methods = []

    if "PUT" in methods:
        dangerous_methods.append("PUT")

    if "DELETE" in methods:
        dangerous_methods.append("DELETE")

    if "TRACE" in methods:
        dangerous_methods.append("TRACE")

    if dangerous_methods:

        findings.append({
            "type": "HTTP Method Security",
            "category": "Security Misconfiguration",
            "name": "Potentially Risky HTTP Methods Enabled",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The target advertises potentially risky HTTP "
                f"methods: {', '.join(dangerous_methods)}."
            ),
            "recommendation": (
                "Disable HTTP methods that are not required "
                "by the application."
            )
        })

    return findings