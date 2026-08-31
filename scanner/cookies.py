def check_cookies(response):

    findings = []

    set_cookie_headers = response.raw.headers.get_all(
        "Set-Cookie"
    )

    if not set_cookie_headers:
        return findings

    for cookie_header in set_cookie_headers:

        cookie_parts = [
            part.strip()
            for part in cookie_header.split(";")
        ]

        cookie_name = cookie_parts[0].split("=", 1)[0]

        attributes = {
            part.split("=", 1)[0].strip().lower()
            for part in cookie_parts[1:]
        }

        missing = []

        if "secure" not in attributes:
            missing.append("Secure")

        if "httponly" not in attributes:
            missing.append("HttpOnly")

        if not any(
            attribute.startswith("samesite")
            for attribute in attributes
        ):
            missing.append("SameSite")

        if missing:

            severity = "High"

            if len(missing) == 1:
                severity = "Medium"

            findings.append({
                "type": "Cookie Security",
                "category": "Security Misconfiguration",
                "name": f"Insecure Cookie: {cookie_name}",
                "severity": severity,
                "confidence": "High",
                "description": (
                    f"The '{cookie_name}' cookie is missing "
                    f"important security attributes: "
                    f"{', '.join(missing)}."
                ),
                "recommendation": (
                    "Configure the cookie with appropriate "
                    "Secure, HttpOnly, and SameSite attributes."
                )
            })

    return findings