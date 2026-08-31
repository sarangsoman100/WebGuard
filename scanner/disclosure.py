def check_information_disclosure(response):

    findings = []

    server = response.headers.get("Server")

    powered_by = response.headers.get("X-Powered-By")

    if server:

        findings.append({
            "type": "Information Disclosure",
            "category": "Informational",
            "name": "Server Information Disclosure",
            "severity": "Low",
            "confidence": "High",
            "description": (
                f"The server response reveals server information: "
                f"{server}."
            ),
            "recommendation": (
                "Avoid exposing unnecessary server software "
                "and version information in HTTP headers."
            )
        })

    if powered_by:

        findings.append({
            "type": "Information Disclosure",
            "category": "Informational",
            "name": "Technology Information Disclosure",
            "severity": "Low",
            "confidence": "High",
            "description": (
                f"The X-Powered-By header reveals technology "
                f"information: {powered_by}."
            ),
            "recommendation": (
                "Remove or suppress the X-Powered-By header "
                "where possible."
            )
        })

    return findings