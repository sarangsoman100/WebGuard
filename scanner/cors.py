import requests


def _request_with_origin(url, origin):
    """
    Send a harmless GET request with a controlled Origin header.
    """

    try:
        return requests.get(
            url,
            headers={
                "Origin": origin
            },
            timeout=5,
            allow_redirects=False
        )

    except requests.RequestException:
        return None


def check_cors(url):
    """
    Detect potentially unsafe CORS configurations.

    Checks:

    1. Wildcard origin + credentials
    2. Arbitrary origin reflection
    3. Origin reflection with credentials

    Does not treat every CORS response as a vulnerability.
    """

    findings = []

    test_origin = "https://webguard-cors-test.example"

    response = _request_with_origin(
        url,
        test_origin
    )

    if response is None:
        return findings


    allow_origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_credentials = response.headers.get(
        "Access-Control-Allow-Credentials",
        ""
    ).lower()


    if not allow_origin:
        return findings


    # =========================================================
    # CASE 1
    # Wildcard + credentials
    # =========================================================

    if (
        allow_origin.strip() == "*"
        and allow_credentials == "true"
    ):

        findings.append({

            "type": "CORS Misconfiguration",

            "category": "Vulnerability",

            "name": "CORS Wildcard With Credentials",

            "severity": "High",

            "confidence": "High",

            "description": (
                "The target allows cross-origin requests from "
                "any origin while also enabling credentials."
            ),

            "recommendation": (
                "Restrict Access-Control-Allow-Origin to trusted "
                "origins and avoid allowing credentials with a "
                "wildcard origin."
            ),

            "detection": "Wildcard origin with credentials",

            "evidence": (
                "Access-Control-Allow-Origin: * and "
                "Access-Control-Allow-Credentials: true "
                "were observed in the response."
            ),

            "url": url
        })

        return findings


    # =========================================================
    # CASE 2
    # Arbitrary origin reflection
    # =========================================================

    if allow_origin.strip() == test_origin:

        # -----------------------------------------------------
        # Reflection + credentials
        # -----------------------------------------------------

        if allow_credentials == "true":

            findings.append({

                "type": "CORS Misconfiguration",

                "category": "Vulnerability",

                "name": "Arbitrary Origin Reflection",

                "severity": "High",

                "confidence": "High",

                "description": (
                    "The target reflects an arbitrary Origin "
                    "value and permits credentials for that "
                    "cross-origin request."
                ),

                "recommendation": (
                    "Validate the Origin against an explicit "
                    "allowlist of trusted origins. Do not "
                    "reflect arbitrary Origin values when "
                    "credentials are permitted."
                ),

                "detection": (
                    "Arbitrary origin reflection with credentials"
                ),

                "evidence": (
                    f"The supplied Origin '{test_origin}' was "
                    "reflected through "
                    "Access-Control-Allow-Origin while "
                    "Access-Control-Allow-Credentials was true."
                ),

                "url": url
            })

        # -----------------------------------------------------
        # Reflection without credentials
        # -----------------------------------------------------

        else:

            findings.append({

                "type": "CORS Misconfiguration",

                "category": "Potential Vulnerability",

                "name": "Arbitrary CORS Origin Reflection",

                "severity": "Medium",

                "confidence": "Medium",

                "description": (
                    "The target reflects an arbitrary Origin "
                    "value in Access-Control-Allow-Origin."
                ),

                "recommendation": (
                    "Restrict CORS origins to trusted domains "
                    "instead of reflecting arbitrary Origin "
                    "values."
                ),

                "detection": "Arbitrary origin reflection",

                "evidence": (
                    f"The supplied Origin '{test_origin}' was "
                    "reflected through "
                    "Access-Control-Allow-Origin."
                ),

                "url": url
            })


    # =========================================================
    # CASE 3
    # Wildcard without credentials
    #
    # This is NOT automatically treated as a vulnerability.
    # =========================================================

    return findings