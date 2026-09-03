import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


# ============================================================
# Supported Redirect Parameters
# ============================================================

REDIRECT_PARAMETERS = {
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "return",
    "return_url",
    "returnurl",
    "continue",
    "dest",
    "destination",
    "target",
    "link",
}


# ============================================================
# Controlled Test Destination
# ============================================================

TEST_DESTINATION = "https://webguard-redirect-test.example/"


# ============================================================
# Replace / Add Parameter
# ============================================================

def _replace_parameter(url, parameter, value):
    parsed = urlparse(url)

    query = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    updated = []
    parameter_found = False

    for key, current_value in query:

        if key.lower() == parameter.lower():

            updated.append(
                (key, value)
            )

            parameter_found = True

        else:

            updated.append(
                (key, current_value)
            )

    # --------------------------------------------------------
    # Endpoint-hint parameters may not already exist in URL.
    # Add the parameter when it is missing.
    # --------------------------------------------------------

    if not parameter_found:

        updated.append(
            (parameter, value)
        )

    new_query = urlencode(
        updated,
        doseq=True,
    )

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


# ============================================================
# Open Redirect Detection
# ============================================================

def check_open_redirect(url, parameter):
    """
    Detect potential open redirects using a controlled
    external destination.

    Only reports a finding when the application actually
    redirects to the supplied external destination.
    """

    if not parameter:
        return None

    if parameter.lower() not in REDIRECT_PARAMETERS:
        return None

    test_url = _replace_parameter(
        url,
        parameter,
        TEST_DESTINATION,
    )

    try:

        response = requests.get(
            test_url,
            timeout=5,
            allow_redirects=False,
        )

    except requests.RequestException:

        return None

    # --------------------------------------------------------
    # Only redirect responses are interesting
    # --------------------------------------------------------

    if response.status_code not in (
        301,
        302,
        303,
        307,
        308,
    ):
        return None

    location = response.headers.get(
        "Location",
        "",
    ).strip()

    if not location:
        return None

    # --------------------------------------------------------
    # Parse redirect destination
    # --------------------------------------------------------

    location_parsed = urlparse(
        location,
    )

    test_parsed = urlparse(
        TEST_DESTINATION,
    )

    # --------------------------------------------------------
    # Confirm external destination
    # --------------------------------------------------------

    if (
        location_parsed.scheme.lower()
        != test_parsed.scheme.lower()
    ):
        return None

    if (
        location_parsed.netloc.lower()
        != test_parsed.netloc.lower()
    ):
        return None

    # --------------------------------------------------------
    # Confirmed finding
    # --------------------------------------------------------

    return {
        "type": "Open Redirect",
        "category": "Vulnerability",
        "name": (
            f"Open Redirect: {parameter}"
        ),
        "severity": "Medium",
        "confidence": "High",
        "description": (
            f"The parameter '{parameter}' allows the application "
            "to redirect the client to an externally controlled "
            "destination."
        ),
        "recommendation": (
            "Validate redirect destinations against an explicit "
            "allowlist of trusted URLs or use server-side route "
            "identifiers instead of accepting arbitrary URLs."
        ),
        "parameter": parameter,
        "detection": "Controlled external redirect",
        "evidence": (
            f"The supplied external destination "
            f"'{TEST_DESTINATION}' was returned through the "
            f"Location header: '{location}'."
        ),
        "url": url,
    }