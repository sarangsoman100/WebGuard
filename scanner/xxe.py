import requests


# ============================================================
# XXE Detection
# ============================================================

XXE_MARKER = "WEBGUARD_XXE_TEST"


SAFE_XXE_PAYLOAD = f"""<?xml version="1.0"?>
<!DOCTYPE test [
    <!ENTITY webguard "{XXE_MARKER}">
]>
<test>&webguard;</test>
"""


def _looks_like_xml(response):
    """
    Determine whether a response appears to contain XML.
    """

    content_type = (
        response.headers.get("Content-Type", "")
        .lower()
    )

    return (
        "xml" in content_type
        or "application/xml" in content_type
        or "text/xml" in content_type
    )


def check_xxe(url):
    """
    Conservative XXE detection.

    Sends a harmless XML entity payload and checks whether
    the server processes the entity.

    This does NOT attempt:
        - local file reads
        - cloud metadata access
        - internal network access
        - external entity callbacks
    """

    try:

        response = requests.post(
            url,
            data=SAFE_XXE_PAYLOAD,
            headers={
                "Content-Type": "application/xml",
            },
            timeout=5,
            allow_redirects=False,
        )

    except requests.RequestException:

        return None

    body = response.text[:10000]

    # --------------------------------------------------------
    # Entity expansion observed
    # --------------------------------------------------------

    if XXE_MARKER in body:

        return {
            "type": "XXE",
            "category": "Potential Vulnerability",
            "name": "Potential XML External Entity Injection",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The XML parser appears to process an XML entity "
                "supplied in the request."
            ),
            "recommendation": (
                "Disable external entity processing and DTD "
                "processing where they are not required. Use a "
                "secure XML parser configuration and validate "
                "untrusted XML input."
            ),
            "detection": (
                "Safe XML entity expansion test"
            ),
            "evidence": (
                f"The controlled XML entity marker "
                f"'{XXE_MARKER}' appeared in the response."
            ),
            "url": url,
        }

    # --------------------------------------------------------
    # XML parser error indicators
    # --------------------------------------------------------

    xml_error_indicators = (
        "xml parse error",
        "xml parsing error",
        "doctype is disallowed",
        "entity",
        "dtd",
        "external entity",
        "xmlsyntaxerror",
        "saxparseexception",
    )

    body_lower = body.lower()

    if (
        response.status_code >= 400
        and any(
            indicator in body_lower
            for indicator in xml_error_indicators
        )
    ):

        return {
            "type": "XXE",
            "category": "Potential Vulnerability",
            "name": "Potential XML Parser Injection",
            "severity": "Medium",
            "confidence": "Low",
            "description": (
                "The endpoint appears to process XML input and "
                "returned an XML parser-related error when "
                "supplied with a controlled entity declaration."
            ),
            "recommendation": (
                "Use a securely configured XML parser and disable "
                "DTD and external entity processing unless "
                "explicitly required."
            ),
            "detection": (
                "XML parser error analysis"
            ),
            "evidence": (
                "The response contained an XML parser-related "
                "error after the controlled XML entity test."
            ),
            "url": url,
        }

    return None