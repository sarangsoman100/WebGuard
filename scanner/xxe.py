import requests

XXE_MARKER = "WEBGUARD_XXE_TEST"

SAFE_XXE_PAYLOAD = f"""<?xml version="1.0"?>
<!DOCTYPE test [
    <!ENTITY webguard "{XXE_MARKER}">
]>
<test>&webguard;</test>
"""


def _looks_like_xml(response):
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
    Conservative XML entity-processing detection.

    This test uses only a harmless local XML entity. It does not
    attempt local file reads, metadata access, internal network access,
    external callbacks, or data exfiltration.

    A positive result proves XML entity processing, not external entity
    resolution, so it is intentionally classified as a potential
    XML entity-processing issue.
    """
    try:
        response = requests.post(
            url,
            data=SAFE_XXE_PAYLOAD,
            headers={"Content-Type": "application/xml"},
            timeout=5,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None

    body = response.text[:10000]

    if XXE_MARKER in body:
        return {
            "type": "XXE",
            "category": "Potential Vulnerability",
            "name": "Potential XML Entity Processing",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The XML endpoint processed a controlled entity "
                "declaration supplied in the request. This indicates "
                "XML entity processing, but the safe test does not "
                "establish external entity resolution."
            ),
            "recommendation": (
                "Disable DTD and external entity processing unless "
                "explicitly required. Use a securely configured XML "
                "parser and validate untrusted XML input."
            ),
            "detection": "Safe XML entity expansion test",
            "evidence": (
                f"The controlled XML entity marker '{XXE_MARKER}' "
                "appeared in the response."
            ),
            "url": url,
        }

    # Deliberately narrow indicators to avoid false positives from
    # generic words such as "entity" or "dtd".
    xml_error_indicators = (
        "xml parse error",
        "xml parsing error",
        "doctype is disallowed",
        "doctype declaration is disallowed",
        "external entity",
        "xmlsyntaxerror",
        "saxparseexception",
        "undefined entity",
        "entity reference",
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
                "returned a specific XML parser-related error after "
                "a controlled entity declaration was supplied."
            ),
            "recommendation": (
                "Use a securely configured XML parser and disable "
                "DTD and external entity processing unless explicitly "
                "required."
            ),
            "detection": "XML parser error analysis",
            "evidence": (
                "The response contained a specific XML parser error "
                "associated with XML entity processing."
            ),
            "url": url,
        }

    return None
