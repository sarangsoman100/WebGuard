import html
import re

import requests


MARKER = "WebGuardXSSTest"


def _classify_reflection(body, marker):
    """
    Determine where the reflection occurs.

    Returns:
        context, encoded
    """

    # ---------------------------------------------------------
    # JavaScript context
    # ---------------------------------------------------------

    javascript_patterns = [
        rf"<script[^>]*>.*?{re.escape(marker)}.*?</script>",
        rf"\b(?:var|let|const)\s+\w+\s*=\s*['\"].*?"
        rf"{re.escape(marker)}.*?['\"]",
    ]

    for pattern in javascript_patterns:

        if re.search(
            pattern,
            body,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            return "JavaScript", False

    # ---------------------------------------------------------
    # HTML attribute context
    # ---------------------------------------------------------

    attribute_pattern = (
        rf'\b[\w:-]+\s*=\s*["\'][^"\']*'
        rf'{re.escape(marker)}[^"\']*["\']'
    )

    if re.search(
        attribute_pattern,
        body,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        return "HTML attribute", False

    # ---------------------------------------------------------
    # HTML text context
    # ---------------------------------------------------------

    if marker in body:
        return "HTML text", False

    return "Unknown", False


def check_reflected_xss(
    url,
    parameter,
    mode="standard",
):
    """
    Safe reflected-XSS indicator.

    This detector uses a harmless reflection marker rather than
    an executable XSS payload.

    Reflection alone is NOT treated as confirmed XSS.

    The detector attempts to determine whether the marker appears
    in:
        - HTML text
        - HTML attributes
        - JavaScript
        - encoded output
    """

    try:

        response = requests.get(
            url,
            params={
                parameter: MARKER
            },
            timeout=5,
            allow_redirects=True,
        )

    except requests.RequestException:
        return None

    # ---------------------------------------------------------
    # Ignore server errors
    # ---------------------------------------------------------

    if response.status_code >= 500:
        return None

    body = response.text

    # ---------------------------------------------------------
    # Marker not reflected
    # ---------------------------------------------------------

    if MARKER not in body and html.escape(MARKER) not in body:
        return None

    # ---------------------------------------------------------
    # Determine reflection context
    # ---------------------------------------------------------

    context, encoded = _classify_reflection(
        body,
        MARKER,
    )

    # ---------------------------------------------------------
    # Encoded reflection is not reported
    # ---------------------------------------------------------

    if encoded:
        return None

    # ---------------------------------------------------------
    # Context-specific severity/confidence
    # ---------------------------------------------------------

    if context == "JavaScript":

        severity = "High"
        confidence = "High"

        description = (
            f"The parameter '{parameter}' was reflected inside "
            "a JavaScript context without evidence of output encoding."
        )

    elif context == "HTML attribute":

        severity = "High"
        confidence = "Medium"

        description = (
            f"The parameter '{parameter}' was reflected inside "
            "an HTML attribute without evidence of appropriate "
            "output encoding."
        )

    elif context == "HTML text":

        severity = "Medium"
        confidence = "Medium"

        description = (
            f"The parameter '{parameter}' was reflected into "
            "HTML response content. Reflection was detected, but "
            "this alone does not confirm executable XSS."
        )

    else:

        severity = "Medium"
        confidence = "Low"

        description = (
            f"The parameter '{parameter}' was reflected in the "
            "HTTP response, but the scanner could not confidently "
            "determine the reflection context."
        )

    return {
        "type": "Reflected XSS",
        "category": "Potential Vulnerability",
        "name": f"Potential Reflected XSS: {parameter}",
        "severity": severity,
        "confidence": confidence,

        "description": description,

        "recommendation": (
            "Apply context-appropriate output encoding, validate "
            "untrusted input, and avoid inserting untrusted data "
            "into HTML, attribute, or JavaScript contexts."
        ),

        "parameter": parameter,

        "detection": "Context-aware benign reflection analysis",

        "context": context,

        "evidence": (
            f"The marker '{MARKER}' was reflected in the "
            f"{context} context without evidence of HTML encoding."
        ),

        "url": response.url,
    }