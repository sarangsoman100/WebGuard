import re
from urllib.parse import urljoin, urlparse

import requests


# Common names used for CSRF protection tokens.
CSRF_TOKEN_NAMES = {
    "csrf",
    "csrf_token",
    "csrftoken",
    "csrf-token",
    "_csrf",
    "_csrf_token", 
    "xsrf",
    "xsrf_token",
    "xsrf-token",
    "_xsrf",
    "authenticity_token",
}


STATE_CHANGING_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


def _normalize_name(name):
    return (
        str(name or "")
        .strip()
        .lower()
        .replace("-", "_")
    )


def _looks_like_csrf_token(name):
    normalized = _normalize_name(name)

    if normalized in {
        name.replace("-", "_")
        for name in CSRF_TOKEN_NAMES
    }:
        return True

    return (
        "csrf" in normalized
        or "xsrf" in normalized
        or "authenticity_token" in normalized
    )


def _extract_forms(html, page_url):
    """
    Extract basic HTML form information.

    This is intentionally lightweight and does not execute
    JavaScript.
    """

    forms = []

    form_matches = re.findall(
        r"<form\b([^>]*)>(.*?)</form>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    for attributes, body in form_matches:

        method_match = re.search(
            r'\bmethod\s*=\s*["\']?([^"\'\s>]+)',
            attributes,
            flags=re.IGNORECASE,
        )

        action_match = re.search(
            r'\baction\s*=\s*["\']([^"\']*)["\']',
            attributes,
            flags=re.IGNORECASE,
        )

        method = (
            method_match.group(1).upper()
            if method_match
            else "GET"
        )

        action = (
            action_match.group(1)
            if action_match
            else page_url
        )

        action_url = urljoin(
            page_url,
            action,
        )

        inputs = re.findall(
            r"<input\b([^>]*)>",
            body,
            flags=re.IGNORECASE | re.DOTALL,
        )

        input_names = []

        for input_attributes in inputs:

            name_match = re.search(
                r'\bname\s*=\s*["\']([^"\']+)["\']',
                input_attributes,
                flags=re.IGNORECASE,
            )

            if name_match:
                input_names.append(
                    name_match.group(1)
                )

        forms.append({
            "method": method,
            "action": action_url,
            "inputs": input_names,
        })

    return forms


def check_csrf(url):
    """
    Detect potentially unsafe state-changing HTML forms
    that do not contain an obvious CSRF token.

    This detector does not claim exploitability by itself.
    """

    findings = []

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return findings

    try:

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
        )

    except requests.RequestException:
        return findings

    if response.status_code != 200:
        return findings

    content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
        .lower()
    )

    if (
        "text/html" not in content_type
        and "<form" not in response.text.lower()
    ):
        return findings

    forms = _extract_forms(
        response.text,
        response.url,
    )

    for form in forms:

        method = form["method"]

        # GET forms are normally not treated as CSRF state-changing
        # operations by this detector.
        if method not in STATE_CHANGING_METHODS:
            continue

        action_url = form["action"]

        action_parsed = urlparse(
            action_url
        )

        # Only inspect same-origin forms.
        if (
            action_parsed.scheme.lower()
            != parsed.scheme.lower()
            or action_parsed.netloc.lower()
            != parsed.netloc.lower()
        ):
            continue

        token_names = [
            name
            for name in form["inputs"]
            if _looks_like_csrf_token(name)
        ]

        if token_names:
            continue

        findings.append({
            "type": "CSRF Protection",
            "category": "Potential Vulnerability",
            "name": "Potential CSRF: Missing Anti-CSRF Token",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                f"A state-changing {method} form was found at "
                f"'{action_url}' without an obvious anti-CSRF "
                "token."
            ),
            "recommendation": (
                "Use a strong, unpredictable anti-CSRF token "
                "for state-changing requests and validate it "
                "server-side. SameSite cookies and appropriate "
                "origin/referrer validation can provide "
                "additional protection."
            ),
            "detection": (
                "HTML form CSRF token analysis"
            ),
            "evidence": (
                f"{method} form action '{action_url}' contains "
                "no input whose name appears to represent a "
                "CSRF/XSRF protection token."
            ),
            "url": response.url,
        })

    return findings