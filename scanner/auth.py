import re
from urllib.parse import urljoin, urlparse

import requests


PASSWORD_FIELD_NAMES = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "current_password",
    "new_password",
}


USERNAME_FIELD_NAMES = {
    "username",
    "user",
    "email",
    "login",
    "userid",
    "user_id",
}


def _normalize_name(name):
    return (
        str(name or "")
        .strip()
        .lower()
        .replace("-", "_")
    )


def _extract_forms(html, page_url):
    forms = []

    matches = re.findall(
        r"<form\b([^>]*)>(.*?)</form>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    for attributes, body in matches:

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

        names = []

        for input_attributes in inputs:

            name_match = re.search(
                r'\bname\s*=\s*["\']([^"\']+)["\']',
                input_attributes,
                flags=re.IGNORECASE,
            )

            type_match = re.search(
                r'\btype\s*=\s*["\']([^"\']+)["\']',
                input_attributes,
                flags=re.IGNORECASE,
            )

            name = (
                name_match.group(1)
                if name_match
                else ""
            )

            field_type = (
                type_match.group(1).lower()
                if type_match
                else "text"
            )

            names.append({
                "name": name,
                "type": field_type,
            })

        forms.append({
            "method": method,
            "action": action_url,
            "inputs": names,
        })

    return forms


def check_authentication_security(url):
    """
    Identify authentication forms and perform conservative
    transport-security checks.

    This does not attempt login credentials.
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

        password_fields = [
            field
            for field in form["inputs"]
            if (
                field["type"] == "password"
                or _normalize_name(field["name"])
                in PASSWORD_FIELD_NAMES
            )
        ]

        if not password_fields:
            continue

        # ----------------------------------------------------
        # Authentication form identified
        # ----------------------------------------------------

        action_url = form["action"]
        action_parsed = urlparse(action_url)

        # ----------------------------------------------------
        # Cross-origin authentication endpoint
        # ----------------------------------------------------

        if (
            action_parsed.netloc.lower()
            != parsed.netloc.lower()
        ):

            findings.append({
                "type": "Authentication Security",
                "category": "Potential Vulnerability",
                "name": "Cross-Origin Authentication Form",
                "severity": "Medium",
                "confidence": "Medium",
                "description": (
                    "A password-containing authentication form "
                    "submits credentials to a different origin."
                ),
                "recommendation": (
                    "Review the authentication endpoint and ensure "
                    "credentials are submitted only to a trusted "
                    "HTTPS origin."
                ),
                "detection": (
                    "Authentication form analysis"
                ),
                "evidence": (
                    f"Password form submits to: {action_url}"
                ),
                "url": response.url,
            })

            continue

        # ----------------------------------------------------
        # Password form submitted over HTTP
        # ----------------------------------------------------

        if action_parsed.scheme.lower() == "http":

            findings.append({
                "type": "Authentication Security",
                "category": "Vulnerability",
                "name": "Credentials Submitted Over HTTP",
                "severity": "High",
                "confidence": "High",
                "description": (
                    "A password-containing authentication form "
                    "submits credentials over unencrypted HTTP."
                ),
                "recommendation": (
                    "Submit authentication credentials exclusively "
                    "over HTTPS and enforce HTTPS for authentication "
                    "endpoints."
                ),
                "detection": (
                    "Authentication transport analysis"
                ),
                "evidence": (
                    f"Password form action uses HTTP: {action_url}"
                ),
                "url": response.url,
            })

    return findings