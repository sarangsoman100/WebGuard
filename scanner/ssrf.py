import re
from urllib.parse import parse_qs, urlencode, urlparse

import requests


# ============================================================
# Configuration
# ============================================================

SSRF_MARKER_HOST = "webguard-ssrf-test.example"

URL_PARAMETER_HINTS = {
    "url",
    "uri",
    "link",
    "redirect",
    "next",
    "target",
    "dest",
    "destination",
    "return",
    "return_url",
    "redirect_url",
    "callback",
    "endpoint",
    "image",
    "file",
    "feed",
    "source",
}


def _looks_like_url_parameter(parameter):
    """
    Identify parameters that commonly contain URLs.
    """

    name = str(parameter or "").strip().lower()

    normalized = re.sub(
        r"[^a-z0-9_]",
        "_",
        name,
    )

    if normalized in URL_PARAMETER_HINTS:
        return True

    return any(
        keyword in normalized
        for keyword in (
            "url",
            "uri",
            "redirect",
            "callback",
            "return",
            "destination",
            "target",
        )
    )


def _replace_parameter(url, parameter, value):
    """
    Replace a query parameter while preserving other parameters.
    """

    parsed = urlparse(url)

    query = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    query[parameter] = [value]

    new_query = urlencode(
        query,
        doseq=True,
    )

    return parsed._replace(
        query=new_query,
    ).geturl()


def _finding(
    url,
    parameter,
    detection,
    evidence,
):
    """
    Build a standard SSRF finding.
    """

    return {
        "type": "SSRF",
        "category": "Potential Vulnerability",
        "name": f"Potential SSRF: {parameter}",
        "severity": "High",
        "confidence": "High",
        "description": (
            f"The parameter '{parameter}' appears to allow "
            "server-side retrieval of a user-controlled URL."
        ),
        "recommendation": (
            "Do not allow arbitrary user-controlled URLs to be "
            "fetched server-side. Validate destinations against "
            "an explicit allowlist and restrict unnecessary "
            "outbound network access."
        ),
        "parameter": parameter,
        "detection": detection,
        "evidence": evidence,
        "url": url,
    }


def check_ssrf(url, parameter):
    """
    Conservative SSRF detector.

    The detector only considers observable server-side behavior.
    Simple reflection of a supplied URL is NOT treated as SSRF.

    For the local WebGuard lab, a controlled marker endpoint can
    be used to validate server-side fetching.

    No private-network or cloud-metadata probing is performed.
    """

    if not parameter:
        return None

    if not _looks_like_url_parameter(parameter):
        return None

    parsed = urlparse(url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
    ):
        return None

    # ========================================================
    # Local WebGuard lab verification
    # ========================================================

    is_local_lab = (
        parsed.hostname in {
            "127.0.0.1",
            "localhost",
        }
        and parsed.port == 5001
    )

    if is_local_lab:

        marker_target = (
            "http://127.0.0.1:5001/ssrf-marker"
        )

        test_url = _replace_parameter(
            url,
            parameter,
            marker_target,
        )

        try:

            response = requests.get(
                test_url,
                timeout=5,
                allow_redirects=False,
            )

        except requests.RequestException:

            return None

        # ----------------------------------------------------
        # The lab endpoint returns a controlled marker when
        # /fetch actually performs the server-side request.
        # ----------------------------------------------------

        if (
            "WEBGUARD_SSRF_MARKER"
            in response.text
        ):

            return _finding(
                url=url,
                parameter=parameter,
                detection=(
                    "Controlled local server-side request"
                ),
                evidence=(
                    "The local WebGuard lab returned the "
                    "controlled SSRF marker after the supplied "
                    "URL parameter was replaced with the lab "
                    "marker endpoint."
                ),
            )

        # ----------------------------------------------------
        # A reflected URL is not SSRF.
        # ----------------------------------------------------

        return None

    # ========================================================
    # Generic authorized target check
    # ========================================================

    marker_url = (
        f"https://{SSRF_MARKER_HOST}/"
    )

    test_url = _replace_parameter(
        url,
        parameter,
        marker_url,
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
    # A redirect to the supplied destination is not enough
    # to prove SSRF. It is handled by the Open Redirect
    # detector instead.
    # --------------------------------------------------------

    return None