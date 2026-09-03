from urllib.parse import (
    urlparse,
    parse_qs,
    urlunparse,
)

import requests

from bs4 import BeautifulSoup


# ============================================================
# Common Parameter Hints
# ============================================================

COMMON_PARAMETER_HINTS = {
    "id",
    "q",
    "query",
    "search",
    "url",
    "uri",
    "link",
    "next",
    "target",
    "dest",
    "destination",
    "redirect",
    "redirect_url",
    "return",
    "return_url",
    "callback",
    "endpoint",
    "image",
    "file",
    "feed",
    "source",
}


# ============================================================
# URL Parameter Discovery
# ============================================================

def _discover_query_parameters(
    url,
    parameters,
):
    parsed = urlparse(url)

    query_params = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    clean_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        "",
        "",
        "",
    ))

    for name in query_params:

        item = {
            "url": clean_url,
            "parameter": name,
            "method": "GET",
            "source": "query",
        }

        if item not in parameters:
            parameters.append(item)


# ============================================================
# HTML Form Parameter Discovery
# ============================================================

def _discover_form_parameters(
    url,
    parameters,
    response,
):
    content_type = response.headers.get(
        "Content-Type",
        "",
    )

    if "text/html" not in content_type.lower():
        return

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    parsed_base = urlparse(url)

    for form in soup.find_all("form"):

        action = form.get(
            "action"
        ) or url

        action_parsed = urlparse(action)

        scheme = (
            action_parsed.scheme
            or parsed_base.scheme
        )

        netloc = (
            action_parsed.netloc
            or parsed_base.netloc
        )

        path = (
            action_parsed.path
            or parsed_base.path
        )

        if scheme not in (
            "http",
            "https",
        ):
            continue

        # Only inspect same-host forms.
        if netloc.lower() != parsed_base.netloc.lower():
            continue

        form_url = urlunparse((
            scheme,
            netloc,
            path,
            "",
            "",
            "",
        ))

        method = (
            form.get("method")
            or "GET"
        ).upper()

        if method not in (
            "GET",
            "POST",
        ):
            method = "GET"

        for input_field in form.find_all(
            [
                "input",
                "textarea",
                "select",
            ]
        ):

            name = input_field.get(
                "name"
            )

            if not name:
                continue

            item = {
                "url": form_url,
                "parameter": name,
                "method": method,
                "source": "form",
            }

            if item not in parameters:
                parameters.append(item)


# ============================================================
# Common Endpoint Parameter Discovery
# ============================================================

def _discover_common_parameters(
    url,
    parameters,
):
    """
    Add conservative parameter candidates for endpoints
    whose parameters are not visible in the URL or HTML.

    These are hints only. The actual scanner decides whether
    a parameter should be actively tested.
    """

    parsed = urlparse(url)

    path = (
        parsed.path
        or "/"
    ).lower()

    endpoint_hints = {}

    # --------------------------------------------------------
    # User / product style endpoints
    # --------------------------------------------------------

    if (
        path.endswith("/user")
        or path.endswith("/product")
        or path.endswith("/item")
    ):

        endpoint_hints["id"] = "GET"

    # --------------------------------------------------------
    # Search endpoints
    # --------------------------------------------------------

    if (
        path.endswith("/search")
        or "/search/" in path
    ):

        endpoint_hints["q"] = "GET"

    # --------------------------------------------------------
    # URL-fetching endpoints
    # --------------------------------------------------------

    if (
        path.endswith("/fetch")
        or path.endswith("/proxy")
        or path.endswith("/download")
    ):

        endpoint_hints["url"] = "GET"

    # --------------------------------------------------------
    # Redirect endpoints
    # --------------------------------------------------------

    if (
        path.endswith("/redirect")
        or path.endswith("/redirect/")
    ):

        endpoint_hints["next"] = "GET"

    # --------------------------------------------------------
    # Add discovered hints
    # --------------------------------------------------------

    clean_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        "",
        "",
        "",
    ))

    for name, method in endpoint_hints.items():

        item = {
            "url": clean_url,
            "parameter": name,
            "method": method,
            "source": "endpoint-hint",
        }

        if item not in parameters:
            parameters.append(item)


# ============================================================
# Main Parameter Discovery
# ============================================================

def discover_parameters(url):
    """
    Discover input parameters from:

    1. Existing URL query strings
    2. HTML GET/POST forms
    3. Conservative endpoint-specific parameter hints

    Parameter discovery does not perform vulnerability testing.
    """

    parameters = []

    parsed = urlparse(url)

    if (
        parsed.scheme not in (
            "http",
            "https",
        )
        or not parsed.netloc
    ):
        return parameters

    # --------------------------------------------------------
    # Existing query parameters
    # --------------------------------------------------------

    _discover_query_parameters(
        url,
        parameters,
    )

    # --------------------------------------------------------
    # Fetch page for HTML/form analysis
    # --------------------------------------------------------

    try:

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
        )

        # ----------------------------------------------------
        # Forms
        # ----------------------------------------------------

        _discover_form_parameters(
            url,
            parameters,
            response,
        )

    except requests.RequestException:

        response = None

    # --------------------------------------------------------
    # Endpoint-specific hints
    #
    # These are useful when an endpoint such as /fetch
    # accepts ?url=... but does not expose that parameter
    # in its HTML.
    # --------------------------------------------------------

    _discover_common_parameters(
        url,
        parameters,
    )

    return parameters