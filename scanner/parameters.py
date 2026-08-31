from urllib.parse import urlparse, parse_qs, urlunparse
import requests
from bs4 import BeautifulSoup


def discover_parameters(url):
    """
    Discover input parameters from:
    - URL query strings
    - HTML GET/POST forms

    Only parameters are discovered here. Testing is handled by the scan
    engine and can be restricted by scan mode.
    """

    parameters = []
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
        parameters.append({
            "url": clean_url,
            "parameter": name,
            "method": "GET",
            "source": "query",
        })

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
        )

        content_type = response.headers.get("Content-Type", "")

        if "text/html" not in content_type.lower():
            return parameters

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

        for form in soup.find_all("form"):
            action = form.get("action") or url

            action_parsed = urlparse(action)

            # Ignore malformed or unsupported external schemes.
            scheme = action_parsed.scheme or parsed.scheme
            netloc = action_parsed.netloc or parsed.netloc
            path = action_parsed.path or parsed.path

            if scheme not in ("http", "https"):
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
                form.get("method") or "GET"
            ).upper()

            for input_field in form.find_all(
                ["input", "textarea", "select"]
            ):
                name = input_field.get("name")

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

    except requests.RequestException:
        pass

    return parameters
