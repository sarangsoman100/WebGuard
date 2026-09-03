import requests

from bs4 import BeautifulSoup

from urllib.parse import (
    urljoin,
    urlparse,
    urldefrag,
)


# ============================================================
# Common endpoint candidates
# ============================================================

COMMON_ENDPOINTS = [
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/admin",
    "/login",
    "/logout",
    "/register",
    "/api",
    "/fetch",
    "/proxy",
    "/redirect",
    "/xml",
    "/change-email",
]


# ============================================================
# URL validation
# ============================================================

def _same_host(url, base_domain):

    parsed = urlparse(url)

    return (
        parsed.scheme in ("http", "https")
        and parsed.netloc.lower() == base_domain
    )


# ============================================================
# Add URL to queue
# ============================================================

def _add_to_queue(url, queue, visited, base_domain):

    url = urldefrag(url)[0]

    if not url:
        return

    if not _same_host(url, base_domain):
        return

    if url in visited:
        return

    if url in queue:
        return

    queue.append(url)


# ============================================================
# Crawler
# ============================================================

def crawl_target(start_url, max_pages=20):

    visited = set()
    queue = [start_url]
    results = []

    parsed_start = urlparse(start_url)

    if (
        parsed_start.scheme not in ("http", "https")
        or not parsed_start.netloc
    ):
        return results

    base_domain = parsed_start.netloc.lower()

    # --------------------------------------------------------
    # Add common endpoints
    # --------------------------------------------------------

    for endpoint in COMMON_ENDPOINTS:

        candidate = urljoin(
            start_url.rstrip("/") + "/",
            endpoint.lstrip("/"),
        )

        _add_to_queue(
            candidate,
            queue,
            visited,
            base_domain,
        )

    # --------------------------------------------------------
    # Crawl
    # --------------------------------------------------------

    while queue and len(visited) < max_pages:

        url = queue.pop(0)

        url = urldefrag(url)[0]

        if url in visited:
            continue

        visited.add(url)

        try:

            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
            )

            final_url = urldefrag(
                response.url
            )[0]

# ------------------------------------------------
# Record the requested endpoint
# ------------------------------------------------
#
# Important:
# Do NOT replace the requested URL with response.url.
#
# Some security-sensitive endpoints intentionally redirect.
# For example:
#
#   /redirect -> /
#
# If we store response.url, /redirect disappears from the
# discovered endpoint list.
#
# The scanner needs to test the endpoint that was actually
# discovered/requested.
# ------------------------------------------------

            results.append({
                "url": url,
                "final_url": final_url,
                "status_code": response.status_code,
            })
            
            content_type = response.headers.get(
                "Content-Type",
                "",
            ).lower()

            # ------------------------------------------------
            # Only parse HTML
            # ------------------------------------------------

            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(
                response.text,
                "html.parser",
            )

            # ------------------------------------------------
            # Discover links
            # ------------------------------------------------

            for link in soup.find_all( 
                "a",
                href=True,
            ):

                next_url = urldefrag(
                    urljoin(
                        final_url,
                        link["href"],
                    )
                )[0]

                _add_to_queue(
                    next_url,
                    queue,
                    visited,
                    base_domain,
                )

            # ------------------------------------------------
            # Discover form actions
            # ------------------------------------------------

            for form in soup.find_all(
                "form",
                action=True,
            ):

                form_url = urldefrag(
                    urljoin(
                        final_url,
                        form["action"],
                    )
                )[0]

                _add_to_queue(
                    form_url,
                    queue,
                    visited,
                    base_domain,
                )

        except requests.RequestException:

            continue

    return results