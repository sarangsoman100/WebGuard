import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag


def crawl_target(start_url, max_pages=10):
    visited = set()
    queue = [start_url]
    results = []

    parsed_start = urlparse(start_url)

    if parsed_start.scheme not in ("http", "https") or not parsed_start.netloc:
        return results

    # Keep the crawler inside the same host.
    base_domain = parsed_start.netloc.lower()

    while queue and len(visited) < max_pages:
        url = queue.pop(0)

        # Remove fragments so /page#section doesn't become a duplicate page.
        url = urldefrag(url)[0]

        if url in visited:
            continue

        visited.add(url)

        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True
            )

            final_url = urldefrag(response.url)[0]

            results.append({
                "url": final_url,
                "status_code": response.status_code
            })

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            # Discover links.
            for link in soup.find_all("a", href=True):
                next_url = urldefrag(
                    urljoin(final_url, link["href"])
                )[0]

                parsed = urlparse(next_url)

                if (
                    parsed.netloc.lower() == base_domain
                    and parsed.scheme in ("http", "https")
                    and next_url not in visited
                    and next_url not in queue
                ):
                    queue.append(next_url)

            # Discover form actions.
            for form in soup.find_all("form", action=True):
                form_url = urldefrag(
                    urljoin(final_url, form["action"])
                )[0]

                parsed = urlparse(form_url)

                if (
                    parsed.netloc.lower() == base_domain
                    and parsed.scheme in ("http", "https")
                    and form_url not in visited
                    and form_url not in queue
                ):
                    queue.append(form_url)

        except requests.RequestException:
            continue

    return results
