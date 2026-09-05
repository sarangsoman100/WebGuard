"""
WebGuard - Phase 2A Fast Crawler
--------------------------------

Fast, bounded discovery crawler designed to remain compatible with:

    crawl_target(url, max_pages=20)

Architecture:
1. Crawl real application links first, concurrently.
2. Discover robots.txt / sitemap.xml separately.
3. Probe WebGuard's security-relevant common endpoints separately.
4. Deduplicate everything.
5. Return real links + supplementary security endpoints.

Important:
`max_pages` is the PRIMARY application crawl budget. Supplementary
security endpoints may be added after that budget so that security coverage
does not disappear simply because a site has few HTML links.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html import unescape
from collections import deque
from urllib.parse import (
    parse_qsl,
    urlencode,
    urldefrag,
    urljoin,
    urlparse,
    urlunparse,
)
import re
import threading
import xml.etree.ElementTree as ET

import requests
from bs4 import BeautifulSoup


# ============================================================================
# Configuration
# ============================================================================

DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_DEPTH = 3
DEFAULT_WORKERS = 6
DEFAULT_TIMEOUT = 3.0
DEFAULT_MAX_RESPONSE_BYTES = 2_000_000

# These are SECURITY DISCOVERY endpoints.
# They are NOT placed into the primary crawl queue.
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

STATIC_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".bz2", ".css", ".csv", ".doc", ".docx",
    ".eot", ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".js", ".m4a",
    ".mov", ".mp3", ".mp4", ".mpeg", ".ogg", ".otf", ".pdf", ".png",
    ".ppt", ".pptx", ".rar", ".svg", ".tar", ".tgz", ".tif", ".tiff",
    ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2", ".xls", ".xlsx",
    ".zip",
}

TRACKING_PARAMETERS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "mc_cid",
    "mc_eid",
}

SKIP_SCHEMES = {
    "javascript",
    "mailto",
    "tel",
    "data",
    "blob",
    "file",
}


# ============================================================================
# Data model
# ============================================================================

@dataclass(frozen=True)
class CrawlTask:
    url: str
    depth: int
    priority: int = 100


# ============================================================================
# Thread-local HTTP sessions
# ============================================================================

_thread_local = threading.local()


def _session() -> requests.Session:
    session = getattr(_thread_local, "session", None)

    if session is None:
        session = requests.Session()

        session.headers.update(
            {
                "User-Agent": (
                    "WebGuard/1.0 "
                    "(authorized security assessment crawler)"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/xml;q=0.9,*/*;q=0.5"
                ),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        _thread_local.session = session

    return session


# ============================================================================
# URL normalization
# ============================================================================

def _host(netloc: str) -> str:
    return netloc.lower().split("@")[-1]


def _same_host(url: str, root_host: str) -> bool:
    try:
        return _host(urlparse(url).netloc) == root_host
    except Exception:
        return False


def _normalize_url(
    value: str,
    base_url: str | None = None,
) -> str | None:
    if not value:
        return None

    try:
        value = unescape(str(value)).strip()

        if base_url:
            value = urljoin(base_url, value)

        value, _ = urldefrag(value)

        parsed = urlparse(value)
        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            return None

        if scheme in SKIP_SCHEMES:
            return None

        if not parsed.hostname:
            return None

        hostname = parsed.hostname.lower()
        port = parsed.port

        if port is None:
            netloc = hostname
        elif (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        ):
            netloc = hostname
        else:
            netloc = f"{hostname}:{port}"

        path = parsed.path or "/"
        path = re.sub(r"/{2,}", "/", path)

        if len(path) > 1:
            path = path.rstrip("/")

        query_items = []

        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        ):
            if key.lower() not in TRACKING_PARAMETERS:
                query_items.append((key, value))

        query = urlencode(
            query_items,
            doseq=True,
        )

        return urlunparse(
            (
                scheme,
                netloc,
                path,
                "",
                query,
                "",
            )
        )

    except (TypeError, ValueError):
        return None


def _key(url: str) -> str:
    normalized = _normalize_url(url) or url
    return normalized.rstrip("/") or "/"


def _is_static(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        filename = path.rsplit("/", 1)[-1]

        if "." not in filename:
            return False

        extension = "." + filename.rsplit(".", 1)[-1]

        return extension in STATIC_EXTENSIONS

    except Exception:
        return True


def _primary_allowed(url: str, root_host: str) -> bool:
    if not _same_host(url, root_host):
        return False

    if _is_static(url):
        return False

    return True


# ============================================================================
# URL prioritization
# ============================================================================

def _priority(url: str, depth: int) -> int:
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception:
        return 100 + depth * 20

    score = 100

    if depth == 0:
        score -= 80
    elif depth == 1:
        score -= 50
    elif depth == 2:
        score -= 25

    if parsed.query:
        score -= 12

    interesting = (
        "login",
        "account",
        "user",
        "profile",
        "admin",
        "api",
        "search",
        "product",
        "item",
        "upload",
        "download",
        "redirect",
        "fetch",
        "proxy",
        "xml",
        "change",
        "payment",
    )

    for word in interesting:
        if word in path or word in query:
            score -= 6

    return max(0, score)


# ============================================================================
# HTTP request
# ============================================================================

def _fetch(
    url: str,
    timeout: float,
) -> dict:
    try:
        response = _session().get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )

        content_type = (
            response.headers.get(
                "Content-Type",
                "",
            )
            or ""
        ).lower()

        body = b""

        # Only read response bodies useful for discovery.
        if (
            "text/html" in content_type
            or "xhtml" in content_type
            or "xml" in content_type
            or not content_type
        ):
            for chunk in response.iter_content(
                chunk_size=32 * 1024,
            ):
                if not chunk:
                    continue

                body += chunk

                if len(body) >= DEFAULT_MAX_RESPONSE_BYTES:
                    body = body[
                        :DEFAULT_MAX_RESPONSE_BYTES
                    ]
                    break

        return {
            "url": url,
            "final_url": (
                _normalize_url(response.url)
                or response.url
            ),
            "status_code": response.status_code,
            "content_type": content_type,
            "headers": dict(response.headers),
            "body": body,
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "url": url,
            "final_url": url,
            "status_code": None,
            "content_type": "",
            "headers": {},
            "body": b"",
            "error": str(exc),
        }


# ============================================================================
# HTML extraction
# ============================================================================

def _extract_links(
    html: str,
    base_url: str,
    root_host: str,
) -> list[str]:
    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    found = []
    seen = set()

    def add(raw: str | None) -> None:
        if not raw:
            return

        normalized = _normalize_url(
            raw,
            base_url,
        )

        if not normalized:
            return

        if not _primary_allowed(
            normalized,
            root_host,
        ):
            return

        key = _key(normalized)

        if key in seen:
            return

        seen.add(key)
        found.append(normalized)

    for tag in soup.find_all(
        "a",
        href=True,
    ):
        add(tag.get("href"))

    for tag in soup.find_all(
        "form",
    ):
        add(
            tag.get("action")
            or base_url
        )

    # Useful for lightweight JS applications that expose internal routes
    # through data attributes.
    for tag in soup.find_all(
        attrs={"data-href": True},
    ):
        add(tag.get("data-href"))

    return found


# ============================================================================
# Sitemap parsing
# ============================================================================

def _parse_sitemap(
    body: bytes,
    root_host: str,
) -> list[str]:
    found = []

    if not body:
        return found

    try:
        root = ET.fromstring(body)

        for element in root.iter():
            tag = element.tag

            if "}" in tag:
                tag = tag.rsplit(
                    "}",
                    1,
                )[-1]

            if (
                tag.lower() == "loc"
                and element.text
            ):
                normalized = _normalize_url(
                    element.text.strip()
                )

                if (
                    normalized
                    and _same_host(
                        normalized,
                        root_host,
                    )
                ):
                    found.append(normalized)

    except Exception:
        text = body.decode(
            "utf-8",
            errors="ignore",
        )

        for match in re.findall(
            r"<loc>\s*(.*?)\s*</loc>",
            text,
            flags=re.I | re.S,
        ):
            normalized = _normalize_url(
                match.strip()
            )

            if (
                normalized
                and _same_host(
                    normalized,
                    root_host,
                )
            ):
                found.append(normalized)

    return found


# ============================================================================
# Supplementary discovery
# ============================================================================

def _supplementary_candidates(
    start_url: str,
    root_host: str,
    timeout: float,
) -> list[str]:
    parsed = urlparse(start_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    discovered = []
    seen = set()

    def add(
        value: str | None,
        *,
        allow_static: bool = False,
    ) -> None:
        normalized = _normalize_url(value or "")

        if not normalized:
            return

        if not _same_host(
            normalized,
            root_host,
        ):
            return

        if (
            not allow_static
            and _is_static(normalized)
        ):
            return

        key = _key(normalized)

        if key in seen:
            return

        seen.add(key)
        discovered.append(normalized)

    # ------------------------------------------------------------------
    # robots.txt
    # ------------------------------------------------------------------

    robots_url = urljoin(
        origin + "/",
        "/robots.txt",
    )

    robots = _fetch(
        robots_url,
        timeout,
    )

    robots_body = robots.get(
        "body",
        b"",
    )

    sitemap_urls = []

    if robots_body:
        text = robots_body.decode(
            "utf-8",
            errors="ignore",
        )

        for line in text.splitlines():
            if ":" not in line:
                continue

            name, value = line.split(
                ":",
                1,
            )

            name = name.strip().lower()
            value = value.strip()

            if (
                name == "sitemap"
                and value
            ):
                candidate = _normalize_url(
                    value
                )

                if (
                    candidate
                    and _same_host(
                        candidate,
                        root_host,
                    )
                ):
                    sitemap_urls.append(
                        candidate
                    )

            elif (
                name == "disallow"
                and value
                and value != "/"
                and value.startswith("/")
            ):
                # Robots paths are useful security discovery hints.
                add(
                    urljoin(
                        origin + "/",
                        value,
                    )
                )

    # ------------------------------------------------------------------
    # Sitemaps from robots + conventional sitemap.xml
    # ------------------------------------------------------------------

    sitemap_urls.append(
        urljoin(
            origin + "/",
            "/sitemap.xml",
        )
    )

    for sitemap_url in sitemap_urls:
        result = _fetch(
            sitemap_url,
            timeout,
        )

        for found_url in _parse_sitemap(
            result.get(
                "body",
                b"",
            ),
            root_host,
        ):
            add(found_url)

            if len(discovered) >= 40:
                return discovered

    # ------------------------------------------------------------------
    # WebGuard security endpoints.
    #
    # These are deliberately supplementary. They are not allowed to
    # consume the primary HTML crawl budget.
    # ------------------------------------------------------------------

    for endpoint in COMMON_ENDPOINTS:
        add(
            urljoin(
                origin + "/",
                endpoint,
            ),
            allow_static=True,
        )

    return discovered


# ============================================================================
# Main crawler
# ============================================================================

def crawl_target(
    start_url: str,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    workers: int = DEFAULT_WORKERS,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict]:
    """
    Fast bounded crawler.

    `max_pages` controls the PRIMARY application crawl.

    Supplementary security endpoints may be returned in addition to those
    primary pages. This is intentional so Phase 1 detectors such as SSRF,
    XXE, CSRF and Open Redirect continue to receive their known lab routes.
    """

    start = _normalize_url(start_url)

    if not start:
        return []

    max_pages = max(
        1,
        int(max_pages),
    )

    max_depth = max(
        0,
        int(max_depth),
    )

    workers = max(
        1,
        min(int(workers), 8),
    )

    timeout = max(
        1.0,
        float(timeout),
    )

    parsed = urlparse(start)
    root_host = _host(
        parsed.netloc
    )

    # ------------------------------------------------------------------
    # Primary crawl state
    # ------------------------------------------------------------------

    queue = deque(
        [
            CrawlTask(
                start,
                0,
                0,
            )
        ]
    )

    queued = {
        _key(start)
    }

    visited = set()
    primary_results = {}

    # ------------------------------------------------------------------
    # Concurrent primary discovery
    # ------------------------------------------------------------------

    while (
        queue
        and len(primary_results) < max_pages
    ):
        batch = []

        # Sort only the current frontier. This keeps the queue bounded.
        candidates = sorted(
            list(queue),
            key=lambda item: (
                item.priority,
                item.depth,
                item.url,
            ),
        )

        queue.clear()

        for task in candidates:
            key = _key(task.url)

            if key in visited:
                continue

            visited.add(key)
            batch.append(task)

            if len(batch) >= min(
                workers,
                max_pages - len(primary_results),
            ):
                break

        selected = {
            _key(task.url)
            for task in batch
        }

        for task in candidates:
            if _key(task.url) not in selected:
                queue.append(task)

        if not batch:
            break

        with ThreadPoolExecutor(
            max_workers=min(
                workers,
                len(batch),
            )
        ) as executor:
            futures = {
                executor.submit(
                    _fetch,
                    task.url,
                    timeout,
                ): task
                for task in batch
            }

            completed = []

            for future in as_completed(futures):
                task = futures[future]

                try:
                    response = future.result()
                except Exception as exc:
                    response = {
                        "url": task.url,
                        "final_url": task.url,
                        "status_code": None,
                        "content_type": "",
                        "headers": {},
                        "body": b"",
                        "error": str(exc),
                    }

                completed.append(
                    (
                        task,
                        response,
                    )
                )

        completed.sort(
            key=lambda item: (
                item[0].depth,
                item[0].priority,
                item[0].url,
            )
        )

        for task, response in completed:
            if len(primary_results) >= max_pages:
                break

            key = _key(task.url)

            if key in primary_results:
                continue

            final_url = (
                response.get(
                    "final_url"
                )
                or task.url
            )

            primary_results[key] = {
                "url": task.url,
                "final_url": final_url,
                "status_code": response.get(
                    "status_code"
                ),
                "content_type": response.get(
                    "content_type",
                    "",
                ),
                "depth": task.depth,
                "discovery_type": "crawl",
            }

            content_type = (
                response.get(
                    "content_type",
                    "",
                )
                or ""
            ).lower()

            body = response.get(
                "body",
                b"",
            ) or b""

            is_html = (
                "text/html" in content_type
                or "xhtml" in content_type
                or (
                    not content_type
                    and bool(body)
                )
            )

            if not is_html:
                continue

            if task.depth >= max_depth:
                continue

            try:
                html = body.decode(
                    "utf-8",
                    errors="ignore",
                )

                links = _extract_links(
                    html,
                    final_url,
                    root_host,
                )
            except Exception:
                links = []

            for link in links:
                key = _key(link)

                if (
                    key in queued
                    or key in visited
                ):
                    continue

                queued.add(key)

                queue.append(
                    CrawlTask(
                        url=link,
                        depth=task.depth + 1,
                        priority=_priority(
                            link,
                            task.depth + 1,
                        ),
                    )
                )

                # Hard queue guard.
                if len(queue) > max_pages * 4:
                    break

    # ------------------------------------------------------------------
    # Supplementary security discovery
    # ------------------------------------------------------------------

    supplementary_results = {}

    try:
        supplementary = _supplementary_candidates(
            start,
            root_host,
            timeout,
        )
    except Exception:
        supplementary = []

    # Do not refetch URLs already returned by the primary crawl.
    supplementary = [
        value
        for value in supplementary
        if _key(value) not in primary_results
    ]

    if supplementary:
        # Keep supplementary work bounded.
        # 14 known security endpoints + up to 40 sitemap/robots hints.
        supplementary = supplementary[
            : len(COMMON_ENDPOINTS) + 40
        ]

        tasks = [
            CrawlTask(
                url=value,
                depth=1,
                priority=_priority(
                    value,
                    1,
                ) + 20,
            )
            for value in supplementary
        ]

        with ThreadPoolExecutor(
            max_workers=min(
                workers,
                len(tasks),
            )
        ) as executor:
            futures = {
                executor.submit(
                    _fetch,
                    task.url,
                    timeout,
                ): task
                for task in tasks
            }

            for future in as_completed(futures):
                task = futures[future]

                try:
                    response = future.result()
                except Exception:
                    continue

                key = _key(task.url)

                if key in primary_results:
                    continue

                supplementary_results[key] = {
                    "url": task.url,
                    "final_url": (
                        response.get(
                            "final_url"
                        )
                        or task.url
                    ),
                    "status_code": response.get(
                        "status_code"
                    ),
                    "content_type": response.get(
                        "content_type",
                        "",
                    ),
                    "depth": task.depth,
                    "discovery_type": "supplementary",
                }

    # ------------------------------------------------------------------
    # Merge
    # ------------------------------------------------------------------

    results = list(
        primary_results.values()
    )

    results.extend(
        supplementary_results.values()
    )

    # Stable, useful ordering:
    # homepage/real crawl first, security-relevant paths next.
    results.sort(
        key=lambda item: (
            0
            if item.get(
                "discovery_type"
            ) == "crawl"
            else 1,
            item.get(
                "depth",
                0,
            ),
            _priority(
                item.get(
                    "url",
                    "",
                ),
                item.get(
                    "depth",
                    0,
                ),
            ),
            item.get(
                "url",
                "",
            ),
        )
    )

    return results


# ============================================================================
# Backward-compatible alias
# ============================================================================

def crawl(
    start_url: str,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> list[dict]:
    return crawl_target(
        start_url,
        max_pages=max_pages,
    )


# ============================================================================
# Simple self-test
# ============================================================================

def _self_test() -> None:
    assert _normalize_url(
        "HTTP://Example.COM/test/#x"
    ) == "http://example.com/test"

    assert _normalize_url(
        "javascript:alert(1)"
    ) is None

    assert _normalize_url(
        "mailto:test@example.com"
    ) is None

    print(
        "WebGuard Phase 2A crawler self-test: OK"
    )


if __name__ == "__main__":
    _self_test()


__all__ = [
    "crawl_target",
    "crawl",
    "COMMON_ENDPOINTS",
]
