# services/page_discovery_service.py

from urllib.parse import urljoin, urlparse, urldefrag
import requests
from bs4 import BeautifulSoup


SKIP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".css", ".js", ".ico", ".woff", ".woff2", ".ttf",
    ".pdf", ".zip", ".rar", ".mp4", ".mp3", ".avi",
)


def _normalize_base_url(base_url: str) -> str:
    return (base_url or "").strip().rstrip("/")


def _get_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _get_path(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"

    if not path.startswith("/"):
        path = "/" + path

    return path


def _is_valid_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and bool(parsed.netloc)


def _should_skip_url(url: str) -> bool:
    lower_url = url.lower()

    if lower_url.startswith("mailto:"):
        return True

    if lower_url.startswith("tel:"):
        return True

    if lower_url.startswith("javascript:"):
        return True

    if any(lower_url.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True

    return False


def discover_public_pages(base_url: str, max_pages: int = 50, max_depth: int = 2):
    """
    Public crawler:
    - Only same origin
    - Only GET requests
    - Only links available from public pages
    - No login
    - No form submit
    """

    base_url = _normalize_base_url(base_url)

    if not base_url:
        return []

    if not _is_valid_http_url(base_url):
        return []

    origin = _get_origin(base_url)
    base_path = _get_path(base_url).rstrip("/")

    visited_urls = set()
    discovered = {}

    queue = [(base_url, 0)]

    headers = {
        "User-Agent": "HWACS-Public-Page-Discovery/1.0"
    }

    while queue and len(visited_urls) < max_pages:
        current_url, depth = queue.pop(0)

        current_url, _fragment = urldefrag(current_url)
        current_url = current_url.rstrip("/")

        if current_url in visited_urls:
            continue

        if _should_skip_url(current_url):
            continue

        parsed_current = urlparse(current_url)

        if f"{parsed_current.scheme}://{parsed_current.netloc}" != origin:
            continue

        current_path = _get_path(current_url)

        # Restrict crawl under base path if base_url has sub-path like /dvwa
        if base_path and base_path != "/" and not current_path.startswith(base_path):
            continue

        visited_urls.add(current_url)

        discovered[current_path] = {
            "path": current_path,
            "full_url": current_url,
            "source": "public_crawler",
        }

        if depth >= max_depth:
            continue

        try:
            response = requests.get(
                current_url,
                headers=headers,
                timeout=6,
                allow_redirects=True,
            )

            content_type = response.headers.get("Content-Type", "").lower()

            if response.status_code >= 400:
                continue

            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                href = (tag.get("href") or "").strip()

                if not href:
                    continue

                if href.startswith("#"):
                    continue

                next_url = urljoin(current_url + "/", href)
                next_url, _fragment = urldefrag(next_url)
                next_url = next_url.rstrip("/")

                if _should_skip_url(next_url):
                    continue

                parsed_next = urlparse(next_url)

                if f"{parsed_next.scheme}://{parsed_next.netloc}" != origin:
                    continue

                next_path = _get_path(next_url)

                if base_path and base_path != "/" and not next_path.startswith(base_path):
                    continue

                if next_url not in visited_urls:
                    queue.append((next_url, depth + 1))

        except Exception:
            continue

    return list(discovered.values())