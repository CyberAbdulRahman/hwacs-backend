# services/browser_discovery_service.py

from urllib.parse import urljoin, urlparse, urldefrag
from playwright.sync_api import sync_playwright


SKIP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".css", ".js", ".ico", ".woff", ".woff2", ".ttf",
    ".pdf", ".zip", ".rar", ".mp4", ".mp3", ".avi",
    ".md", ".yml", ".yaml", ".txt", ".dist", ".lock",
)


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    url, _fragment = urldefrag(url)
    return url.rstrip("/")


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
    lower_url = (url or "").lower()
    parsed = urlparse(lower_url)
    path = parsed.path or ""

    if lower_url.startswith("mailto:"):
        return True

    if lower_url.startswith("tel:"):
        return True

    if lower_url.startswith("javascript:"):
        return True

    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True

    blocked_keywords = [
        "readme",
        "license",
        "composer",
        "package.json",
        "package-lock",
        "dockerfile",
        "compose",
        ".git",
        ".env",
        "config.inc.php.dist",
    ]

    if any(keyword in path for keyword in blocked_keywords):
        return True

    blocked_paths = [
        "/logout.php",
        "/phpinfo.php",
    ]

    if any(path.endswith(p) for p in blocked_paths):
        return True

    return False


def discover_authenticated_pages(
    base_url: str,
    login_url: str,
    username: str,
    password: str,
    max_pages: int = 70,
    max_depth: int = 2,
):
    """
    Authenticated browser discovery:
    - Opens login URL
    - Fills common username/email and password fields
    - Submits login form
    - Crawls internal authenticated pages
    - Same origin only
    - No form submission after login
    """

    base_url = _normalize_url(base_url)
    login_url = _normalize_url(login_url)

    if not base_url or not login_url:
        return []

    if not _is_valid_http_url(base_url) or not _is_valid_http_url(login_url):
        return []

    origin = _get_origin(base_url)
    base_path = _get_path(base_url).rstrip("/")

    discovered = {}
    visited = set()
    queue = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        page = browser.new_page(
            user_agent="HWACS-Authenticated-Discovery/1.0"
        )

        try:
            page.goto(login_url, wait_until="networkidle", timeout=15000)
            page.wait_for_timeout(1000)

            username_selectors = [
                'input[name="username"]',
                'input[name="user"]',
                'input[name="email"]',
                'input[type="email"]',
                'input[placeholder*="email" i]',
                'input[placeholder*="username" i]',
                'input[type="text"]',
            ]

            password_selectors = [
                'input[name="password"]',
                'input[type="password"]',
                'input[placeholder*="password" i]',
            ]

            username_filled = False
            password_filled = False

            for selector in username_selectors:
                try:
                    el = page.locator(selector).first
                    if el.count() > 0:
                        el.fill(username, timeout=3000)
                        username_filled = True
                        break
                except Exception:
                    continue

            for selector in password_selectors:
                try:
                    el = page.locator(selector).first
                    if el.count() > 0:
                        el.fill(password, timeout=3000)
                        password_filled = True
                        break
                except Exception:
                    continue

            if not username_filled or not password_filled:
                browser.close()
                raise Exception("Could not find username/email or password field.")

            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Login")',
                'button:has-text("Log in")',
                'button:has-text("Sign in")',
                'button:has-text("Submit")',
                'input[value*="Login" i]',
                'input[value*="Sign in" i]',
            ]

            clicked = False

            for selector in submit_selectors:
                try:
                    btn = page.locator(selector).first
                    if btn.count() > 0:
                        btn.click(timeout=3000)
                        clicked = True
                        break
                except Exception:
                    continue

            if not clicked:
                page.keyboard.press("Enter")

            page.wait_for_load_state("networkidle", timeout=15000)
            page.wait_for_timeout(1500)

            current_after_login = _normalize_url(page.url)

            queue.append((current_after_login, 0))

            # Also collect links from current page immediately
            hrefs = page.eval_on_selector_all(
                "a[href]",
                """
                elements => elements
                  .map(a => a.getAttribute('href'))
                  .filter(Boolean)
                """
            )

            for href in hrefs:
                next_url = urljoin(current_after_login, href)
                next_url = _normalize_url(next_url)

                if not next_url or _should_skip_url(next_url):
                    continue

                parsed_next = urlparse(next_url)

                if f"{parsed_next.scheme}://{parsed_next.netloc}" != origin:
                    continue

                next_path = _get_path(next_url)

                if base_path and base_path != "/" and not next_path.startswith(base_path):
                    continue

                queue.append((next_url, 1))

            while queue and len(visited) < max_pages:
                current_url, depth = queue.pop(0)
                current_url = _normalize_url(current_url)

                if not current_url or current_url in visited:
                    continue

                if _should_skip_url(current_url):
                    continue

                parsed_current = urlparse(current_url)

                if f"{parsed_current.scheme}://{parsed_current.netloc}" != origin:
                    continue

                current_path = _get_path(current_url)

                if base_path and base_path != "/" and not current_path.startswith(base_path):
                    continue

                visited.add(current_url)

                discovered[current_path] = {
                    "path": current_path,
                    "full_url": current_url,
                    "source": "auth_browser_crawler",
                }

                if depth >= max_depth:
                    continue

                try:
                    page.goto(current_url, wait_until="networkidle", timeout=12000)
                    page.wait_for_timeout(800)

                    hrefs = page.eval_on_selector_all(
                        "a[href]",
                        """
                        elements => elements
                          .map(a => a.getAttribute('href'))
                          .filter(Boolean)
                        """
                    )

                    for href in hrefs:
                        next_url = urljoin(current_url, href)
                        next_url = _normalize_url(next_url)

                        if not next_url or _should_skip_url(next_url):
                            continue

                        parsed_next = urlparse(next_url)

                        if f"{parsed_next.scheme}://{parsed_next.netloc}" != origin:
                            continue

                        next_path = _get_path(next_url)

                        if base_path and base_path != "/" and not next_path.startswith(base_path):
                            continue

                        if next_url not in visited:
                            queue.append((next_url, depth + 1))

                except Exception as e:
                    print("Authenticated discovery page failed:", current_url, str(e))
                    continue

        finally:
            browser.close()

    return list(discovered.values())

def start_authenticated_discovery_session(
    base_url: str,
    login_url: str,
    username: str,
    password: str,
):
    base_url = _normalize_url(base_url)
    login_url = _normalize_url(login_url)

    if not base_url or not login_url:
        raise Exception("Base URL and login URL are required.")

    if not _is_valid_http_url(base_url) or not _is_valid_http_url(login_url):
        raise Exception("Invalid base URL or login URL.")

    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(user_agent="HWACS-2FA-Discovery/1.0")

    try:
        page.goto(login_url, wait_until="networkidle", timeout=15000)
        page.wait_for_timeout(1000)

        username_selectors = [
            'input[name="username"]',
            'input[name="user"]',
            'input[name="email"]',
            'input[type="email"]',
            'input[placeholder*="email" i]',
            'input[placeholder*="username" i]',
            'input[type="text"]',
        ]

        password_selectors = [
            'input[name="password"]',
            'input[type="password"]',
            'input[placeholder*="password" i]',
        ]

        username_filled = False
        password_filled = False

        for selector in username_selectors:
            try:
                field = page.locator(selector).first
                if field.count() > 0:
                    field.fill(username, timeout=3000)
                    username_filled = True
                    break
            except Exception:
                continue

        for selector in password_selectors:
            try:
                field = page.locator(selector).first
                if field.count() > 0:
                    field.fill(password, timeout=3000)
                    password_filled = True
                    break
            except Exception:
                continue

        if not username_filled or not password_filled:
            raise Exception("Could not find username/email or password field.")

        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Login")',
            'button:has-text("Log in")',
            'button:has-text("Sign in")',
            'button:has-text("Submit")',
            'input[value*="Login" i]',
            'input[value*="Sign in" i]',
        ]

        clicked = False

        for selector in submit_selectors:
            try:
                btn = page.locator(selector).first
                if btn.count() > 0:
                    btn.click(timeout=3000)
                    clicked = True
                    break
            except Exception:
                continue

        if not clicked:
            page.keyboard.press("Enter")

        page.wait_for_load_state("networkidle", timeout=15000)
        page.wait_for_timeout(1500)

        requires_otp = _detect_otp_screen(page)

        return {
            "playwright": playwright,
            "browser": browser,
            "page": page,
            "base_url": base_url,
            "current_url": page.url,
            "requires_otp": requires_otp,
        }

    except Exception:
        try:
            browser.close()
        except Exception:
            pass

        try:
            playwright.stop()
        except Exception:
            pass

        raise

def discover_browser_pages(base_url: str, max_pages: int = 50, max_depth: int = 2):
    """
    Browser-based public discovery using Playwright.

    Best for:
    - React
    - Vue
    - Angular
    - JavaScript-rendered pages

    Safe behavior:
    - Same origin only
    - GET navigation only
    - No form submission
    - No destructive actions
    """

    base_url = _normalize_url(base_url)

    if not base_url or not _is_valid_http_url(base_url):
        return []

    origin = _get_origin(base_url)
    base_path = _get_path(base_url).rstrip("/")

    discovered = {}
    visited = set()
    queue = [(base_url, 0)]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        page = browser.new_page(
            user_agent="HWACS-Browser-Discovery/1.0"
        )

        while queue and len(visited) < max_pages:
            current_url, depth = queue.pop(0)
            current_url = _normalize_url(current_url)

            if not current_url or current_url in visited:
                continue

            if _should_skip_url(current_url):
                continue

            parsed_current = urlparse(current_url)

            if f"{parsed_current.scheme}://{parsed_current.netloc}" != origin:
                continue

            current_path = _get_path(current_url)

            if base_path and base_path != "/" and not current_path.startswith(base_path):
                continue

            visited.add(current_url)

            discovered[current_path] = {
                "path": current_path,
                "full_url": current_url,
                "source": "browser_crawler",
            }

            if depth >= max_depth:
                continue

            try:
                page.goto(current_url, wait_until="networkidle", timeout=12000)
                page.wait_for_timeout(1000)

                hrefs = page.eval_on_selector_all(
                    "a[href]",
                    """
                    elements => elements
                      .map(a => a.getAttribute('href'))
                      .filter(Boolean)
                    """
                )

                for href in hrefs:
                    next_url = urljoin(current_url, href)
                    next_url = _normalize_url(next_url)

                    if not next_url or _should_skip_url(next_url):
                        continue

                    parsed_next = urlparse(next_url)

                    if f"{parsed_next.scheme}://{parsed_next.netloc}" != origin:
                        continue

                    next_path = _get_path(next_url)

                    if base_path and base_path != "/" and not next_path.startswith(base_path):
                        continue

                    if next_url not in visited:
                        queue.append((next_url, depth + 1))

            except Exception as e:
                print("Browser discovery page failed:", current_url, str(e))
                continue

        browser.close()

    return list(discovered.values())

def crawl_from_logged_in_page(page, base_url: str, max_pages: int = 80, max_depth: int = 2):
    base_url = _normalize_url(base_url)

    origin = _get_origin(base_url)
    base_path = _get_path(base_url).rstrip("/")

    discovered = {}
    visited = set()

    start_url = _normalize_url(page.url)
    queue = [(start_url, 0)]

    try:
        hrefs = page.eval_on_selector_all(
            "a[href]",
            """
            elements => elements
              .map(a => a.getAttribute('href'))
              .filter(Boolean)
            """
        )

        for href in hrefs:
            next_url = urljoin(start_url, href)
            next_url = _normalize_url(next_url)

            if not next_url or _should_skip_url(next_url):
                continue

            parsed_next = urlparse(next_url)

            if f"{parsed_next.scheme}://{parsed_next.netloc}" != origin:
                continue

            next_path = _get_path(next_url)

            if base_path and base_path != "/" and not next_path.startswith(base_path):
                continue

            queue.append((next_url, 1))
    except Exception:
        pass

    while queue and len(visited) < max_pages:
        current_url, depth = queue.pop(0)
        current_url = _normalize_url(current_url)

        if not current_url or current_url in visited:
            continue

        if _should_skip_url(current_url):
            continue

        parsed_current = urlparse(current_url)

        if f"{parsed_current.scheme}://{parsed_current.netloc}" != origin:
            continue

        current_path = _get_path(current_url)

        if base_path and base_path != "/" and not current_path.startswith(base_path):
            continue

        visited.add(current_url)

        discovered[current_path] = {
            "path": current_path,
            "full_url": current_url,
            "source": "auth_2fa_browser_crawler",
        }

        if depth >= max_depth:
            continue

        try:
            page.goto(current_url, wait_until="networkidle", timeout=12000)
            page.wait_for_timeout(800)

            hrefs = page.eval_on_selector_all(
                "a[href]",
                """
                elements => elements
                  .map(a => a.getAttribute('href'))
                  .filter(Boolean)
                """
            )

            for href in hrefs:
                next_url = urljoin(current_url, href)
                next_url = _normalize_url(next_url)

                if not next_url or _should_skip_url(next_url):
                    continue

                parsed_next = urlparse(next_url)

                if f"{parsed_next.scheme}://{parsed_next.netloc}" != origin:
                    continue

                next_path = _get_path(next_url)

                if base_path and base_path != "/" and not next_path.startswith(base_path):
                    continue

                if next_url not in visited:
                    queue.append((next_url, depth + 1))

        except Exception as e:
            print("2FA authenticated crawl page failed:", current_url, str(e))
            continue

    return list(discovered.values())


def _detect_otp_screen(page):
    otp_selectors = [
        'input[name="otp"]',
        'input[name="code"]',
        'input[name="verification_code"]',
        'input[name="two_factor_code"]',
        'input[type="tel"]',
        'input[placeholder*="otp" i]',
        'input[placeholder*="code" i]',
        'input[placeholder*="verification" i]',
    ]

    for selector in otp_selectors:
        try:
            if page.locator(selector).count() > 0:
                return True
        except Exception:
            continue

    try:
        body_text = page.locator("body").inner_text(timeout=2000).lower()

        otp_words = [
            "otp",
            "one-time",
            "verification code",
            "two-factor",
            "2fa",
            "authentication code",
            "enter code",
        ]

        return any(word in body_text for word in otp_words)
    except Exception:
        return False


def _fill_otp_and_submit(page, otp: str):
    otp_selectors = [
        'input[name="otp"]',
        'input[name="code"]',
        'input[name="verification_code"]',
        'input[name="two_factor_code"]',
        'input[type="tel"]',
        'input[placeholder*="otp" i]',
        'input[placeholder*="code" i]',
        'input[placeholder*="verification" i]',
    ]

    filled = False

    for selector in otp_selectors:
        try:
            field = page.locator(selector).first
            if field.count() > 0:
                field.fill(otp, timeout=3000)
                filled = True
                break
        except Exception:
            continue

    if not filled:
        raise Exception("Could not find OTP input field.")

    submit_selectors = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Verify")',
        'button:has-text("Continue")',
        'button:has-text("Submit")',
        'button:has-text("Confirm")',
        'button:has-text("Login")',
    ]

    clicked = False

    for selector in submit_selectors:
        try:
            btn = page.locator(selector).first
            if btn.count() > 0:
                btn.click(timeout=3000)
                clicked = True
                break
        except Exception:
            continue

    if not clicked:
        page.keyboard.press("Enter")

    page.wait_for_load_state("networkidle", timeout=15000)
    page.wait_for_timeout(1200)