import os
import sqlite3
from http.cookies import SimpleCookie
from urllib.parse import urlparse, urlunparse

import requests
import urllib3

# SSL verification is intentionally disabled to allow scanning local/self-signed
# targets (DVWA, bWAPP, Juice Shop, etc.). Suppress the per-request noise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.abspath(os.path.join(BASE_DIR, "../../database/scanner.db"))

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
}


def normalize_target_url(url):
    """Return scheme://host[:port]/optional-path without query/fragment/trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if path == "/":
        path = ""

    normalized = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
    return normalized.rstrip("/")


def get_origin(url):
    parsed = urlparse(normalize_target_url(url))
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")


def get_scope_root(url):
    """Return the best base URL for crawling/fuzzing.

    Examples:
      http://host/vulnerable.php?id=1 -> http://host
      http://host/app/vulnerable.php?id=1 -> http://host/app
      http://host/app/ -> http://host/app
    """
    normalized = normalize_target_url(url)
    parsed = urlparse(normalized)
    path = parsed.path.rstrip("/")

    if not path:
        return get_origin(normalized)

    segments = path.strip("/").split("/")
    last = segments[-1]

    # File-like endpoint: crawl/fuzz its parent directory instead of endpoint/word.
    if "." in last:
        parent = "/" + "/".join(segments[:-1]) if len(segments) > 1 else ""
        return urlunparse((parsed.scheme, parsed.netloc, parent, "", "", "")).rstrip(
            "/"
        )

    return normalized


def same_origin(url, root):
    a = urlparse(url)
    b = urlparse(root)
    return a.scheme in ("http", "https") and a.netloc == b.netloc


def parse_cookie_header(cookie_header):
    cookies = {}
    if not cookie_header:
        return cookies

    simple_cookie = SimpleCookie()
    try:
        simple_cookie.load(cookie_header)
        for key, morsel in simple_cookie.items():
            cookies[key] = morsel.value
    except Exception:
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def build_session(options=None):
    options = options or {}
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    # Disable SSL verification for local test environments (DVWA, bWAPP, etc.)
    session.verify = False

    cookie_header = (
        options.get("cookie_header")
        or options.get("cookieHeader")
        or os.getenv("SCANNER_COOKIE_HEADER")
        or ""
    )
    for key, value in parse_cookie_header(cookie_header).items():
        session.cookies.set(key, value)

    # Support explicit security level (e.g., DVWA security=low)
    security_level = options.get("security_level") or options.get("securityLevel") or ""
    if security_level:
        session.cookies.set("security", security_level)

    return session



def connect_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def get_or_create_target(cursor, url):
    target_url = normalize_target_url(url)
    try:
        cursor.execute("INSERT INTO cibles (url) VALUES (?)", (target_url,))
        return cursor.lastrowid, target_url
    except sqlite3.IntegrityError:
        cursor.execute("SELECT id FROM cibles WHERE url = ?", (target_url,))
        return cursor.fetchone()["id"], target_url


def start_scan(cursor, url):
    target_id, target_url = get_or_create_target(cursor, url)
    cursor.execute(
        "INSERT INTO scans (cible_id, statut) VALUES (?, 'En cours')", (target_id,)
    )
    return cursor.lastrowid, target_url


def finish_scan(conn, cursor, scan_id, status):
    cursor.execute("UPDATE scans SET statut = ? WHERE id = ?", (status, scan_id))
    conn.commit()


def add_vulnerability(
    cursor, scan_id, type_faille, criticite, description, remediation
):
    cursor.execute(
        """
        INSERT INTO vulnerabilites (scan_id, type, criticite, description, remediation)
        VALUES (?, ?, ?, ?, ?)
        """,
        (scan_id, type_faille, criticite, description, remediation),
    )
