import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from urllib.parse import urldefrag, urljoin, urlparse

import requests

try:
    from .common import (
        add_vulnerability,
        build_session,
        connect_db,
        finish_scan,
        get_depth_config,
        get_scope_root,
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
        same_origin,
        start_scan,
    )

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_FILE = os.path.join(BASE_DIR, "wordlist.txt")

INTERESTING_HINTS = {
    "admin",
    "administrator",
    "backup",
    "bak",
    "config",
    "dashboard",
    "database",
    "db",
    "debug",
    "dev",
    "graphql",
    "install",
    "login",
    "manager",
    "old",
    "phpinfo",
    "portal",
    "private",
    "secret",
    "server-status",
    "setup",
    "sql",
    "staging",
    "swagger",
    "tmp",
    "vendor",
    "wp-admin",
    "wp-login",
    # REST/API hints
    "api",
    "rest",
    "api-docs",
    "graphiql",
    "playground",
    "actuator",
    # Operational and intentionally hidden application areas
    "ftp",
    "encryptionkeys",
    "metrics",
    "promotion",
    "score-board",
    "snippets",
    "dataerasure",
    "accounting",
    # Common sensitive
    "uploads",
    "files",
    "logs",
    "temp",
    "internal",
    "hidden",
    "console",
}

SENSITIVE_FILE_HINTS = (
    ".env",
    ".git",
    ".htaccess",
    ".htpasswd",
    ".bak",
    ".old",
    ".sql",
    ".zip",
    ".tar",
    ".gz",
    "backup",
    "config",
    "dump",
    "phpinfo",
    "swagger",
    "server-status",
    # Additional sensitive patterns
    "package.json",
    "composer.json",
    ".npmrc",
    ".dockerignore",
    "Dockerfile",
    "docker-compose",
    "web.config",
    "terraform",
    "Vagrantfile",
    "Makefile",
    ".aws",
    ".azure",
    "openapi",
    "swagger.json",
    "swagger.yaml",
    "api-docs",
)

BENIGN_PUBLIC_HINTS = {
    "css",
    "fonts",
    "images",
    "img",
    "js",
    "public",
    "static",
    "media",
    "robots.txt",
    "sitemap.xml",
    "humans.txt",
    "favicon.ico",
}

EXPOSURE_PATH_HINTS = (
    "admin",
    "backup",
    "config",
    "console",
    "database",
    "debug",
    "dump",
    "encryptionkeys",
    "ftp",
    "internal",
    "logs",
    "metrics",
    "phpinfo",
    "private",
    "secret",
    "server-status",
    "setup",
    "actuator",
)


def _join_url(root, path):
    return f"{root.rstrip('/')}/{path.strip('/')}"


def _read_wordlist():
    if not os.path.exists(WORDLIST_FILE):
        raise FileNotFoundError(f"Wordlist introuvable: {WORDLIST_FILE}")

    with open(WORDLIST_FILE, "r", encoding="utf-8") as file:
        words = []
        for line in file:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
        return words


def _compact(text):
    return " ".join(text.lower().split())[:8000]


def _similar(a, b):
    return SequenceMatcher(None, _compact(a), _compact(b)).ratio()


def _extract_title(html):
    """Extract the <title> text from an HTML page (lowered, stripped)."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip().lower() if match else ""


def _strip_dynamic_tokens(html):
    """Remove CSRF tokens, nonces, timestamps, and session IDs that change per request
    so that two renders of the same page compare as identical."""
    text = re.sub(r'(csrf|token|nonce|timestamp|_t|sid)=["\']?[a-zA-Z0-9_\-]+["\']?', '', html, flags=re.IGNORECASE)
    text = re.sub(r'[0-9a-f]{32,}', '', text)  # hex hashes / session IDs
    text = re.sub(r'\d{10,13}', '', text)  # Unix timestamps (seconds/ms)
    return text


def _get_page_fingerprint(response):
    """Build a fingerprint dict from a response for comparison."""
    body = response.text or ""
    stripped = _strip_dynamic_tokens(body)
    return {
        "status": response.status_code,
        "title": _extract_title(body),
        "length": len(stripped),
        "compact": _compact(stripped),
    }


def _build_baselines(session, target_url):
    """Send multiple random probes AND fetch the homepage to build robust baselines.

    Returns a dict with:
      - 'probes': list of fingerprints for random non-existent paths
      - 'homepage': fingerprint of the homepage (GET /)
    """
    baselines = {"probes": [], "homepage": None}

    # 1) Fetch the real homepage
    try:
        home_resp = session.get(target_url.rstrip("/") + "/", timeout=5, allow_redirects=True)
        baselines["homepage"] = _get_page_fingerprint(home_resp)
        print(f"  [i] Homepage fingerprint: title='{baselines['homepage']['title']}', "
              f"{baselines['homepage']['length']} octets")
    except requests.exceptions.RequestException:
        pass

    # 2) Send random probes to detect wildcard / custom-404 behaviour.
    #    Mix generic paths AND file-extension paths — some platforms (Vercel,
    #    Cloudflare Pages) return different status codes depending on whether
    #    the path looks like a file or a directory.
    random_paths = [
        f"__scanner_missing_{uuid.uuid4().hex[:12]}_0.html",
        f"__scanner_missing_{uuid.uuid4().hex[:12]}_1",
        f"__scanner_fake_config_{uuid.uuid4().hex[:8]}.bak",
        f"__scanner_fake_backup_{uuid.uuid4().hex[:8]}.zip",
    ]
    for random_path in random_paths:
        try:
            resp = session.get(
                _join_url(target_url, random_path), timeout=5, allow_redirects=False
            )
            fp = _get_page_fingerprint(resp)
            baselines["probes"].append(fp)
        except requests.exceptions.RequestException:
            pass

    probe_statuses = [p["status"] for p in baselines["probes"]]
    if probe_statuses:
        print(f"  [i] Baseline probes: statuses={probe_statuses}, "
              f"body_sizes={[p['length'] for p in baselines['probes']]}")

    return baselines


# Keywords commonly found in custom error / "not found" pages even when HTTP 200
_SOFT_404_KEYWORDS = [
    "page not found", "not found", "404", "does not exist", "n'existe pas",
    "page introuvable", "erreur", "nothing here", "no results",
    "sorry", "oops", "we couldn't find", "the page you",
    "requested page", "cette page", "page demandée",
]


def _is_soft_404(response, baselines, word):
    """Return True if the response is very likely a soft-404 / false-positive.

    Checks performed (any match -> soft 404):
      1. Non-200 wildcard statuses — any 4xx if ALL probes are also 4xx.
      2. 401/403 body is similar to any probe body (cross-status comparison).
      3. Response is near-identical to ANY of the random-path probes (same status).
      4. Response is near-identical to the homepage (the #1 false positive cause).
      5. Response body contains common 'not found' keywords.
      6. Redirect points back to site root (Location header == /).
    """
    status = response.status_code
    fp = _get_page_fingerprint(response)
    probes = baselines.get("probes", [])

    # ── 1. Wildcard 4xx detection ───────────────────────────────────
    # If ALL baseline probes returned a 4xx status, then the server treats
    # unknown paths as 4xx.  Any 4xx we get is therefore not a real finding.
    # This catches Vercel (403), Cloudflare Pages (403), standard 404, etc.
    if status in (401, 403, 404, 410) and probes:
        # Matching a status code alone is insufficient: a real protected path
        # can return 403 while random paths return a different generic 403 page.
        for probe in probes:
            if probe["status"] != status:
                continue
            if _similar(fp["compact"], probe["compact"]) > 0.72:
                return True
            if (
                fp["title"]
                and fp["title"] == probe["title"]
                and abs(fp["length"] - probe["length"])
                <= max(80, probe["length"] * 0.15)
            ):
                return True

        # All probes are 4xx → server returns errors for missing pages;
        # the specific code varies but they are all "not found" semantically.
    # ── 2. Cross-status body comparison for 401/403 ─────────────────
    # Even when probe status differs (e.g. probes got 404 but we got 403),
    # if the response body looks like the probe body, it's a generic error.
    if status in (401, 403) and probes:
        for probe in probes:
            # Compare content regardless of status code
            if _similar(fp["compact"], probe["compact"]) > 0.65:
                print(f"  [~] Soft-404 (body ~= probe, {status} vs {probe['status']}): /{word}")
                return True
            # Short error pages with matching titles are generic
            if (fp["title"] and probe["title"]
                    and fp["title"] == probe["title"]
                    and fp["length"] < 5000):
                print(f"  [~] Soft-404 (same title as probe error): /{word}")
                return True

    # ── 3. Compare against random-path probes (wildcard 200 pages) ──
    for probe in probes:
        if probe["status"] != status:
            continue
        # Title match is a very strong signal
        if fp["title"] and probe["title"] and fp["title"] == probe["title"]:
            length_close = abs(fp["length"] - probe["length"]) <= max(80, probe["length"] * 0.15)
            if length_close:
                return True
        # Content similarity
        if _similar(fp["compact"], probe["compact"]) > 0.75:
            return True

    # ── 4. Compare against homepage ─────────────────────────────────
    home = baselines.get("homepage")
    if home and status == 200:
        # Same title as homepage -> almost certainly soft-404
        if fp["title"] and home["title"] and fp["title"] == home["title"]:
            if _similar(fp["compact"], home["compact"]) > 0.70:
                print(f"  [~] Soft-404 (matches homepage): /{word}")
                return True
        # Very high content similarity to homepage
        if _similar(fp["compact"], home["compact"]) > 0.80:
            print(f"  [~] Soft-404 (content ~= homepage): /{word}")
            return True

    # ── 5. Body contains 'not found' keywords on 200 ────────────────
    if status == 200:
        body_lower = response.text.lower()
        title = fp["title"]
        for keyword in _SOFT_404_KEYWORDS:
            if keyword in title:
                print(f"  [~] Soft-404 (title contains '{keyword}'): /{word}")
                return True
        # Only flag keywords in body if page is small (avoids matching
        # legitimate pages that incidentally mention "404" somewhere)
        if len(response.text) < 5000:
            for keyword in _SOFT_404_KEYWORDS:
                if keyword in body_lower:
                    print(f"  [~] Soft-404 (body contains '{keyword}'): /{word}")
                    return True

    # ── 6. Redirect points back to site root ────────────────────────
    if status in (301, 302, 307, 308):
        location = response.headers.get("Location", "")
        parsed_loc = urlparse(location)
        if parsed_loc.path in ("", "/", "/index.html", "/index.php"):
            print(f"  [~] Soft-404 (redirects to root): /{word}")
            return True

    return False


def _discover_paths(session, root, timeout, max_scripts):
    """Collect same-origin paths disclosed by HTML, robots, sitemaps and JS."""
    paths = set()
    script_urls = []

    def add_url(value, base=root):
        if not value or value.startswith(("data:", "mailto:", "javascript:")):
            return
        absolute, _ = urldefrag(urljoin(base.rstrip("/") + "/", value))
        if not same_origin(absolute, root):
            return
        parsed = urlparse(absolute)
        path = parsed.path.strip("/")
        if path and len(path) <= 220 and "{" not in path:
            paths.add(path)

    try:
        home = session.get(root.rstrip("/") + "/", timeout=timeout, allow_redirects=True)
        for attr, value in re.findall(
            r"\b(href|src|action)\s*=\s*[\"']([^\"']+)",
            home.text,
            flags=re.IGNORECASE,
        ):
            add_url(value, home.url)
            if attr.lower() == "src" and ".js" in value.lower():
                script_url = urljoin(home.url, value)
                if same_origin(script_url, root):
                    script_urls.append(script_url)
    except requests.exceptions.RequestException:
        pass

    for metadata_path in ("robots.txt", "sitemap.xml"):
        try:
            response = session.get(
                _join_url(root, metadata_path), timeout=timeout, allow_redirects=True
            )
        except requests.exceptions.RequestException:
            continue
        if response.status_code >= 400:
            continue
        if metadata_path == "robots.txt":
            for value in re.findall(
                r"^(?:allow|disallow|sitemap)\s*:\s*(\S+)",
                response.text,
                flags=re.IGNORECASE | re.MULTILINE,
            ):
                add_url(value, response.url)
        else:
            for value in re.findall(r"<loc>\s*(.*?)\s*</loc>", response.text, re.I):
                add_url(value, response.url)

    js_path_pattern = re.compile(
        r"[\"'`](\/[^\"'`\s<>]{1,220})[\"'`]"
    )
    total_bytes = 0
    for script_url in list(dict.fromkeys(script_urls))[:max_scripts]:
        try:
            response = session.get(script_url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException:
            continue
        if response.status_code >= 400:
            continue
        total_bytes += len(response.content)
        if total_bytes > 15_000_000:
            break
        source = response.text.replace("\\/", "/")
        for match in js_path_pattern.finditer(source):
            add_url(match.group(1).split("?", 1)[0], script_url)

    backup_variants = set()
    for path in paths:
        name = path.rsplit("/", 1)[-1]
        if "." in name and not name.endswith((".map", ".min.js")):
            backup_variants.update(
                {f"{path}.bak", f"{path}.old", f"{path}~", f"{path}.save"}
            )
    return list(paths | backup_variants)


def _probe_paths(paths, target_url, options, timeout, workers):
    """Fetch path candidates concurrently with one session per worker thread."""
    local_state = threading.local()

    def probe(word):
        if not hasattr(local_state, "session"):
            local_state.session = build_session(options)
        try:
            response = local_state.session.get(
                _join_url(target_url, word), timeout=timeout, allow_redirects=False
            )
            return word, response
        except requests.exceptions.RequestException:
            return word, None

    results = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [executor.submit(probe, word) for word in paths]
        for future in as_completed(futures):
            word, response = future.result()
            if response is not None:
                results[word] = response
    return results


def _is_interesting_path(word):
    lowered = word.lower().strip("/")
    if lowered in BENIGN_PUBLIC_HINTS:
        return False
    if any(hint in lowered for hint in SENSITIVE_FILE_HINTS):
        return True
    parts = lowered.replace(".", "/").replace("-", "/").split("/")
    return any(part in INTERESTING_HINTS for part in parts) or any(
        hint in lowered for hint in INTERESTING_HINTS if len(hint) >= 5
    )


def _classify(word, status_code, content_type="", response_text=""):
    """Classify only evidence-backed exposures, not every successful JSON page."""
    lowered = word.lower()
    body = (response_text or "").lower()
    is_sensitive_file = any(hint.lower() in lowered for hint in SENSITIVE_FILE_HINTS)
    sensitive_signatures = (
        "password", "passwd", "api_key", "apikey", "access_token",
        "client_secret", "private key", "database_url", "aws_secret",
        "begin rsa private key", "begin openssh private key",
    )
    has_sensitive_content = any(signature in body for signature in sensitive_signatures)
    is_directory_listing = (
        "index of /" in body
        or "directory listing for" in body
        or ("parent directory" in body and "<a href=" in body)
    )
    is_json = "json" in content_type.lower()
    has_sensitive_path = any(hint in lowered for hint in EXPOSURE_PATH_HINTS)
    has_sensitive_json = is_json and any(
        key in body
        for key in (
            '"password"', '"token"', '"secret"', '"api_key"',
            '"access_token"', '"email"', '"users"',
        )
    )

    # Authentication and authorization are protections, not vulnerabilities.
    # Keep these routes in console discovery output but do not count them as
    # security findings solely because they exist.
    if status_code != 200:
        return None, None
    if is_sensitive_file and has_sensitive_content:
        return "Élevé", "Fichier sensible exposé"
    if is_directory_listing:
        return "Élevé", "Indexation de répertoire activée"
    if has_sensitive_json:
        return "Élevé", "Endpoint API exposant des données sensibles"
    if is_sensitive_file:
        return "Moyen", "Fichier potentiellement sensible accessible"
    if any(
        hint in lowered for hint in ("backup", "dump", "encryptionkeys", "private")
    ):
        return "Élevé", "Ressource sensible accessible"
    if has_sensitive_path:
        return "Moyen", "Chemin sensible accessible"
    # A public JSON endpoint or a generic successful route is not a
    # vulnerability without sensitive content or a security-relevant path.
    return None, None


def decouvrir_contenu(url_cible, options=None, _ctx=None):
    options = options or {}
    depth_config = get_depth_config(options)
    timeout = int(options.get("timeout", depth_config["timeout"]))
    workers = int(options.get("fuzzer_workers", depth_config["fuzzer_workers"]))
    max_paths = int(options.get("fuzzer_max_paths", depth_config["fuzzer_max_paths"]))
    max_scripts = int(
        options.get("fuzzer_max_scripts", depth_config["fuzzer_max_scripts"])
    )
    recursive_limit = int(
        options.get(
            "fuzzer_recursive_dirs", depth_config["fuzzer_recursive_dirs"]
        )
    )
    root = get_scope_root(url_cible)
    print(f"[*] Démarrage du fuzzing sur : {root}")

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

        words = _read_wordlist()
        session = build_session(options)
        discovered_paths = _discover_paths(
            session, target_url, timeout, max_scripts
        )
        dynamic_priority = [
            path for path in discovered_paths if _is_interesting_path(path)
        ]
        dynamic_other = [
            path for path in discovered_paths if path not in dynamic_priority
        ]
        words = list(dict.fromkeys(dynamic_priority + words + dynamic_other))[:max_paths]
        print(
            f"  [i] {len(discovered_paths)} chemin(s) découverts dans HTML/JS/robots; "
            f"{len(words)} chemin(s) testés avec {workers} workers."
        )

        # Build robust baselines: multiple random probes + homepage fingerprint
        baselines = _build_baselines(session, target_url)

        findings = 0
        seen = set()
        # Track discovered directories for recursive sub-path probing
        discovered_dirs = []

        # VALID_STATUS: now includes redirects (301, 302, 307, 308)
        valid_statuses = {200, 201, 204, 301, 302, 307, 308, 401, 403}
        responses = _probe_paths(words, target_url, options, timeout, workers)

        for word in words:
            if word in seen:
                continue
            seen.add(word)

            # Test ALL paths from wordlist, not just "interesting" ones.
            # Classify severity AFTER we get a response.
            url_test = _join_url(target_url, word)
            response = responses.get(word)
            if response is None:
                continue

            if response.status_code not in valid_statuses:
                continue

            # Robust soft-404 detection: compare against multiple baselines,
            # homepage fingerprint, title, content similarity, and keywords.
            if _is_soft_404(response, baselines, word):
                continue

            content_type = response.headers.get("Content-Type", "").split(";", 1)[0]

            # Only report if the path is actually interesting
            if not _is_interesting_path(word):
                # But still track directories for recursive probing
                if response.status_code == 200 and ("html" in content_type or "json" in content_type):
                    discovered_dirs.append(word)
                continue

            severity, finding_type = _classify(word, response.status_code, content_type, response.text)
            if not severity:
                continue

            # For redirects, note the redirect target
            redirect_info = ""
            if response.status_code in (301, 302, 307, 308):
                redirect_target = response.headers.get("Location", "inconnu")
                redirect_info = f" Redirige vers: {redirect_target}."

            description = (
                f"Le chemin '/{word}' répond avec HTTP {response.status_code} "
                f"({content_type or 'type inconnu'}, {len(response.text)} octets).{redirect_info} "
                "Le résultat a été filtré contre une page 404 aléatoire pour réduire les faux positifs."
            )
            remediation = (
                "Supprimer les fichiers sensibles du répertoire web, désactiver l'indexation, "
                "protéger les interfaces d'administration par authentification forte et bloquer "
                "l'accès direct aux sauvegardes/configurations via le serveur web."
            )

            add_vulnerability(
                cursor,
                scan_id,
                f"{finding_type} : /{word}",
                severity,
                description,
                remediation,
            )
            findings += 1
            print(f"  [+] HTTP {response.status_code}: {url_test} -> {severity}")

            # Track directories for recursive probing
            if response.status_code == 200 and "/" not in word:
                discovered_dirs.append(word)


        # ── Recursive sub-path probing ──────────────────────────────
        # For discovered directories, try common sub-paths
        recursive_subpaths = [
            "v1", "v2", "v3", "docs", "schema", "health", "status",
            "search", "login", "users", "admin", "config", "info",
        ]

        for parent_dir in discovered_dirs[:recursive_limit]:
            for subpath in recursive_subpaths:
                combined = f"{parent_dir}/{subpath}"
                if combined in seen:
                    continue
                seen.add(combined)

                url_test = _join_url(target_url, combined)
                try:
                    response = session.get(url_test, timeout=timeout, allow_redirects=False)
                except requests.exceptions.RequestException:
                    continue

                if response.status_code not in valid_statuses:
                    continue
                if _is_soft_404(response, baselines, combined):
                    continue

                content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
                severity, finding_type = _classify(combined, response.status_code, content_type, response.text)
                if not severity:
                    continue

                description = (
                    f"Le sous-chemin '/{combined}' (découvert récursivement) répond avec HTTP {response.status_code} "
                    f"({content_type or 'type inconnu'}, {len(response.text)} octets)."
                )
                remediation = (
                    "Supprimer les fichiers sensibles du répertoire web, désactiver l'indexation, "
                    "protéger les interfaces d'administration par authentification forte et bloquer "
                    "l'accès direct aux sauvegardes/configurations via le serveur web."
                )

                add_vulnerability(
                    cursor,
                    scan_id,
                    f"{finding_type} : /{combined}",
                    severity,
                    description,
                    remediation,
                )
                findings += 1
                print(f"  [+] HTTP {response.status_code}: {url_test} -> {severity} (récursif)")


        if not _ctx:
            finish_scan(conn, cursor, scan_id, "Terminé")
        print(
            f"[*] Fuzzing terminé. {findings} chemin(s) intéressant(s) sauvegardé(s)."
        )

    except Exception as exc:
        print(f"  [X] Erreur fuzzing : {exc}")
        if not _ctx and scan_id is not None:
            finish_scan(conn, cursor, scan_id, "Erreur")
    finally:
        if not _ctx:
            conn.close()


if __name__ == "__main__":
    decouvrir_contenu("http://localhost")
