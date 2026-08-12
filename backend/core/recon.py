from urllib.parse import urlparse

try:
    from .common import (
        add_vulnerability,
        build_session,
        connect_db,
        finish_scan,
        normalize_target_url,
        start_scan,
    )
except ImportError:
    from common import (
        add_vulnerability,
        build_session,
        connect_db,
        finish_scan,
        normalize_target_url,
        start_scan,
    )

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS Manquant",
        "description": "Le serveur ne force pas l'utilisation de HTTPS via l'en-tête Strict-Transport-Security.",
        "remediation": "Activer HTTPS et configurer Strict-Transport-Security avec une durée suffisante, par exemple max-age=31536000; includeSubDomains.",
    },
    "Content-Security-Policy": {
        "name": "CSP Manquant",
        "description": "Aucune Content-Security-Policy n'est présente pour limiter les sources de scripts, styles et contenus.",
        "remediation": "Définir une Content-Security-Policy stricte adaptée à l'application afin de réduire l'impact des XSS.",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options Manquant",
        "description": "Le site peut potentiellement être intégré dans une iframe, ce qui augmente le risque de clickjacking.",
        "remediation": "Ajouter X-Frame-Options: DENY ou SAMEORIGIN, ou utiliser frame-ancestors dans la CSP.",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options Manquant",
        "description": "Le navigateur peut tenter de deviner le type MIME des ressources servies.",
        "remediation": "Ajouter X-Content-Type-Options: nosniff sur les réponses HTTP.",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy Manquant",
        "description": "Le site ne contrôle pas précisément les informations Referrer envoyées vers d'autres origines.",
        "remediation": "Configurer Referrer-Policy, par exemple strict-origin-when-cross-origin ou no-referrer selon le besoin.",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy Manquant",
        "description": "Le site ne limite pas l'accès aux fonctionnalités du navigateur (caméra, micro, géolocalisation, etc.).",
        "remediation": "Configurer Permissions-Policy pour désactiver les fonctionnalités non utilisées (ex: geolocation=(), camera=()).",
    },
}

# Patterns that indicate server/technology version disclosure
VERSION_DISCLOSURE_PATTERNS = [
    ("Server", "server"),
    ("X-Powered-By", "x-powered-by"),
]

# Cookie flags to check
COOKIE_SECURITY_FLAGS = {
    "HttpOnly": {
        "check": lambda cookie: not cookie.has_nonstandard_attr("HttpOnly") and not cookie.get("httponly"),
        "name": "Cookie sans HttpOnly",
        "description": "Le cookie '{name}' est défini sans l'attribut HttpOnly, ce qui le rend accessible via JavaScript et vulnérable au vol via XSS.",
        "remediation": "Ajouter l'attribut HttpOnly à tous les cookies de session pour empêcher l'accès JavaScript.",
        "severity": "Moyen",
    },
    "Secure": {
        "check": lambda cookie: not cookie.get("secure"),
        "name": "Cookie sans Secure",
        "description": "Le cookie '{name}' est défini sans l'attribut Secure, ce qui permet sa transmission en clair via HTTP.",
        "remediation": "Ajouter l'attribut Secure à tous les cookies sensibles pour forcer la transmission via HTTPS uniquement.",
        "severity": "Moyen",
    },
    "SameSite": {
        "check": lambda cookie: not cookie.get("samesite"),
        "name": "Cookie sans SameSite",
        "description": "Le cookie '{name}' n'a pas d'attribut SameSite, ce qui peut faciliter les attaques CSRF.",
        "remediation": "Ajouter SameSite=Strict ou SameSite=Lax aux cookies pour limiter leur envoi dans les requêtes cross-site.",
        "severity": "Faible",
    },
}


def _check_security_headers(response, cursor, scan_id):
    """Check for missing security headers."""
    headers = response.headers
    findings = 0
    for header, details in SECURITY_HEADERS.items():
        if header not in headers:
            add_vulnerability(
                cursor,
                scan_id,
                details["name"],
                "Faible",
                details["description"],
                details["remediation"],
            )
            findings += 1
            print(f"  [!] {details['name']} détecté -> Classé: Faible")
    return findings


def _check_version_disclosure(response, cursor, scan_id):
    """Check if server headers disclose technology/version information."""
    headers = response.headers
    findings = 0
    for header_name, _ in VERSION_DISCLOSURE_PATTERNS:
        value = headers.get(header_name, "")
        if not value:
            continue
        # Only flag if the header contains version-like info or specific tech names
        # Generic values like "nginx" alone are less concerning than "nginx/1.19.0"
        has_version = any(c.isdigit() for c in value)
        tech_names = [
            "express", "nginx", "apache", "iis", "tomcat", "jetty",
            "php", "asp.net", "node", "python", "ruby", "java",
            "openresty", "litespeed", "caddy", "gunicorn", "uvicorn",
            "kestrel", "werkzeug", "flask", "django", "laravel",
        ]
        has_tech = any(tech in value.lower() for tech in tech_names)

        if has_version or has_tech:
            severity = "Moyen" if has_version else "Faible"
            description = (
                f"L'en-tête '{header_name}' divulgue des informations technologiques : '{value}'. "
                "Cela aide un attaquant à identifier la pile logicielle et cibler des vulnérabilités connues."
            )
            remediation = (
                f"Supprimer ou masquer l'en-tête '{header_name}' dans la configuration du serveur web. "
                "Par exemple, avec Express.js : app.disable('x-powered-by'); ou utiliser Helmet."
            )
            add_vulnerability(
                cursor, scan_id,
                f"Divulgation de technologie ({header_name})",
                severity, description, remediation,
            )
            findings += 1
            print(f"  [!] Divulgation '{header_name}: {value}' -> Classé: {severity}")
    return findings


def _check_cookie_security(response, cursor, scan_id, is_https=False):
    """Check cookies for missing security attributes."""
    findings = 0
    # Parse Set-Cookie headers from the response
    set_cookie_headers = response.headers.get("Set-Cookie", "")
    if not set_cookie_headers:
        # Also check response.cookies for cookies set in the jar
        if not response.cookies:
            return 0

    # Check cookies from the response
    for cookie in response.cookies:
        cookie_name = cookie.name
        for flag_name, flag_info in COOKIE_SECURITY_FLAGS.items():
            # Skip "Secure" flag check on plain HTTP targets — the Secure
            # attribute only makes sense over TLS.  Flagging it on
            # http://localhost (DVWA, Juice Shop) is a false positive.
            if flag_name == "Secure" and not is_https:
                continue

            # Check the raw Set-Cookie header for flags since requests
            # doesn't fully expose all cookie attributes
            missing = False
            # For HttpOnly and Secure, check the cookie jar attributes
            if flag_name == "HttpOnly":
                # Check in raw Set-Cookie header
                raw_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, 'getlist') else []
                if not raw_headers:
                    raw_headers = [response.headers.get("Set-Cookie", "")]
                for raw in raw_headers:
                    if cookie_name in raw and "httponly" not in raw.lower():
                        missing = True
                        break
            elif flag_name == "Secure":
                if not cookie.secure:
                    missing = True
            elif flag_name == "SameSite":
                raw_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, 'getlist') else []
                if not raw_headers:
                    raw_headers = [response.headers.get("Set-Cookie", "")]
                for raw in raw_headers:
                    if cookie_name in raw and "samesite" not in raw.lower():
                        missing = True
                        break

            if missing:
                description = flag_info["description"].format(name=cookie_name)
                add_vulnerability(
                    cursor, scan_id,
                    f"{flag_info['name']} ({cookie_name})",
                    flag_info["severity"],
                    description,
                    flag_info["remediation"],
                )
                findings += 1
                print(f"  [!] {flag_info['name']} sur '{cookie_name}' -> Classé: {flag_info['severity']}")
    return findings


def _check_cors_misconfiguration(response, cursor, scan_id):
    """Check for overly permissive CORS configuration."""
    findings = 0
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*" and acac == "true":
        # This is the actually dangerous combination — wildcard origin
        # with credentials means any site can make authenticated requests.
        description = (
            "Le serveur utilise Access-Control-Allow-Origin: * avec "
            "Allow-Credentials: true, ce qui permet à n'importe quel site "
            "d'envoyer des requêtes authentifiées et de lire les réponses."
        )
        remediation = (
            "Restreindre Access-Control-Allow-Origin aux domaines de confiance spécifiques "
            "et ne jamais combiner '*' avec Allow-Credentials: true."
        )
        add_vulnerability(
            cursor, scan_id,
            "CORS Mal Configuré (Critique)",
            "Élevé", description, remediation,
        )
        findings += 1
        print(f"  [!] CORS ouvert (Allow-Origin: * + Credentials) -> Classé: Élevé")
    elif acao == "*":
        # Standalone wildcard without credentials — common on public APIs
        # and CDNs.  Only a concern if sensitive data is exposed.
        description = (
            "Le serveur utilise Access-Control-Allow-Origin: *. "
            "Ceci est normal pour les API publiques mais peut représenter un "
            "risque si des données sensibles ou privées sont exposées sans authentification."
        )
        remediation = (
            "Si l'API expose des données sensibles, restreindre Access-Control-Allow-Origin "
            "aux domaines de confiance spécifiques au lieu de '*'."
        )
        add_vulnerability(
            cursor, scan_id,
            "CORS Permissif",
            "Faible", description, remediation,
        )
        findings += 1
        print(f"  [!] CORS ouvert (Allow-Origin: *) -> Classé: Faible")
    return findings


def _check_error_page_disclosure(session, base_url, cursor, scan_id):
    """Send a bad request and check if error pages leak information."""
    findings = 0
    # Try a few error-triggering paths
    error_paths = [
        "/%00",                    # null byte
        "/this-does-not-exist-404",
        "/..%2f..%2fetc%2fpasswd", # path traversal attempt
    ]

    stack_trace_indicators = [
        "traceback", "stack trace", "at module", "at object",
        "at function", "error at", "syntaxerror", "typeerror",
        "referenceerror", "unhandled", "exception", "node_modules",
        "internal server error", "debug", "file \"",
        ".js:", ".py:", ".php:", ".java:",
    ]

    for path in error_paths:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            resp = session.get(url, timeout=8, allow_redirects=True)

            # Only check 4xx/5xx error pages
            if resp.status_code < 400:
                continue

            lowered = resp.text.lower()
            matched = [ind for ind in stack_trace_indicators if ind in lowered]
            if len(matched) >= 3:  # Need at least 3 indicators to reduce false positives
                description = (
                    f"La page d'erreur (HTTP {resp.status_code}) sur '{path}' divulgue des détails techniques. "
                    f"Indicateurs détectés : {', '.join(matched[:5])}. "
                    "Ces informations aident un attaquant à comprendre la pile technologique."
                )
                remediation = (
                    "Configurer des pages d'erreur personnalisées qui ne révèlent aucun détail technique. "
                    "Désactiver le mode debug en production."
                )
                add_vulnerability(
                    cursor, scan_id,
                    "Divulgation dans les pages d'erreur",
                    "Moyen", description, remediation,
                )
                findings += 1
                print(f"  [!] Page d'erreur verbeuse sur '{path}' -> Classé: Moyen")
                break  # One finding is enough
        except Exception:
            continue
    return findings


def analyser_en_tetes(url, options=None, _ctx=None):
    print(f"[*] Démarrage de la reconnaissance passive sur : {url}")

    if _ctx:
        conn, cursor, scan_id = _ctx
    else:
        conn = connect_db()
        cursor = conn.cursor()
        scan_id = None

    try:
        if not _ctx:
            scan_id, target_url = start_scan(cursor, url)
            conn.commit()
        else:
            target_url = normalize_target_url(url)

        session = build_session(options)
        response = session.get(target_url, timeout=10, allow_redirects=True)

        findings = 0

        # Check 1: Missing security headers (original)
        findings += _check_security_headers(response, cursor, scan_id)

        # Check 2: Server/technology version disclosure (NEW)
        findings += _check_version_disclosure(response, cursor, scan_id)

        # Check 3: Cookie security flags (NEW)
        is_https = urlparse(target_url).scheme == "https"
        findings += _check_cookie_security(response, cursor, scan_id, is_https=is_https)

        # Check 4: CORS misconfiguration (NEW)
        findings += _check_cors_misconfiguration(response, cursor, scan_id)

        # Check 5: Error page information disclosure (NEW)
        findings += _check_error_page_disclosure(session, target_url, cursor, scan_id)

        if not _ctx:
            finish_scan(conn, cursor, scan_id, "Terminé")
        print(
            f"[*] Reconnaissance terminée. {findings} problème(s) de configuration sauvegardé(s)."
        )

    except Exception as exc:
        print(f"  [X] Erreur reconnaissance : {exc}")
        if not _ctx and scan_id is not None:
            finish_scan(conn, cursor, scan_id, "Erreur")
    finally:
        if not _ctx:
            conn.close()


if __name__ == "__main__":
    analyser_en_tetes("http://localhost")
