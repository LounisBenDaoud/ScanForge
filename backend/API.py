import os
import sqlite3
import sys
import threading
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS

# Initialisation de l'application Flask
app = Flask(__name__)
CORS(app)

# Configuration des chemins
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "../database/scanner.db")

# Ajout du dossier backend au path Python pour les imports core
sys.path.insert(0, BASE_DIR)

from core.common import connect_db as scanner_connect_db, finish_scan as scanner_finish_scan, start_scan as scanner_start_scan
from core.fuzzer import decouvrir_contenu
from core.payloads import tester_injections
from core.recon import analyser_en_tetes


@app.route("/api/scans", methods=["GET"])
def get_scans():
    """Récupère l'historique complet des scans avec l'URL de la cible."""
    try:
        if not os.path.exists(DB_FILE):
            return jsonify(
                {"status": "error", "message": "Base de données introuvable."}
            ), 404

        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT scans.id, scans.statut, scans.date_scan, cibles.url
            FROM scans
            JOIN cibles ON scans.cible_id = cibles.id
            ORDER BY scans.date_scan DESC
        """)
        scans = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return jsonify({"status": "success", "count": len(scans), "data": scans})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Calcule le nombre total de vulnérabilités par niveau de criticité."""
    try:
        if not os.path.exists(DB_FILE):
            return jsonify({"status": "error", "message": "Database not found."}), 404

        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT criticite, COUNT(*) as count FROM vulnerabilites GROUP BY criticite"
        )
        rows = cursor.fetchall()

        stats = {"Faible": 0, "Moyen": 0, "\u00c9lev\u00e9": 0, "Critique": 0}
        for row in rows:
            if row["criticite"] in stats:
                stats[row["criticite"]] = row["count"]

        conn.close()
        return jsonify({"status": "success", "data": stats})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Lance un audit complet en arrière-plan sur l'URL fournie."""
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify(
            {"status": "error", "message": "URL manquante dans la requ\u00eate."}
        ), 400

    if not data.get("confirmAuthorized"):
        return jsonify(
            {
                "status": "error",
                "message": "Vous devez confirmer que vous êtes autorisé à auditer cette cible.",
            }
        ), 403

    url = data["url"].strip().rstrip("/")
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        return jsonify(
            {
                "status": "error",
                "message": "URL invalide. Utilisez une cible http:// ou https://.",
            }
        ), 400

    scan_options = {
        "profile": data.get("profile", os.getenv("SCANNER_PROFILE", "generic")),
        "cookie_header": data.get("cookieHeader", ""),
        "depth": data.get("securityLevel", "standard"),
        "dvwa_security_level": data.get("dvwaSecurityLevel", ""),
        "tests": data.get("tests", {}),
    }

    def run_full_scan():
        conn = scanner_connect_db()
        cursor = conn.cursor()
        scan_id = None
        try:
            scan_id, target_url = scanner_start_scan(cursor, url)
            conn.commit()
            ctx = (conn, cursor, scan_id)

            # Module 1 : Reconnaissance passive (analyse des en-têtes HTTP)
            analyser_en_tetes(url, options=scan_options, _ctx=ctx)
            conn.commit()

            # Module 2 : Découverte de contenu (fuzzing de répertoires)
            decouvrir_contenu(url, options=scan_options, _ctx=ctx)
            conn.commit()

            # Module 3 : Tests d'injection actifs (XSS & SQLi)
            tester_injections(url, options=scan_options, _ctx=ctx)

            scanner_finish_scan(conn, cursor, scan_id, "Terminé")
        except Exception as exc:
            print(f"  [X] Erreur scan : {exc}")
            if scan_id is not None:
                try:
                    scanner_finish_scan(conn, cursor, scan_id, "Erreur")
                except Exception:
                    pass
        finally:
            conn.close()

    # Exécution en arrière-plan pour ne pas bloquer l'API
    thread = threading.Thread(target=run_full_scan, daemon=True)
    thread.start()

    return jsonify(
        {
            "status": "success",
            "message": f"Audit de '{url}' lanc\u00e9 en arri\u00e8re-plan. Rafra\u00eechissez dans quelques secondes.",
        }
    )


@app.route("/api/last-scan", methods=["GET"])
def get_last_scan():
    """Retourne le dernier audit (URL la plus récente) avec toutes ses vulnérabilités."""
    try:
        if not os.path.exists(DB_FILE):
            return jsonify(
                {"status": "error", "message": "Base de données introuvable."}
            ), 404

        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # URL la plus récemment scannée
        cursor.execute("""
            SELECT cibles.url, MAX(scans.date_scan) as last_date
            FROM scans
            JOIN cibles ON scans.cible_id = cibles.id
            GROUP BY cibles.url
            ORDER BY last_date DESC
            LIMIT 1
        """)
        last_target = cursor.fetchone()

        if not last_target:
            conn.close()
            return jsonify({"status": "success", "data": None})

        url = last_target["url"]
        last_date = last_target["last_date"]

        # Vulnérabilités uniques pour cette URL (GROUP BY élimine les doublons
        # issus de scans répétés sur la même cible)
        cursor.execute(
            """
            SELECT MIN(v.id) as id, v.type, v.criticite, v.description, v.remediation
            FROM vulnerabilites v
            JOIN scans s ON v.scan_id = s.id
            JOIN cibles c ON s.cible_id = c.id
            WHERE c.url = ?
            GROUP BY v.type, v.criticite, v.description, v.remediation
            ORDER BY
                CASE v.criticite
                    WHEN 'Critique' THEN 1
                    WHEN '\u00c9lev\u00e9'    THEN 2
                    WHEN 'Moyen'    THEN 3
                    WHEN 'Faible'   THEN 4
                    ELSE 5
                END, MIN(v.id)
        """,
            (url,),
        )

        vulns = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return jsonify(
            {
                "status": "success",
                "data": {
                    "url": url,
                    "date": last_date,
                    "count": len(vulns),
                    "vulnerabilities": vulns,
                },
            }
        )

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan_detail(scan_id):
    """Retourne le détail d'un scan spécifique avec ses vulnérabilités."""
    try:
        if not os.path.exists(DB_FILE):
            return jsonify(
                {"status": "error", "message": "Base de données introuvable."}
            ), 404

        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT scans.id, scans.statut, scans.date_scan, cibles.url
            FROM scans
            JOIN cibles ON scans.cible_id = cibles.id
            WHERE scans.id = ?
        """, (scan_id,))
        scan = cursor.fetchone()

        if not scan:
            conn.close()
            return jsonify({"status": "error", "message": "Scan introuvable."}), 404

        cursor.execute("""
            SELECT id, type, criticite, description, remediation
            FROM vulnerabilites
            WHERE scan_id = ?
            ORDER BY
                CASE criticite
                    WHEN 'Critique' THEN 1
                    WHEN '\u00c9lev\u00e9'    THEN 2
                    WHEN 'Moyen'    THEN 3
                    WHEN 'Faible'   THEN 4
                    ELSE 5
                END, id
        """, (scan_id,))
        vulns = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return jsonify({
            "status": "success",
            "data": {
                "id": scan["id"],
                "url": scan["url"],
                "statut": scan["statut"],
                "date": scan["date_scan"],
                "count": len(vulns),
                "vulnerabilities": vulns,
            },
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/health", methods=["GET"])
def health_check():
    """Vérifie que l'API est en ligne."""
    return jsonify({"status": "online", "message": "Backend API is fully functional!"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
