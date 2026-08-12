import sqlite3
import os

# Ensure the database is always created inside the 'database' folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'scanner.db')

def initialiser_base_de_donnees():
    # Preserve existing data — CREATE TABLE IF NOT EXISTS handles schema safely
    is_new = not os.path.exists(DB_FILE)
    if is_new:
        print("[i] Création d'une nouvelle base de données.")

    connexion = sqlite3.connect(DB_FILE)
    curseur = connexion.cursor()

    # 1. Table: Cibles (Targets)
    curseur.execute('''
    CREATE TABLE IF NOT EXISTS cibles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE NOT NULL,
        date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # 2. Table: Scans
    curseur.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cible_id INTEGER,
        statut TEXT DEFAULT 'En attente',
        date_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(cible_id) REFERENCES cibles(id)
    )
    ''')

    # 3. Table: Vulnérabilités (UPDATED with Classification)
    curseur.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        type TEXT NOT NULL,
        criticite TEXT NOT NULL,
        description TEXT,
        remediation TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    ''')

    connexion.commit()
    connexion.close()
    print("[+] Base de données initialisée avec succès (données existantes préservées) !")

if __name__ == '__main__':
    initialiser_base_de_donnees()