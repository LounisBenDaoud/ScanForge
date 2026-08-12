"""
reset_db.py -- Clears all data from scanner.db and resets auto-increment counters.
Run this script from anywhere inside the project:
    python database/reset_db.py
"""

import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "scanner.db")


def reset_database():
    if not os.path.exists(DB_FILE):
        print("[!] Database not found at: " + DB_FILE)
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Delete all rows (order matters due to foreign keys)
    cursor.execute("DELETE FROM vulnerabilites")
    cursor.execute("DELETE FROM scans")
    cursor.execute("DELETE FROM cibles")

    # Reset auto-increment counters
    cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'vulnerabilites'")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'cibles'")

    conn.commit()
    conn.close()
    print("[+] Database cleaned. All scans, targets and vulnerabilities deleted.")
    print("[+] Auto-increment IDs reset to 1.")


if __name__ == "__main__":
    confirm = input("Wipe ALL data? Type 'yes' to confirm: ").strip().lower()
    if confirm == "yes":
        reset_database()
    else:
        print("[-] Cancelled. No data was deleted.")
