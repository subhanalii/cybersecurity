# vigilanteye/siem/database.py

import sqlite3

DB = "siem.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # Table for Raw Logs (simulating input from Wazuh/Agent/Snort)
    c.execute("""CREATE TABLE IF NOT EXISTS logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT,
                    event TEXT,
                    ip_address TEXT,
                    username TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )""")

    # Table for Alerts (created by our custom Rule/CTI/UEBA processor)
    c.execute("""CREATE TABLE IF NOT EXISTS alerts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT,
                    message TEXT,
                    priority INTEGER DEFAULT 1,
                    log_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )""")

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    init_db()