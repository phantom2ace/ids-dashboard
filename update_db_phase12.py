import sqlite3

def update_db():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action_type TEXT NOT NULL,
            user TEXT DEFAULT 'System',
            details TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("Created incident_logs table.")

if __name__ == "__main__":
    update_db()
