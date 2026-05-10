import sqlite3

def init_db():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    
    # Create alerts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT,
        payload TEXT,
        prediction TEXT,
        cve TEXT,
        status TEXT DEFAULT 'New'
    )
    ''')
    
    # Create attackers table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS attackers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        country TEXT,
        total_hits INTEGER DEFAULT 0,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'Active'
    )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == '__main__':
    init_db()
