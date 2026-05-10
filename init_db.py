import sqlite3

conn = sqlite3.connect("alerts.db")

cursor = conn.cursor()

# Create alerts table with Suricata-specific fields
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT,
    src_ip TEXT,
    dest_ip TEXT,

    signature TEXT,
    category TEXT,

    severity INTEGER,

    ml_prediction TEXT,
    confidence REAL
)
""")

# Also create attackers table for IP intelligence tracking
cursor.execute("""
CREATE TABLE IF NOT EXISTS attackers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    country TEXT,
    total_hits INTEGER DEFAULT 0,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Active'
)
""")

conn.commit()
conn.close()

print("Database initialized.")
