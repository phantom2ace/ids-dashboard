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

    severity TEXT,

    ml_prediction TEXT,
    confidence REAL,
    
    cve TEXT,
    cvss REAL,
    behavior TEXT,
    
    country TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL
)
""")

# Also create attackers table for IP intelligence tracking
cursor.execute("""
CREATE TABLE IF NOT EXISTS attackers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    country TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    total_hits INTEGER DEFAULT 0,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Active'
)
""")

# Create incident_logs table for orchestration timeline
cursor.execute("""
CREATE TABLE IF NOT EXISTS incident_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action_type TEXT NOT NULL,
    user TEXT DEFAULT 'System',
    details TEXT NOT NULL
)
""")

conn.commit()
conn.close()

print("Database initialized.")
