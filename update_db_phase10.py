import sqlite3
import datetime

def update_database_phase10():
    conn = sqlite3.connect('/home/spade/ids-dashboard/alerts.db')
    cursor = conn.cursor()

    # 1. Create the incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT,
            severity TEXT,
            status TEXT DEFAULT 'NEW',
            assigned_analyst TEXT DEFAULT 'Unassigned',
            analyst_notes TEXT DEFAULT '',
            src_ip TEXT,
            org_name TEXT,
            alert_count INTEGER DEFAULT 1,
            created_at TEXT,
            updated_at TEXT,
            mitre_id TEXT,
            mitre_tactic TEXT,
            recommendation TEXT
        )
    ''')

    # 2. Migrate existing alerts into incidents
    # We will group existing alerts by incident_id (since they currently have unique INC- IDs, they will just port over 1:1 for now, or we could group them. 
    # For simplicity of migration and keeping history, we will group by src_ip and signature for the migration if possible, but since we already assigned incident_ids, 
    # let's just insert one incident per existing incident_id to maintain consistency.)
    
    print("Migrating existing data to incidents table...")
    cursor.execute("""
        SELECT incident_id, signature, severity, status, assigned_analyst, analyst_notes, src_ip, org_name, timestamp, mitre_id, mitre_tactic, recommendation, COUNT(id)
        FROM alerts
        WHERE incident_id != 'N/A' AND incident_id IS NOT NULL
        GROUP BY incident_id
    """)
    rows = cursor.fetchall()
    
    for row in rows:
        incident_id, sig, sev, status, analyst, notes, src_ip, org, ts, mitre_id, tactic, rec, count = row
        title = f"{sig} Campaign"
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO incidents (
                    incident_id, title, severity, status, assigned_analyst, analyst_notes, src_ip, org_name, alert_count, created_at, updated_at, mitre_id, mitre_tactic, recommendation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (incident_id, title, sev, status, analyst, notes, src_ip, org, count, ts, ts, mitre_id, tactic, rec))
        except Exception as e:
            print(f"Error migrating {incident_id}: {e}")

    # Remove status, analyst_notes, assigned_analyst, mitre_id, mitre_tactic, recommendation from alerts? 
    # SQLite doesn't easily support dropping columns. We can just ignore them in alerts table from now on.
    
    conn.commit()
    conn.close()
    print("Phase 10 database updates completed successfully.")

if __name__ == '__main__':
    update_database_phase10()
