import sqlite3

def update_database_phase9():
    conn = sqlite3.connect('/home/spade/ids-dashboard/alerts.db')
    cursor = conn.cursor()

    columns_to_add = [
        ("incident_id", "TEXT DEFAULT 'N/A'"),
        ("assigned_analyst", "TEXT DEFAULT 'Unassigned'")
    ]

    for col_name, col_def in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_def}")
            print(f"Added column {col_name}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print(f"Column '{col_name}' already exists.")
            else:
                print(f"Error adding {col_name}: {e}")

    # Generate incident IDs for existing alerts that have 'N/A'
    try:
        cursor.execute("SELECT id FROM alerts WHERE incident_id = 'N/A' OR incident_id IS NULL")
        rows = cursor.fetchall()
        for row in rows:
            alert_id = row[0]
            incident_id = f"INC-2026-{alert_id:04d}"
            cursor.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
        print(f"Updated {len(rows)} alerts with generated incident IDs.")
    except Exception as e:
        print(f"Error updating existing alerts: {e}")

    conn.commit()
    conn.close()
    print("Phase 9 database updates completed successfully.")

if __name__ == '__main__':
    update_database_phase9()
