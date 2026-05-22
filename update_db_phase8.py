import sqlite3

def update_database_phase8():
    conn = sqlite3.connect('/home/spade/ids-dashboard/alerts.db')
    cursor = conn.cursor()

    columns_to_add = [
        ("mitre_id", "TEXT DEFAULT 'N/A'"),
        ("mitre_tactic", "TEXT DEFAULT 'N/A'"),
        ("recommendation", "TEXT DEFAULT 'N/A'"),
        ("status", "TEXT DEFAULT 'OPEN'"),
        ("analyst_notes", "TEXT DEFAULT ''")
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

    conn.commit()
    conn.close()
    print("Phase 8 database updates completed successfully.")

if __name__ == '__main__':
    update_database_phase8()
