import sqlite3

def update_database():
    conn = sqlite3.connect('/home/spade/ids-dashboard/alerts.db')
    cursor = conn.cursor()

    # Create organizations table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        api_key TEXT UNIQUE NOT NULL
    )
    ''')

    # Insert mock organizations (ignore if they already exist)
    try:
        cursor.execute("INSERT INTO organizations (name, api_key) VALUES ('School A', 'school_a_123')")
    except sqlite3.IntegrityError:
        pass
        
    try:
        cursor.execute("INSERT INTO organizations (name, api_key) VALUES ('Hospital B', 'hospital_b_123')")
    except sqlite3.IntegrityError:
        pass

    # Add org_name to alerts table if it doesn't exist
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN org_name TEXT DEFAULT 'Local Sensor'")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("Column 'org_name' already exists in alerts table.")
        else:
            print(f"Error altering table: {e}")

    conn.commit()
    conn.close()
    print("Database updated successfully for Multi-Tenant Architecture.")

if __name__ == '__main__':
    update_database()
