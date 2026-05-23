import sqlite3

def update_orgs():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM organizations")
    
    orgs = [
        ('Oakridge Public Schools', 'oakridge_api_123'),
        ('Mercy General Hospital', 'mercy_api_123'),
        ('TechCorp Global', 'techcorp_api_123'),
        ('Apex Financial', 'apex_api_123'),
        ('City Municipal Network', 'city_api_123')
    ]
    
    for name, key in orgs:
        cursor.execute("INSERT INTO organizations (name, api_key) VALUES (?, ?)", (name, key))
        
    cursor.execute("UPDATE alerts SET org_name = 'Oakridge Public Schools' WHERE org_name = 'School A'")
    cursor.execute("UPDATE alerts SET org_name = 'Mercy General Hospital' WHERE org_name = 'Hospital B'")
    cursor.execute("UPDATE incidents SET org_name = 'Oakridge Public Schools' WHERE org_name = 'School A'")
    cursor.execute("UPDATE incidents SET org_name = 'Mercy General Hospital' WHERE org_name = 'Hospital B'")
        
    conn.commit()
    conn.close()
    print("Orgs updated!")

if __name__ == '__main__':
    update_orgs()
