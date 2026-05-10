import sqlite3
import os

DB_NAME = "alerts.db"

def get_connection():
    # Use absolute path for DB to avoid issues with different CWDs
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), DB_NAME)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def insert_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Insert into alerts table
        cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                src_ip,
                dest_ip,
                signature,
                category,
                severity,
                ml_prediction,
                confidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["timestamp"],
            alert["src_ip"],
            alert["dest_ip"],
            alert["signature"],
            alert["category"],
            alert["severity"],
            alert["ml_prediction"],
            alert["confidence"]
        ))

        # Also update attackers table for historical intelligence
        cursor.execute("""
            INSERT INTO attackers (ip_address, total_hits, last_seen)
            VALUES (?, 1, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
            total_hits = total_hits + 1,
            last_seen = ?
        """, (alert["src_ip"], alert["timestamp"], alert["timestamp"]))

        conn.commit()
    except Exception as e:
        print(f"Error inserting alert: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_recent_alerts(limit=100):
    conn = get_connection()
    alerts = conn.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(a) for a in alerts]
