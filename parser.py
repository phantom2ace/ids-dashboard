import json
import time
import os
import sys

# Add parent directory to path to import database module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from database.db import insert_alert

# Adjust path if running in a test environment or if path differs
EVE_LOG = "/var/log/suricata/eve.json"

# For local development/testing if Suricata isn't installed in the system path
if not os.path.exists(EVE_LOG):
    EVE_LOG = "eve.json" # Fallback to local file

def follow(file):
    # Go to the end of the file
    file.seek(0, 2)

    while True:
        line = file.readline()

        if not line:
            time.sleep(0.5)
            continue

        yield line

print(f"[*] Starting Suricata Log Parser on {EVE_LOG}...")

if not os.path.exists(EVE_LOG):
    print(f"[!] Warning: {EVE_LOG} not found. Please ensure Suricata is running or provide a mock eve.json.")
    # Create an empty file if it doesn't exist to avoid crash
    with open(EVE_LOG, "w") as f:
        pass

with open(EVE_LOG, "r") as f:
    for line in follow(f):
        try:
            event = json.loads(line)

            if event.get("event_type") != "alert":
                continue

            alert_data = event.get("alert", {})
            
            alert = {
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "signature": alert_data.get("signature", ""),
                "category": alert_data.get("category", ""),
                "severity": alert_data.get("severity", 3),
                "ml_prediction": "Pending",
                "confidence": 0.0
            }

            insert_alert(alert)

            print(
                f"[+] Alert Saved: "
                f"{alert['src_ip']} -> "
                f"{alert['signature']}"
            )

        except Exception as e:
            print(f"Error parsing line: {e}")
