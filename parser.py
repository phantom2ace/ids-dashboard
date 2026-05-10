import json
import time
import os
import sys
import joblib
import numpy as np
import requests

# Add parent directory to path to import database module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from database.db import insert_alert

# GeoIP Cache to avoid redundant API calls
geoip_cache = {}

def get_geoip(ip):
    """Fetch geographical data for an IP address."""
    # Skip private IPs
    if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3', '127.')):
        return {"country": "Local Network", "city": "Internal", "lat": 0.0, "lon": 0.0}

    if ip in geoip_cache:
        return geoip_cache[ip]

    try:
        # Using ip-api.com (Free for non-commercial, no API key needed for basic usage)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0)
                }
                geoip_cache[ip] = result
                return result
    except Exception as e:
        print(f"[!] GeoIP Error for {ip}: {e}")
    
    return {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}

# Load ML Model
MODEL_PATH = "ids_model.pkl"
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print(f"[*] ML Model loaded successfully from {MODEL_PATH}")
    except Exception as e:
        print(f"[!] Error loading ML Model: {e}")

def predict_attack(event):
    if model is None:
        return "N/A", 0.0

    try:
        # Check how many features the model expects
        n_features = getattr(model, "n_features_in_", 41)
        
        # If the model expects 41 features (NSL-KDD), we need to provide a full vector
        if n_features == 41:
            # Map protocol to numeric
            proto_map = {"tcp": 1, "udp": 2, "icmp": 3}
            proto = proto_map.get(event.get("proto", "").lower(), 0)
            
            src_port = event.get("src_port", 0)
            dest_port = event.get("dest_port", 0)
            severity = event.get("alert", {}).get("severity", 3)
            
            # Create a 41-feature vector (mostly placeholders for now, but correct size)
            # In a real system, you would extract all these from the Suricata flow/event
            features_list = [0.0] * 41
            features_list[1] = proto
            features_list[4] = src_port
            features_list[5] = dest_port
            features_list[30] = severity # Just a placeholder mapping
            
            features = np.array([features_list])
        else:
            # Fallback to the 4-feature style if model expects 4
            proto_map = {"tcp": 1, "udp": 2, "icmp": 3}
            proto = proto_map.get(event.get("proto", "").lower(), 0)
            src_port = event.get("src_port", 0)
            dest_port = event.get("dest_port", 0)
            severity = event.get("alert", {}).get("severity", 3)
            features = np.array([[proto, src_port, dest_port, severity]])
        
        prediction = model.predict(features)[0]
        
        if hasattr(model, "predict_proba"):
            confidence = round(np.max(model.predict_proba(features)) * 100, 2)
        else:
            confidence = 95.0

        return str(prediction), confidence

    except Exception as e:
        print(f"[!] Prediction Error: {e}")
        return "Mismatch", 0.0

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
            
            # Phase 1: Connect ML Prediction to Live Alert
            ml_pred, ml_conf = predict_attack(event)
            
            # GeoIP Lookup
            geo = get_geoip(event.get("src_ip", ""))
            
            alert = {
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "signature": alert_data.get("signature", ""),
                "category": alert_data.get("category", ""),
                "severity": alert_data.get("severity", 3),
                "ml_prediction": ml_pred,
                "confidence": ml_conf,
                "country": geo["country"],
                "city": geo["city"],
                "latitude": geo["lat"],
                "longitude": geo["lon"]
            }

            insert_alert(alert)

            print(
                f"[+] Alert Saved: "
                f"{alert['src_ip']} -> "
                f"{alert['signature']}"
            )

        except Exception as e:
            print(f"Error parsing line: {e}")
