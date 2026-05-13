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
from cve_mapping import get_cve_info

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

# Load Hybrid ML Models
RF_MODEL_PATH = "rf_model.pkl"
ISO_MODEL_PATH = "iso_model.pkl"
rf_model = None
iso_model = None
try:
    if os.path.exists(RF_MODEL_PATH):
        rf_model = joblib.load(RF_MODEL_PATH)
        print("[*] Random Forest Classifier loaded successfully")
    if os.path.exists(ISO_MODEL_PATH):
        iso_model = joblib.load(ISO_MODEL_PATH)
        print("[*] Isolation Forest loaded successfully")
except Exception as e:
    print(f"[!] Error loading ML Models: {e}")

def predict_attack(event):
    if rf_model is None or iso_model is None:
        return "N/A", 0.0

    try:
        # Create a 41-feature vector
        features_list = [0.0] * 41
        
        # Map protocol to numeric
        proto_map = {"tcp": 1, "udp": 2, "icmp": 3}
        features_list[1] = proto_map.get(event.get("proto", "").lower(), 0)
        features_list[4] = event.get("src_port", 0)
        features_list[5] = event.get("dest_port", 0)
        
        # Use signature to mock some features for testing purposes
        signature = event.get("alert", {}).get("signature", "").lower()
        if "nmap" in signature or "scan" in signature:
            features_list[31] = 0.9 # Probe
            features_list[29] = 0.9
        elif "log4j" in signature or "sql" in signature:
            features_list[13] = 0.9 # U2R
            features_list[16] = 0.9
        elif "brute" in signature or "ssh" in signature:
            features_list[10] = 0.9 # R2L
            features_list[21] = 0.9
        elif "ddos" in signature or "flood" in signature:
            features_list[22] = 0.9 # DoS
            features_list[23] = 0.9
            
        features = np.array([features_list])
        
        # Hybrid Inference
        iso_pred = iso_model.predict(features)[0]
        prediction = rf_model.predict(features)[0]
        probability = rf_model.predict_proba(features)[0].max()
        
        if iso_pred == -1 and prediction == 'Normal':
            prediction = 'Zero-Day Anomaly'
            probability = 0.85
            
        confidence = round(float(probability) * 100, 2)
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

def main():
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
                
                # Phase 2: CVE Enrichment
                cve_info = get_cve_info(alert_data.get("signature", ""))
                
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
                    "cve": cve_info["cve"],
                    "cvss": cve_info["cvss"],
                    "behavior": cve_info["behavior"],
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

if __name__ == "__main__":
    main()
