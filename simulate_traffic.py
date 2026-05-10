import requests
import random
import time
import json
from datetime import datetime

# Realistic feature simulation (based on common IDS datasets like NSL-KDD)
FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

def get_random_features(is_attack=False):
    """Generates a pseudo-random feature vector."""
    if is_attack:
        return [
            random.uniform(0.5, 1.0) if i % 3 == 0 else random.uniform(0, 0.5)
            for i in range(len(FEATURES))
        ]
    else:
        return [
            random.uniform(0, 0.2) if i % 3 == 0 else random.uniform(0, 0.1)
            for i in range(len(FEATURES))
        ]

def simulate_traffic():
    url = "http://localhost:5000/api/predict"
    
    attack_scenarios = [
        {"type": "DDoS", "severity": "Critical", "prob": 0.05, "cve": "CVE-2023-1234"},
        {"type": "SQL Injection", "severity": "High", "prob": 0.03, "cve": "CVE-2024-5678"},
        {"type": "Brute Force", "severity": "Medium", "prob": 0.07, "cve": "CVE-2022-9012"},
        {"type": "Port Scan", "severity": "Low", "prob": 0.10, "cve": "CVE-2021-3456"}
    ]
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] IDS Traffic Simulator Started...")
    print(f"Targeting: {url}")
    
    while True:
        roll = random.random()
        current_event = None
        
        cumulative_prob = 0
        for scenario in attack_scenarios:
            cumulative_prob += scenario["prob"]
            if roll < cumulative_prob:
                current_event = scenario
                break
        
        is_attack = current_event is not None
        source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        payload = {
            "source_ip": source_ip,
            "destination_ip": "10.0.0.5",
            "type": current_event["type"] if is_attack else "Normal Traffic",
            "severity": current_event["severity"] if is_attack else "Low",
            "cve": current_event["cve"] if is_attack else "N/A",
            "features": get_random_features(is_attack)
        }
        
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                result = response.json()
                status_icon = "🚨" if result['prediction'] == 1 else "✅"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {status_icon} Source: {source_ip.ljust(15)} | Type: {payload['type'].ljust(15)} | Prediction: {result['severity']}")
            else:
                print(f"Error {response.status_code}: {response.text}")
        except requests.exceptions.ConnectionError:
            print("❌ Connection Error: Is the Flask app running?")
        except Exception as e:
            print(f"❌ Unexpected Error: {e}")
        
        # Sleep for a random interval to simulate varied traffic flow
        time.sleep(random.uniform(1.0, 5.0))

if __name__ == "__main__":
    simulate_traffic()
