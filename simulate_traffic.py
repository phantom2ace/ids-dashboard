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

def get_random_features(is_attack=False, category="Normal"):
    """Generates a pseudo-random feature vector."""
    features = [random.uniform(0, 0.1) for _ in range(41)]
    
    if not is_attack:
        return features
        
    if "Web Application Attack" in category:
        features[13] = random.uniform(0.8, 1.0) # U2R
        features[16] = random.uniform(0.8, 1.0)
    elif "Information Leak" in category:
        features[31] = random.uniform(0.8, 1.0) # Probe
        features[29] = random.uniform(0.8, 1.0)
    elif "Privilege Gain" in category:
        features[10] = random.uniform(0.5, 1.0) # R2L
        features[21] = random.uniform(0.8, 1.0)
    elif "DDoS" in category:
        features[4] = random.uniform(0.8, 1.0)  # DoS
        features[22] = random.uniform(0.8, 1.0)
        features[23] = random.uniform(0.8, 1.0)
    else:
        # Zero-Day Anomaly Simulation (Extremely weird values)
        features[0] = random.uniform(5.0, 10.0)
        features[7] = random.uniform(5.0, 10.0)
        
    return features

def simulate_traffic():
    url = "http://localhost:5000/api/predict"
    
    attack_scenarios = [
        {"signature": "ET WEB_SERVER Apache Log4j Attempt", "category": "Web Application Attack", "severity": "Critical", "prob": 0.05},
        {"signature": "ET EXPLOIT Possible SQL Injection Attempt", "category": "Web Application Attack", "severity": "High", "prob": 0.03},
        {"signature": "ET POLICY SSH Brute Force Attempt", "category": "Attempted Admin Privilege Gain", "severity": "Medium", "prob": 0.07},
        {"signature": "ET SCAN Nmap Scripting Engine", "category": "Information Leak", "severity": "Low", "prob": 0.10}
    ]
    
    # Mix of public IPs for GeoIP visualization
    public_ips = [
        "8.8.8.8", "1.1.1.1", "185.22.14.102", "45.12.99.11", 
        "103.21.244.0", "141.101.64.0", "173.245.48.0", "190.93.240.0"
    ]
    
    api_keys = [
        ("oakridge_api_123", "Oakridge Public Schools"),
        ("mercy_api_123", "Mercy General Hospital"),
        ("techcorp_api_123", "TechCorp Global"),
        ("apex_api_123", "Apex Financial"),
        ("city_api_123", "City Municipal Network"),
        (None, "Local Sensor")
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
        
        # Randomly choose between local and public IP
        if random.random() < 0.7:
            source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        else:
            source_ip = random.choice(public_ips)
        
        payload = {
            "source_ip": source_ip,
            "destination_ip": "10.0.0.5",
            "signature": current_event["signature"] if is_attack else "Normal Traffic",
            "category": current_event["category"] if is_attack else "Misc activity",
            "severity": current_event["severity"] if is_attack else "Low",
            "features": get_random_features(is_attack, current_event["category"] if is_attack else "Normal")
        }
        
        # Pick random tenant
        tenant_key, tenant_name = random.choice(api_keys)
        headers = {'Content-Type': 'application/json'}
        if tenant_key:
            headers['X-API-KEY'] = tenant_key
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                result = response.json()
                status_icon = "🚨" if result.get('severity') in ['High', 'Critical'] else "✅"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {status_icon} Tenant: {tenant_name[:10].ljust(10)} | Src: {source_ip.ljust(15)} | Sig: {payload['signature'][:25].ljust(25)} | Sev: {result['severity']}")
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
