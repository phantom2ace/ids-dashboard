import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
import joblib
import random

# Synthetic NSL-KDD Feature Generation (41 features)
# We create distinct mathematical profiles for each class so the Random Forest can learn them.

def generate_synthetic_data(num_samples=10000):
    data = []
    labels = []
    
    classes = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    
    for _ in range(num_samples):
        attack_type = random.choice(classes)
        
        # Base normal features
        features = [random.uniform(0, 0.1) for _ in range(41)]
        
        if attack_type == 'Normal':
            pass # Keep base features
        elif attack_type == 'DoS':
            # DoS: High traffic, many connections to same service
            features[4] = random.uniform(0.8, 1.0)  # src_bytes
            features[22] = random.uniform(0.8, 1.0) # count
            features[23] = random.uniform(0.8, 1.0) # srv_count
        elif attack_type == 'Probe':
            # Probe: Scanning many different ports/hosts
            features[31] = random.uniform(0.8, 1.0) # dst_host_count
            features[29] = random.uniform(0.8, 1.0) # diff_srv_rate
        elif attack_type == 'R2L':
            # R2L: Failed logins, guest logins
            features[10] = random.uniform(0.5, 1.0) # num_failed_logins
            features[21] = random.uniform(0.8, 1.0) # is_guest_login
        elif attack_type == 'U2R':
            # U2R: Root shell, file creations
            features[13] = random.uniform(0.8, 1.0) # root_shell
            features[16] = random.uniform(0.8, 1.0) # num_file_creations
            
        data.append(features)
        labels.append(attack_type)
        
    return np.array(data), np.array(labels)

if __name__ == "__main__":
    print("[*] Generating synthetic NSL-KDD dataset...")
    X, y = generate_synthetic_data(20000)

    print("[*] Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=50, random_state=42)
    rf.fit(X, y)

    print("[*] Training Isolation Forest (Anomaly Detector)...")
    # Train Isolation Forest only on Normal traffic to learn baseline behavior
    X_normal = X[y == 'Normal']
    iso = IsolationForest(contamination=0.01, random_state=42)
    iso.fit(X_normal)

    print("[*] Saving models...")
    joblib.dump(rf, 'rf_model.pkl')
    joblib.dump(iso, 'iso_model.pkl')

    print("[+] Models successfully generated: rf_model.pkl, iso_model.pkl")
