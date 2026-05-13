from flask import Flask, render_template, jsonify, request, redirect, url_for
import sqlite3
import joblib
import os
import numpy as np

from database.db import get_connection, insert_alert, get_recent_alerts
from alert_bot import AlertBot
from database.db import get_connection, insert_alert, get_recent_alerts
from alert_bot import AlertBot
from parser import get_geoip
from dotenv import load_dotenv
from cve_mapping import get_cve_info

# Load environment variables from .env if it exists
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key-change-me')

# Initialize Alert Bot
bot = AlertBot()

# Load Hybrid ML Models
RF_MODEL_PATH = "rf_model.pkl"
ISO_MODEL_PATH = "iso_model.pkl"
rf_model = None
iso_model = None
try:
    if os.path.exists(RF_MODEL_PATH):
        rf_model = joblib.load(RF_MODEL_PATH)
    if os.path.exists(ISO_MODEL_PATH):
        iso_model = joblib.load(ISO_MODEL_PATH)
except Exception as e:
    print(f"Error loading models: {e}")

@app.route('/')
def dashboard():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM alerts')
    total_alerts = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE severity = "High"')
    high_severity = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM attackers WHERE status = "Active"')
    active_attackers = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('dashboard.html', 
                           total_alerts=total_alerts, 
                           high_severity=high_severity, 
                           active_attackers=active_attackers)

@app.route('/analytics')
def analytics():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Avg Confidence
    cursor.execute('SELECT AVG(confidence) FROM alerts')
    avg_conf_row = cursor.fetchone()[0]
    avg_confidence = round(avg_conf_row, 1) if avg_conf_row else 0.0
    
    # High/Critical count for Threat Level
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE severity IN ("High", "Critical")')
    high_critical_count = cursor.fetchone()[0]
    if high_critical_count > 50:
        threat_level = "Severe"
    elif high_critical_count > 10:
        threat_level = "Elevated"
    else:
        threat_level = "Normal"
        
    # Top 5 Attackers
    cursor.execute('''
        SELECT ip_address as src_ip, total_hits, 
               (SELECT category FROM alerts WHERE alerts.src_ip = attackers.ip_address ORDER BY id DESC LIMIT 1) as primary_method
        FROM attackers 
        ORDER BY total_hits DESC LIMIT 5
    ''')
    top_attackers = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('analytics.html', 
                           avg_confidence=avg_confidence, 
                           threat_level=threat_level, 
                           top_attackers=top_attackers)

@app.route('/attackers')
def attackers():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM attackers ORDER BY last_seen DESC')
    attackers_list = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return render_template('attackers.html', attackers=attackers_list)

@app.route('/settings')
def settings():
    import json
    import os
    config = {
        'model_path': 'ids_model.pkl',
        'sensitivity': 75,
        'bot_token': '',
        'chat_id': ''
    }
    if os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            try:
                config.update(json.load(f))
            except:
                pass
    return render_template('settings.html', config=config)

@app.route('/rules')
def ips_rules():
    import os
    rules_content = ""
    rule_paths = [
        '/var/lib/suricata/rules/suricata.rules',
        '/etc/suricata/rules/local.rules',
        '/etc/suricata/suricata.rules'
    ]
    for path in rule_paths:
        if os.path.exists(path):
            with open(path, 'r') as f:
                rules_content = f.read()
            break
            
    if not rules_content:
        rules_content = "# No active Suricata rules found.\n# Ensure suricata-update has been run."
        
    return render_template('rules.html', rules=rules_content)

import pandas as pd
from datetime import datetime

# ... existing code ...

@app.route('/api/predict', methods=['POST'])
def predict():
    if rf_model is None or iso_model is None:
        return jsonify({'error': 'Models not loaded'}), 500
    
    try:
        data = request.json
        features_list = data['features']
        
        if len(features_list) < 41:
            features_list.extend([0.0] * (41 - len(features_list)))
        elif len(features_list) > 41:
            features_list = features_list[:41]
            
        # The trained models expect a 2D array/DataFrame. Random Forest specifically might warn if feature names aren't present but it will work.
        features = np.array([features_list])
        
        # Hybrid Inference
        iso_pred = iso_model.predict(features)[0]
        prediction = rf_model.predict(features)[0]
        probability = rf_model.predict_proba(features)[0].max()
        
        if iso_pred == -1 and prediction == 'Normal':
            prediction = 'Zero-Day Anomaly'
            probability = 0.85
        
        # Determine severity
        if 'severity' in data and data['severity'] not in ["Low", "Normal"]:
            severity = data['severity']
        elif prediction in ['DoS', 'U2R', 'R2L', 'Zero-Day Anomaly']:
            severity = 'High'
        elif prediction == 'Probe':
            severity = 'Medium'
        else:
            severity = 'Low'
            
        # Get CVE Intelligence mapping
        signature = data.get('signature', data.get('type', 'Unknown Event'))
        cve_info = get_cve_info(signature)
        
        # Get GeoIP Data
        geo_info = get_geoip(data.get('source_ip', '0.0.0.0'))
        
        # Construct unified alert dictionary
        alert = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": data.get('source_ip', '0.0.0.0'),
            "dest_ip": data.get('destination_ip', '0.0.0.0'),
            "signature": signature,
            "category": data.get('category', 'Simulation'),
            "severity": severity,
            "ml_prediction": str(prediction),
            "confidence": round(float(probability) * 100, 2),
            "cve": data.get('cve', cve_info['cve']),
            "cvss": data.get('cvss', cve_info['cvss']),
            "behavior": data.get('behavior', cve_info['behavior']),
            "country": geo_info['country'],
            "city": geo_info['city'],
            "latitude": geo_info['lat'],
            "longitude": geo_info['lon']
        }
        
        # Save to database and update attackers (handled internally)
        insert_alert(alert)
        
        # Send Alert if High or Critical Severity
        if severity in ['High', 'Critical']:
            msg = f"<b>Attack Detected!</b>\nSignature: {signature}\nSource: {alert['src_ip']}\nCVE: {alert['cve']}"
            bot.send_alert(msg)
        
        return jsonify({
            'prediction': str(prediction),
            'probability': float(probability),
            'severity': severity
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/analytics')
def get_analytics():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Attack Distribution (Pie)
    cursor.execute('SELECT COALESCE(category, "Unknown"), COUNT(*) FROM alerts GROUP BY COALESCE(category, "Unknown")')
    distribution = dict(cursor.fetchall())
    
    # Severity Breakdown (Bar)
    cursor.execute('SELECT COALESCE(severity, "Unknown"), COUNT(*) FROM alerts GROUP BY COALESCE(severity, "Unknown")')
    severity = dict(cursor.fetchall())
    
    # Traffic over time (last 24 hours)
    cursor.execute("SELECT COALESCE(strftime('%H:00', timestamp), '00:00'), COUNT(*) FROM alerts GROUP BY strftime('%H:00', timestamp) LIMIT 24")
    timeline = dict(cursor.fetchall())
    
    conn.close()
    
    return jsonify({
        'distribution': distribution,
        'severity': severity,
        'timeline': timeline
    })

@app.route('/api/threat-map')
def get_threat_map():
    conn = get_connection()
    cursor = conn.cursor()
    # Get recent unique attacker locations
    cursor.execute('''
        SELECT src_ip, country, city, latitude, longitude, severity, signature
        FROM alerts 
        WHERE latitude != 0 AND longitude != 0
        ORDER BY timestamp DESC LIMIT 100
    ''')
    locations = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(locations)

@app.route('/api/dashboard-stats')
def get_dashboard_stats():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Line chart data (last 6 segments of time)
    cursor.execute("SELECT strftime('%H:%M', timestamp), COUNT(*) FROM alerts GROUP BY strftime('%H:%M', timestamp) ORDER BY timestamp DESC LIMIT 6")
    line_data = dict(cursor.fetchall()[::-1])
    
    # Bar chart data (Severity)
    cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
    bar_data = dict(cursor.fetchall())
    
    # Pie chart data (Type/Category)
    cursor.execute('SELECT category, COUNT(*) FROM alerts GROUP BY category')
    pie_data = dict(cursor.fetchall())
    
    conn.close()
    
    return jsonify({
        'line': line_data,
        'bar': bar_data,
        'pie': pie_data
    })

@app.route('/api/attackers/toggle-status', methods=['POST'])
def toggle_attacker_status():
    data = request.json
    ip = data.get('ip')
    new_status = data.get('status')
    
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE attackers SET status = ? WHERE ip_address = ?', (new_status, ip))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/settings/update', methods=['POST'])
def update_settings():
    config = {
        'model_path': request.form.get('model_path'),
        'sensitivity': request.form.get('sensitivity'),
        'bot_token': request.form.get('bot_token'),
        'chat_id': request.form.get('chat_id')
    }
    
    # Save to file
    import json
    with open('config.json', 'w') as f:
        json.dump(config, f)
        
    # Re-initialize bot if token changed
    if config['bot_token'] and config['chat_id']:
        bot.token = config['bot_token']
        bot.chat_id = config['chat_id']
        
    return redirect(url_for('settings'))

@app.route('/api/alerts')
def get_alerts():
    alerts = get_recent_alerts(50)
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
