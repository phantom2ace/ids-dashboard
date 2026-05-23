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

@app.route('/ai-analysis')
def ai_analysis():
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
        
    # Get recent predictions
    cursor.execute('''
        SELECT signature as attack, confidence, ml_prediction, timestamp
        FROM alerts
        WHERE ml_prediction != 'Normal'
        ORDER BY id DESC LIMIT 10
    ''')
    recent_predictions = [dict(row) for row in cursor.fetchall()]
    
    # Calculate False Positive Rate (mocked for demo based on RESOLVED FALSE POSITIVE cases)
    cursor.execute('''
        SELECT COUNT(*) as count FROM incidents WHERE status = 'FALSE_POSITIVE'
    ''')
    fp_count = cursor.fetchone()[0]
    cursor.execute('''
        SELECT COUNT(*) as count FROM incidents
    ''')
    total_incidents = cursor.fetchone()[0]
    fp_rate = f"{(fp_count / total_incidents * 100):.1f}%" if total_incidents > 0 else "0.0%"
    
    conn.close()
    
    return render_template('ai_analysis.html', 
                           avg_confidence=avg_confidence, 
                           threat_level=threat_level, 
                           recent_predictions=recent_predictions,
                           fp_rate=fp_rate)

@app.route('/threat-intel')
def threat_intel():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get active attackers
    cursor.execute('SELECT * FROM attackers ORDER BY last_seen DESC LIMIT 50')
    attackers_list = [dict(row) for row in cursor.fetchall()]
    
    # Get Top CVEs
    cursor.execute('''
        SELECT cve, COUNT(*) as count 
        FROM alerts 
        WHERE cve != 'N/A' AND cve IS NOT NULL 
        GROUP BY cve 
        ORDER BY count DESC LIMIT 5
    ''')
    top_cves = [dict(row) for row in cursor.fetchall()]
    
    # Get MITRE Techniques
    cursor.execute('''
        SELECT mitre_tactic, COUNT(*) as count 
        FROM incidents 
        WHERE mitre_tactic != 'Unknown' AND mitre_tactic != 'N/A' AND mitre_tactic IS NOT NULL
        GROUP BY mitre_tactic 
        ORDER BY count DESC LIMIT 5
    ''')
    top_mitre = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return render_template('threat_intel.html', 
                           attackers=attackers_list, 
                           top_cves=top_cves, 
                           top_mitre=top_mitre)

@app.route('/incidents')
def incidents_page():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM incidents 
        ORDER BY created_at DESC LIMIT 500
    ''')
    incidents = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return render_template('incidents.html', incidents=incidents)

@app.route('/sensors')
def sensors_page():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM organizations ORDER BY name ASC')
    orgs = [dict(row) for row in cursor.fetchall()]
    
    # Calculate traffic volume per org
    for org in orgs:
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE org_name = ?", (org['name'],))
        org['traffic_volume'] = cursor.fetchone()[0]
        # Mask the API key
        org['api_key'] = org['api_key'][:4] + "*" * 8 + org['api_key'][-4:]
        
    conn.close()
    return render_template('sensors.html', orgs=orgs)

@app.route('/investigations')
def investigations_page():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM incidents 
        WHERE assigned_analyst != 'Unassigned' 
        ORDER BY updated_at DESC
    ''')
    investigations = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('investigations.html', investigations=investigations)

@app.route('/attack-map')
def attack_map_page():
    return render_template('attack_map.html')

@app.route('/reports')
def reports_page():
    return render_template('reports.html')

@app.route('/team')
def team_page():
    return render_template('team.html')

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
        api_key = request.headers.get('X-API-KEY')
        org_name = 'Local Sensor'
        if api_key:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM organizations WHERE api_key = ?", (api_key,))
            row = cursor.fetchone()
            if row:
                org_name = row[0]
            conn.close()
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
            "longitude": geo_info['lon'],
            "org_name": org_name,
            "mitre_id": cve_info.get('mitre_id', 'N/A'),
            "mitre_tactic": cve_info.get('mitre_tactic', 'N/A'),
            "recommendation": cve_info.get('recommendation', 'N/A')
        }
        
        # Save to database and update attackers (handled internally)
        insert_alert(alert)
        
        # Send Alert if High or Critical Severity
        if severity in ['High', 'Critical']:
            msg = f"<b>Attack Detected at {org_name}!</b>\nSignature: {signature}\nSource: {alert['src_ip']}\nCVE: {alert['cve']}"
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

@app.route('/api/incidents')
def get_incidents():
    from database.db import get_recent_incidents
    incidents = get_recent_incidents(50)
    return jsonify(incidents)

@app.route('/api/incidents/<incident_id>/update', methods=['POST'])
def update_incident(incident_id):
    data = request.json
    status = data.get('status')
    notes = data.get('notes')
    analyst = data.get('analyst')
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE incidents 
        SET status = ?, analyst_notes = ?, assigned_analyst = ? 
        WHERE incident_id = ?
    ''', (status, notes, analyst, incident_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
