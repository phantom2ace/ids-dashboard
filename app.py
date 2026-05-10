from flask import Flask, render_template, jsonify, request, redirect, url_for
import sqlite3
import joblib
import os

from alert_bot import AlertBot
from dotenv import load_dotenv

# Load environment variables from .env if it exists
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key-change-me')

# Initialize Alert Bot
bot = AlertBot()

# Load the IDS model (placeholder for now)
MODEL_PATH = 'ids_model.pkl'
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"Error loading model: {e}")

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
    return render_template('analytics.html')

@app.route('/attackers')
def attackers():
    conn = sqlite3.connect('alerts.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM attackers ORDER BY last_seen DESC')
    attackers_list = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return render_template('attackers.html', attackers=attackers_list)

@app.route('/settings')
def settings():
    return render_template('settings.html')

import pandas as pd
from datetime import datetime

# ... existing code ...

@app.route('/api/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 500
    
    try:
        data = request.json
        # Assuming the model expects a DataFrame or list of features
        # This is a generic implementation - adjust based on your model's input requirements
        features = pd.DataFrame([data['features']])
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0].max() if hasattr(model, 'predict_proba') else 1.0
        
        # Determine severity based on prediction/probability
        if 'severity' in data:
            severity = data['severity']
        elif prediction == 1:
            if probability > 0.9:
                severity = 'Critical'
            elif probability > 0.7:
                severity = 'High'
            else:
                severity = 'Medium'
        else:
            severity = 'Low'
        
        # Save to database
        conn = sqlite3.connect('alerts.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (type, severity, source_ip, destination_ip, payload, prediction, cve)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('type', 'Unknown'),
            severity,
            data.get('source_ip', '0.0.0.0'),
            data.get('destination_ip', '0.0.0.0'),
            str(data.get('features')),
            str(prediction),
            data.get('cve', 'N/A')
        ))
        
        # Update attacker stats
        cursor.execute('''
            INSERT INTO attackers (ip_address, total_hits, last_seen)
            VALUES (?, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(ip_address) DO UPDATE SET
            total_hits = total_hits + 1,
            last_seen = CURRENT_TIMESTAMP
        ''', (data.get('source_ip', '0.0.0.0'),))
        
        conn.commit()
        conn.close()
        
        # Send Alert if High Severity
        if severity == 'High':
            msg = f"<b>Attack Detected!</b>\nType: {data.get('type')}\nSource: {data.get('source_ip')}\nCVE: {data.get('cve')}"
            bot.send_alert(msg)
        
        return jsonify({
            'prediction': int(prediction),
            'probability': float(probability),
            'severity': severity
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/analytics')
def get_analytics():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    
    # Attack Distribution (Pie)
    cursor.execute('SELECT type, COUNT(*) FROM alerts GROUP BY type')
    distribution = dict(cursor.fetchall())
    
    # Severity Breakdown (Bar)
    cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
    severity = dict(cursor.fetchall())
    
    # Traffic over time (last 24 hours)
    cursor.execute("SELECT strftime('%H:00', timestamp), COUNT(*) FROM alerts GROUP BY strftime('%H:00', timestamp) LIMIT 24")
    timeline = dict(cursor.fetchall())
    
    conn.close()
    
    return jsonify({
        'distribution': distribution,
        'severity': severity,
        'timeline': timeline
    })

@app.route('/api/dashboard-stats')
def get_dashboard_stats():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    
    # Line chart data (last 6 segments of time)
    cursor.execute("SELECT strftime('%H:%M', timestamp), COUNT(*) FROM alerts GROUP BY strftime('%H:%M', timestamp) ORDER BY timestamp DESC LIMIT 6")
    line_data = dict(cursor.fetchall()[::-1])
    
    # Bar chart data (Severity)
    cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
    bar_data = dict(cursor.fetchall())
    
    # Pie chart data (Type)
    cursor.execute('SELECT type, COUNT(*) FROM alerts GROUP BY type')
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
    conn = sqlite3.connect('alerts.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50')
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
