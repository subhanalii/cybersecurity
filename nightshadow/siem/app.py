# vigilanteye/siem/app.py

from flask import Flask, request, render_template
import sqlite3
from database import init_db, DB
from processor import process_log
from ueba import train_ueba_model 
import requests
import json
import time
import os

# --- External SIEM/Log Management Configuration (Hardcoded Placeholders) ---
SPLUNK_HEC_TOKEN = "YOUR_SPLUNK_HEC_TOKEN"
SPLUNK_HEC_URL = "https://your.splunk.server:8088/services/collector/event"

app = Flask(__name__)
init_db()

def forward_log_to_siem_tool(log_data):
    """
    Simulates forwarding the log to an external SIEM (Splunk/Elasticsearch).
    TEMPORARILY COMMENTED OUT for testing due to missing Splunk token.
    """
    
    # --- TEMPORARILY COMMENTED OUT FOR TESTING ---
    return 

    # --- FULL IMPLEMENTATION LOGIC (Ready for Uncommenting) ---
    # if not SPLUNK_HEC_TOKEN or SPLUNK_HEC_TOKEN == "YOUR_SPLUNK_HEC_TOKEN":
    #     return
    # headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
    # try:
    #     hec_payload = {"event": log_data, "time": time.time()}
    #     requests.post(SPLUNK_HEC_URL, headers=headers, json=hec_payload, timeout=2)
    # except requests.exceptions.RequestException:
    #     pass


@app.route("/")
def dashboard():
    """Serves the main SIEM Dashboard."""
    conn = sqlite3.connect(DB)
    logs = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 15").fetchall()
    alerts = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("dashboard.html", logs=logs, alerts=alerts)

# --- WEBHOOK 1: Agent/Snort Log Collector ---
@app.route("/collect", methods=["GET", "POST"]) # <-- FIXED: Accepts GET and POST
def collect_log():
    """Receives logs from our local agent or Snort/IDS polling script."""
    # Ensure we get data if POST or check if GET (for browser check)
    data = request.json if request.method == 'POST' else request.args
    
    # Simple check for GET request
    if request.method == 'GET':
        return {"status": "Endpoint is running. Send POST request with log data."}

    # 1. Store Log Locally
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs(source, event, ip_address, username) VALUES(?,?,?,?)",
                   (data.get("source"), data.get("event"), data.get("ip_address"), data.get("username")))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # 2. Forward to External SIEM (Splunk/ES)
    forward_log_to_siem_tool(data)

    # 3. Process with Custom Intelligence
    rule_hit = process_log(log_id, data.get("event", ""), data)
    
    return {"status": "received & processed", "alert_triggered": rule_hit}

# --- WEBHOOK 2: Wazuh Alert Receiver (The primary integration point) ---
@app.route("/wazuh_alert", methods=["GET", "POST"]) # <-- FIXED: Accepts GET and POST
def receive_wazuh_alert():
    """
    Receives an instant alert JSON webhook from Wazuh's integrator daemon.
    This demonstrates the core integration planned in your proposal (Wazuh -> SOAR).
    """
    # Ensure we get data if POST or check if GET (for browser check)
    if request.method == 'GET':
        return {"status": "Wazuh endpoint is running. Send POST request with alert JSON."}

    wazuh_data = request.json
    
    # Extracting necessary fields from Wazuh JSON structure
    alert_info = wazuh_data.get('alert', {})
    agent_info = wazuh_data.get('agent', {})
    rule_info = alert_info.get('rule', {})

    source = agent_info.get('name', 'Wazuh Manager')
    event_summary = rule_info.get('description', 'No description')
    ip_address = agent_info.get('ip', 'N/A')
    
    # Create a local log entry for Wazuh alert for tracking
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs(source, event, ip_address, username) VALUES(?,?,?,?)",
                   (source, f"WAZUH ALERT: {event_summary}", ip_address, 'system'))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Process the new alert with our custom CTI/UEBA/SOAR logic
    log_data = {"source": source, "event": event_summary, "ip_address": ip_address, "username": 'system'}
    rule_hit = process_log(log_id, event_summary, log_data)
    
    return {"status": "Wazuh alert processed", "action_taken": rule_hit}

# --- UEBA/Training endpoint ---
@app.route("/train_ueba", methods=["GET"])
def train_route():
    train_ueba_model()
    return {"status": "UEBA model training initiated. Check console for details."}


if __name__ == "__main__":
    app.run(debug=True, port=5000)