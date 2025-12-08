# vigilanteye/siem/processor.py

from rules import RULES
import sqlite3
from database import DB
import requests
import re
from soar_actions import trigger_shuffle_workflow
from ueba import check_anomaly 
# import os removed

# --- CTI Configuration (Hardcoded Placeholder) ---
ABUSEIPDB_API_KEY = "7ea3f2805ffdb89b1282a9aa0817093c0f9e3d26bbe5ecf6f3da28ef39268d8c62835f14d3662feb"

def extract_ip(text):
    """Finds an IPv4 address in a log message."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, text)
    return match.group(0) if match else None

def check_cti(ip_address):
    """Checks the IP against AbuseIPDB."""
    if not ip_address or not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ACTUAL_ABUSEIPDB_KEY_HERE":
        # If key is missing/placeholder, assume clean status for the demo
        return {"status": "N/A - Key Missing", "score": 0}
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=3)
        response.raise_for_status()
        data = response.json().get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        
        if score > 60:
            return {"status": "MALICIOUS", "score": score}
        elif score > 20:
            return {"status": "Suspicious", "score": score}
        else:
            return {"status": "CLEAN", "score": score}
            
    except requests.exceptions.RequestException:
        return {"status": "API_ERROR", "score": 0}

def process_log(log_id, log_text, log_data):
    """The main function: checks rules, CTI, UEBA, and triggers SOAR."""
    
    ip_address = log_data.get('ip_address', extract_ip(log_text))
    cti_result = check_cti(ip_address)
    is_ueba_anomaly = check_anomaly(log_text, log_id) 

    # 1. Rule Check
    rule_hit = None
    for rule in RULES:
        if rule["keyword"] in log_text.lower():
            rule_hit = rule["name"]
            break

    # 2. Decision Logic: Trigger Alert and SOAR Action
    if rule_hit or cti_result["status"] == "MALICIOUS" or is_ueba_anomaly:
        
        # --- Create Local Alert (for dashboard display) ---
        alert_name = rule_hit if rule_hit else "Intelligent Alert"
        message = (
            f"Rule: {rule_hit or 'N/A'}. "
            f"CTI: {cti_result['status']} ({cti_result['score']}%). "
            f"UEBA: {is_ueba_anomaly}. "
            f"IP: {ip_address or 'None'}."
        )
        
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("INSERT INTO alerts(rule_name, message, log_id, priority) VALUES(?,?,?,?)",
                  (alert_name, message, log_id, 10))
        conn.commit()
        conn.close()
        
        print(f"[ALERT TRIGGERED] Rule: {alert_name}. CTI: {cti_result['status']}")

        # 3. --- Execute SOAR Action (Full Integration: Calls Shuffle) ---
        trigger_shuffle_workflow(log_id, alert_name, ip_address, cti_result, is_ueba_anomaly)

        return alert_name
            
    return None