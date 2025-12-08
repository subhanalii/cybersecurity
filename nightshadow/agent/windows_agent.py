# vigilanteye/agent/windows_agent.py

import requests
import time
import random

SIEM_URL = "http://127.0.0.1:5000/collect"

# Log templates simulating real endpoint data, some containing keywords from rules.py
LOG_TEMPLATES = [
    {
        "source": "Hassan-Laptop",
        "event": "System login successful. Process ID: 4567.",
        "ip_address": "192.168.1.101",
        "username": "hassan"
    },
    {
        "source": "Subhan-Desktop",
        "event": "Error: User 'maaz' failed login attempt. Source IP: 10.10.10.5.",
        "ip_address": "10.10.10.5", 
        "username": "subhan"
    },
    {
        "source": "Maaz-Workstation",
        "event": "CRITICAL: USB device inserted into port 3.", # Triggers "USB Activity" rule
        "ip_address": "172.16.0.25",
        "username": "maaz"
    },
    {
        "source": "Hassan-Laptop",
        "event": "Antivirus Scan: Found no threats. Scan completed in 30s.",
        "ip_address": "192.168.1.101",
        "username": "hassan"
    },
    {
        "source": "Subhan-Desktop",
        "event": "Malware detected: Suspicious file 'exploit.exe' quarantined.", # Triggers "Malware Confirmation" rule
        "ip_address": "10.10.10.5",
        "username": "subhan"
    }
]

def send_log(log_data):
    """Sends a single log dictionary to the Flask SIEM collector."""
    try:
        response = requests.post(SIEM_URL, json=log_data, timeout=5)
        # Check if the SIEM sent an 'alert_triggered' flag
        result = response.json()
        print(f"Log sent. Status: {result.get('status')}. Alert: {result.get('alert_triggered', 'None')}")
        
    except requests.exceptions.RequestException as e:
        print(f"!!! Error sending log: {e}. Is the SIEM backend running?")

if __name__ == "__main__":
    print("--- VigilantEye Endpoint Agent Starting ---")
    
    # Continuously send a random log every 3 seconds
    while True:
        log_to_send = random.choice(LOG_TEMPLATES)
        send_log(log_to_send)
        time.sleep(3)