# vigilanteye/siem/snort_poller.py

import requests
import time
import os
import re

# --- Configuration ---
# NOTE: CHANGED PATH to local file for Windows compatibility
SNORT_ALERT_FILE = "snort_alerts.log" 
# Your Flask SIEM collector endpoint
SIEM_URL = "http://127.0.0.1:5000/collect"

# Checkpoint file to track which line number was last processed
CHECKPOINT_FILE = "snort_checkpoint.txt"

def get_last_processed_line():
    """Reads the line number from which processing should start."""
    try:
        with open(CHECKPOINT_FILE, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0

def update_checkpoint(line_number):
    """Saves the line number up to which alerts have been processed."""
    with open(CHECKPOINT_FILE, 'w') as f:
        f.write(str(line_number))

def extract_ip_from_snort_log(log_line):
    """Extracts the source IP from a common Snort alert format."""
    # Regex pattern to find an IPv4 address immediately followed by ' ->'
    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+->', log_line)
    return match.group(1) if match else "N/A"

def process_snort_logs():
    """Reads Snort alert file, forwards new alerts to the SIEM, and updates the checkpoint."""
    if not os.path.exists(SNORT_ALERT_FILE):
        print(f"!!! SNORT ERROR: Alert file not found at {SNORT_ALERT_FILE} !!!")
        return

    last_processed_line = get_last_processed_line()
    current_line = 0
    
    print(f"Starting Snort poll from line: {last_processed_line + 1}")

    try:
        with open(SNORT_ALERT_FILE, 'r') as f:
            for line in f:
                current_line += 1
                if current_line > last_processed_line and line.strip(): # Check if line is not empty
                    
                    source_ip = extract_ip_from_snort_log(line)
                    
                    log_data = {
                        "source": "SNORT_IDS",
                        "event": line.strip(),
                        "ip_address": source_ip,
                        "username": "system_alert"
                    }
                    
                    # Send the log to your Flask SIEM's /collect endpoint
                    requests.post(SIEM_URL, json=log_data, timeout=5)
                    print(f"Snort Alert Sent (Line {current_line}): {line.strip()[:60]}...")
        
        # Update checkpoint after successfully processing all new lines
        update_checkpoint(current_line)

    except requests.exceptions.RequestException as e:
        print(f"!!! SIEM Connection Error: Could not send Snort log. {e} !!!")
    except Exception as e:
        print(f"An unexpected error occurred during Snort processing: {e}")

if __name__ == "__main__":
    print("--- VigilantEye Snort Poller Starting ---")
    
    # Run the poller every 30 seconds
    while True:
        process_snort_logs()
        time.sleep(30)