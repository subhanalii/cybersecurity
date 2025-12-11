# vigilanteye/siem/soar_actions.py

import requests
import json
# os import removed

# --- Shuffle Configuration (CRITICAL: Hardcoded Credentials) ---
# Your actual Shuffle API Key
SHUFFLE_API_KEY = ""
# Base URL for your Shuffle server
SHUFFLE_BASE_URL = "https://shuffler.io/api/v1/workflows/" 
# The unique ID of the specific Shuffle playbook you created
ISOLATE_WORKFLOW_ID = ""

def trigger_shuffle_workflow(log_id, alert_name, ip_address, cti_result, is_ueba_anomaly):
    """
    Sends a request to the Shuffle API to execute a specific SOAR workflow.
    """
    if not SHUFFLE_API_KEY or not ISOLATE_WORKFLOW_ID:
        print("!!! SOAR ERROR: Shuffle configuration incomplete. Skipping trigger. !!!")
        return
        
    # Data package containing all the intelligence context to send to Shuffle
    execution_argument = {
        "alert_id": log_id,
        "threat_name": alert_name,
        "target_ip": ip_address,
        "cti_status": cti_result["status"],
        "ueba_anomaly": is_ueba_anomaly,
        "priority": 10,
        "trigger_source": "VigilantEye_Intelligent_Processor"
    }
    
    # Shuffle API Execution Endpoint
    url = f"{SHUFFLE_BASE_URL}{ISOLATE_WORKFLOW_ID}/execute"
    headers = {
        "Authorization": f"Bearer {SHUFFLE_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            url, 
            headers=headers, 
            json={"execution_argument": json.dumps(execution_argument)}, 
            timeout=5
        )
        response.raise_for_status()
        
        if response.status_code == 200:
            print(f"*** SOAR SUCCESS: Shuffle workflow '{ISOLATE_WORKFLOW_ID}' triggered for IP: {ip_address} ***")
        else:
            print(f"!!! SOAR WARNING: Shuffle responded with status {response.status_code} !!!")
            
    except requests.exceptions.RequestException as e:
        print(f"!!! SOAR FAILED: Could not connect to Shuffle API. Error: {e} !!!")
