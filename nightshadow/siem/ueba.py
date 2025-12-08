# vigilanteye/siem/ueba.py

from sklearn.ensemble import IsolationForest
import numpy as np
import sqlite3
from database import DB

# The global variable to hold the trained ML model
ueba_model = None

def train_ueba_model():
    """Trains the Isolation Forest model on log event lengths to establish a baseline."""
    global ueba_model
    conn = sqlite3.connect(DB)
    # Fetch log events to train the model on log length as a behavioral metric
    logs = conn.execute("SELECT event FROM logs").fetchall()
    conn.close()

    if len(logs) < 10:
        print("Warning: Insufficient logs for training (<10). Training skipped.")
        ueba_model = None
        return 

    # Prepare data for IsolationForest
    data = [len(log[0]) for log in logs]
    X = np.array(data).reshape(-1, 1)

    # Train the model
    ueba_model = IsolationForest(contamination='auto', random_state=42)
    ueba_model.fit(X)
    print("UEBA Model trained successfully!")

def check_anomaly(log_text, log_id):
    """
    Checks a single log's length against the trained model using decision_function
    to robustly identify anomalies, fixing the offset_ error.
    """
    global ueba_model
    if ueba_model is None:
        return False
    
    log_length = len(log_text)
    
    # Use decision_function to get the anomaly score (lower score = higher anomaly)
    try:
        anomaly_score = ueba_model.decision_function(np.array([log_length]).reshape(1, -1))[0]
    except AttributeError:
        # Fallback in case of model load failure
        return False
    
    # If the score is below the threshold, it is considered an anomaly
    if anomaly_score < -0.1: # Threshold set to -0.1 for a strong negative score (anomaly)
        
        # Insert a separate UEBA alert entry directly (since processor only returns True/False)
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        
        message = f"[UEBA ANOMALY] Score: {anomaly_score:.2f}. Length: {log_length} chars."
        c.execute("INSERT INTO alerts(rule_name, message, log_id, priority) VALUES(?,?,?,?)",
                  ("UEBA Anomaly", message, log_id, 7))
        conn.commit()
        conn.close()
        
        return True
    return False