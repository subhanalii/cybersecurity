import os
import base64
import requests

# Generate high-entropy random data
data = os.urandom(1024 * 100)  # 100KB
print(" Generated 100KB of high-entropy data.")

# Encode it to simulate covert exfiltration (e.g., base64 or XOR)
encoded = base64.b64encode(data)
print(" Encoded data using Base64.")

# Send as HTTP POST to a dummy endpoint (e.g., httpbin or localhost listener)
url = "http://localhost:5000/fake-upload"
try:
    response = requests.post(url, data=encoded)
    print(f" Sent to {url} — Response: {response.status_code}")
except Exception as e:
    print(f" Could not send: {e}")
