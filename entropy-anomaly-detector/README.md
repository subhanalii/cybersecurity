# entropy-anomaly-detector
A forensic detection tool to identify covert data exfiltration using entropy analysis. Detects encrypted or hidden content in files and network traffic, and features live packet sniffing with anomaly alerts.


# 🔍 Entropy-Based Anomaly Detector

A forensic detection tool designed to trace sophisticated data exfiltration attacks using entropy analysis. Capable of analyzing files, PCAP traffic, and live packets to detect encrypted, obfuscated, or steganographic behavior often missed by traditional tools.

---

## 🎯 Project Objective

To build a real-world detection tool tailored to a defined cybercrime scenario:  
**Insider exfiltration of sensitive data using encrypted or steganographic channels.**

---

## 🧠 Key Features

- 📁 Upload-based entropy detection (files, PCAPs)
- 📡 Live packet sniffer with entropy alerts
- 📊 Entropy graph generation & visualization
- 🧾 CSV export of flagged packets/files
- 🛡️ Detects base64, XOR, and high-entropy content
- 🚦 Verdict engine: Normal vs Suspicious
- 🔒 Simulated covert exfiltration demo (`attack.py`)

---

## 📁 Folder Structure

entropy-anomaly-detector/
├── app.py # Flask web server
├── attack.py # Simulates exfiltration attack (base64 encoded POST)
├── requirements.txt # Required Python packages
├── README.md # This documentation
├── templates/
│ └── index.html # Web interface with Bootstrap
├── static/
│ └── entropy_plot.png # Generated entropy graph
├── uploads/
│ ├── pcap_analyzer.py # Analyzes PCAPs for high-entropy packets
│ ├── entropy_plot.py # Generates entropy plot using matplotlib
│ ├── entropy_utils.py # Calculates Shannon entropy
│ └── live_sniffer.py # Real-time sniffer + alert logging
├── live_alerts.csv # (Auto-generated) Sniffer alerts
├── entropy_alerts.csv # (Auto-generated) File/PCAP analysis results

## 🖼️ Web Interface Preview

![image](https://github.com/user-attachments/assets/f8db734a-1788-4448-b324-45837b234302)


---

## 🚀 Getting Started

### 🔧 Requirements

Install dependencies:

```bash
pip install -r requirements.txt

To launch the Web App:
  python app.py
  Then open: http://localhost:5000


🛠️ Usage Instructions
🔍 File/PCAP Analysis
Choose either "File Entropy" or "PCAP Entropy" tab

Upload .bin, .png, .pcap, or .pcapng file

Click Analyze

See:

Entropy Graph

CSV download

"Verdict" label (OK or Suspicious)

📡 Live Packet Monitoring
Click 🟢 Start Live Sniffer

Generate traffic or simulate an attack (see below)

Refresh browser to see Live Entropy Alerts

Click 🛑 Stop Sniffer to end


💣 Simulate a Covert Exfiltration Attack
python attack.py
Sends 100KB base64-encoded random data to /fake-upload
Detected by the live sniffer as high-entropy traffic


📤 Output Files
File	Description
entropy_alerts.csv	Analysis results for file/PCAP uploads
live_alerts.csv	Log of live high-entropy packet alerts
entropy_plot.png	Generated entropy visualization

