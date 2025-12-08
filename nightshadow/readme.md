# NightShadow – Lightweight SIEM + UEBA + SOAR System

NightShadow is a lightweight, modular Security Information & Event Management (SIEM) platform combined with basic User & Entity Behavior Analytics (UEBA) and automated SOAR-style response actions.  

It includes:

- 🚨 **Real-time log collection** via REST API  
- 📊 **Web dashboard** for viewing alerts and processed logs  
- 🧠 **UEBA anomaly detection** using machine learning  
- 🛡️ **SOAR automated responses** (block IP, isolate host, send notifications)  
- 🧩 **Extensible rules engine** for detection logic  
- 🖥️ **Windows endpoint agent** for simulating incoming logs  
- 🐳 **Docker Compose support** for easy deployment  

---

## **Project Structure**

nightshadow/
│── docker-compose.yml
│
├── agent/
│ └── windows_agent.py # Simulated endpoint agent sending logs
│
└── siem/
├── app.py # Flask API + dashboard
├── database.py # SQLite database operations
├── processor.py # Core event processing engine
├── rules.py # Rule-based detections
├── soar_actions.py # Automated response actions
├── ueba.py # UEBA machine learning model
├── static/style.css # Dashboard styling
├── templates/dashboard.html
├── requirements.txt
└── siem.db # SQLite database

---

## **Features**

### 1. Log Collection API
- POST endpoint `/collect` receives logs from agents.
- Processes logs with rule-based detection, UEBA anomaly scoring, and SOAR automation.

### 2. Windows Endpoint Agent
- Located in `agent/windows_agent.py`.
- Sends simulated logs every few seconds to the SIEM backend.

### 3. UEBA Analytics
- Uses machine learning to analyze behavioral patterns and assign anomaly scores.

### 4. SOAR Automation
- Alerts, notifications, IP blocking, host isolation (mock logic).

### 5. Web Dashboard
- Runs at `http://localhost:5000`.
- Displays alerts, logs, anomaly scores, and rule-triggered events.

---

## **Installation & Setup**

### Clone Repo
```bash
git clone https://github.com/subhanalii/cybersecurity.git
cd cybersecurity/nightshadow
Run Backend (Docker recommended)
docker-compose up --build

Or run manually with Python:
cd siem
pip install -r requirements.txt
python app.py
<img width="1346" height="592" alt="image" src="https://github.com/user-attachments/assets/5979accd-6b33-40e7-a471-65536e4d3a0c" />
then open another terminal
cd agent
pip install requests
python windows_agent.py
Future Improvements

Additional ML models
Threat intelligence feed support
Multi-node distributed backend
Real-time websocket dashboard
