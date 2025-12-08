# vigilanteye/siem/rules.py

RULES = [
    {
        "name": "High Severity: USB Activity",
        "keyword": "usb inserted",
        "message": "Immediate alert: Unauthorized USB device activity detected.",
        "priority": 8
    },
    {
        "name": "Suspicious: Failed Login Attempts",
        "keyword": "failed login",
        "message": "Multiple failed login attempts detected on endpoint.",
        "priority": 5
    },
    {
        "name": "Critical: Malware Confirmation",
        "keyword": "malware detected",
        "message": "AV alert confirmation: Confirmed malware quarantined.",
        "priority": 10
    }
]