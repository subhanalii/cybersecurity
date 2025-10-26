from scapy.all import sniff, TCP, Raw, IP
from .entropy_utils import shannon_entropy
import csv
import os

sniffer_running = False
ALERT_LOG = "live_alerts.csv"

def log_alert(row):
    file_exists = os.path.exists(ALERT_LOG)
    with open(ALERT_LOG, "a", newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Source IP", "Dest IP", "Source Port", "Dest Port", "Entropy"])
        writer.writerow(row)

def process_packet(packet, threshold=7.5):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        entropy = shannon_entropy(payload)
        if entropy > threshold:
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            row = [src, dst, sport, dport, round(entropy, 5)]
            print(f"[⚠ALERT] {src}:{sport} → {dst}:{dport} | Entropy: {entropy:.3f}")
            log_alert(row)

def start_sniffer():
    global sniffer_running
    sniffer_running = True
    print(" Live sniffer started...")
    sniff(prn=process_packet, filter="tcp", store=False, stop_filter=lambda x: not sniffer_running)

def stop_sniffer():
    global sniffer_running
    sniffer_running = False
    print(" Live sniffer stopped.")

def get_logged_alerts():
    if not os.path.exists(ALERT_LOG):
        return []
    with open(ALERT_LOG, newline='') as f:
        reader = csv.DictReader(f)
        return list(reader)
