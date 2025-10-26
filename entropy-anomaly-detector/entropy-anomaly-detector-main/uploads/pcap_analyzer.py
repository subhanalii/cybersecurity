import csv
from scapy.all import rdpcap, TCP, Raw, IP
from uploads.entropy_utils import shannon_entropy

def analyze_pcap(file_path, threshold=7.5):
    packets = rdpcap(file_path)
    results = []

    for i, packet in enumerate(packets):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            entropy = shannon_entropy(payload)
            if entropy >= threshold and len(payload) > 50:
                src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
                dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                results.append([
                    i + 1, src_ip, dst_ip, src_port, dst_port, len(payload), round(entropy, 5)
                ])
                print(f"[ALERT] #{i+1} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Entropy: {entropy:.2f}")

    with open("entropy_alerts.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Packet#", "Source IP", "Destination IP", "Source Port", "Dest Port", "Size (bytes)", "Entropy"
        ])
        writer.writerows(results)
