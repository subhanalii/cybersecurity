import matplotlib.pyplot as plt
import csv

def plot_entropy(csv_file="entropy_alerts.csv"):
    packet_nums = []
    entropy_vals = []

    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

        is_packet = "Packet#" in rows[0]
        for i, row in enumerate(rows):
            packet_nums.append(int(row["Packet#"]) if is_packet else i + 1)
            entropy_vals.append(float(row["Entropy"]))

    label = "Packet Entropy" if is_packet else "File Entropy"

    plt.figure(figsize=(14, 6))
    plt.plot(packet_nums, entropy_vals, marker='o', markersize=3, linestyle='-', label=label)
    plt.axhline(y=7.5, color='red', linestyle='--', label='High Entropy Threshold')

    # Updated titles and labels
    plt.title("Entropy Analysis\nHigher entropy means greater likelihood of encryption, obfuscation, or steganography", fontsize=14)
    plt.xlabel("Packet Number" if is_packet else "File", fontsize=12)
    plt.ylabel("Shannon Entropy (0–8)", fontsize=12)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("static/entropy_plot.png")
