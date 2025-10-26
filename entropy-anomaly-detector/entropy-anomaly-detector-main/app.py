import os
import threading
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from uploads.pcap_analyzer import analyze_pcap
from uploads.entropy_plot import plot_entropy
from uploads.entropy_utils import shannon_entropy
from uploads.live_sniffer import start_sniffer, stop_sniffer, get_logged_alerts

app = Flask(__name__)
app.secret_key = "entropy"
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

sniffer_thread = None


@app.route("/")
@app.route("/", methods=["GET", "POST"])
def index():
    plot_generated = False
    verdict = None
    alerts = get_logged_alerts()

    if request.method == "POST":
        file = request.files.get("pcap_input") or request.files.get("file_input")
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            try:
                if filename.endswith((".pcap", ".pcapng")):
                    analyze_pcap(file_path)
                    with open("entropy_alerts.csv") as f:
                        lines = f.readlines()
                        verdict = "suspicious" if len(lines) > 1 else "ok"
                else:
                    with open(file_path, "rb") as f:
                        content = f.read()
                        entropy = shannon_entropy(content)
                        verdict = "suspicious" if entropy > 7.5 else "ok"
                        with open("entropy_alerts.csv", "w") as report:
                            report.write("File,Entropy\n")
                            report.write(f"{filename},{entropy:.6f}\n")

                plot_entropy()
                plot_generated = True

            except Exception as e:
                flash(f"❌ Error analyzing file: {str(e)}")
        else:
            flash("❌ No file received.")

    return render_template("index.html", plot_generated=plot_generated, verdict=verdict, alerts=alerts)

@app.route("/start-sniffer")
def start_sniffer_route():
    global sniffer_thread
    if not sniffer_thread or not sniffer_thread.is_alive():
        sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
        sniffer_thread.start()
        flash(" Live sniffer started.")
    else:
        flash(" Sniffer already running.")
    return redirect(url_for("index"))

@app.route("/stop-sniffer")
def stop_sniffer_route():
    stop_sniffer()
    flash(" Live sniffer stopped.")
    return redirect(url_for("index"))

@app.route("/fake-upload", methods=["POST"])
def fake_upload():
    print(f"[ RECEIVED] {len(request.data)} bytes of simulated exfiltration.")
    return "Received", 200

@app.route("/download")
def download_csv():
    return send_file("entropy_alerts.csv", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
