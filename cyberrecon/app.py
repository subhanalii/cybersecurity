# app.py
import os
import re
import json
import logging
import traceback
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory

# === Paths ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# === Logging ===
logging.basicConfig(
    filename=os.path.join(LOGS_DIR, "app.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

app = Flask(__name__, template_folder="templates", static_folder="static")

# Domain validation (simple)
DOMAIN_REGEX = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")
def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain))

# Import your real scan builder
try:
    from scan_parser import build_summary_for_domain, write_summary_file
except Exception:
    # Minimal fallback so the app still runs if scan_parser missing; replace as needed.
    def build_summary_for_domain(domain):
        return {
            "domain": domain,
            "scan_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "dns": {"A": []},
            "headers": {},
            "ports": {"open": []},
            "subdomains": [],
            "whois": {},
            "snapshot": {},
            "status": "fallback"
        }
    def write_summary_file(summary, out_path):
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)

# --- Routes ---

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    target = (data.get("target") or "").strip().lower()
    if not target:
        return jsonify({"ok": False, "error": "No target provided"}), 400
    if not is_valid_domain(target):
        return jsonify({"ok": False, "error": "Invalid domain format"}), 400

    logging.info(f"Starting scan for {target}")
    try:
        summary = build_summary_for_domain(target)

        # timestamped report
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_name = f"{target}_{ts}.json"
        report_path = os.path.join(REPORTS_DIR, report_name)
        write_summary_file(summary, out_path=report_path)

        # also write compatibility summary.json at project root
        write_summary_file(summary, out_path=os.path.join(BASE_DIR, "summary.json"))

        logging.info(f"Saved report: {report_path}")
        return jsonify({"ok": True, "summary": summary, "report_file": f"/reports/{report_name}"})
    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"Scan error for {target}: {tb}")
        return jsonify({"ok": False, "error": str(e), "traceback_preview": tb.splitlines()[-10:]}), 500

@app.route("/reports", methods=["GET"])
def list_reports():
    files = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")], reverse=True)
    reports = [{"name": f, "url": f"/reports/{f}"} for f in files]
    return jsonify({"ok": True, "reports": reports})

@app.route("/summary", methods=["GET"])
def summary_compat():
    path = os.path.join(BASE_DIR, "summary.json")
    if not os.path.exists(path):
        return jsonify({"error": "summary.json not found"}), 404
    with open(path, "r", encoding="utf-8") as fh:
        return jsonify(json.load(fh))

@app.route("/summary/latest", methods=["GET"])
def latest_summary():
    files = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")], reverse=True)
    if not files:
        return jsonify({"error": "no reports"}), 404
    with open(os.path.join(REPORTS_DIR, files[0]), "r", encoding="utf-8") as fh:
        return jsonify(json.load(fh))

@app.route("/summary/<domain>", methods=["GET"])
def summary_for_domain(domain):
    files = sorted([f for f in os.listdir(REPORTS_DIR) if f.startswith(domain) and f.endswith(".json")], reverse=True)
    if not files:
        return jsonify({"error": f"No reports for {domain}"}), 404
    with open(os.path.join(REPORTS_DIR, files[0]), "r", encoding="utf-8") as fh:
        return jsonify(json.load(fh))

@app.route("/report/<domain>", methods=["GET"])
def report_page(domain):
    """
    Pretty HTML report page for a domain.
    Finds the latest report for this domain and renders report.html with `summary`.
    """
    files = sorted([f for f in os.listdir(REPORTS_DIR) if f.startswith(domain) and f.endswith(".json")], reverse=True)
    if not files:
        return render_template("scan_report.html", target=domain, summary={}, error=f"No reports for {domain}")
    with open(os.path.join(REPORTS_DIR, files[0]), "r", encoding="utf-8") as fh:
        summary = json.load(fh)
    return render_template("scan_report.html", target=domain, summary=summary)

# Serve static JSON reports under /reports/<filename>
@app.route("/reports/<path:filename>", methods=["GET"])
def serve_report_file(filename):
    return send_from_directory(REPORTS_DIR, filename)

# --- Startup banner ---
if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    url = f"http://{host}:{port}"
    print("\033[92m" + "=" * 60)
    print(" CYBERRECON TOOL — Flask-based Recon Framework")
    print(" Developer: Subhan Ali")
    print(f" Open in browser: {url}")
    print("=" * 60 + "\033[0m\n")
    app.run(host=host, port=port, debug=True)
