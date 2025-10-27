# recon/screenshot.py
import requests
import os
from datetime import datetime

def save_html_snapshot(domain: str, out_dir="snapshots"):
    try:
        r = requests.get(f"https://{domain}", timeout=6)
        r.raise_for_status()
        os.makedirs(out_dir, exist_ok=True)
        fname = f"{domain.replace('.','_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        path = os.path.join(out_dir, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(r.text)
        return {"ok": True, "path": path, "filepath": path}
    except Exception as e:
        return {"ok": False, "error": str(e)}
