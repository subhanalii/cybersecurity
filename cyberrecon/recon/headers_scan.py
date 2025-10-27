# recon/headers_scan.py
import requests

def fetch_headers(domain: str):
    url = f"https://{domain}"
    try:
        r = requests.head(url, timeout=6, allow_redirects=True)
        if r.status_code >= 400:
            # fallback to GET
            r = requests.get(url, timeout=6, allow_redirects=True)
        return {"ok": True, "headers": dict(r.headers)}
    except Exception as e:
        return {"ok": False, "error": str(e), "headers": {}}

def extract_security_headers(headers: dict):
    # normalize keys to lowercase for detection but return original-case mapping for readability
    found = {}
    lmap = {k.lower(): k for k in headers.keys()}
    for want in ["strict-transport-security","x-frame-options","x-content-type-options","referrer-policy","permissions-policy","content-security-policy","server"]:
        key = lmap.get(want)
        if key:
            found[key] = headers.get(key)
    return found
