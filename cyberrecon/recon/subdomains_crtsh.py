# recon/subdomains_crtsh.py
import requests

def crtsh_subdomains(domain: str, timeout: int = 6):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        names = set()
        for item in data:
            name = item.get("name_value") or item.get("common_name")
            if not name:
                continue
            for n in str(name).splitlines():
                n = n.strip()
                if n.endswith(domain):
                    names.add(n)
        return {"ok": True, "subdomains": sorted(names)}
    except Exception as e:
        return {"ok": False, "subdomains": [], "error": str(e)}
