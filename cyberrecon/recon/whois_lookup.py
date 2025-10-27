# recon/whois_lookup.py
try:
    import whois
except Exception:
    whois = None

def lookup(domain: str):
    if whois is None:
        return {"error": "python-whois not installed"}
    try:
        w = whois.whois(domain)
        result = {}
        # pack main keys safely
        for key in ["domain_name","registrar","creation_date","expiration_date","name_servers","emails","status"]:
            val = w.get(key) if isinstance(w, dict) else getattr(w, key, None)
            result[key] = val
        return result
    except Exception as e:
        return {"error": str(e)}
