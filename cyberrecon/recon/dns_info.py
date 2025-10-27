# recon/dns_info.py
import socket
from typing import Dict, List

try:
    import dns.resolver
except Exception:
    dns = None

def get_a_records(domain: str) -> List[str]:
    try:
        _, _, addrs = socket.gethostbyname_ex(domain)
        return list(dict.fromkeys(addrs))
    except Exception:
        return []

def get_txt(domain: str) -> List[str]:
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        out = []
        for r in answers:
            try:
                txt = b"".join(r.strings).decode(errors="ignore")
            except Exception:
                txt = str(r)
            out.append(txt)
        return out
    except Exception:
        return []

def get_cname(domain: str) -> List[str]:
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
        return [str(r.target).rstrip('.') for r in answers]
    except Exception:
        return []

def get_all_dns(domain: str) -> Dict[str, List[str]]:
    data = {"A": get_a_records(domain), "CNAME": get_cname(domain), "TXT": get_txt(domain)}
    return data
