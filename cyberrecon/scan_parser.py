# scan_parser.py
import os
import json
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Safe imports
try:
    from recon.dns_info import get_all_dns
    from recon.headers_scan import fetch_headers, extract_security_headers
    from recon.port_scan import scan_ports
    from recon.subdomains_crtsh import crtsh_subdomains
    from recon.whois_lookup import lookup
    from recon.screenshot import save_html_snapshot
except ImportError:
    logging.warning("Some recon modules missing — using fallbacks.")

# === Summary Writer ===
def write_summary_file(summary: dict, out_path="summary.json"):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
    return out_path


# === Task registry ===
TASKS = {
    "dns": lambda domain: get_all_dns(domain),
    "headers": lambda domain: fetch_headers(domain),
    "ports": lambda domain: scan_ports(domain, ports=[21,22,23,25,53,80,443,8080], timeout=1.0),
    "subdomains": lambda domain: crtsh_subdomains(domain),
    "whois": lambda domain: lookup(domain),
    "snapshot": lambda domain: save_html_snapshot(domain),
}


# === Core Builder ===
def build_summary_for_domain(domain: str):
    summary = {
        "domain": domain,
        "generated_at": datetime.utcnow().isoformat(),
        "results": {},
        "errors": [],
        "risk_score": 0,
    }

    logging.info(f"Building summary for {domain}")

    # Run all modules in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_task = {executor.submit(func, domain): name for name, func in TASKS.items()}

        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                result = future.result()
                summary["results"][task] = result
            except Exception as e:
                summary["errors"].append(f"{task}: {e}")
                summary["results"][task] = {"error": str(e)}

    # Simple heuristic: missing headers or open ports increase risk
    headers = summary["results"].get("headers", {}).get("headers", {})
    open_ports = summary["results"].get("ports", {}).get("open_ports", [])
    if "Content-Security-Policy" not in [k.lower() for k in headers.keys()]:
        summary["risk_score"] += 10
    summary["risk_score"] += len(open_ports) * 2

    return summary
