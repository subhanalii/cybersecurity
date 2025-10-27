# main.py
import json
import argparse
from datetime import datetime
from recon.dns_info import get_dns_records
from recon.headers_scan import fetch_headers
from recon.port_scan import scan_ports
from recon.subdomains_crtsh import get_subdomains
from recon.whois_lookup import get_whois_info
from recon.screenshot import take_screenshot

def run_all_recon(domain, selected_modules=None):
    results = {"domain": domain, "timestamp": datetime.utcnow().isoformat()}
    print(f"\n Running recon for: {domain}")
    print("=" * 60)

    modules = {
        "whois": ("WHOIS Lookup", lambda: get_whois_info(domain)),
        "dns": ("DNS Records", lambda: get_dns_records(domain)),
        "subdomains": ("Subdomain Enumeration", lambda: get_subdomains(domain)),
        "headers": ("Security Headers", lambda: fetch_headers(domain)),
        "ports": ("Port Scan", lambda: scan_ports(domain, ports=[21,22,80,443,8080], timeout=1.5)),
        "screenshot": ("Screenshot", lambda: take_screenshot(domain)),
    }

    for key, (title, func) in modules.items():
        if selected_modules and key not in selected_modules:
            continue
        print(f"\n🔹 {title}...")
        try:
            results[key] = func()
        except Exception as e:
            results[key] = {"error": str(e)}
            print(f"  Error: {e}")

    print("\n Recon complete!")
    print("=" * 60)
    print(json.dumps(results, indent=2))
    return results


def main():
    parser = argparse.ArgumentParser(description="CyberRecon - Lightweight Recon Tool")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-m", "--modules", nargs="+", help="Modules to run (e.g. dns whois ports)")
    parser.add_argument("-o", "--output", help="Output file name (optional)")
    args = parser.parse_args()

    selected = args.modules or []
    report = run_all_recon(args.domain, selected_modules=selected)

    filename = args.output or f"{args.domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n Results saved to {filename}")


if __name__ == "__main__":
    main()
