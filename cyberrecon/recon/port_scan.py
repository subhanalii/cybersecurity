# recon/port_scan.py
import socket
from typing import List

def scan_ports(host: str, ports: List[int] = None, timeout: float = 0.6) -> List[int]:
    if ports is None:
        ports = [21,22,23,25,53,80,443,8080]
    open_ports = []
    banners = {}
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((host, p))
                if res == 0:
                    open_ports.append(p)
                    try:
                        # attempt simple banner read with small timeout
                        s.settimeout(0.6)
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        resp = s.recv(1024).decode(errors="ignore")
                        banners[str(p)] = resp.strip()
                    except Exception:
                        banners[str(p)] = ""
        except Exception:
            continue
    return {"target": host, "ip": host, "open_ports": open_ports, "banners": banners, "scanned_ports": ports, "errors": [], "skipped_private": False}
