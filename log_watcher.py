import time
import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = "/var/log/nginx/access.log"

# Seuils de détection
BRUTE_FORCE_THRESHOLD = 10  # tentatives login en 10s
SPIKE_THRESHOLD = 20         # requêtes en 5s
ENUM_THRESHOLD = 5           # endpoints différents en 10s

ip_requests = defaultdict(list)
ip_endpoints = defaultdict(set)

def parse_line(line):
    pattern = r'(\S+) - - \[(.+?)\] "(\S+) (\S+) \S+" (\d+) (\d+)'
    match = re.match(pattern, line)
    if match:
        return {
            "ip": match.group(1),
            "time": match.group(2),
            "method": match.group(3),
            "path": match.group(4),
            "status": int(match.group(5)),
            "size": int(match.group(6)),
        }
    return None

def detect_attacks(entry):
    ip = entry["ip"]
    path = entry["path"]
    now = time.time()

    # Enregistrer la requête
    ip_requests[ip].append(now)
    ip_endpoints[ip].add(path)

    # Garder seulement les 10 dernières secondes
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < 10]

    alerts = []

    # Brute force login
    if "/login" in path and len(ip_requests[ip]) >= BRUTE_FORCE_THRESHOLD:
        alerts.append(f"[🔴 BRUTE FORCE] IP: {ip} — {len(ip_requests[ip])} tentatives login en 10s")

    # Spike
    if len(ip_requests[ip]) >= SPIKE_THRESHOLD:
        alerts.append(f"[🟠 SPIKE] IP: {ip} — {len(ip_requests[ip])} requêtes en 10s")

    # Enumération
    if len(ip_endpoints[ip]) >= ENUM_THRESHOLD:
        alerts.append(f"[🟡 ENUM] IP: {ip} — {len(ip_endpoints[ip])} endpoints différents")

    return alerts

def watch():
    print(f"[*] Surveillance de {LOG_FILE} en temps réel...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # aller à la fin du fichier
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            entry = parse_line(line.strip())
            if entry:
                print(f"[+] {entry['method']} {entry['path']} — {entry['ip']} — {entry['status']}")
                alerts = detect_attacks(entry)
                for alert in alerts:
                    print(alert)

if __name__ == "__main__":
    watch()
