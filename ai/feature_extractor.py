import re
import pandas as pd
from collections import defaultdict

LOG_FILE = "/var/log/nginx/access.log"

def parse_log(line):
    pattern = r'(\S+) - - \[(.+?)\] "(\S+) (\S+) \S+" (\d+) (\d+)'
    match = re.match(pattern, line)
    if match:
        return {
            "ip": match.group(1),
            "method": match.group(3),
            "path": match.group(4),
            "status": int(match.group(5)),
            "size": int(match.group(6)),
        }
    return None

def extract_features(log_file=LOG_FILE):
    ip_data = defaultdict(lambda: {
        "total_requests": 0,
        "login_attempts": 0,
        "error_404": 0,
        "error_401": 0,
        "unique_endpoints": set(),
        "post_requests": 0,
        "total_bytes": 0,
    })

    with open(log_file, "r") as f:
        for line in f:
            entry = parse_log(line.strip())
            if not entry:
                continue
            ip = entry["ip"]
            ip_data[ip]["total_requests"] += 1
            ip_data[ip]["total_bytes"] += entry["size"]
            ip_data[ip]["unique_endpoints"].add(entry["path"])
            if "/login" in entry["path"]:
                ip_data[ip]["login_attempts"] += 1
            if entry["status"] == 404:
                ip_data[ip]["error_404"] += 1
            if entry["status"] == 401:
                ip_data[ip]["error_401"] += 1
            if entry["method"] == "POST":
                ip_data[ip]["post_requests"] += 1

    rows = []
    for ip, data in ip_data.items():
        rows.append({
            "ip": ip,
            "total_requests": data["total_requests"],
            "login_attempts": data["login_attempts"],
            "error_404": data["error_404"],
            "error_401": data["error_401"],
            "unique_endpoints": len(data["unique_endpoints"]),
            "post_requests": data["post_requests"],
            "total_bytes": data["total_bytes"],
        })

    return pd.DataFrame(rows)

if __name__ == "__main__":
    df = extract_features()
    print(df.to_string())
