"""
Parser de logs API mobiles.
Étend le parser VulnSentinel existant avec des features spécifiques mobile.
"""
 
import re
import pandas as pd
from datetime import datetime
 
 
# Regex pour parser les logs Nginx
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<endpoint>[^\s]+) HTTP/[\d\.]+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"[^"]*" "(?P<user_agent>[^"]*)"'
)
 
MOBILE_UA_PATTERNS = [
    "Mobile", "Android", "iPhone", "iPad",
    "okhttp", "Dart", "CFNetwork", "ReactNative", "Flutter",
]
 
 
def is_mobile_request(user_agent: str) -> bool:
    """Vérifie si la requête provient d'un client mobile."""
    return any(p.lower() in user_agent.lower() for p in MOBILE_UA_PATTERNS)
 
 
def parse_log_line(line: str) -> dict | None:
    """Parse une ligne de log Nginx. Retourne None si invalide."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
 
    data = match.groupdict()
 
    # Convertir le timestamp
    try:
        ts = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S +0000")
    except ValueError:
        ts = None
 
    return {
        "ip":            data["ip"],
        "timestamp":     ts,
        "method":        data["method"],
        "endpoint":      data["endpoint"],
        "status":        int(data["status"]),
        "size":          int(data["size"]),
        "user_agent":    data["user_agent"],
        "is_mobile":     is_mobile_request(data["user_agent"]),
    }
 
 
def parse_log_file(filepath: str) -> pd.DataFrame:
    """
    Parse un fichier de logs complet.
    Retourne un DataFrame pandas avec toutes les features.
    """
    records = []
 
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                records.append(parsed)
 
    if not records:
        print("[!] Aucun log parsé.")
        return pd.DataFrame()
 
    df = pd.DataFrame(records)
 
    # Features supplémentaires
    df["hour"]          = df["timestamp"].dt.hour
    df["minute"]        = df["timestamp"].dt.minute
    df["is_auth_fail"]  = (df["endpoint"].str.contains("login") & (df["status"] == 401)).astype(int)
    df["is_rate_limit"] = (df["status"] == 429).astype(int)
    df["is_404"]        = (df["status"] == 404).astype(int)
 
    print(f"[✓] {len(df)} entrées parsées depuis '{filepath}'")
    return df
 
 
if __name__ == "__main__":
    df = parse_log_file("samples/mobile_api_logs.txt")
    print(df.head())
    print(f"\nRequêtes mobiles : {df['is_mobile'].sum()} / {len(df)}")
