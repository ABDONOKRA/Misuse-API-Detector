"""
Générateur de logs API mobiles simulés.
Produit des logs Nginx réalistes incluant des attaques typiques.
"""
 
import random
import datetime
import json
from faker import Faker
 
fake = Faker()
 
# User-agents mobiles réalistes
MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Dart/3.0 (dart:io) - Flutter App",
    "okhttp/4.11.0",                         # Android natif
    "CFNetwork/1400.0.4 Darwin/22.0.0",      # iOS natif
    "ReactNativeApp/1.2.3",
]
 
# Endpoints d'API mobile typiques
API_ENDPOINTS = [
    "/api/v1/login",
    "/api/v1/logout",
    "/api/v1/register",
    "/api/v1/user/profile",
    "/api/v1/user/settings",
    "/api/v1/products",
    "/api/v1/orders",
    "/api/v1/payment",
    "/api/v1/notifications",
    "/api/v1/search",
    "/api/v1/refresh-token",
    "/api/v1/password-reset",
]
 
# Codes HTTP
HTTP_CODES_NORMAL   = [200, 200, 200, 201, 204, 304]
HTTP_CODES_ATTACK   = [401, 403, 429, 400, 500]
 
 
def generate_normal_log(ip: str, timestamp: datetime.datetime) -> dict:
    """Génère un log de requête normale."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": random.choice(["GET", "POST", "GET", "GET"]),
        "endpoint": random.choice(API_ENDPOINTS),
        "status": random.choice(HTTP_CODES_NORMAL),
        "size": random.randint(200, 5000),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "normal",
    }
 
 
def generate_brute_force_log(ip: str, timestamp: datetime.datetime) -> dict:
    """Génère un log de tentative brute force (login répété)."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": "POST",
        "endpoint": "/api/v1/login",
        "status": 401,
        "size": random.randint(50, 200),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "brute_force",
    }
 
 
def generate_spike_log(ip: str, timestamp: datetime.datetime) -> dict:
    """Génère un log de spike (flood de requêtes)."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": random.choice(["GET", "POST"]),
        "endpoint": random.choice(API_ENDPOINTS),
        "status": random.choice([200, 429]),
        "size": random.randint(100, 1000),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "spike",
    }
 
 
def generate_enumeration_log(ip: str, timestamp: datetime.datetime, index: int) -> dict:
    """Génère un log d'énumération d'endpoints."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": "GET",
        "endpoint": f"/api/v1/user/{index}",
        "status": random.choice([200, 404]),
        "size": random.randint(50, 500),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "enumeration",
    }
 
 
def generate_logs(
    n_normal: int = 500,
    n_brute_force_ips: int = 3,
    n_spike_ips: int = 2,
    n_enum_ips: int = 2,
    output_file: str = "samples/mobile_api_logs.txt",
) -> list:
    """
    Génère un fichier de logs complet avec trafic normal et attaques.
    Retourne la liste de tous les logs générés.
    """
    logs = []
    base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
 
    # Logs normaux
    normal_ips = [fake.ipv4() for _ in range(50)]
    for i in range(n_normal):
        ts = base_time + datetime.timedelta(seconds=i * 5)
        ip = random.choice(normal_ips)
        logs.append(generate_normal_log(ip, ts))
 
    # Attaque brute force (plusieurs IPs distinctes)
    bf_ips = [fake.ipv4() for _ in range(n_brute_force_ips)]
    for ip in bf_ips:
        for j in range(random.randint(20, 50)):
            ts = base_time + datetime.timedelta(minutes=30, seconds=j * 2)
            logs.append(generate_brute_force_log(ip, ts))
 
    # Spikes de requêtes
    spike_ips = [fake.ipv4() for _ in range(n_spike_ips)]
    for ip in spike_ips:
        for j in range(random.randint(100, 200)):
            ts = base_time + datetime.timedelta(minutes=60, seconds=j * 0.5)
            logs.append(generate_spike_log(ip, ts))
 
    # Énumération d'endpoints
    enum_ips = [fake.ipv4() for _ in range(n_enum_ips)]
    for ip in enum_ips:
        for idx in range(1, random.randint(50, 100)):
            ts = base_time + datetime.timedelta(minutes=90, seconds=idx * 1)
            logs.append(generate_enumeration_log(ip, ts, idx))
 
    # Mélanger les logs
    random.shuffle(logs)
 
    # Format Nginx commun
    lines = []
    for log in logs:
        line = (
            f'{log["ip"]} - - [{log["timestamp"]}] '
            f'"{log["method"]} {log["endpoint"]} HTTP/1.1" '
            f'{log["status"]} {log["size"]} '
            f'"-" "{log["user_agent"]}"'
        )
        lines.append(line)
 
    # Sauvegarder
    import os
    os.makedirs("samples", exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(lines))
 
    print(f"[✓] {len(logs)} logs générés dans '{output_file}'")
    return logs
 
 
if __name__ == "__main__":
    generate_logs()
