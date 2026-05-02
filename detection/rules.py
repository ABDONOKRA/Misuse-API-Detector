"""
Moteur de détection par règles.
Détecte : brute force, spikes, énumération, hammering d'endpoints.
"""
 
import pandas as pd
from dataclasses import dataclass
 
 
@dataclass
class Alert:
    """Représente une alerte de sécurité."""
    type:        str
    ip:          str
    severity:    str        # LOW, MEDIUM, HIGH, CRITICAL
    count:       int
    details:     str
    endpoint:    str = ""
 
 
def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[Alert]:
    """
    Détecte les tentatives de brute force.
    Règle : N échecs de login depuis la même IP dans une fenêtre de temps.
    """
    alerts = []
 
    # Filtrer les échecs de login
    login_fails = df[(df["endpoint"].str.contains("login", na=False)) &
                     (df["status"] == 401)].copy()
 
    if login_fails.empty:
        return alerts
 
    # Grouper par IP et fenêtre de temps
    for ip, group in login_fails.groupby("ip"):
        group = group.sort_values("timestamp")
        count = len(group)
 
        if count >= threshold:
            severity = "CRITICAL" if count >= 30 else "HIGH" if count >= 20 else "MEDIUM"
            alerts.append(Alert(
                type="BRUTE_FORCE",
                ip=ip,
                severity=severity,
                count=count,
                details=f"{count} échecs de login en {window_minutes} min",
                endpoint="/api/v1/login",
            ))
 
    return alerts
 
 
def detect_request_spikes(
    df: pd.DataFrame,
    threshold_per_minute: int = 60,
) -> list[Alert]:
    """
    Détecte les spikes de requêtes (flood).
    Règle : Plus de N requêtes/minute depuis une même IP.
    """
    alerts = []
 
    if df.empty or "timestamp" not in df.columns:
        return alerts
 
    df = df.copy()
    df["minute"] = df["timestamp"].dt.floor("min")   # Arrondir à la minute
 
    # Compter par IP et minute
    counts = df.groupby(["ip", "minute"]).size().reset_index(name="count")
    spikes  = counts[counts["count"] >= threshold_per_minute]
 
    for _, row in spikes.iterrows():
        alerts.append(Alert(
            type="REQUEST_SPIKE",
            ip=row["ip"],
            severity="HIGH",
            count=int(row["count"]),
            details=f"{row['count']} req/min à {row['minute']}",
        ))
 
    return alerts
 
 
def detect_endpoint_enumeration(
    df: pd.DataFrame,
    threshold_unique: int = 20,
) -> list[Alert]:
    """
    Détecte l'énumération d'endpoints.
    Règle : Une IP accède à N endpoints distincts avec beaucoup de 404.
    """
    alerts = []
 
    for ip, group in df.groupby("ip"):
        unique_endpoints = group["endpoint"].nunique()
        nb_404           = (group["status"] == 404).sum()
        ratio_404        = nb_404 / max(len(group), 1)
 
        if unique_endpoints >= threshold_unique and ratio_404 > 0.3:
            alerts.append(Alert(
                type="ENDPOINT_ENUMERATION",
                ip=ip,
                severity="MEDIUM",
                count=int(unique_endpoints),
                details=f"{unique_endpoints} endpoints distincts, {ratio_404:.0%} de 404",
            ))
 
    return alerts
 
 
def detect_endpoint_hammering(
    df: pd.DataFrame,
    threshold: int = 100,
) -> list[Alert]:
    """
    Détecte le hammering (martelage) d'un endpoint spécifique.
    Règle : Une IP frappe le même endpoint plus de N fois.
    """
    alerts = []
 
    counts = df.groupby(["ip", "endpoint"]).size().reset_index(name="count")
    heavy  = counts[counts["count"] >= threshold]
 
    for _, row in heavy.iterrows():
        alerts.append(Alert(
            type="ENDPOINT_HAMMERING",
            ip=row["ip"],
            severity="MEDIUM",
            count=int(row["count"]),
            details=f"{row['count']} requêtes sur {row['endpoint']}",
            endpoint=row["endpoint"],
        ))
 
    return alerts
 
 
def run_all_detections(df: pd.DataFrame) -> list[Alert]:
    """Lance toutes les détections et retourne la liste d'alertes."""
    all_alerts = []
    all_alerts.extend(detect_brute_force(df))
    all_alerts.extend(detect_request_spikes(df))
    all_alerts.extend(detect_endpoint_enumeration(df))
    all_alerts.extend(detect_endpoint_hammering(df))
 
    print(f"[✓] {len(all_alerts)} alerte(s) détectée(s)")
    return all_alerts
