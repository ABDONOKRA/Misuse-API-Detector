"""
Module IA : Clustering K-Means des comportements suspects.
Regroupe automatiquement les IPs par profil de comportement.
"""
 
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
 
 
CLUSTER_LABELS = {
    0: {"name": "Comportement normal",    "color": "#27ae60", "severity": "LOW"},
    1: {"name": "Comportement suspect",   "color": "#f39c12", "severity": "MEDIUM"},
    2: {"name": "Attaquant probable",     "color": "#e74c3c", "severity": "HIGH"},
    3: {"name": "Bot / Scanner",          "color": "#8e44ad", "severity": "CRITICAL"},
}
 
 
def extract_ip_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extrait les features par IP pour le clustering.
    Chaque ligne = une IP avec ses métriques comportementales.
    """
    if df.empty:
        return pd.DataFrame()
 
    features = df.groupby("ip").agg(
        total_requests    = ("ip", "count"),
        unique_endpoints  = ("endpoint", "nunique"),
        auth_failures     = ("is_auth_fail", "sum"),
        rate_limit_hits   = ("is_rate_limit", "sum"),
        nb_404            = ("is_404", "sum"),
        avg_response_size = ("size", "mean"),
        is_mobile         = ("is_mobile", "mean"),
    ).reset_index()
 
    # Ratios normalisés
    features["auth_fail_ratio"]  = features["auth_failures"]  / features["total_requests"].clip(lower=1)
    features["rate_limit_ratio"] = features["rate_limit_hits"] / features["total_requests"].clip(lower=1)
    features["404_ratio"]        = features["nb_404"]          / features["total_requests"].clip(lower=1)
 
    return features
 
 
def run_clustering(features: pd.DataFrame, n_clusters: int = 4) -> pd.DataFrame:
    """
    Applique K-Means clustering sur les features des IPs.
    Retourne le DataFrame enrichi avec le cluster et le label.
    """
    if features.empty or len(features) < n_clusters:
        print("[!] Pas assez de données pour le clustering.")
        return features
 
    feature_cols = [
        "total_requests", "unique_endpoints", "auth_fail_ratio",
        "rate_limit_ratio", "404_ratio", "avg_response_size",
    ]
 
    X = features[feature_cols].fillna(0).values
 
    # Normalisation
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
 
    # K-Means
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    features = features.copy()
    features["cluster"] = kmeans.fit_predict(X_scaled)
 
    # Score qualité
    if len(features) > n_clusters:
        score = silhouette_score(X_scaled, features["cluster"])
        print(f"[✓] Silhouette Score : {score:.3f} (plus proche de 1 = meilleur)")
 
    # Assignation automatique des labels selon les centroids
    # (cluster avec le plus d'auth_fail_ratio = Attaquant, etc.)
    cluster_stats = features.groupby("cluster").agg(
        avg_requests   = ("total_requests", "mean"),
        avg_auth_fail  = ("auth_fail_ratio", "mean"),
        avg_404        = ("404_ratio", "mean"),
    )
 
    # Trier les clusters par danger croissant (simple heuristique)
    danger_score = (
        cluster_stats["avg_auth_fail"] * 5
        + cluster_stats["avg_404"]     * 3
        + cluster_stats["avg_requests"].rank() * 0.5
    )
    sorted_clusters = danger_score.sort_values().index.tolist()
    label_map = {c: i for i, c in enumerate(sorted_clusters)}
 
    features["cluster_label"] = features["cluster"].map(label_map)
    features["cluster_name"]  = features["cluster_label"].map(
        lambda x: CLUSTER_LABELS.get(x, CLUSTER_LABELS[0])["name"]
    )
    features["cluster_color"] = features["cluster_label"].map(
        lambda x: CLUSTER_LABELS.get(x, CLUSTER_LABELS[0])["color"]
    )
 
    print(f"[✓] Clustering terminé — {n_clusters} groupes identifiés")
    return features
 
 
def find_optimal_k(features: pd.DataFrame, max_k: int = 8) -> int:
    """
    Trouve le K optimal via la méthode du coude (Elbow Method).
    Retourne le K recommandé.
    """
    feature_cols = [
        "total_requests", "unique_endpoints", "auth_fail_ratio",
        "rate_limit_ratio", "404_ratio", "avg_response_size",
    ]
    X = features[feature_cols].fillna(0).values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
 
    inertias = []
    k_range  = range(2, min(max_k + 1, len(features)))
 
    for k in k_range:
        km = KMeans(n_clusters=k, random_state=42, n_init=10)
        km.fit(X_scaled)
        inertias.append(km.inertia_)
 
    # Méthode du coude : trouver le coude
    deltas       = [inertias[i] - inertias[i+1] for i in range(len(inertias)-1)]
    optimal_idx  = deltas.index(max(deltas)) + 1
    optimal_k    = list(k_range)[optimal_idx]
 
    print(f"[✓] K optimal suggéré : {optimal_k}")
    return optimal_k
