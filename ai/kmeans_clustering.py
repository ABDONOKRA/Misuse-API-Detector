import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai.feature_extractor import extract_features

def run_kmeans(n_clusters=3):
    df = extract_features()

    if len(df) < n_clusters:
        n_clusters = max(2, len(df))

    features = ["total_requests", "login_attempts", "error_404",
                "unique_endpoints", "post_requests", "total_bytes"]

    X = df[features].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    df["cluster"] = kmeans.fit_predict(X_scaled)

    # Labelliser les clusters
    cluster_labels = {}
    for c in range(n_clusters):
        cluster_df = df[df["cluster"] == c]
        avg_login = cluster_df["login_attempts"].mean()
        avg_requests = cluster_df["total_requests"].mean()
        avg_endpoints = cluster_df["unique_endpoints"].mean()

        if avg_login > 20:
            cluster_labels[c] = "🔴 ATTAQUANT"
        elif avg_requests > 50 or avg_endpoints > 5:
            cluster_labels[c] = "🟠 SUSPECT"
        else:
            cluster_labels[c] = "🟢 NORMAL"

    df["label"] = df["cluster"].map(cluster_labels)

    return df, kmeans, scaler

if __name__ == "__main__":
    df, _, _ = run_kmeans()
    print(df[["ip", "total_requests", "login_attempts", "unique_endpoints", "cluster", "label"]].to_string())
