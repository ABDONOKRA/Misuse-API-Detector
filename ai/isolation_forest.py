import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai.feature_extractor import extract_features

def run_isolation_forest(contamination=0.3):
    df = extract_features()

    features = ["total_requests", "login_attempts", "error_404",
                "unique_endpoints", "post_requests", "total_bytes"]

    X = df[features].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(contamination=contamination, random_state=42)
    df["anomaly"] = iso.fit_predict(X_scaled)
    df["anomaly_score"] = iso.score_samples(X_scaled)

    # -1 = anomalie, 1 = normal
    df["anomaly_label"] = df["anomaly"].map({1: "✅ Normal", -1: "🚨 Anomalie"})

    return df

if __name__ == "__main__":
    df = run_isolation_forest()
    print(df[["ip", "total_requests", "login_attempts", "unique_endpoints", "anomaly_label", "anomaly_score"]].to_string())
