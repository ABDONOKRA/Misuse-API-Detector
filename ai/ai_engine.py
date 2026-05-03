import pandas as pd
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai.kmeans_clustering import run_kmeans
from ai.isolation_forest import run_isolation_forest

def run_ai_analysis():
    df_kmeans, _, _ = run_kmeans()
    df_iso = run_isolation_forest()

    df = df_kmeans.merge(
        df_iso[["ip", "anomaly_label", "anomaly_score"]],
        on="ip"
    )

    # Recommandations
    def recommend(row):
        if row["anomaly_label"] == "🚨 Anomalie" and row["label"] == "🔴 ATTAQUANT":
            return "🔒 Bloquer IP + CAPTCHA + Rate-limit"
        elif row["anomaly_label"] == "🚨 Anomalie":
            return "⚠️ Rate-limit + Surveillance renforcée"
        elif row["label"] == "🟠 SUSPECT":
            return "👁️ Surveillance + CAPTCHA adaptatif"
        else:
            return "✅ Aucune action requise"

    df["recommendation"] = df.apply(recommend, axis=1)
    return df

if __name__ == "__main__":
    df = run_ai_analysis()
    print(df[["ip", "label", "anomaly_label", "recommendation"]].to_string())
