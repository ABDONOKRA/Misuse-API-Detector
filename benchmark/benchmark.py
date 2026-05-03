import subprocess
import re
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai.ai_engine import run_ai_analysis

# =====================
# GROUND TRUTH (labels connus car on contrôle le trafic)
# =====================
GROUND_TRUTH = {
    "::1":               1,  # attaque (brute force curl)
    "127.0.0.1":         1,  # attaque (app émulateur)
    "172.16.0.3":        1,  # attaque simulée Faker
    "192.168.1.50":      1,  # attaque simulée Faker
    "192.168.1.10":      0,  # normal simulé
    "192.168.1.20":      0,  # normal simulé
    "10.0.0.5":          0,  # normal simulé
    "192.168.110.181":   1,  # attaque téléphone réel
    "192.168.110.21":    1,  # attaque téléphone réel
}

def get_fail2ban_banned():
    """Récupère les IPs bannies par Fail2ban"""
    banned = set()
    jails = ["nginx-login-brute", "nginx-spike", "nginx-enum"]
    for jail in jails:
        try:
            result = subprocess.run(
                ["sudo", "fail2ban-client", "status", jail],
                capture_output=True, text=True
            )
            match = re.search(r"Banned IP list:\s+(.*)", result.stdout)
            if match:
                ips = match.group(1).strip().split()
                banned.update(ips)
        except Exception as e:
            print(f"Erreur jail {jail}: {e}")
    return banned

def evaluate_fail2ban(banned_ips, ground_truth):
    """Calcule les métriques de Fail2ban"""
    ips = list(ground_truth.keys())
    y_true = [ground_truth[ip] for ip in ips]
    y_pred = [1 if ip in banned_ips else 0 for ip in ips]

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    return precision, recall, f1, y_true, y_pred

def evaluate_our_system(ground_truth):
    """Calcule les métriques de notre système IA"""
    df = run_ai_analysis()

    ips = list(ground_truth.keys())
    y_true = []
    y_pred = []

    for ip in ips:
        row = df[df["ip"] == ip]
        y_true.append(ground_truth[ip])
        if row.empty:
            y_pred.append(0)
        else:
            label = row["label"].values[0]
            anomaly = row["anomaly_label"].values[0]
            pred = 1 if ("ATTAQUANT" in label or "Anomalie" in anomaly) else 0
            y_pred.append(pred)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    return precision, recall, f1, y_true, y_pred

def run_benchmark():
    print("\n" + "="*60)
    print("  BENCHMARK — Fail2ban vs Notre Système IA")
    print("="*60)

    # Fail2ban
    banned = get_fail2ban_banned()
    print(f"\n[Fail2ban] IPs bannies : {banned if banned else 'Aucune'}")
    f2b_p, f2b_r, f2b_f1, y_true, y_pred_f2b = evaluate_fail2ban(banned, GROUND_TRUTH)

    # Notre système
    ai_p, ai_r, ai_f1, _, y_pred_ai = evaluate_our_system(GROUND_TRUTH)

    # Tableau comparatif
    print("\n" + "-"*60)
    print(f"{'Métrique':<20} {'Fail2ban':>15} {'Notre Système':>15}")
    print("-"*60)
    print(f"{'Precision':<20} {f2b_p:>15.3f} {ai_p:>15.3f}")
    print(f"{'Recall':<20} {f2b_r:>15.3f} {ai_r:>15.3f}")
    print(f"{'F1-Score':<20} {f2b_f1:>15.3f} {ai_f1:>15.3f}")
    print("-"*60)

    # Détail par IP
    print("\n[Détail par IP]")
    print(f"{'IP':<20} {'Ground Truth':>15} {'Fail2ban':>10} {'Notre IA':>10}")
    print("-"*60)
    ips = list(GROUND_TRUTH.keys())
    for i, ip in enumerate(ips):
        gt = "ATTAQUE" if GROUND_TRUTH[ip] == 1 else "NORMAL"
        f2b = "DÉTECTÉ" if y_pred_f2b[i] == 1 else "MANQUÉ"
        ai = "DÉTECTÉ" if y_pred_ai[i] == 1 else "MANQUÉ"
        print(f"{ip:<20} {gt:>15} {f2b:>10} {ai:>10}")

    print("\n✅ Benchmark terminé !")

if __name__ == "__main__":
    run_benchmark()
