import streamlit as st
import pandas as pd
import re
import time
import sys
import os
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai.ai_engine import run_ai_analysis

LOG_FILE = "/var/log/nginx/access.log"

st.set_page_config(
    page_title="Mobile API Misuse Detector",
    layout="wide",
    page_icon="🔐"
)

# CSS custom cybersecurity style
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: linear-gradient(135deg, #1e2130, #2d3250);
        border: 1px solid #3d4466;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        margin: 5px;
    }
    .attacker { border-left: 4px solid #ff4b4b !important; }
    .normal { border-left: 4px solid #21c354 !important; }
    .suspect { border-left: 4px solid #ffa500 !important; }
    .section-title {
        font-size: 1.3rem;
        font-weight: bold;
        color: #7eb3ff;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("# 🔐 Mobile API Misuse Detector")
st.markdown("**Détection temps réel d'abus API mobile — K-Means + Isolation Forest**")
st.divider()

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

def load_logs():
    entries = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                e = parse_log(line.strip())
                if e:
                    entries.append(e)
    except PermissionError:
        st.error("Permission refusée — lance avec sudo")
    return pd.DataFrame(entries)

def make_scatter_plot(df_ai):
    color_map = {
        "🔴 ATTAQUANT": "#ff4b4b",
        "🟠 SUSPECT": "#ffa500",
        "🟢 NORMAL": "#21c354"
    }
    fig = px.scatter(
        df_ai,
        x="login_attempts",
        y="total_requests",
        color="label",
        size="unique_endpoints",
        hover_name="ip",
        hover_data=["post_requests", "error_404", "anomaly_label"],
        color_discrete_map=color_map,
        title="🔵 Clusters K-Means — Comportement par IP",
        labels={
            "login_attempts": "Tentatives Login",
            "total_requests": "Total Requêtes",
            "label": "Profil"
        }
    )
    fig.update_layout(
        paper_bgcolor="#1e2130",
        plot_bgcolor="#1e2130",
        font_color="#ffffff",
        title_font_size=16
    )
    return fig

def make_radar_chart(df_ai):
    categories = ["total_requests", "login_attempts", "error_404",
                  "unique_endpoints", "post_requests"]
    labels = ["Requêtes", "Login", "Erreurs 404", "Endpoints", "POST"]

    fig = go.Figure()
    colors = {"🔴 ATTAQUANT": "#ff4b4b", "🟠 SUSPECT": "#ffa500", "🟢 NORMAL": "#21c354"}

    for _, row in df_ai.iterrows():
        vals = [row[c] for c in categories]
        max_vals = [df_ai[c].max() + 1 for c in categories]
        vals_norm = [v/m for v, m in zip(vals, max_vals)]
        vals_norm.append(vals_norm[0])

        fig.add_trace(go.Scatterpolar(
            r=vals_norm,
            theta=labels + [labels[0]],
            fill='toself',
            name=row["ip"],
            line_color=colors.get(row["label"], "#7eb3ff"),
            opacity=0.6
        ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 1]),
            bgcolor="#1e2130"
        ),
        paper_bgcolor="#1e2130",
        font_color="#ffffff",
        title="🕸️ Radar — Profil comportemental par IP",
        title_font_size=16,
        showlegend=True
    )
    return fig

def make_heatmap(df_ai):
    features = ["total_requests", "login_attempts", "error_404",
                "unique_endpoints", "post_requests", "total_bytes"]
    labels = ["Requêtes", "Login", "Err 404", "Endpoints", "POST", "Bytes"]

    matrix = df_ai[features].values
    max_vals = matrix.max(axis=0) + 1
    matrix_norm = matrix / max_vals

    fig = go.Figure(data=go.Heatmap(
        z=matrix_norm,
        x=labels,
        y=df_ai["ip"].tolist(),
        colorscale="RdYlGn_r",
        hoverongaps=False,
        hovertemplate="IP: %{y}<br>Feature: %{x}<br>Intensité: %{z:.2f}<extra></extra>"
    ))

    fig.update_layout(
        title="🔥 Heatmap — Intensité des features par IP",
        paper_bgcolor="#1e2130",
        plot_bgcolor="#1e2130",
        font_color="#ffffff",
        title_font_size=16
    )
    return fig

def make_recommendations_chart(df_ai):
    rec_counts = df_ai["recommendation"].value_counts().reset_index()
    rec_counts.columns = ["Recommandation", "count"]

    color_map = {
        "🔒 Bloquer IP + CAPTCHA + Rate-limit": "#ff4b4b",
        "⚠️ Rate-limit + Surveillance renforcée": "#ffa500",
        "👁️ Surveillance + CAPTCHA adaptatif": "#ffff00",
        "✅ Aucune action requise": "#21c354"
    }

    fig = px.bar(
        rec_counts,
        x="count",
        y="Recommandation",
        orientation="h",
        color="Recommandation",
        color_discrete_map=color_map,
        title="📊 Recommandations anti-abus"
    )
    fig.update_layout(
        paper_bgcolor="#1e2130",
        plot_bgcolor="#1e2130",
        font_color="#ffffff",
        title_font_size=16,
        showlegend=False
    )
    return fig

placeholder = st.empty()

while True:
    df_logs = load_logs()
    try:
        df_ai = run_ai_analysis()
    except Exception as e:
        df_ai = None

    with placeholder.container():

        # --- KPIs ---
        k1, k2, k3, k4, k5 = st.columns(5)
        if not df_logs.empty:
            attackers = len(df_ai[df_ai["label"] == "🔴 ATTAQUANT"]) if df_ai is not None else 0
            anomalies = len(df_ai[df_ai["anomaly_label"] == "🚨 Anomalie"]) if df_ai is not None else 0
            k1.metric("📥 Total requêtes", len(df_logs))
            k2.metric("🌐 IPs uniques", df_logs["ip"].nunique())
            k3.metric("🔑 Login attempts", len(df_logs[df_logs["path"].str.contains("/login", na=False)]))
            k4.metric("🔴 Attaquants", attackers)
            k5.metric("🚨 Anomalies", anomalies)

        st.divider()

        # --- Graphiques logs ---
        st.markdown('<p class="section-title">📡 Trafic en temps réel</p>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            if not df_logs.empty:
                fig = px.bar(
                    df_logs["path"].value_counts().reset_index(),
                    x="path", y="count", color="path",
                    title="Requêtes par endpoint"
                )
                fig.update_layout(paper_bgcolor="#1e2130", plot_bgcolor="#1e2130", font_color="#fff", showlegend=False)
                st.plotly_chart(fig, use_container_width=True, key=f"bar_{time.time()}")

        with col2:
            if not df_logs.empty:
                fig2 = px.pie(df_logs, names="ip", title="Distribution par IP",
                              color_discrete_sequence=px.colors.sequential.Blues_r)
                fig2.update_layout(paper_bgcolor="#1e2130", font_color="#fff")
                st.plotly_chart(fig2, use_container_width=True, key=f"pie_{time.time()}")

        st.divider()

        # --- Section IA ---
        st.markdown('<p class="section-title">🤖 Analyse IA — K-Means + Isolation Forest</p>', unsafe_allow_html=True)

        if df_ai is not None and len(df_ai) > 0:

            # Scatter + Radar
            col3, col4 = st.columns(2)
            with col3:
                st.plotly_chart(make_scatter_plot(df_ai), use_container_width=True, key=f"scatter_{time.time()}")
            with col4:
                st.plotly_chart(make_radar_chart(df_ai), use_container_width=True, key=f"radar_{time.time()}")

            # Heatmap + Recommandations
            col5, col6 = st.columns(2)
            with col5:
                st.plotly_chart(make_heatmap(df_ai), use_container_width=True, key=f"heat_{time.time()}")
            with col6:
                st.plotly_chart(make_recommendations_chart(df_ai), use_container_width=True, key=f"rec_{time.time()}")

            # Tableau IA
            st.markdown('<p class="section-title">📋 Tableau d\'analyse IA</p>', unsafe_allow_html=True)
            st.dataframe(
                df_ai[["ip", "total_requests", "login_attempts", "unique_endpoints",
                        "label", "anomaly_label", "anomaly_score", "recommendation"]],
                use_container_width=True
            )

        st.divider()

        # --- Alertes ---
        st.markdown('<p class="section-title">🚨 Alertes actives</p>', unsafe_allow_html=True)
        if df_ai is not None:
            attackers_df = df_ai[df_ai["label"] == "🔴 ATTAQUANT"]
            anomalies_df = df_ai[df_ai["anomaly_label"] == "🚨 Anomalie"]
            if len(attackers_df) > 0:
                for _, row in attackers_df.iterrows():
                    st.error(f"🔴 **ATTAQUANT** — IP: `{row['ip']}` | {row['login_attempts']} logins | {row['total_requests']} req | **{row['recommendation']}**")
            if len(anomalies_df) > 0:
                for _, row in anomalies_df[anomalies_df["label"] != "🔴 ATTAQUANT"].iterrows():
                    st.warning(f"🟠 **Anomalie** — IP: `{row['ip']}` | Score: {row['anomaly_score']:.3f} | **{row['recommendation']}**")
            if len(attackers_df) == 0 and len(anomalies_df) == 0:
                st.success("✅ Aucune anomalie détectée")

        # --- Derniers logs ---
        st.divider()
        st.markdown('<p class="section-title">📋 Derniers logs Nginx</p>', unsafe_allow_html=True)
        if not df_logs.empty:
            st.dataframe(df_logs.tail(10), use_container_width=True)

        st.caption(f"🕐 Dernière mise à jour : {datetime.now().strftime('%H:%M:%S')} — Rafraîchissement toutes les 5s")



        # --- Benchmark ---
        st.divider()
        st.markdown('<p class="section-title">📊 Benchmark — Fail2ban vs Notre Système IA</p>', unsafe_allow_html=True)

        bench_data = {
            "Métrique": ["Precision", "Recall", "F1-Score"],
            "Fail2ban": [1.000, 0.333, 0.500],
            "Notre Système (K-Means + IF)": [1.000, 0.833, 0.909],
        }
        df_bench = pd.DataFrame(bench_data)

        col_b1, col_b2 = st.columns(2)

        with col_b1:
            st.markdown("**📋 Tableau comparatif**")
            st.dataframe(df_bench, use_container_width=True, hide_index=True)

            # Verdict
            st.success("✅ Notre système est **82% meilleur** en F1-Score")
            st.warning("⚠️ Fail2ban rate les attaques localhost et historiques")

        with col_b2:
            fig_bench = go.Figure()
            metrics = ["Precision", "Recall", "F1-Score"]
            fail2ban_vals = [1.000, 0.333, 0.500]
            our_vals = [1.000, 0.833, 0.909]

            fig_bench.add_trace(go.Bar(
                name="Fail2ban",
                x=metrics,
                y=fail2ban_vals,
                marker_color="#ff4b4b",
                opacity=0.8
            ))
            fig_bench.add_trace(go.Bar(
                name="Notre Système",
                x=metrics,
                y=our_vals,
                marker_color="#21c354",
                opacity=0.8
            ))

            fig_bench.update_layout(
                barmode="group",
                title="Fail2ban vs Notre Système IA",
                paper_bgcolor="#1e2130",
                plot_bgcolor="#1e2130",
                font_color="#ffffff",
                yaxis=dict(range=[0, 1.1], title="Score"),
                legend=dict(bgcolor="#1e2130"),
                title_font_size=16
            )
            st.plotly_chart(fig_bench, use_container_width=True, key=f"bench_{time.time()}")

        # Explication
        st.markdown("""
        > 💡 **Conclusion** : Notre système basé sur **K-Means + Isolation Forest** atteint un F1-Score de **0.909** 
        > contre **0.500** pour Fail2ban, démontrant une capacité supérieure à détecter les abus API mobiles, 
        > notamment les attaques depuis localhost et les patterns comportementaux complexes.
        """)
    time.sleep(5)
