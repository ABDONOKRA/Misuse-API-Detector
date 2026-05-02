import streamlit as st
import pandas as pd
import re
import time
from collections import defaultdict
from datetime import datetime
import plotly.express as px

LOG_FILE = "/var/log/nginx/access.log"

st.set_page_config(page_title="Mobile API Misuse Detector", layout="wide")
st.title("🔐 Mobile API Misuse Detector — Dashboard V2")

BRUTE_FORCE_THRESHOLD = 10
SPIKE_THRESHOLD = 20
ENUM_THRESHOLD = 5

def parse_log(line):
    pattern = r'(\S+) - - \[(.+?)\] "(\S+) (\S+) \S+" (\d+) (\d+)'
    match = re.match(pattern, line)
    if match:
        return {
            "ip": match.group(1),
            "time": match.group(2),
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
        st.error("Permission refusée — lance avec sudo ou change les permissions du log")
    return pd.DataFrame(entries)

def detect_alerts(df):
    alerts = []
    if df.empty:
        return alerts
    ip_counts = df[df["path"].str.contains("/login", na=False)].groupby("ip").size()
    for ip, count in ip_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append(f"🔴 BRUTE FORCE — IP: {ip} ({count} tentatives login)")
    ip_total = df.groupby("ip").size()
    for ip, count in ip_total.items():
        if count >= SPIKE_THRESHOLD:
            alerts.append(f"🟠 SPIKE — IP: {ip} ({count} requêtes)")
    ip_endpoints = df.groupby("ip")["path"].nunique()
    for ip, count in ip_endpoints.items():
        if count >= ENUM_THRESHOLD:
            alerts.append(f"🟡 ÉNUMÉRATION — IP: {ip} ({count} endpoints différents)")
    return alerts

# Layout
col1, col2 = st.columns(2)

placeholder = st.empty()

while True:
    df = load_logs()
    alerts = detect_alerts(df)

    with placeholder.container():
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Requêtes par endpoint")
            if not df.empty:
                fig = px.bar(df["path"].value_counts().reset_index(),
                             x="path", y="count", color="path")
                st.plotly_chart(fig, use_container_width=True, key=f"bar_{time.time()}")

        with col2:
            st.subheader("🌐 Requêtes par IP")
            if not df.empty:
                fig2 = px.pie(df, names="ip", title="Distribution par IP")
                st.plotly_chart(fig2, use_container_width=True, key=f"pie_{time.time()}")

        st.subheader("🚨 Alertes détectées")
        if alerts:
            for alert in alerts:
                st.error(alert)
        else:
            st.success("✅ Aucune anomalie détectée")

        st.subheader("📋 Derniers logs")
        if not df.empty:
            st.dataframe(df.tail(20), use_container_width=True)

        st.caption(f"Dernière mise à jour : {datetime.now().strftime('%H:%M:%S')}")

    time.sleep(5)
