import streamlit as st
import pandas as pd
import os
import time
from sklearn.metrics import classification_report
import joblib
from PIL import Image
import json

# configuration
st.set_page_config(page_title="📊 Intrusion Detection Dashboard", layout="wide")
st.title("🔐 Intrusion Detection System (IDS) Dashboard")

alert_log = "alerts.log"
model_path = "ids_model.pkl"

if not os.path.exists(alert_log):
    with open(alert_log, "w") as f:
        f.write("")

# loading the data
with open(alert_log, "r") as file:
    lines = file.readlines()
    recent_alerts = [line for line in lines if "[ALERT]" in line or "]" in line]

df_alerts = pd.DataFrame(recent_alerts, columns=["raw"])
if not df_alerts.empty:
    df_alerts["timestamp"] = df_alerts["raw"].str.extract(r"\[(.*?)\]")
    df_alerts["source_ip"] = df_alerts["raw"].str.extract(r"from ([\d\.]+)")
    df_alerts["type"] = df_alerts["raw"].apply(lambda x: "ML Detected" if "ML-Detected" in x else "Rule-Based")

# recent alerts
st.subheader("🚨 Recent Alerts")
if not df_alerts.empty:
    for alert in reversed(df_alerts["raw"].tail(10).tolist()):
        if "ML-Detected" in alert:
            st.error(alert.strip())
        else:
            st.warning(alert.strip())
else:
    st.info("✅ No alerts to display yet.")


# 📈 ATTACK TREND (TIME SERIES)
st.subheader("📈 Alerts Per Minute")
df_alerts["timestamp"] = df_alerts["raw"].str.extract(r"\[ALERT\] \[(.*?)\]")
if df_alerts["timestamp"].isna().any():
    alt_timestamps = df_alerts["raw"].str.extract(r"\[ALERT\] (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) -")
    df_alerts["timestamp"] = df_alerts["timestamp"].fillna(alt_timestamps[0])
df_alerts["time"] = pd.to_datetime(df_alerts["timestamp"], errors='coerce', format='%Y-%m-%d %H:%M:%S')
df_valid_times = df_alerts.dropna(subset=["time"]).copy()
if not df_valid_times.empty:
    df_valid_times.set_index("time", inplace=True)
    trend = df_valid_times.resample("1min").size()
    st.line_chart(trend)
else:
    st.info("📬 Not enough valid timestamps to show trend chart. Check the format in alerts.log.")

# 🛁 Live Detection Stats (Dynamic)
st.subheader("Live Detection Stats")

# Read stats from stats.json
try:
    with open("stats.json", "r") as f:
        stats = json.load(f)
except FileNotFoundError:
    # If stats.json doesn't exist, initialize with zeros
    stats = {
        "total_packets": 0,
        "detected_attacks": 0,
        "normal_packets": 0
    }

st.metric("Total Packets Seen", stats["total_packets"])
st.metric("Detected Attacks", stats["detected_attacks"])
st.metric("Benign Packets", stats["normal_packets"])

if stats["total_packets"] > 0:
    detection_rate = (stats["detected_attacks"] / stats["total_packets"]) * 100
    st.metric("Live Detection Rate", f"{detection_rate:.2f}%")
else:
    st.metric("Live Detection Rate", "0.00%")
