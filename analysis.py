import pandas as pd
from scapy.layers.inet import IP, TCP, UDP, ICMP
from alerting import raise_alert
import joblib
import numpy as np
import time
from collections import defaultdict

# Load trained ML model
model = joblib.load("ids_model.pkl")

# ✅ Match exactly with trained features
feature_names = [
    "pkt_size", "is_tcp", "is_udp", "is_icmp", "ttl",
    "has_payload", "proto_count"
]

# Track last alert time per IP to avoid spamming
last_alert_time = defaultdict(lambda: 0)
alert_interval = 60  # Alert only once per IP per 60 sec

# ✅ Updated feature extractor to include all trained features
def extract_features(packet):
    pkt_size = len(packet)
    is_tcp = int(TCP in packet)
    is_udp = int(UDP in packet)
    is_icmp = int(ICMP in packet)
    ttl = packet[IP].ttl if IP in packet else 0

    has_payload = int(pkt_size > 0)
    proto_count = is_tcp + is_udp + is_icmp

    return [
        pkt_size, is_tcp, is_udp, is_icmp, ttl,
        has_payload, proto_count
    ]

def analyze_packet(packet):
    if IP in packet:
        try:
            raw_features = extract_features(packet)
            df_features = pd.DataFrame([raw_features], columns=feature_names)

            prediction = model.predict(df_features)
            print(f"[DEBUG] Features: {raw_features}, Prediction: {prediction}")

            src_ip = packet[IP].src
            now = time.time()

            if (prediction[0] == "attack" or prediction[0] == 1) and (now - last_alert_time[src_ip] > alert_interval):
                last_alert_time[src_ip] = now
                raise_alert(f"ML-Detected Threat from {src_ip}")

        except Exception as e:
            print(f"[!] ML prediction error: {e}")
