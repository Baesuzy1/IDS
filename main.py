# === main.py ===
import time
import pandas as pd
import joblib
import json
from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict

stats = {
    "total_packets": 0,
    "detected_attacks": 0,
    "normal_packets": 0
}

# Buffer for alerts to reduce file I/O
alert_buffer = []
ALERT_BUFFER_SIZE = 10  # Write to file after 10 alerts

# === Load trained ML model and scaler (if available) ===
try:
    model = joblib.load("ids_model.pkl")
    print("[INFO] Model loaded successfully")
except Exception as e:
    print(f"[ERROR] Failed to load model: {e}")
    exit(1)

try:
    scaler = joblib.load("scaler.pkl")
    print("[INFO] Scaler loaded successfully")
except Exception as e:
    print(f"[INFO] Scaler not found, proceeding without scaling: {e}")

# === Updated feature list (MUST match training) ===
feature_names = [
    "pkt_size", "is_tcp", "is_udp", "is_icmp", "ttl",
    "has_payload", "proto_count"
]

# === Track last alert times per IP to prevent spam ===
alert_interval = 10  # Reduced to 10 seconds for testing (adjust as needed)
last_alert_time = defaultdict(lambda: 0)

# === Alert function ===
def raise_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alert_message = f"[ALERT] [{timestamp}] {message}"
    print(alert_message)  # Print to console immediately
    alert_buffer.append(alert_message)

    # Write to file when buffer is full
    if len(alert_buffer) >= ALERT_BUFFER_SIZE:
        try:
            with open("alerts.log", "a") as f:
                f.write("\n".join(alert_buffer) + "\n")
            alert_buffer.clear()  # Clear buffer after writing
        except Exception as e:
            print(f"[ERROR] Failed to write to alerts.log: {e}")

# === Save stats to a file ===
def save_stats():
    try:
        with open("stats.json", "w") as f:
            json.dump(stats, f)
    except Exception as e:
        print(f"[ERROR] Failed to write to stats.json: {e}")

# === Feature extraction from packet ===
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

# === Analyze individual packet ===
def analyze_packet(packet):
    try:
        # Only print packet summary for every 100th packet or when an attack is detected
        if stats["total_packets"] % 100 == 0 or (IP in packet and model.predict(scaler.transform(pd.DataFrame([extract_features(packet)], columns=feature_names)) if 'scaler' in globals() else pd.DataFrame([extract_features(packet)], columns=feature_names)))[0] == 1:
            print(f"[DEBUG] Packet received: {packet.summary()}")

        if IP in packet:
            stats["total_packets"] += 1

            raw_features = extract_features(packet)
            df_features = pd.DataFrame([raw_features], columns=feature_names)

            # Scale features before prediction (if scaler is loaded)
            scaled_features = scaler.transform(df_features) if 'scaler' in globals() else df_features

            prediction = model.predict(scaled_features)
            src_ip = packet[IP].src
            now = time.time()

            # Handle both numeric and string predictions
            label_map = {0: "normal", 1: "attack"}
            predicted_label = label_map.get(prediction[0], prediction[0])

            if predicted_label == "attack":
                print(f"[DEBUG] Features extracted: {raw_features}")
                print(f"[DEBUG] Model prediction for packet from {src_ip}: {prediction[0]}")

                stats["detected_attacks"] += 1
                if now - last_alert_time[src_ip] > alert_interval:
                    last_alert_time[src_ip] = now
                    print(f"[ATTACK DETECTED] From {src_ip} | Features: {raw_features}")
                    raise_alert(f"ML-Detected Threat from {src_ip}")
            else:
                stats["normal_packets"] += 1

            # Save stats after each packet
            save_stats()

        else:
            if stats["total_packets"] % 100 == 0:
                print(f"[DEBUG] Non-IP packet received: {packet.summary()}")

    except Exception as e:
        print(f"[!] ML prediction error: {e}")

# === Flush remaining alerts on script exit ===
import atexit

@atexit.register
def flush_alerts():
    if alert_buffer:
        try:
            with open("alerts.log", "a") as f:
                f.write("\n".join(alert_buffer) + "\n")
            print("[INFO] Flushed remaining alerts to alerts.log")
        except Exception as e:
            print(f"[ERROR] Failed to flush alerts.log: {e}")

# === Sniffing packets ===
def main():
    print("[INFO] Available network interfaces:")
    for iface in get_if_list():
        print(f" - {iface}")
    
    interface = None  # Replace with your interface if needed, e.g., "Wi-Fi"
    print(f"[INFO] IDS is running and sniffing traffic on interface: {interface or 'default'}...")
    sniff(prn=analyze_packet, store=0, iface=interface, filter="ip")

if __name__ == "__main__":
    main()