import time

def raise_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[ALERT] [{timestamp}] {message}"
    print(log_line)
    with open("alerts.log", "a", encoding="utf-8") as f:
        f.write(log_line + "\n")