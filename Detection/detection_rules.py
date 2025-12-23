import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# =========================
# PATHS
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
EVENTS_FILE = BASE_DIR / "parsed_events.json"
ALERTS_FILE = BASE_DIR / "alerts" / "alerts.json"

# =========================
# CONFIG
# =========================

FAILED_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
SUSPICIOUS_HOURS = range(0, 5)

# =========================
# LOAD EVENTS
# =========================

def load_events():
    with open(EVENTS_FILE, "r") as f:
        return json.load(f)

# =========================
# DETECTIONS
# =========================

def detect_brute_force(events):
    alerts = []
    attempts = defaultdict(list)

    for event in events:
        if event["event_type"] == "FAILED_LOGIN":
            key = (event["ip"], event["user"])
            timestamp = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
            attempts[key].append(timestamp)

    for (ip, user), times in attempts.items():
        times.sort()
        for i in range(len(times)):
            window = times[i:i + FAILED_THRESHOLD]
            if len(window) < FAILED_THRESHOLD:
                continue

            if window[-1] - window[0] <= timedelta(minutes=TIME_WINDOW_MINUTES):
                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "description": "Brute force attack detected",
                    "user": user,
                    "ip": ip,
                    "mitre_technique": "T1110",
                    "timestamp": window[-1].strftime("%Y-%m-%d %H:%M:%S")
                })
                break

    return alerts

def detect_suspicious_login(events):
    alerts = []

    for event in events:
        if event["event_type"] == "SUCCESS_LOGIN":
            ts = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
            if ts.hour in SUSPICIOUS_HOURS:
                alerts.append({
                    "alert_type": "SUSPICIOUS_LOGIN_TIME",
                    "severity": "MEDIUM",
                    "description": "Login occurred during suspicious hours",
                    "user": event["user"],
                    "ip": event["ip"],
                    "mitre_technique": "T1078",
                    "timestamp": event["timestamp"]
                })

    return alerts

# =========================
# RUN ALL RULES
# =========================

def run_detection(events):
    alerts = []
    alerts.extend(detect_suspicious_login(events))
    alerts.extend(detect_brute_force(events))
    return alerts

# =========================
# SAVE ALERTS
# =========================

def save_alerts(alerts):
    ALERTS_FILE.parent.mkdir(exist_ok=True)
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"[+] {len(alerts)} alerts generated → {ALERTS_FILE}")

# =========================
# MAIN
# =========================

if __name__ == "__main__":
    events = load_events()
    alerts = run_detection(events)
    save_alerts(alerts)
