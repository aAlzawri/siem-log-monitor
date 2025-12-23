import re
import json
from datetime import datetime
from pathlib import Path

# =========================
# PATHS
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "sample_security_logs.txt"
OUTPUT_FILE = BASE_DIR / "parsed_events.json"

# =========================
# REGEX PATTERNS
# =========================

FAILED_EVENT = re.compile(r"4625")
SUCCESS_EVENT = re.compile(r"4624")
IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
USER_PATTERN = re.compile(r"Account Name:\s*(\w+)")

# =========================
# PARSER
# =========================

def parse_logs():
    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            event = {}

            if FAILED_EVENT.search(line):
                event["event_type"] = "FAILED_LOGIN"
            elif SUCCESS_EVENT.search(line):
                event["event_type"] = "SUCCESS_LOGIN"
            else:
                continue

            ip_match = IP_PATTERN.search(line)
            user_match = USER_PATTERN.search(line)

            event["ip"] = ip_match.group(1) if ip_match else "UNKNOWN"
            event["user"] = user_match.group(1) if user_match else "UNKNOWN"
            event["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            events.append(event)

    return events

# =========================
# SAVE OUTPUT
# =========================

def save_events(events):
    with open(OUTPUT_FILE, "w") as f:
        json.dump(events, f, indent=4)

    print(f"[+] Parsed {len(events)} events → {OUTPUT_FILE}")

# =========================
# MAIN
# =========================

if __name__ == "__main__":
    parsed_events = parse_logs()
    save_events(parsed_events)
