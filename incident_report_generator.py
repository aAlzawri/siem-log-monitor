import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# =========================
# PATHS
# =========================

BASE_DIR = Path(__file__).resolve().parent
ALERTS_FILE = BASE_DIR / "alerts" / "alerts.json"
REPORT_FILE = BASE_DIR / "reports" / "incident_report.md"

# =========================
# LOAD ALERTS
# =========================

def load_alerts():
    with open(ALERTS_FILE, "r") as f:
        return json.load(f)

# =========================
# GROUP INCIDENTS
# =========================

def group_incidents(alerts):
    incidents = defaultdict(list)
    for alert in alerts:
        key = (alert["alert_type"], alert["user"], alert["ip"])
        incidents[key].append(alert)
    return incidents

# =========================
# SEVERITY RANK
# =========================

def severity_rank(level):
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(level, 0)

# =========================
# GENERATE REPORT
# =========================

def generate_report(incidents):
    lines = []
    lines.append("# SOC Incident Report\n")
    lines.append(f"Generated: {datetime.now()}\n")
    lines.append("---\n")

    incident_id = 1

    for (alert_type, user, ip), alerts in incidents.items():
        highest = max(alerts, key=lambda x: severity_rank(x["severity"]))

        lines.append(f"## Incident {incident_id}")
        lines.append(f"- Type: {alert_type}")
        lines.append(f"- User: {user}")
        lines.append(f"- Source IP: {ip}")
        lines.append(f"- Severity: {highest['severity']}")
        lines.append(f"- MITRE ATT&CK: {highest['mitre_technique']}\n")

        lines.append("### Timeline")
        for alert in alerts:
            lines.append(f"- [{alert['timestamp']}] {alert['description']}")

        lines.append("\n### Recommended Actions")
        lines.append("- Reset affected credentials")
        lines.append("- Block or monitor source IP")
        lines.append("- Review authentication logs\n")
        lines.append("---\n")

        incident_id += 1

    return "\n".join(lines)

# =========================
# SAVE REPORT
# =========================

def save_report(content):
    REPORT_FILE.parent.mkdir(exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        f.write(content)

    print(f"[+] Incident report generated → {REPORT_FILE}")

# =========================
# MAIN
# =========================

if __name__ == "__main__":
    alerts = load_alerts()
    incidents = group_incidents(alerts)
    report = generate_report(incidents)
    save_report(report)
