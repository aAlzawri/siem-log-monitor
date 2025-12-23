# 🛡️ SIEM-Style Log Monitoring & Alerting System

## 📌 Overview
This project simulates a Security Information and Event Management (SIEM) system designed for SOC Analysts. It ingests system logs, detects security threats, generates alerts, and produces incident reports.

## 🧰 Tools & Technologies
- Python
- Regex
- Windows Security Logs / Linux auth logs
- MITRE ATT&CK Framework
- Git & GitHub

## 🔍 Features
- Log parsing and normalization
- Brute-force attack detection
- Suspicious login time detection
- Alert severity classification
- MITRE ATT&CK mapping
- SOC-style incident reporting

## 🗂️ Project Structure
siem-log-monitor/
├── parser/
├── detection/
├── alerts/
├── reports/

## ▶️ How to Run
```bash
python parser/log_parser.py
python detection/detection_rules.py
python incident_report_generator.py

🛡️ SOC Relevance

This project mirrors real SOC workflows, including log ingestion, event correlation, alert triage, and incident response documentation.
