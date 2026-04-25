from collections import defaultdict
from .detectors import (
    detect_flood, 
    detect_sqli, 
    detect_bruteforce, 
    detect_sensitive_access, 
    detect_directory_scan, 
    detect_suspicious_user_agents
)
from .parser import parse_line
from .report import generate_report

FILTER_KEYWORDS = {
    "flood": "flood",
    "sqli": "sql injection",
    "brute": "brute force",
    "scan": "directory enumeration",
    "sensitive": "sensitive path",}

def filter_alerts(alerts, filter_type):
    if not filter_type:
        return alerts
    filtered = []

    for alert in alerts:
        text = alert.lower()
        if any (FILTER_KEYWORDS[key] in text for key in filter_type):
            filtered.append(alert)

    return filtered

def analyze_log(file_path : str, output_file=None, filter_type=None):
    ip_timestamps = defaultdict(list)
    events = []

    with open(file_path) as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                ip_timestamps[parsed["ip"]].append(parsed["time"])
                events.append(parsed)
    alerts = []

    alerts.extend(detect_flood(ip_timestamps))
    alerts.extend(detect_sqli(events))
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_sensitive_access(events))
    alerts.extend(detect_directory_scan(events))
    alerts.extend(detect_suspicious_user_agents(events))

    filtered_alerts = filter_alerts(alerts, filter_type)

    print("---- Security Alerts ----")
    for alert in filtered_alerts:
        print(f"[ALERT] {alert}")
    print(f"\nTotal alerts: {len(filtered_alerts)}")

    generate_report(events, filtered_alerts, output_file)