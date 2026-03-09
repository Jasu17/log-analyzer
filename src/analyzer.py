from collections import defaultdict
from .detectors import detect_flood, detect_sqli, detect_bruteforce, detect_sensitive_access, detect_directory_scan
from .parser import parse_line

def analyze_log(file_path : str):
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

    print("---- Security Alerts ----")
    for alert in alerts:
        print(f"[ALERT] {alert}")
    print(f"\nTotal alerts: {len(alerts)}")