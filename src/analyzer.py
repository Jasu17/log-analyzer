from collections import defaultdict
from .detectors import detect_flood
from .parser import parse_line

def analyze_log(file_path : str):
    ip_timestamps = defaultdict(list)

    with open(file_path) as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                ip_timestamps[parsed["ip"]].append(parsed["time"])
    alerts = []

    alerts.extend(detect_flood(ip_timestamps))

    for alert in alerts:
        print(f"[ALERT] {alert}")