from collections import defaultdict
from datetime import timedelta
from src.parser import parse_line

WINDOW = timedelta(seconds=10)
THRESHOLD = 10

ip_timestamps = defaultdict(list)

with open("/var/log/httpd/access_log") as f:
    for line in f:
        parsed = parse_line(line)
        if parsed:
            ip_timestamps[parsed["ip"]].append(parsed["time"])

for ip, timestamps in ip_timestamps.items():
    timestamps.sort()

    for i in range(len(timestamps)):
        count = 1
        for j in range(i + 1, len(timestamps)):
            if timestamps[j] - timestamps[i] <= WINDOW:
                count += 1
            else:
                break

        if count >= THRESHOLD:
            print(f"[ALERT] Possible flood from {ip}: {count} requests in {WINDOW}")
            break
