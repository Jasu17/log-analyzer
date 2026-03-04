from datetime import timedelta
import re
from urllib.parse import unquote_plus
from collections import defaultdict

WINDOW = timedelta(seconds=10)
THRESHOLD = 10

def detect_flood(ip_timestamps: dict):
    alerts = []

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
                alerts.append(
                    f"Possible flood from {ip}: {count} requests in {WINDOW}"
                )
                break

    return alerts

SQLI_PATTERN = re.compile(
    r"(union|select|--|or\s+\d=\d)",
    re.IGNORECASE
)

def detect_sqli(events: list):

    grouped = defaultdict(int)

    for event in events:
        decoded_path = unquote_plus(event["path"])

        if SQLI_PATTERN.search(decoded_path):
            key = (event["ip"], decoded_path)
            grouped[key] +=1
    alerts = []

    for (ip, path), count in grouped.items():
        alerts.append(
            f"Possible SQL injection attempt from {ip} on {path} ({count} times)"
        )


    return alerts