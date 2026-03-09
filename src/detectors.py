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

def detect_bruteforce(logs, threshold=10, window=30):

    attempts = defaultdict(list)
    alerts = []

    for log in logs:
        ip = log["ip"]
        path = log["path"]
        method = log["method"]
        time = log["time"]

        if method == "POST" and "login" in path:
            attempts[ip].append(time)

    for ip, times in attempts.items():
        times.sort()

        start = 0

        for end in range(len(times)):
            while times[end] - times[start] > timedelta(seconds=window):
                start += 1

            count = end - start + 1

            if count >= threshold:
                alerts.append(
                    f"Possible brute force attack from {ip}: {count} login attempts in {window}s"
                )
                break

    return alerts

SENSITIVE_PATHS = [
    "/.env",
    "/.git",
    "/.git/config",
    "/phpmyadmin",
    "/wp-login.php",
    "/wp-admin",
    "/config.php",
    "/backup",
    "/backup.zip",
    "/db.sql"
]

def detect_sensitive_access(events):
    attempts = defaultdict(int)
    status_map = {}
    alerts = []

    for event in events:
        path = event["path"]
        ip = event["ip"]
        status = event["status"]

        for sensitive in SENSITIVE_PATHS:
            if sensitive in path:
                key = (ip, sensitive)
                attempts[key] += 1
                status_map[key] = status

    for (ip, path), count in attempts.items():
        status = status_map [(ip, path)]
        alerts.append(
            f"Sensitive path scan from {ip}: {path} requested {count} times (status {status})"
            )

    return alerts

def detect_directory_scan(events, threshold=20, window=30):
    
    attempts = defaultdict(list)
    alerts = []

    for event in events:

        ip = event["ip"]
        status = event["status"]
        time = event["time"]

        if status == 404:
            attempts[ip].append(time)

    for ip, times in attempts.items():

        times.sort()
        start = 0

        for end in range(len(times)):

            while times[end] - times[start] > timedelta(seconds=window):
                start += 1

            count = end - start +1

            if count >= threshold:

                alerts.append(
                    f"Possible directory enumeration from {ip}: {count} 404 responses in {window}"                    
                )
                break

    return alerts

SUSPICIOUS_AGENTS = [
    "sqlmap",
    "nikto",
    "gobuster",
    "dirsearch",
    "ffuf",
    "wpscan",
    "curl",
    "wget",
    "python-requests"
]

def detect_suspicious_user_agents(events):

    alerts = []

    for event in events:

        ip = event["ip"]
        ua = event["user_agent"].lower()

        for agent in SUSPICIOUS_AGENTS:
            if agent in ua:
                alerts.append(
                    f"Suspicious user-agent detected from {ip}: {event['user_agent']}"
                )
                break
    return alerts