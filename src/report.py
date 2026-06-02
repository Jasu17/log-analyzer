from collections import Counter
import re
import json
from datetime import datetime

ALERT_TYPES = [
    ("flood",      "flood",                "Flood"),
    ("sqli",       "sql injection",        "SQLi"),
    ("brute",      "brute force",          "Brute force"),
    ("scan",       "directory enumeration","Directory scan"),
    ("sensitive",  "sensitive path",       "Sensitive path"),
    ("user-agent", "user-agent",           "User-agent"),
]

RISK_WEIGHTS = {
    "flood":1,
    "sqli":3,
    "brute":3,
    "scan":2,
    "sensitive":2,
    "user-agent":1
}
def classify_alert(alert: str) -> tuple[str, str] | None:
    text = alert.lower()
    for key, keyword, label in ALERT_TYPES:
        if keyword in text:
            return key, label
    return None

def extract_ip(alert: str):
    match = re.search(r'from ([0-9a-fA-F\.:]+)', alert)
    if not match:
        return "unknown"
    
    return match.group(1).rstrip(":")

def _serialize_alert(alerts: list[str]) -> list[dict]:
    serialized = []
    for alert in alerts:
        classification = classify_alert(alert)
        serialized.append({
            "type" : classification[0] if classification else "unknown",
            "ip": extract_ip(alert),
            "message": alert,
            "timestamp": datetime.now().isoformat()
        })
    return serialized


def export_to_json(events, alerts, ip_counter, risk_score, filename="report.json"):
    report = {
        "timestamp": datetime.now().isoformat(),
        "events_analyzed": len(events),
        "unique_ips": len({event["ip"] for event in events}),
        "total_alerts":len(alerts),
        "alerts": _serialize_alert(alerts),
        "top_ips":dict(ip_counter),
        "risk_score":dict(risk_score)
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n-- Report exported to {filename}")

def generate_report(events, alerts, output_file = None, quiet=False):
    alert_types = Counter()
    ip_counter = Counter()
    risk_score = Counter()

    for alert in alerts:
        ip = extract_ip(alert)
        ip_counter[ip] += 1

        classification = classify_alert(alert)
        if classification:
            key, label = classification
            alert_types[label] += 1
            risk_score[ip] += RISK_WEIGHTS[key]
    if not quiet:  
        print("\n---- Security Report ----\n")
        print(f"Events analyzed: {len(events)}")
        print(f"Unique IPs: {len({event["ip"] for event in events})}")
        print(f"Total alerts: {len(alerts)}\n")

        print("Alerts by type")

        for label, count in alert_types.items():
            print(f"{label}: {count}")

        # top attacking IPs
        print("\nTop attacking IPs")
        for ip, count in ip_counter.most_common():
            print(f"{ip} - {count} alerts")

        #Risk score by ip        
        print("\nRisk score by ip")

        for ip, score in risk_score.most_common():
            level = "HIGH" if score >=10 else "MEDIUM" if score >=5 else "LOW"
            print(f"{ip} - {level} ({score})")

    if output_file:
        export_to_json(events, alerts, ip_counter, risk_score, output_file)
