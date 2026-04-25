from collections import Counter
import re
import json
from datetime import datetime

RISK_WEIGHTS = {
    "flood":1,
    "sqli":3,
    "brute":3,
    "scan":2,
    "sensitive":2,
    "user-agent":1
}

def extract_ip(alert: str):
    match = re.search(r'from ([0-9a-fA-F\.:]+)', alert)
    if not match:
        return "unknown"
    
    return match.group(1).rstrip(":")

def export_to_json(events, alerts, ip_counter, risk_score, filename="report.json"):
    report = {
        "timestamp": datetime.now().isoformat(),
        "events_analyzed": len(events),
        "unique_ips": len({event["ip"] for event in events}),
        "total_alerts":len(alerts),
        "alerts": alerts,
        "top_ips":dict(ip_counter),
        "risk_score":dict(risk_score)
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n-- Report exported to {filename}")

def generate_report(events, alerts, output_file = None):

    print("\n---- Security Report ----\n")

    print(f"Events analyzed: {len(events)}")

    unique_ips = {event["ip"] for event in events}
    print(f"Unique IPs: {len(unique_ips)}")

    print(f"Total alerts: {len(alerts)}\n")

    alert_types = Counter()

    for alert in alerts:

        if "flood" in alert.lower():
            alert_types["Flood"] += 1
        
        elif "sql injection" in alert.lower():
            alert_types["SQLi"] += 1
        
        elif "brute force" in alert.lower():
            alert_types["Brute force"] += 1
        
        elif "directory enumeration" in alert.lower():
            alert_types["Directory scan"] += 1
        
        elif "sensitive path" in alert.lower():
            alert_types["Sensitive path"] += 1
        
        elif "user-agent" in alert.lower():
            alert_types["User-agent"] += 1
    
    print("Alerts by type")

    for k, v in alert_types.items():
        print(f"{k}: {v}")

    # top attacking IPs
    ip_counter = Counter()
    for alert in alerts:
        ip = extract_ip(alert)
        ip_counter[ip   ] +=1
    
    print("\nTop attacking IPs")
    for ip, count in ip_counter.most_common():
        print(f"{ip} - {count} alerts")

    #Risk score by ip
    risk_score = Counter()
    for alert in alerts:
        ip = extract_ip(alert)
        text = alert.lower()

        if "flood" in text:
            risk_score[ip] += RISK_WEIGHTS['flood']

        elif "sql injection" in text:
            risk_score[ip] += RISK_WEIGHTS['sqli']

        elif "brute force" in text:
            risk_score[ip] += RISK_WEIGHTS['brute']

        elif "directory enumeration" in text:
            risk_score[ip] += RISK_WEIGHTS['scan']

        elif "sensitive path" in text:
            risk_score[ip] += RISK_WEIGHTS['sensitive']

        elif "user-agent" in text:
            risk_score[ip] += RISK_WEIGHTS['user-agent']
            
    print("\nRisk score by ip")
    for ip, score in risk_score.most_common():
        if score>=10:
            level = "HIGH"
        elif score >=5:
            level = "MEDIUM"
        else:
            level = "LOW"
        print(f"{ip} - {level} ({score})")
    
    if output_file:
        export_to_json(events, alerts, ip_counter, risk_score, output_file)
             