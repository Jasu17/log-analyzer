from collections import Counter

def generate_report(events, alerts):

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