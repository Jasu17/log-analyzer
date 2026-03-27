from src.detectors import (
    detect_bruteforce,
    detect_flood,
    detect_sqli
)
from datetime import datetime, timedelta
def test_detect_sqli():
    logs = [{
            "ip": "127.0.0.1",
            "path": "/index.php?id=1 OR 1=1",
            "method": "GET",
            "time": datetime.now()        
    }]

    alerts = detect_sqli(logs)

    assert len(alerts) > 0

def test_detect_brute_force():
    base_time = datetime.now()

    logs = []
    for i in range(10):
        logs.append({
            "ip": "127.0.0.1",
            "path": "/login",
            "method": "POST",
            "time": base_time + timedelta(seconds=1)
        })

    alerts = detect_bruteforce(logs)

    assert len(alerts) > 0

def test_detect_flood():
    from collections import defaultdict
    ip_timestamps = defaultdict(list)
    base_time = datetime.now()

    for i in range(30):
        ip_timestamps["127.0.0.1"].append(base_time+timedelta(seconds=1))

    alerts = detect_flood(ip_timestamps)

    assert len(alerts) > 0

