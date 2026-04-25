from src.detectors import (
    detect_bruteforce,
    detect_flood,
    detect_sqli,
    detect_directory_scan,
    detect_suspicious_user_agents,
    detect_sensitive_access
)
from datetime import datetime, timedelta
from collections import defaultdict

# --- Helpers ---

def make_event(ip="127.0.0.1", path="/index.php", method="GET",
                status=200, user_agent="-", time=None):

    return {
        "ip": ip,
        "path": path,
        "method": method,
        "status": status,
        "user_agent": user_agent,
        "time": time or datetime.now()
    }

# --- Tests SQL Injection ---
def test_detect_sqli_or():
    logs = [make_event(path="/index.php?id=1 OR 1=1")]
    assert len(detect_sqli(logs)) > 0

def test_detect_sqli_union():
    logs = [make_event(path="/search?q=1 UNION SELECT username,password FROM users")]
    assert len(detect_sqli(logs)) > 0

def test_detect_sqli_no_match():
    logs = [make_event(path="/index.php?id=42")]
    assert detect_sqli(logs) == []

def test_detect_sqli_deduplicates():
    logs = [make_event(path="/index.php?id=1 OR 1=1")] * 5
    alerts = detect_sqli(logs)
    assert len(alerts) == 1
    assert "5 times" in alerts[0]

# --- Tests Brute Force  ---
def test_detect_brute_force():
    base_time = datetime.now()
    logs = [make_event(path="/login", method="POST",
                       time=base_time + timedelta(seconds=i)) for i in range(10)]
    assert len(detect_bruteforce(logs)) > 0

def test_detect_brute_force_no_match():
    logs = [make_event(path="/login", method="POST")]
    assert detect_bruteforce(logs) == []

def test_detect_brute_force_ignores_get():
    base_time = datetime.now()
    logs = [make_event(path="/login", method="GET",
                       time=base_time + timedelta(seconds=i)) for i in range(10)]
    assert detect_bruteforce(logs) == []

# --- Tests Flood ---
def test_detect_flood():
    ip_timestamps = defaultdict(list)
    base_time = datetime.now()

    for i in range(30):
        ip_timestamps["127.0.0.1"].append(base_time + timedelta(seconds=i))
    assert len(detect_flood(ip_timestamps)) > 0

def test_detect_flood_no_match():
    ip_timestamps = defaultdict(list)
    base_time = datetime.now()

    for i in range(5):
        ip_timestamps["127.0.0.1"].append(base_time + timedelta(seconds=i*10))
    assert detect_flood(ip_timestamps) == []

# --- Tests sensitive access ---

def test_detect_sensitive_access_env():
    logs = [make_event(path="/.env", status=404)]
    alerts = detect_sensitive_access(logs)
    assert len(alerts) > 0
    assert "/.env" in alerts[0]

def test_detect_sensitive_access_counts():
    logs = [make_event(path="/.git/config", status=404)] * 3
    alerts = detect_sensitive_access(logs)
    assert any("3 times" in alert for alert in alerts)

def test_detect_sensitive_access_no_match():
    logs = [make_event(path="/index.php", status=200)]
    assert detect_sensitive_access(logs) == []

# --- Tests directory scan ---

def test_detect_directory_scan():
    base_time = datetime.now()
    logs = [make_event(path="/fake-{i}", status=404,
                        time=base_time + timedelta(seconds=i)) for i in range(20)]
    assert len(detect_directory_scan(logs)) > 0


def test_detect_directory_scan_no_match():
    logs = [make_event(path="/index.php", status=200)]
    assert detect_directory_scan(logs) == []

def test_detect_directory_scan_ignores_200():
    base_time = datetime.now()
    logs = [make_event(path=f"/page-{i}", status=200,
                       time=base_time + timedelta(seconds=i)) for i in range(20)]
    assert detect_directory_scan(logs) == []

# --- Tests suspicious user agents ---
def test_detect_suspicious_user_agent_sqlmap():
    logs = [make_event(user_agent="sqlmap/1.0")]
    alerts = detect_suspicious_user_agents(logs)
    assert len(alerts) > 0
    assert "sqlmap" in alerts[0].lower()

def test_detect_suspicious_user_agent_deduplicates():
    logs = [make_event(user_agent="gobuster/3.0")] * 10
    alerts = detect_suspicious_user_agents(logs)
    assert len(alerts) == 1
    assert "10 requests" in alerts[0]

def test_detect_suspicious_user_agent_no_match():
    logs = [make_event(user_agent="Mozilla/5.0 (Windows NT 10.0)")]
    assert detect_suspicious_user_agents(logs) == []