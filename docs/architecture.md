# Architecture

## Overview
This project is a web server log analyzer designed to detect common web-based attacks by parsing and analyzing HTTP access logs (Apache/Nginx).

It process raw log files and transform them into structured events, which are then analyzed usign detection rules.

---

## Components

### 1. parser.py
Responsible for converting raw log files into structured Python dictionaries.

**Input:**
Raw log line

**Output:**
```json
{
    "ip": "127.0.0.1",
    "time": "...",
    "method": "GET",
    "path": "/index.php?id=1",
    "status": 200
}
```
---
### 2. detectors.py
Contains detection logic for different attack types.

Implemented detectors:
- Flood / DoS detection
- SQL Injection detection
- Brute force detection
- Sensitive path access
- Directory enumeration
- Suspicious user-agent detection
  
Each detector returns a list of alerts

---
### 3. analyzer.py
Core orchestrator of the system

Workflow:

1. Read log file
2. Parse lines into events
3. Apply detection using functions
4. Aggregate alerts
5. Filter alerts (optional)
6. Send results to reporting module

---

### 4. report.py
Generates:

- Console output
- Summary statistics
- Risk scoring
- JSON export

---

## Data flow
```
Raw Logs -> Parser -> Events -> Detectors -> Alerts -> report
```

## Design Principles

- Modular design (each component has a clear responsibility)
- Extensible (new detectors can be added easily)
- CLI-driven (no harcoded values)
- Reproducible (supports sample logs)

---
