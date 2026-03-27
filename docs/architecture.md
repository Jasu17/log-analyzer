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
'''json
{
    "ip": "127.0.0.1",
    "time": "...",
    "method": "GET",
    "path": "/index.php?id=1",
    "status": 200
}

### 2. detectors.py