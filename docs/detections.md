# Detection Techniques

This document describes how different attack types are identified from log data.

---

## 1. Flood / DoS Detection

### Description
A large number of requests from the same IP in a short period of time.

### Logic
- Group requests by IP
- Count requests within a time window
- Trigger alert if threshold exceeded

---

## 2. SQL Injection

### Description
Injection of malicious SQL queries via URL parameters.

### Indicators
- UNION SELECT
- OR 1=1
- '--' comments

### Detection
Regex pattern matching in request paths.

---

## 3. Brute Force

### Description
Multiple login attempts in a short period.

### Logic
- Filter POST requests to login endpoints
- Count attempts per IP
- Trigger alert if threshold exceeded

---

## 4. Sensitive Path Access

### Description
Attempts to access hidden or critical files.

### Examples
- /.env
- /.git/config
- /backup.zip
- /phpmyadmin

### Detection
Match request paths against a list of sensitive targets.

---

## 5. Directory Enumeration

### Description
Automated scanning of non-existent paths.

### Indicators
- High number of 404 responses
- Short time window

---

## 6. Suspicious User-Agent

### Description
Requests made by automated tools.

### Examples
- sqlmap
- gobuster
- nikto

### Detection
Check user-agent string against known tools.

---