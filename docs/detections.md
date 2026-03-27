# Detection Techniques

This document describes how different attack types are identifies from log data.

---

## 1. Flood / DoS Detection

### Description
A large numer of request from the same IP in a short period of time.

### Logic
- Group request by IP
- Count request within a time window
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
Regrex pattern matching in request paths.

---

## 3. Brute force

### Description
Multiple login attempts in a short period.

### Logic
- Filter POST requests to login endpoints
- Count attempts per IP
- Trigger alert if threshold exceeded

---

## 4. Sensitive Path Access

### Description
Attempts to acces hidden or critical files.

### Examples
- /.env
- /.git/config
- /backup.zip
- /phpmyadmin

### Detection
Match request paths a list of sensitive targets.

---

## 5. Directory Enumeration

### Description
Automated scanning of non-existent paths.

### Indicators
- High number of 404 responces
- Short time window

---

## 6. Suspicious User-Agent

### Description
Request made by automated tools.

### Examples
- sqlmap
- gobuster
- nikto

### Detection
Check user-agent string against known tools.

---
