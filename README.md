# Web Log Security Analyzer

A lightweight security tool that analyzes web server logs (Apache/Nginx) to detect common attack patterns such as SQL injection, brute force attempts, and automated scanning.

Designed as a practical cybersecurity project with real detection logic, CLI usage and structured reporting.

---

## Features
- SQL Injection detection
- Brute force detection (login attempts)
- Flood / DoS detection
- Sensitive path scanning (e.g. /.env /.git)
- Directory enumeration detection (based on 404 patterns)
- Suspicious user-agent detection (sqlmap, gobuster, etc.)
- Risk scoring per IP
- Top attacking IPs ranking
- JSON report export
- CLI filtering by attack type

---

## How it works

```
Raw logs -> Parser -> Structured Events -> Detectors -> Alerts -> Report
```

1. Logs are parsed into structured data
2. Detection rules analyze patterns
3. Alerts are generated and aggregated
4. A report is created (console + optional JSON)

---

## Installation

Clone the repository:

```
git clone https://github.com/Jasu17/log-analyzer.git
cd log-analyzer
```

Install dependencies

```
pip install pytest
```

---

## Usage

### Basic analysis

```
python main.py --file /var/log/httpd/access_log
```

### Export report to JSON

```
python main.py --file /var/log/httpd/access_log --output report.json
```

---

### Filter by attack type

```
python main.py --only sqli
python main.py --only brute
python main.py --only scan
```

Available filters:

- flood
- sqli
- brute
- scan
- sensitive
- agent

---

## Example Output

```
---- Security Alerts ----  
[ALERT] Possible SQL injection attempt from ::1 on /index.php?id=1 OR 1=1
[ALERT] Possible brute force attack from ::1: 10 login attempts in 30s

Top attacking IPs
::1 → 11 alerts

Risk score by IP
::1 → HIGH (18)
```

## Proyect Structure

```
log-analyzer/
├── src/
│   ├── parser.py
│   ├── detectors.py
│   ├── analyzer.py
│   └── report.py
├── tests/
├── docs/
├── sample_logs/
├── main.py
├── pytest.ini
└── README.md
```

---

## Documentation

Detailed documentation is available in the `docs/` folder:

- docs/architecture.md -> system design
- docs/detections.md -> detection logic
- docs/usage.md -> usage examples

---

## Testing

Run tests using:

```
pytest
```

## Future improvements

- Real-time monitoring mode (tail -f)
- Multiple filter support
- Web dashboard for visualization
- Integration with SIEM tools
- Machine learning-based anomaly detection

---

## Disclaimer

This tool is intended for educational and defensive cybersecurity purposes only.

---

## Author

Developed as a hands-on cybersecurity learning project focused on log analysis and attack detection.
