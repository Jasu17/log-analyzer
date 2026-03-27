# Usage

## Basic
```
python main.py --file /var/log/httpd/access_log
```

---

## With JSON export

```
python main.py --file /var/log/httpd/access_log --output report.json
```

---

## Filter by attack type

```
python main.py --only sqli
python main.py --only brute
python main.py --only scan
```

---

## Default behavior

If no file is provided, the tool attempts to use:
```
/var/log/httpd/access_log
```
