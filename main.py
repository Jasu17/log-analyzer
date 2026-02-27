from src.parser import parse_line
from collections import defaultdict

ip_counter = defaultdict(int)

with open("/var/log/httpd/access_log") as f:
    for line in f:
        parsed = parse_line(line)
        if parsed:
            ip_counter[parsed["ip"]] +=1

print(dict(ip_counter))