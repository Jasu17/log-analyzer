import re
from datetime import datetime

COMMON_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>.*?)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+)'
)

COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>.*?)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+) '
    r'"(?P<referer>.*?)" '
    r'"(?P<user_agent>.*?)"'
)

def parse_line(line: str) -> dict | None:
    match = COMBINED_LOG_PATTERN.match(line)
    if match:
        data = match.groupdict()
    else:
        match = COMMON_LOG_PATTERN.match(line)

        if not match:
            return None
        
        data = match.groupdict()
        data["referer"] = "-"
        data["user_agent"] = "-"
    
    data["status"] = int(data["status"])
    data["size"] = 0 if data["size"] == "-" else int(data["size"])

    data["time"] = datetime.strptime(
        data["time"],
        "%d/%b/%Y:%H:%M:%S %z"
    )

    return data