import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>.*?)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+)'
)

def parse_line(line: str) -> dict | None:
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()

    # Convertimos tipos
    data["status"] = int(data["status"])
    data["size"] = 0 if data["size"] == "-" else int(data["size"])

    # Parseo de fecha
    data["time"] = datetime.strptime(
        data["time"],
        "%d/%b/%Y:%H:%M:%S %z"
    )

    return data