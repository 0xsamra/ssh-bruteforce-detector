import re
from datetime import datetime

LOG_FILE = "sample_logs/auth_sample.log"
YEAR = 2026  # auth.log has no year, so we add it ourselves

# One pattern that matches both failed and accepted password lines
PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_line(line):
    """Turn one log line into a dictionary, or None if it's not a login line."""
    match = PATTERN.search(line)
    if not match:
        return None
    timestamp = datetime.strptime(
        f"{YEAR} {match['month']} {match['day']} {match['time']}",
        "%Y %b %d %H:%M:%S",
    )
    return {
        "time": timestamp,
        "status": match["status"],
        "user": match["user"],
        "ip": match["ip"],
    }


def parse_log(path):
    """Read the whole file and return a list of parsed events."""
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


if __name__ == "__main__":
    events = parse_log(LOG_FILE)
    print(f"Parsed {len(events)} events\n")
    for e in events:
        print(f"{e['time']}  {e['status']:<9} {e['user']:<10} {e['ip']}")
