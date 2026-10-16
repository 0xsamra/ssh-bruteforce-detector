import re
from collections import Counter, defaultdict
from datetime import datetime

LOG_FILE = "sample_logs/auth_sample.log"
YEAR = 2026  # auth.log has no year, so we add it ourselves
FAIL_THRESHOLD = 5  # flag an IP with this many failures or more

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


def count_failures(events):
    """Count failed logins per IP and collect the usernames each IP tried."""
    failed = [e for e in events if e["status"] == "Failed"]
    counts = Counter(e["ip"] for e in failed)
    users = defaultdict(set)
    for e in failed:
        users[e["ip"]].add(e["user"])
    return counts, users


if __name__ == "__main__":
    events = parse_log(LOG_FILE)
    counts, users = count_failures(events)
    total = sum(counts.values())

    print(f"Parsed {len(events)} events, {total} failed logins from {len(counts)} IPs\n")
    print(f"{'IP':<16}{'FAILED':>7}  {'USERS':>5}  STATUS")
    for ip, n in counts.most_common():
        status = "FLAGGED" if n >= FAIL_THRESHOLD else "ok"
        print(f"{ip:<16}{n:>7}  {len(users[ip]):>5}  {status}")
