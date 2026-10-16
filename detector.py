import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LOG_FILE = "sample_logs/auth_sample.log"
YEAR = 2026  # auth.log has no year, so we add it ourselves
FAIL_THRESHOLD = 5       # Step 4 rule: total failures
WINDOW_MINUTES = 5       # Step 5 rule: size of the time window
BURST_THRESHOLD = 10     # Step 5 rule: failures inside one window

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


def find_bursts(events):
    """For each IP, find the most failures inside any WINDOW_MINUTES stretch.

    Returns {ip: (peak_count, window_start, window_end)}.
    """
    window = timedelta(minutes=WINDOW_MINUTES)
    times_by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "Failed":
            times_by_ip[e["ip"]].append(e["time"])

    bursts = {}
    for ip, times in times_by_ip.items():
        times.sort()
        best = (0, None, None)
        start = 0  # left edge of the sliding window
        for end in range(len(times)):
            # move the left edge forward until the window fits
            while times[end] - times[start] > window:
                start += 1
            count = end - start + 1
            if count > best[0]:
                best = (count, times[start], times[end])
        bursts[ip] = best
    return bursts


if __name__ == "__main__":
    events = parse_log(LOG_FILE)
    counts, users = count_failures(events)
    bursts = find_bursts(events)
    total = sum(counts.values())

    print(f"Parsed {len(events)} events, {total} failed logins from {len(counts)} IPs")
    print(f"Rules: {FAIL_THRESHOLD}+ total failures | "
          f"{BURST_THRESHOLD}+ failures within {WINDOW_MINUTES} min\n")

    print(f"{'IP':<16}{'TOTAL':>6}{'PEAK':>6}  {'COUNT RULE':<12}{'WINDOW RULE'}")
    for ip, n in counts.most_common():
        peak = bursts[ip][0]
        count_rule = "FLAGGED" if n >= FAIL_THRESHOLD else "ok"
        window_rule = "BURST" if peak >= BURST_THRESHOLD else "ok"
        print(f"{ip:<16}{n:>6}{peak:>6}  {count_rule:<12}{window_rule}")

    print("\nBursts detected:")
    for ip, (peak, first, last) in bursts.items():
        if peak >= BURST_THRESHOLD:
            print(f"  {ip}: {peak} failures between {first} and {last}")
