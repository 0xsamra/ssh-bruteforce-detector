import csv
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LOG_FILE = "sample_logs/auth_sample.log"
OUTPUT_FILE = "output/report.csv"
YEAR = 2026  # auth.log has no year, so we add it ourselves
FAIL_THRESHOLD = 5       # Step 4 rule: total failures
WINDOW_MINUTES = 5       # Step 5 rule: size of the time window
BURST_THRESHOLD = 10     # Step 5 rule: failures inside one window
LOOKBACK_MINUTES = 10    # Step 6 rule: how far back to look before a success
COMPROMISE_FAILS = 5     # Step 6 rule: failures before a success = suspicious

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


def find_compromises(events):
    """Find successful logins that came right after many failures from the same IP."""
    lookback = timedelta(minutes=LOOKBACK_MINUTES)
    failures_by_ip = defaultdict(list)  # failures seen so far, per IP
    alerts = []

    for e in sorted(events, key=lambda x: x["time"]):  # walk through time in order
        if e["status"] == "Failed":
            failures_by_ip[e["ip"]].append(e)
        else:  # an Accepted login
            recent = [
                f for f in failures_by_ip[e["ip"]]
                if e["time"] - f["time"] <= lookback
            ]
            if len(recent) >= COMPROMISE_FAILS:
                alerts.append({
                    "ip": e["ip"],
                    "user": e["user"],
                    "success_time": e["time"],
                    "failures": len(recent),
                    "first_failure": recent[0]["time"],
                    "users_tried": sorted({f["user"] for f in recent}),
                })
    return alerts


def get_verdict(ip, total, peak, compromised_ips):
    """One place that decides the label for an IP."""
    if ip in compromised_ips:
        return "LIKELY COMPROMISE"
    if peak >= BURST_THRESHOLD:
        return "BRUTE FORCE (no success)"
    if total >= FAIL_THRESHOLD:
        return "SUSPICIOUS (many failures, not a burst)"
    return "ok"


def build_rows(events, counts, users, bursts, compromised_ips):
    """Turn all results into one row (dictionary) per IP."""
    first_last = {}  # ip -> [first failure time, last failure time]
    for e in events:
        if e["status"] != "Failed":
            continue
        span = first_last.setdefault(e["ip"], [e["time"], e["time"]])
        span[0] = min(span[0], e["time"])
        span[1] = max(span[1], e["time"])

    rows = []
    for ip, total in counts.most_common():
        peak = bursts[ip][0]
        verdict = get_verdict(ip, total, peak, compromised_ips)
        rows.append({
            "ip": ip,
            "failed_count": total,
            "peak_in_window": peak,
            "first_seen": first_last[ip][0],
            "last_seen": first_last[ip][1],
            "usernames_tried": "; ".join(sorted(users[ip])),
            "flagged": "no" if verdict == "ok" else "yes",
            "verdict": verdict,
        })
    return rows


def write_csv(rows, path):
    """Save the rows to a CSV file, creating the folder if needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fields = ["ip", "failed_count", "peak_in_window", "first_seen",
              "last_seen", "usernames_tried", "flagged", "verdict"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    events = parse_log(LOG_FILE)
    counts, users = count_failures(events)
    bursts = find_bursts(events)
    compromises = find_compromises(events)
    compromised_ips = {a["ip"] for a in compromises}
    rows = build_rows(events, counts, users, bursts, compromised_ips)
    total = sum(counts.values())

    print(f"Parsed {len(events)} events, {total} failed logins from {len(counts)} IPs")
    print(f"Rules: {FAIL_THRESHOLD}+ total failures | "
          f"{BURST_THRESHOLD}+ failures within {WINDOW_MINUTES} min | "
          f"success after {COMPROMISE_FAILS}+ failures\n")

    print(f"{'IP':<16}{'TOTAL':>6}{'PEAK':>6}  VERDICT")
    for r in rows:
        print(f"{r['ip']:<16}{r['failed_count']:>6}{r['peak_in_window']:>6}  {r['verdict']}")

    print("\nPossible compromises:")
    if not compromises:
        print("  none")
    for a in compromises:
        print(f"  {a['ip']} logged in as '{a['user']}' at {a['success_time']} "
              f"after {a['failures']} failures (first at {a['first_failure']})")
        print(f"    usernames tried: {', '.join(a['users_tried'])}")

    write_csv(rows, OUTPUT_FILE)
    print(f"\nReport saved to {OUTPUT_FILE}")
