import os

import matplotlib
matplotlib.use("Agg")  # draw straight to a file, no window needed
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

from detector import (
    FAIL_THRESHOLD,
    LOG_FILE,
    build_rows,
    count_failures,
    find_bursts,
    find_compromises,
    parse_log,
)

CHART_FILE = "output/top_attackers.png"
TOP_N = 10  # show at most this many IPs

# One colour per verdict, so the chart matches report.csv
COLORS = {
    "LIKELY COMPROMISE": "#d62728",
    "BRUTE FORCE (no success)": "#ff7f0e",
    "SUSPICIOUS (many failures, not a burst)": "#ffbb33",
    "ok": "#9e9e9e",
}


def draw_chart(rows, path):
    top = rows[:TOP_N][::-1]  # reversed so the biggest bar ends up on top
    ips = [r["ip"] for r in top]
    counts = [r["failed_count"] for r in top]
    colors = [COLORS[r["verdict"]] for r in top]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(ips, counts, color=colors)

    # write the number at the end of each bar
    for bar, n in zip(bars, counts):
        ax.text(n + 0.2, bar.get_y() + bar.get_height() / 2, str(n), va="center")

    # dashed line showing the Step 4 count threshold
    ax.axvline(FAIL_THRESHOLD, color="black", linestyle="--", linewidth=1)
    ax.text(FAIL_THRESHOLD + 0.1, -0.7, f"count threshold ({FAIL_THRESHOLD})", fontsize=8)

    # legend only for verdicts that actually appear
    seen = []
    for r in top[::-1]:
        if r["verdict"] not in seen:
            seen.append(r["verdict"])
    ax.legend(handles=[Patch(color=COLORS[v], label=v) for v in seen], loc="lower right")

    ax.set_title("Top attacker IPs by failed SSH logins")
    ax.set_xlabel("Failed logins")
    ax.set_xlim(0, max(counts) + 2)
    plt.tight_layout()

    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.savefig(path, dpi=150)


if __name__ == "__main__":
    events = parse_log(LOG_FILE)
    counts, users = count_failures(events)
    bursts = find_bursts(events)
    compromised_ips = {a["ip"] for a in find_compromises(events)}
    rows = build_rows(events, counts, users, bursts, compromised_ips)
    draw_chart(rows, CHART_FILE)
    print(f"Chart saved to {CHART_FILE}")
