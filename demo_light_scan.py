"""
demo_light_scan.py — Lightweight scan mode for the CSP header demo.

Runs ZAP's spider + passive scan ONLY (skips active scan, which is the
resource-heavy phase that fires real attack payloads with concurrency and
was crashing the machine on a Juice Shop instance with accumulated state).

Passive scan checks — including "CSP Header Not Set" — run automatically as
the spider crawls pages and reads their response headers. No active attack
traffic is needed to detect a missing header, so this gives identical CSP
findings to a full scan while using a fraction of the RAM/CPU.

Saves results through the same save_scan() used by the normal app.py flow,
so the resulting scan shows up normally in /api/scans and the Compare view.

Usage:
    python demo_light_scan.py http://host.docker.internal:3000
    python demo_light_scan.py http://host.docker.internal:3001
"""

import sys
import time
from collections import Counter

import requests

from database import save_scan

ZAP_BASE = "http://127.0.0.1:8080"
POLL_INTERVAL_SECONDS = 2


def spider_and_passive_scan(target_url: str) -> list[dict]:
    # ── 1. Start the spider ──────────────────────────────────────────────
    r = requests.get(f"{ZAP_BASE}/JSON/spider/action/scan/", params={"url": target_url})
    r.raise_for_status()
    scan_id = r.json()["scan"]

    print(f"Spider started (scan id {scan_id})...")
    while True:
        status = requests.get(
            f"{ZAP_BASE}/JSON/spider/view/status/", params={"scanId": scan_id}
        ).json()["status"]
        print(f"  Spider progress: {status}%")
        if int(status) >= 100:
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    # ── 2. Let the passive scanner drain its queue ───────────────────────
    # Passive checks (including CSP Header Not Set) run asynchronously as
    # pages are discovered — this waits until ZAP has finished analyzing
    # every page the spider found.
    print("Waiting for passive scan queue to drain...")
    while True:
        records_left = requests.get(
            f"{ZAP_BASE}/JSON/pscan/view/recordsToScan/"
        ).json()["recordsToScan"]
        print(f"  Records left to passively scan: {records_left}")
        if int(records_left) == 0:
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    # ── 3. Pull the alerts found so far (spider + passive only) ─────────
    alerts = requests.get(
        f"{ZAP_BASE}/JSON/core/view/alerts/", params={"baseurl": target_url}
    ).json()["alerts"]

    return alerts


def main():
    if len(sys.argv) != 2:
        print("Usage: python demo_light_scan.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    findings = spider_and_passive_scan(target_url)

    counts = Counter(f.get("risk", "Informational") for f in findings)

    scan_id = save_scan(
        target_url=target_url,
        findings=findings,
        total_findings=len(findings),
        high_count=counts.get("High", 0),
        medium_count=counts.get("Medium", 0),
        low_count=counts.get("Low", 0),
        info_count=counts.get("Informational", 0),
    )

    print(f"\nDone. Saved as scan_id={scan_id} — {len(findings)} findings.")
    print(f"View it via: curl.exe http://127.0.0.1:5000/api/scan/{scan_id}")


if __name__ == "__main__":
    main()