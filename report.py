from database import get_all_scans
import json

def print_latest_report():
    scans = get_all_scans()

    if not scans:
        print("No scans available yet.")
        return

    latest = scans[0]  # most recent scan (we ordered by timestamp descending)

    print("=" * 50)
    print(f"SCAN REPORT — ID {latest.id}")
    print("=" * 50)
    print(f"Target: {latest.target_url}")
    print(f"Scanned at: {latest.timestamp}")
    print(f"\nTotal findings: {latest.total_findings}")
    print(f"  High:          {latest.high_count}")
    print(f"  Medium:        {latest.medium_count}")
    print(f"  Low:           {latest.low_count}")
    print(f"  Informational: {latest.info_count}")

    findings = json.loads(latest.findings_json)

    print("\n" + "-" * 50)
    print("TOP FINDINGS (first 5)")
    print("-" * 50)

    for f in findings[:5]:
        print(f"\n[{f.get('risk', 'Unknown')}] {f.get('name', 'Unnamed issue')}")
        print(f"  URL: {f.get('url', 'N/A')}")
        print(f"  Fix: {f.get('solution', 'No solution provided')[:150]}...")


if __name__ == "__main__":
    print_latest_report()