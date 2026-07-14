from database import get_all_scans
import json

scans = get_all_scans()

if not scans:
    print("No scans found in database yet.")
else:
    for scan in scans:
        print(f"\n--- Scan ID {scan.id} ---")
        print(f"Target: {scan.target_url}")
        print(f"Time: {scan.timestamp}")
        print(f"Total findings: {scan.total_findings}")
        print(f"  High: {scan.high_count} | Medium: {scan.medium_count} | Low: {scan.low_count} | Info: {scan.info_count}")