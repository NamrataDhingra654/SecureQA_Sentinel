from zapv2 import ZAPv2
import time
import os

# Connect to ZAP running in Docker.
# Reads ZAP_API_URL from environment when set (docker-compose sets this to
# http://zap:8080, since containers on the same compose network reach each
# other by service name, not 127.0.0.1). Falls back to the old localhost
# value for running scanner.py directly on the host, same as before.
ZAP_API_URL = os.environ.get('ZAP_API_URL', 'http://127.0.0.1:8080')

zap = ZAPv2(apikey='', proxies={'http': ZAP_API_URL, 'https': ZAP_API_URL})

def run_scan(target_url):
    """
    Runs a full spider + active scan on the target URL.
    Returns a list of findings (alerts).
    """
    print(f"Starting spider scan on {target_url}...")
    scan_id = zap.spider.scan(target_url)

    # Wait for spider to finish
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)

    print("Spider complete. Starting active scan...")
    ascan_id = zap.ascan.scan(target_url)

    # Wait for active scan to finish
    while int(zap.ascan.status(ascan_id)) < 100:
        print(f"Active scan progress: {zap.ascan.status(ascan_id)}%")
        time.sleep(5)

    print("Active scan complete. Fetching alerts...")
    alerts = zap.core.alerts(baseurl=target_url)

    return alerts


from database import save_scan

# Quick test — run this file directly to test
if __name__ == "__main__":
    target = "http://host.docker.internal:3000"
    results = run_scan(target)
    print(f"\nFound {len(results)} alerts")

    scan_id = save_scan(target, results)
    print(f"Check your database — scan ID {scan_id} is now saved.")