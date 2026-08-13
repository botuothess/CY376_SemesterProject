"""
run.py

Single-command launcher for distributed_ids -- no Docker required.

Starts the collector (Flask API + dashboard) and the simulated
multi-segment sensors as two child processes, waits for the collector
to come up, opens your browser to the dashboard, and then just sits
and waits. Ctrl+C stops both processes cleanly.

Usage:
    python run.py
"""

import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def wait_for_collector(url="http://127.0.0.1:5000/api/stats", timeout=15):
    """Polls the collector's API until it responds or we give up."""
    import urllib.request
    import urllib.error

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    return False


def main():
    print("Starting distributed_ids...")
    print("  -> collector (API + dashboard)")
    collector_proc = subprocess.Popen(
        [sys.executable, "app.py"], cwd=str(ROOT / "collector")
    )

    if wait_for_collector():
        print("  -> collector is up")
    else:
        print("  -> collector didn't respond in time; continuing anyway "
              "(check its output above for errors)")

    print("  -> simulated segment sensors (DMZ, INTERNAL, OT_IOT)")
    sensors_proc = subprocess.Popen(
        [sys.executable, "simulate_multi_segment.py"], cwd=str(ROOT)
    )

    dashboard_url = "http://127.0.0.1:5000"
    print(f"\nDashboard: {dashboard_url}")
    try:
        webbrowser.open(dashboard_url)
    except Exception:
        pass  # headless environment, no browser to open -- that's fine

    print("Press Ctrl+C to stop everything.\n")

    try:
        while True:
            time.sleep(1)
            if collector_proc.poll() is not None:
                print("\nCollector process exited unexpectedly -- stopping.")
                break
            if sensors_proc.poll() is not None:
                print("\nSensor process exited unexpectedly -- stopping.")
                break
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        for proc, name in ((sensors_proc, "sensors"), (collector_proc, "collector")):
            if proc.poll() is None:
                proc.terminate()
        time.sleep(1)
        for proc, name in ((sensors_proc, "sensors"), (collector_proc, "collector")):
            if proc.poll() is None:
                proc.kill()
        print("Stopped.")


if __name__ == "__main__":
    main()
