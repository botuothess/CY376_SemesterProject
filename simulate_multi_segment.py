"""
simulate_multi_segment.py

Launches one simulated sensor agent per segment defined in config.yaml,
all in-process using threads. This is the fastest way to demo the whole
distributed_ids pipeline end-to-end on a single machine:

    Terminal 1:  python collector/app.py
    Terminal 2:  python simulate_multi_segment.py

Then open http://127.0.0.1:5000 to watch alerts and cross-segment
correlations appear live.
"""

import sys
import threading
import time
from pathlib import Path
import os

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent"))
from sensor_agent import SensorAgent  # noqa: E402


def main():
    config_path = Path(__file__).resolve().parent / "config.yaml"
    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    collector_cfg = cfg["collector"]
    collector_host = os.environ.get("COLLECTOR_HOST", collector_cfg["host"])
    collector_port = os.environ.get("COLLECTOR_PORT", collector_cfg["port"])
    collector_url = f"http://{collector_host}:{collector_port}"

    threads = []
    for seg in cfg["segments"]:
        agent = SensorAgent(
            segment_id=seg["segment_id"],
            collector_url=collector_url,
            api_key=collector_cfg["api_key"],
            detection_config=cfg["detection"],
        )
        t = threading.Thread(target=agent.run_simulation, kwargs={"duration": None}, daemon=True)
        threads.append(t)

    print(f"Launching {len(threads)} simulated segment agents "
          f"against collector at {collector_url} ...")
    for t in threads:
        t.start()
        time.sleep(0.3)  # stagger startup slightly

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping simulated agents.")


if __name__ == "__main__":
    main()
