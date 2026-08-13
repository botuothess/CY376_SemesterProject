"""
app.py

Central collector for the distributed IDS framework.

Responsibilities:
  1. Expose POST /api/alert for sensor agents to report detections.
  2. Persist alerts to SQLite (storage.py).
  3. Run a background correlation thread (correlation.py) that joins
     alerts across segments.
  4. Serve a small live dashboard + read-only JSON API for the UI.

Run:
    python app.py --config ../config.yaml
"""

import argparse
import os
import sys
import threading
from pathlib import Path

import yaml
from flask import Flask, jsonify, render_template, request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import correlation  # noqa: E402
import storage  # noqa: E402

app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent.parent / "dashboard" / "templates"),
    static_folder=str(Path(__file__).resolve().parent.parent / "dashboard" / "static"),
)
CONFIG = {}
stop_event = threading.Event()


def require_api_key():
    key = request.headers.get("X-API-Key")
    return key == CONFIG["collector"]["api_key"]


@app.route("/api/alert", methods=["POST"])
def receive_alert():
    if not require_api_key():
        return jsonify({"error": "invalid or missing API key"}), 401

    alert = request.get_json(force=True, silent=True)
    if not alert:
        return jsonify({"error": "invalid JSON body"}), 400

    required = {"alert_id", "segment_id", "type", "severity", "timestamp"}
    missing = required - alert.keys()
    if missing:
        return jsonify({"error": f"missing fields: {sorted(missing)}"}), 400

    storage.insert_alert(alert)
    return jsonify({"status": "stored", "alert_id": alert["alert_id"]}), 200


@app.route("/api/alerts", methods=["GET"])
def list_alerts():
    limit = int(request.args.get("limit", 200))
    return jsonify(storage.get_recent_alerts(limit=limit))


@app.route("/api/correlations", methods=["GET"])
def list_correlations():
    limit = int(request.args.get("limit", 100))
    return jsonify(storage.get_recent_correlations(limit=limit))


@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify(storage.get_stats())


@app.route("/", methods=["GET"])
def dashboard():
    return render_template("index.html")


def start_correlation_thread(corr_cfg):
    t = threading.Thread(
        target=correlation.correlation_loop,
        kwargs=dict(
            poll_interval=corr_cfg.get("poll_interval_seconds", 5),
            window_seconds=corr_cfg.get("cross_segment_window_seconds", 120),
            min_segments=corr_cfg.get("cross_segment_min_segments", 2),
            stop_event=stop_event,
        ),
        daemon=True,
    )
    t.start()
    return t


def main():
    global CONFIG
    parser = argparse.ArgumentParser(description="Distributed IDS collector")
    default_config = str(Path(__file__).resolve().parent.parent / "config.yaml")
    parser.add_argument("--config", default=default_config)
    args = parser.parse_args()

    with open(args.config, "r") as f:
        CONFIG = yaml.safe_load(f)

    storage.init_db()
    start_correlation_thread(CONFIG["correlation"])

    host = os.environ.get("COLLECTOR_BIND_HOST", CONFIG["collector"]["host"])
    port = int(os.environ.get("COLLECTOR_BIND_PORT", CONFIG["collector"]["port"]))
    print(f"[collector] listening on http://{host}:{port}")
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
