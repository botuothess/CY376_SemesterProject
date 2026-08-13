"""
storage.py

Thin SQLite wrapper for the collector. Two tables:
  - alerts: raw alerts as reported by sensor agents
  - correlated_alerts: higher-confidence findings produced by joining
    alerts across segments (see correlation.py)
"""

import os
import sqlite3
import threading
import time
from pathlib import Path

_default_path = Path(__file__).resolve().parent.parent / "data" / "ids_data.db"
_default_path.parent.mkdir(parents=True, exist_ok=True)
DB_PATH = os.environ.get("IDS_DB_PATH", str(_default_path))

_local = threading.local()


def get_conn():
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn


def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        segment_id TEXT NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        src_ip TEXT,
        detail TEXT,
        timestamp REAL NOT NULL,
        received_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS correlated_alerts (
        correlation_id TEXT PRIMARY KEY,
        src_ip TEXT NOT NULL,
        segments TEXT NOT NULL,      -- comma-separated segment_ids
        alert_types TEXT NOT NULL,   -- comma-separated alert types involved
        alert_ids TEXT NOT NULL,     -- comma-separated alert_ids involved
        severity TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at REAL NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_alerts_src_ts ON alerts(src_ip, timestamp);
    """)
    conn.commit()


def insert_alert(alert):
    conn = get_conn()
    conn.execute(
        """INSERT OR IGNORE INTO alerts
           (alert_id, segment_id, type, severity, src_ip, detail, timestamp, received_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert["alert_id"], alert["segment_id"], alert["type"],
            alert["severity"], alert.get("src_ip"), alert.get("detail", ""),
            alert["timestamp"], time.time(),
        ),
    )
    conn.commit()


def get_recent_alerts(limit=200):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_alerts_since(cutoff_ts):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp ASC",
        (cutoff_ts,),
    ).fetchall()
    return [dict(r) for r in rows]


def insert_correlation(corr):
    conn = get_conn()
    conn.execute(
        """INSERT OR IGNORE INTO correlated_alerts
           (correlation_id, src_ip, segments, alert_types, alert_ids,
            severity, summary, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            corr["correlation_id"], corr["src_ip"], corr["segments"],
            corr["alert_types"], corr["alert_ids"], corr["severity"],
            corr["summary"], time.time(),
        ),
    )
    conn.commit()


def get_recent_correlations(limit=100):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM correlated_alerts ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    by_segment = conn.execute(
        "SELECT segment_id, COUNT(*) c FROM alerts GROUP BY segment_id"
    ).fetchall()
    by_type = conn.execute(
        "SELECT type, COUNT(*) c FROM alerts GROUP BY type"
    ).fetchall()
    correlations = conn.execute(
        "SELECT COUNT(*) c FROM correlated_alerts"
    ).fetchone()["c"]
    return {
        "total_alerts": total,
        "by_segment": {r["segment_id"]: r["c"] for r in by_segment},
        "by_type": {r["type"]: r["c"] for r in by_type},
        "total_correlations": correlations,
    }
