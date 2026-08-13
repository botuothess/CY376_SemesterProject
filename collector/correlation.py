"""
correlation.py

The whole point of a *distributed* IDS rather than N independent IDS boxes:
join alerts across segments to surface patterns no single sensor can see
on its own -- e.g. the same source IP performing recon in the DMZ and then
showing up minutes later in the internal segment (classic lateral movement
signature).

Runs as a background thread that periodically scans recent alerts and
writes any new correlated findings to storage.
"""

import time
import uuid
from collections import defaultdict

import storage


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_severity(severities):
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))


def run_correlation_pass(window_seconds, min_segments):
    """
    Looks at alerts within the trailing `window_seconds`, groups them by
    src_ip, and flags any src_ip whose alerts span >= min_segments
    distinct segments. Returns the list of newly created correlation dicts.
    """
    cutoff = time.time() - window_seconds
    recent = storage.get_alerts_since(cutoff)

    by_src = defaultdict(list)
    for alert in recent:
        if alert.get("src_ip"):
            by_src[alert["src_ip"]].append(alert)

    new_correlations = []
    for src_ip, alerts in by_src.items():
        segments = {a["segment_id"] for a in alerts}
        if len(segments) < min_segments:
            continue

        alert_types = sorted({a["type"] for a in alerts})
        alert_ids = sorted({a["alert_id"] for a in alerts})
        severity = _max_severity([a["severity"] for a in alerts])

        # Deterministic ID from the sorted alert_ids so re-running a pass
        # over the same evidence doesn't create duplicate correlations.
        correlation_id = str(uuid.uuid5(uuid.NAMESPACE_OID, ",".join(alert_ids)))

        summary = (
            f"Source {src_ip} triggered {', '.join(alert_types)} across "
            f"{len(segments)} segments ({', '.join(sorted(segments))}) "
            f"within {window_seconds}s -- possible reconnaissance / "
            f"lateral movement."
        )

        corr = {
            "correlation_id": correlation_id,
            "src_ip": src_ip,
            "segments": ",".join(sorted(segments)),
            "alert_types": ",".join(alert_types),
            "alert_ids": ",".join(alert_ids),
            "severity": severity,
            "summary": summary,
        }
        storage.insert_correlation(corr)
        new_correlations.append(corr)

    return new_correlations


def correlation_loop(poll_interval, window_seconds, min_segments, stop_event):
    print(f"[correlation] engine started (poll={poll_interval}s, "
          f"window={window_seconds}s, min_segments={min_segments})")
    while not stop_event.is_set():
        try:
            found = run_correlation_pass(window_seconds, min_segments)
            if found:
                for c in found:
                    print(f"[correlation] NEW FINDING: {c['summary']}")
        except Exception as e:
            print(f"[correlation] error during pass: {e}")
        stop_event.wait(poll_interval)
