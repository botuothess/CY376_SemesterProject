"""
detections.py

Lightweight, dependency-free detection logic shared by sensor agents.
Each detector consumes normalized "flow events" (dicts) and emits alert
dicts when a rule fires. Kept intentionally simple/explainable for a
lab/assignment context -- these are illustrative heuristics, not
production-grade signatures.
"""

import time
from collections import defaultdict, deque


class PortScanDetector:
    """Flags a source IP touching many distinct destination ports quickly."""

    def __init__(self, distinct_ports_threshold=15, window_seconds=10):
        self.threshold = distinct_ports_threshold
        self.window = window_seconds
        # src_ip -> deque[(timestamp, dst_port)]
        self._history = defaultdict(deque)

    def process(self, event):
        src = event.get("src_ip")
        dport = event.get("dst_port")
        ts = event["timestamp"]
        if dport is None or src is None:
            return None

        hist = self._history[src]
        hist.append((ts, dport))

        # drop entries outside the window
        cutoff = ts - self.window
        while hist and hist[0][0] < cutoff:
            hist.popleft()

        distinct_ports = {p for _, p in hist}
        if len(distinct_ports) >= self.threshold:
            return {
                "type": "PORT_SCAN",
                "severity": "medium",
                "src_ip": src,
                "detail": f"{len(distinct_ports)} distinct destination ports "
                          f"in {self.window}s (threshold {self.threshold})",
            }
        return None


class SynFloodDetector:
    """Flags a source IP sending many SYNs to one destination quickly."""

    def __init__(self, syn_count_threshold=50, window_seconds=5):
        self.threshold = syn_count_threshold
        self.window = window_seconds
        # (src_ip, dst_ip) -> deque[timestamp]
        self._history = defaultdict(deque)

    def process(self, event):
        if not event.get("syn_flag") or not event.get("src_ip"):
            return None
        key = (event["src_ip"], event.get("dst_ip"))
        ts = event["timestamp"]
        hist = self._history[key]
        hist.append(ts)

        cutoff = ts - self.window
        while hist and hist[0] < cutoff:
            hist.popleft()

        if len(hist) >= self.threshold:
            return {
                "type": "SYN_FLOOD",
                "severity": "high",
                "src_ip": event["src_ip"],
                "detail": f"{len(hist)} SYNs to {event.get('dst_ip')} "
                          f"in {self.window}s (threshold {self.threshold})",
            }
        return None


class ArpSpoofDetector:
    """Flags when one IP address maps to more than one MAC address."""

    def __init__(self):
        self._ip_to_mac = {}

    def process(self, event):
        if event.get("proto") != "ARP":
            return None
        ip = event.get("arp_ip")
        mac = event.get("arp_mac")
        if not ip or not mac:
            return None

        known_mac = self._ip_to_mac.get(ip)
        if known_mac is None:
            self._ip_to_mac[ip] = mac
            return None
        if known_mac != mac:
            alert = {
                "type": "ARP_SPOOF",
                "severity": "high",
                "src_ip": ip,
                "detail": f"IP {ip} seen with MAC {known_mac} then {mac}",
            }
            self._ip_to_mac[ip] = mac  # update, but still alert
            return alert
        return None


class PayloadSignatureDetector:
    """Flags packets whose payload contains a suspicious keyword/pattern."""

    def __init__(self, keywords=None):
        self.keywords = keywords or []

    def process(self, event):
        payload = event.get("payload", "")
        if not payload:
            return None
        for kw in self.keywords:
            if kw.lower() in payload.lower():
                return {
                    "type": "SUSPICIOUS_PAYLOAD",
                    "severity": "medium",
                    "src_ip": event.get("src_ip"),
                    "detail": f"Payload matched signature: {kw!r}",
                }
        return None


class DetectionEngine:
    """Runs all configured detectors against each incoming event."""

    def __init__(self, detection_config):
        ps = detection_config.get("port_scan", {})
        sf = detection_config.get("syn_flood", {})
        arp_cfg = detection_config.get("arp_spoof", {})
        keywords = detection_config.get("suspicious_payload_keywords", [])

        self.detectors = [
            PortScanDetector(
                distinct_ports_threshold=ps.get("distinct_ports_threshold", 15),
                window_seconds=ps.get("window_seconds", 10),
            ),
            SynFloodDetector(
                syn_count_threshold=sf.get("syn_count_threshold", 50),
                window_seconds=sf.get("window_seconds", 5),
            ),
            PayloadSignatureDetector(keywords=keywords),
        ]
        if arp_cfg.get("enabled", True):
            self.detectors.append(ArpSpoofDetector())

    def process_event(self, event):
        """Returns a list of alert dicts (usually 0 or 1) for this event."""
        event.setdefault("timestamp", time.time())
        alerts = []
        for detector in self.detectors:
            result = detector.process(event)
            if result:
                alerts.append(result)
        return alerts
