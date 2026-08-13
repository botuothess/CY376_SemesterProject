"""
sensor_agent.py

Runs on (or represents) a single network segment. Two modes:

  - "simulate": generates synthetic but realistic traffic events, including
    injected attack patterns, so the whole framework can be demoed on one
    laptop with no special privileges or network taps. This is the mode
    used by simulate_multi_segment.py.

  - "live": sniffs real traffic from a NIC/mirror port using scapy
    (requires root/admin + npcap on Windows, or CAP_NET_RAW on Linux).

Either way, normalized events are fed through detections.DetectionEngine,
and any fired alerts are POSTed to the central collector.

Usage:
    python sensor_agent.py --segment DMZ --mode simulate
    python sensor_agent.py --segment DMZ --mode live --interface eth0
"""

import argparse
import os
import random
import sys
import time
import uuid
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from detections import DetectionEngine  # noqa: E402


def load_config(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)


class SensorAgent:
    def __init__(self, segment_id, collector_url, api_key, detection_config):
        self.segment_id = segment_id
        self.collector_url = collector_url.rstrip("/")
        self.api_key = api_key
        self.engine = DetectionEngine(detection_config)
        self.session = requests.Session()

    def report_alert(self, alert):
        alert = dict(alert)
        alert["segment_id"] = self.segment_id
        alert["timestamp"] = alert.get("timestamp", time.time())
        alert["alert_id"] = str(uuid.uuid4())
        try:
            resp = self.session.post(
                f"{self.collector_url}/api/alert",
                json=alert,
                headers={"X-API-Key": self.api_key},
                timeout=3,
            )
            if resp.status_code == 200:
                print(f"[{self.segment_id}] ALERT sent: {alert['type']} "
                      f"src={alert.get('src_ip')} ({alert['severity']})")
            else:
                print(f"[{self.segment_id}] collector rejected alert: "
                      f"{resp.status_code} {resp.text}")
        except requests.exceptions.RequestException as e:
            print(f"[{self.segment_id}] failed to reach collector: {e}")

    def handle_event(self, event):
        for alert in self.engine.process_event(event):
            self.report_alert(alert)

    # ------------------------------------------------------------------
    # Simulation mode
    # ------------------------------------------------------------------
    def run_simulation(self, duration=None, attacker_ip_pool=None):
        """
        Generates a mix of benign traffic and periodic injected attacks
        (port scan, SYN flood, ARP spoof, suspicious payload) so the
        detection + correlation pipeline has something real to catch.
        """
        print(f"[{self.segment_id}] starting SIMULATED sensor "
              f"(collector={self.collector_url})")
        attacker_ip_pool = attacker_ip_pool or ["10.13.37.66", "10.13.37.67"]
        internal_hosts = [f"192.168.{random.randint(0,3)}.{i}" for i in range(2, 20)]

        start = time.time()
        tick = 0
        while duration is None or (time.time() - start) < duration:
            tick += 1

            # Mostly benign background traffic
            for _ in range(random.randint(2, 5)):
                event = {
                    "src_ip": random.choice(internal_hosts),
                    "dst_ip": random.choice(internal_hosts),
                    "dst_port": random.choice([80, 443, 53, 22]),
                    "proto": "TCP",
                    "syn_flag": False,
                    "timestamp": time.time(),
                }
                self.handle_event(event)

            # Every ~8 ticks, inject a port scan burst from an "attacker"
            if tick % 8 == 0:
                attacker = random.choice(attacker_ip_pool)
                victim = random.choice(internal_hosts)
                for port in random.sample(range(1, 1024), 20):
                    self.handle_event({
                        "src_ip": attacker,
                        "dst_ip": victim,
                        "dst_port": port,
                        "proto": "TCP",
                        "syn_flag": True,
                        "timestamp": time.time(),
                    })

            # Every ~13 ticks, inject a SYN flood
            if tick % 13 == 0:
                attacker = random.choice(attacker_ip_pool)
                victim = random.choice(internal_hosts)
                for _ in range(60):
                    self.handle_event({
                        "src_ip": attacker,
                        "dst_ip": victim,
                        "dst_port": 443,
                        "proto": "TCP",
                        "syn_flag": True,
                        "timestamp": time.time(),
                    })

            # Every ~17 ticks, inject an ARP spoof
            if tick % 17 == 0:
                victim_ip = random.choice(internal_hosts)
                self.handle_event({
                    "proto": "ARP", "arp_ip": victim_ip,
                    "arp_mac": "AA:AA:AA:AA:AA:01", "timestamp": time.time(),
                })
                self.handle_event({
                    "proto": "ARP", "arp_ip": victim_ip,
                    "arp_mac": "BB:BB:BB:BB:BB:66", "timestamp": time.time(),
                })

            # Every ~21 ticks, inject a suspicious payload
            if tick % 21 == 0:
                attacker = random.choice(attacker_ip_pool)
                self.handle_event({
                    "src_ip": attacker,
                    "dst_ip": random.choice(internal_hosts),
                    "dst_port": 80,
                    "proto": "TCP",
                    "syn_flag": False,
                    "payload": "GET /admin?id=1 SELECT * FROM users",
                    "timestamp": time.time(),
                })

            time.sleep(1)

    # ------------------------------------------------------------------
    # Live capture mode (requires scapy + privileges)
    # ------------------------------------------------------------------
    def run_live(self, interface):
        try:
            from scapy.all import sniff, TCP, IP, ARP  # noqa: E402
        except ImportError:
            print("scapy is required for live mode: pip install scapy")
            sys.exit(1)

        print(f"[{self.segment_id}] starting LIVE sensor on {interface} "
              f"(collector={self.collector_url})")

        def on_packet(pkt):
            event = {"timestamp": time.time()}
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                event.update({
                    "proto": "ARP",
                    "arp_ip": arp.psrc,
                    "arp_mac": arp.hwsrc,
                })
                self.handle_event(event)
                return
            if pkt.haslayer(IP):
                ip = pkt[IP]
                event.update({"src_ip": ip.src, "dst_ip": ip.dst, "proto": "IP"})
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    event["dst_port"] = tcp.dport
                    event["syn_flag"] = bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10)
                    if pkt.haslayer("Raw"):
                        try:
                            event["payload"] = bytes(pkt["Raw"].load).decode(
                                "utf-8", errors="ignore")
                        except Exception:
                            pass
                self.handle_event(event)

        sniff(iface=interface, prn=on_packet, store=False)


def main():
    parser = argparse.ArgumentParser(description="Distributed IDS sensor agent")
    parser.add_argument("--segment", required=True, help="Segment ID, e.g. DMZ")
    parser.add_argument("--mode", choices=["simulate", "live"], default="simulate")
    parser.add_argument("--interface", default=None, help="NIC for live mode")
    default_config = str(Path(__file__).resolve().parent.parent / "config.yaml")
    parser.add_argument("--config", default=default_config)
    parser.add_argument("--duration", type=float, default=None,
                         help="Simulation duration in seconds (default: run forever)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    collector_cfg = cfg["collector"]
    collector_host = os.environ.get("COLLECTOR_HOST", collector_cfg["host"])
    collector_port = os.environ.get("COLLECTOR_PORT", collector_cfg["port"])
    collector_url = f"http://{collector_host}:{collector_port}"

    agent = SensorAgent(
        segment_id=args.segment,
        collector_url=collector_url,
        api_key=collector_cfg["api_key"],
        detection_config=cfg["detection"],
    )

    if args.mode == "simulate":
        agent.run_simulation(duration=args.duration)
    else:
        if not args.interface:
            print("--interface is required for live mode")
            sys.exit(1)
        agent.run_live(args.interface)


if __name__ == "__main__":
    main()
