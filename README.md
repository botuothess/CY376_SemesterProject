# distributed_ids

A distributed intrusion detection framework for multi-segment network
monitoring, built in Python. Each network segment runs its own lightweight
sensor agent; a central collector aggregates alerts and runs a
cross-segment correlation engine to surface attack patterns invisible to
any single segment on its own (e.g. one source IP scanning the DMZ, then
appearing in the internal segment minutes later).

## Architecture

```
 Segment: DMZ        Segment: INTERNAL     Segment: OT_IOT
 ┌─────────────┐     ┌─────────────┐       ┌─────────────┐
 │ sensor_agent│     │ sensor_agent│       │ sensor_agent│
 │  detections │     │  detections │       │  detections │
 └──────┬──────┘     └──────┬──────┘       └──────┬──────┘
        │  POST /api/alert (JSON, API-key auth)    │
        └───────────────────┼───────────────────────┘
                             ▼
                  ┌────────────────────┐
                  │     collector       │
                  │  Flask API + SQLite │
                  │  correlation engine │  (background thread)
                  │  live dashboard     │
                  └────────────────────┘
```

- **Sensor agent** (`agent/sensor_agent.py`): one instance per monitored
  segment. Reads packets (live via `scapy`, or synthetic in simulation
  mode), normalizes them into flow events, and runs them through a
  detection engine.
- **Detection engine** (`agent/detections.py`): pluggable rule-based
  detectors — port scan, SYN flood, ARP spoofing, suspicious payload
  signature matching. Each is a small, independently testable class.
- **Collector** (`collector/app.py`): Flask REST API that receives
  alerts, persists them to SQLite (`collector/storage.py`), and serves
  the live dashboard.
- **Correlation engine** (`collector/correlation.py`): background thread
  that periodically groups recent alerts by source IP and flags any
  source seen across `cross_segment_min_segments` or more distinct
  segments within `cross_segment_window_seconds` — this is the "why
  distributed matters" piece of the assignment.
- **Dashboard** (`dashboard/templates/index.html`): live-polling web UI
  showing segment topology, the raw alert feed, and correlated findings.

## Setup

### Option A: One command, no Docker needed (recommended if Docker isn't available)

```bash
pip install -r requirements.txt
python run.py
```

`run.py` starts the collector and the simulated multi-segment sensors
together as two child processes, waits for the collector to come up,
and opens your browser to the dashboard automatically. Alerts start
appearing within seconds; a cross-segment correlation finding usually
shows up within 10-20 seconds. Press `Ctrl+C` once to stop both
processes cleanly.

This doesn't require Docker, admin/root privileges, or virtualization
support — it's plain Python subprocesses, so it works even on machines
where Docker Desktop can't start (e.g. no hardware virtualization
available, or it conflicts with other hypervisors like VMware/VirtualBox).

### Option B: Docker (if you have it working)

```bash
docker compose up --build
```

This builds the image once and starts two containers: the collector
(dashboard at http://127.0.0.1:5000) and the simulated multi-segment
sensors, already wired together on a private Docker network. Requires
Docker Desktop (or Docker Engine + Compose plugin) with a working
virtualization backend.

- Alerts start appearing within seconds; correlated cross-segment
  findings appear shortly after.
- The SQLite database persists in a named Docker volume (`ids-data`)
  across restarts. To wipe it and start fresh: `docker compose down -v`.
- To stop: `Ctrl+C`, then `docker compose down`.
- Only the simulated sensors run in Docker by default — live packet
  capture (`--mode live`) needs host network access and raw-socket
  privileges that aren't set up in the compose file, so run that mode
  natively (see "Running against real traffic" below) rather than in
  a container.

### Option C: Run each piece by hand

```bash
cd distributed_ids
pip install -r requirements.txt
```

(`scapy` is only needed if you plan to run a sensor in `--mode live`
against a real interface; simulation mode works without it.)

## Running the demo (simulation mode — no root/privileges needed)

**Terminal 1 — start the collector:**
```bash
cd collector
python app.py
```

**Terminal 2 — start all simulated segment sensors at once:**
```bash
python simulate_multi_segment.py
```

**Browser:** open http://127.0.0.1:5000 to watch alerts and cross-segment
correlations appear live, roughly every few seconds. The simulator
periodically injects a port scan, a SYN flood, an ARP spoof, and a
suspicious payload from a shared "attacker" IP across all three
simulated segments, so you should see a correlated finding appear
within ~10–20 seconds.

Alternatively, run individual agents by hand (useful if you want to
demo segments as genuinely separate processes/machines):
```bash
python agent/sensor_agent.py --segment DMZ --mode simulate
python agent/sensor_agent.py --segment INTERNAL --mode simulate
python agent/sensor_agent.py --segment OT_IOT --mode simulate
```

## Running against real traffic (live mode)

1. Set up a SPAN/mirror port or tap for the segment.
2. Edit `config.yaml`, set that segment's `mode: live` and `interface`
   to the correct NIC name.
3. Run with elevated privileges (needed for raw packet capture):
   ```bash
   sudo python agent/sensor_agent.py --segment DMZ --mode live --interface eth0
   ```

Live mode uses the same `DetectionEngine` as simulation mode — packets
are normalized into the same event schema, so no detection logic
changes between the two modes.

## API reference (collector)

| Endpoint              | Method | Description                                   |
|------------------------|--------|------------------------------------------------|
| `/api/alert`           | POST   | Sensor agents report an alert (requires `X-API-Key` header) |
| `/api/alerts`          | GET    | Recent raw alerts (`?limit=N`)                |
| `/api/correlations`    | GET    | Recent cross-segment correlated findings (`?limit=N`) |
| `/api/stats`           | GET    | Summary counts by segment/type                |
| `/`                    | GET    | Live dashboard                                |

## Configuration

All tunables live in `config.yaml`: collector host/port/API key, which
segments exist and their mode/interface, detection thresholds (port
scan sensitivity, SYN flood sensitivity, payload signature list), and
correlation parameters (time window, minimum segment count to flag).

## Design notes / talking points for write-up

- **Why distributed rather than one IDS box for the whole network?**
  A single sensor at the network core sees aggregate traffic but loses
  segment context, and it's a single point of failure/blind spot for
  segmented or air-gapped zones (e.g. OT/IoT). Per-segment sensors keep
  visibility even if segments are isolated from each other, and let the
  collector reason about *where* an attacker has been seen, not just
  *that* something looked bad.
- **Why a separate correlation stage instead of alerting per-sensor?**
  Individual detectors on one sensor only see their own segment. The
  correlation engine is what actually detects lateral movement /
  reconnaissance patterns — the distinguishing capability of a
  *distributed* IDS versus N independent IDS instances.
- **Extending detection**: add a new detector class in
  `agent/detections.py` following the existing pattern (a `process(event)`
  method returning an alert dict or `None`), then register it in
  `DetectionEngine.__init__`.
- **Known simplifications** (worth calling out in an assignment
  write-up): alerts are transported over plain HTTP with a shared API
  key rather than mTLS/Kafka (fine for a lab, not for production);
  SQLite rather than a real time-series store; detection rules are
  simple threshold heuristics, not full signature/anomaly ML models.
  These are the natural "next steps" to mention if asked how you'd
  productionize it.

## Project layout

```
distributed_ids/
├── agent/
│   ├── sensor_agent.py     # per-segment sensor (simulate or live capture)
│   └── detections.py       # detection rule engine
├── collector/
│   ├── app.py               # Flask API + dashboard server
│   ├── correlation.py       # cross-segment correlation engine
│   └── storage.py           # SQLite persistence layer
├── dashboard/
│   └── templates/index.html # live dashboard UI
├── simulate_multi_segment.py # launches all segment agents at once
├── run.py                    # one-command launcher (no Docker needed)
├── Dockerfile
├── docker-compose.yml
├── config.yaml
├── requirements.txt
└── README.md
```
