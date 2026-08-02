# Sentinel-DFIR

Real-time DFIR (Digital Forensics & Incident Response) engine with a web dashboard. Monitors SSH auth, running processes, and persistence mechanisms — maps detections to MITRE ATT&CK.

## Stack

- **Engine** — Python 3.11+, psutil, journald
- **API** — Flask
- **UI** — Vanilla JS / D3 / vis.js

## Setup

```bash
pip install -r requirements.txt
```

Set optional env vars:

```bash
export ABUSEIPDB_API_KEY=your_key_here      # IP enrichment (optional)
export FLASK_DEBUG=1                         # Enable Flask debug mode
export SENTINEL_INCIDENTS_FILE=/path/to/incidents.json
export SENTINEL_CAMPAIGNS_FILE=/path/to/campaigns.json
```

## Run

Start the API server:

```bash
cd api
python3 app.py
```

Start the detection engine (separate terminal):

```bash
python3 -m engine.main
```

Dashboard available at `http://localhost:5000`.

## Detection Coverage

| Attack Type | MITRE ID | Tactic |
|---|---|---|
| SSH Brute Force | T1110 | Credential Access |
| Cron Persistence | T1053.003 | Persistence |
| Reverse Shell | T1059 | Execution |
| File Tampering | T1565 | Impact |

## Demo Attacks

Scripts in `demo/` simulate each attack type and generate incidents automatically. Run them via the **Attack Demos** page in the dashboard, or directly:

```bash
bash demo/ssh_bruteforce_demo.sh
bash demo/persistence_demo.sh
```

## Project Layout

```
Sentinel-DFIR/
├── api/
│   ├── app.py              # Flask app, all routes
│   └── routes/
│       └── control.py      # Engine control + system info endpoints
├── engine/
│   ├── main.py             # Entry point, spawns monitor threads
│   ├── collector.py        # journald SSH log streaming
│   ├── parser.py           # Raw event normalisation
│   ├── correlator.py       # SSH brute-force correlation
│   ├── persistence_correlator.py
│   ├── process_monitor.py  # psutil-based reverse shell detection
│   ├── file_monitor.py     # Crontab change detection
│   ├── file_correlator.py  # File path classification
│   ├── reverse_shell_correlator.py
│   ├── evidence.py         # Incident persistence
│   ├── intel.py            # AbuseIPDB enrichment + campaign tracking
│   ├── risk.py             # Risk scoring
│   ├── mitre.py            # ATT&CK mapping
│   ├── timeline.py         # Event normalisation
│   └── event_bus.py        # In-process event queue
├── ui/                     # Frontend (HTML/CSS/JS)
├── demo/                   # Attack simulation scripts
├── data/                   # incidents.json, campaigns.json (gitignored)
└── test_collector.py       # Smoke test for the collector pipeline
```
