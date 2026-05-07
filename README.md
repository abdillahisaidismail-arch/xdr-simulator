# XDR Simulator — Banking SOC

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PCI-DSS v4.0](https://img.shields.io/badge/PCI--DSS-v4.0-critical.svg)](https://www.pcisecuritystandards.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-purple.svg)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/status-portfolio--ready-brightgreen.svg)](#)

> **Extended Detection & Response simulator for a banking information system.**
> Built around the **Banque Centrale de Djibouti** use case, fully compliant
> with **PCI-DSS v4.0** logging, detection and incident-response requirements.
> Includes a real-time **SOC HUD** (dark-themed dashboard) with live KPIs,
> MITRE ATT&CK breakdown, incident feed and run history.

---

## Table of Contents

- [What is this project?](#what-is-this-project)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [The SOC HUD](#the-soc-hud)
- [Detected Incidents (3 types)](#detected-incidents-3-types)
- [PCI-DSS v4.0 Coverage](#pci-dss-v40-coverage)
- [API Reference](#api-reference)
- [Project Layout](#project-layout)
- [Tests](#tests)
- [Roadmap](#roadmap)
- [License](#license)

---

## What is this project?

The **XDR Simulator** reproduces, end-to-end, what a Security Operations Center
team in a regulated banking environment would face during a normal operating
day. It generates realistic security telemetry from three different log
sources, parses and normalises it, runs a **multi-source correlation** pass,
applies **automated detection rules** mapped to **MITRE ATT&CK**, and finally
produces a **PCI-DSS v4.0 audit trail** with one structured incident report
(`IR-*.json`) per detected case.

It is a **portfolio project** designed to demonstrate, in a single repository:

- understanding of **banking regulatory constraints** (PCI-DSS v4.0,
  retention, audit trail, segregation),
- a clean, testable **Python pipeline** (Generators → Parser → Correlation →
  Detection → Compliance → Reporting),
- the ability to ship a **production-grade Flask API** and a polished
  **single-file SOC HUD** (HTML/CSS/JS — no build system required),
- mapping of detections to **MITRE ATT&CK techniques** (T1110, T1078, T1548).

---

## Architecture

```text
┌───────────────────────────────────────────────────────────────────────┐
│                         XDR SIMULATOR PIPELINE                        │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   [1] GENERATORS                                                      │
│       ├── syslog_generator.py     (RFC 5424 — firewalls, SSH, …)      │
│       ├── filebeat_generator.py   (JSON envelope — application logs)  │
│       └── json_generator.py       (REST API — banking core events)    │
│                            │                                          │
│                            ▼                                          │
│   [2] PARSER & NORMALISER                                             │
│       └── event_parser.py         → unified Event model               │
│                            │                                          │
│                            ▼                                          │
│   [3] CORRELATION ENGINE                                              │
│       └── correlation_engine.py   → multi-source matching             │
│                            │                                          │
│                            ▼                                          │
│   [4] DETECTION ENGINE  (3 rules · MITRE-mapped)                      │
│       ├── SSH brute-force          → T1110                            │
│       ├── Abnormal access          → T1078                            │
│       └── Privilege escalation     → T1548                            │
│                            │                                          │
│                            ▼                                          │
│   [5] PCI-DSS COMPLIANCE                                              │
│       ├── compliance_report.json  (Req. 6 / 8 / 10)                   │
│       ├── audit_trail_*.jsonl     (90-day retention)                  │
│       └── IR-<id>.json            (one per incident)                  │
│                            │                                          │
│                            ▼                                          │
│   [6] REPORTING & SOC HUD                                             │
│       ├── reporter.py             → data/xdr_report.json              │
│       └── api.py + hud.html       → http://localhost:5000             │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

Live state is published by `_write_progress()` at every phase to
`data/progress.json`. The HUD polls `/api/progress` every **1.5 s**, so each
phase lights up green progressively while the simulation runs.

---

## Prerequisites

- **Python 3.11+** (tested on 3.11 and 3.12 / macOS, Linux)
- **pip** ≥ 23.0
- A **modern browser** (Chrome, Edge, Firefox, Safari ≥ 16) for the HUD
- **No Node.js, no npm, no webpack** — the dashboard is plain HTML/CSS/JS,
  served by Flask and using two CDN-hosted libraries (Google Fonts +
  [Chart.js 4](https://www.chartjs.org/)).

---

## Installation

```bash
# 1. Clone
git clone https://github.com/abdillahisaidismail-arch/xdr-simulator.git
cd xdr-simulator

# 2. Virtual environment (named .venv as per convention)
python3.11 -m venv .venv
source .venv/bin/activate                # macOS / Linux
# .venv\Scripts\activate                 # Windows PowerShell

# 3. Runtime dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. (Optional) install the package itself in editable mode for the
#    `xdr-simulator` console script
pip install -e .
```

That's it. No compilation, no native extensions.

---

## Usage

The simulator can run in two modes — **single-terminal** (recommended, via the
HUD button) or **two-terminal** (classic CLI workflow).

### Single-terminal — recommended

```bash
python api.py
# Open http://localhost:5000
# → Click ▶ LAUNCH SIMULATION
```

The control bar at the bottom of the HUD lets you tune `--events` and
`--attack-prob` directly, then triggers the run via `POST /api/run`. The
progress bar, KPIs, MITRE chart and incident feed update **live** during
execution.

### Two-terminal — classic

```bash
# Terminal 1 — start the API + HUD
python api.py

# Terminal 2 — run the pipeline (live updates appear in the browser)
python -m xdr_simulator --events 5000 --attack-prob 0.25
```

### CLI options

| Flag                | Default | Description                              |
| ------------------- | ------- | ---------------------------------------- |
| `--events`, `-e`    | `12000` | Number of events to generate per day     |
| `--attack-prob`,`-a`| `0.12`  | Probability of attack events (0.0 – 1.0) |
| `--output`, `-o`    | `data`  | Output directory for reports             |
| `--log-dir`         | `logs`  | Directory for application logs           |
| `--quiet`, `-q`     | off     | Suppress the textual dashboard           |

Examples:

```bash
python -m xdr_simulator --events 20000                  # bigger run
python -m xdr_simulator --events 5000 --attack-prob 0.4 # heavy attack day
python -m xdr_simulator --output reports/ --quiet       # CI-friendly
```

---

## The SOC HUD

The HUD lives at `http://localhost:5000` and is a **single-file** dark-theme
dashboard with the same look-and-feel as a real bank SOC console.

What it shows:

| Panel                  | What it tells you                                                  |
| ---------------------- | ------------------------------------------------------------------ |
| **KPI strip**          | Total events · Incidents · Critical · Correlations · Parse rate    |
| **Events by Severity** | Bar chart (Critical / High / Medium / Low / Info)                  |
| **Incident Feed**      | Live, click any row to open a full incident modal (PCI-DSS Req. 10)|
| **MITRE ATT&CK**       | T1110 · T1078 · T1548 with relative volume bars                    |
| **Pipeline Health**    | The 5 pipeline phases light up in real time                        |
| **Log Sources**        | Distribution Syslog / Filebeat / JSON API + severity donut         |
| **Recent Runs**        | History of past simulations (timestamp · events · incidents)       |
| **PCI-DSS v4.0**       | Status of requirements 6 / 8 / 10 + 90-day retention check         |

Keyboard shortcuts: `R` refresh, `A` toggle auto-poll, `L` launch a run,
`Esc` close the incident modal.

---

## Detected Incidents (3 types)

Every detection rule produces a structured `IR-<id>.json` file under `data/`
and is mapped to a **MITRE ATT&CK technique**.

| #   | Incident type             | MITRE   | Severity range | Trigger logic (summary)                                            |
| --- | ------------------------- | ------- | -------------- | ------------------------------------------------------------------ |
| 1   | **SSH Brute Force**       | `T1110` | High → Critical| ≥ N failed SSH auths from the same source IP within a short window |
| 2   | **Abnormal Access**       | `T1078` | Medium → High  | Valid credentials used from an unusual location / outside business hours |
| 3   | **Privilege Escalation**  | `T1548` | Critical       | `sudo` / role change shortly after a suspicious authentication event|

Each incident report contains: `incident_id`, `incident_type`, `severity`,
`mitre_technique`, `source_ip`, `target`, `event_count`, `description`,
`recommended_action`, and a `pci_dss` reference (Req. 10 audit entry).

---

## PCI-DSS v4.0 Coverage

| Requirement     | How the simulator addresses it                                  |
| --------------- | --------------------------------------------------------------- |
| **Req. 6**      | Documented detection rules with versioned MITRE mapping         |
| **Req. 8**      | Authentication / privilege escalation events fully traced       |
| **Req. 10**     | Append-only audit trail (`audit_trail_*.jsonl`) + per-incident report (`IR-*.json`) |
| **Retention**   | 90-day rotation policy enforced by the compliance module        |

---

## API Reference

All routes are exposed by `api.py` on `http://localhost:5000`.

| Method | Route                | Description                                              |
| ------ | -------------------- | -------------------------------------------------------- |
| GET    | `/`                  | Serves the SOC HUD (`hud.html`)                          |
| GET    | `/api/status`        | Health check (server time, project root, version)        |
| GET    | `/api/progress`      | Live pipeline state (phase 0–5 + counters)               |
| GET    | `/api/report`        | Final XDR report (`data/xdr_report.json`)                |
| GET    | `/api/incidents`     | All individual incident reports (`IR-*.json`)            |
| GET    | `/api/history`       | History of past simulation runs                          |
| GET    | `/api/run/status`    | Status of the current `/api/run` subprocess              |
| POST   | `/api/run`           | Launch a new simulation — body `{"events": 5000, "attack_prob": 0.25}` |

CORS is permissive on `/*` to allow opening `hud.html` directly from disk
during development.

---

## Project Layout

```text
xdr-simulator/
├── api.py                          ← Flask API + HUD server (port 5000)
├── requirements.txt                ← Runtime deps (Flask, flask-cors, PyYAML)
├── pyproject.toml                  ← Packaging metadata
├── README.md
├── LICENSE
├── tests/                          ← Pytest test suite
│   ├── test_detection.py
│   ├── test_generators.py
│   ├── test_integration.py
│   └── test_parser.py
├── xdr_simulator/
│   ├── __main__.py                 ← `python -m xdr_simulator`
│   ├── main.py                     ← 6-phase pipeline + _write_progress()
│   ├── generators/                 ← Syslog / Filebeat / JSON API
│   ├── parsers/                    ← Normalisation
│   ├── correlation/                ← Multi-source correlation
│   ├── detection/                  ← 3 detection rules (MITRE)
│   ├── compliance/                 ← PCI-DSS v4.0 + audit trail
│   ├── dashboard/
│   │   ├── reporter.py             ← Builds data/xdr_report.json
│   │   └── hud.html                ← Single-file SOC HUD
│   └── utils/
└── data/                           ← Created at runtime
    ├── progress.json               ← Live pipeline state (HUD reads this)
    ├── xdr_report.json             ← Final report (phase 6)
    ├── history.json                ← Run history
    └── IR-*.json                   ← One file per detected incident
```

---

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The suite covers parsers, generators, the detection engine and an end-to-end
integration scenario that runs a small simulation and checks the produced
artefacts.

---

## Roadmap

- [ ] More detection rules (data exfiltration, lateral movement)
- [ ] Sigma rule export
- [ ] Optional ElasticSearch sink for the audit trail
- [ ] Server-Sent Events (SSE) instead of HUD polling
- [ ] Docker image (`docker run -p 5000:5000 xdr-simulator`)

---

## License

[MIT](LICENSE) © Abdillahi Said Ismail — banking cybersecurity portfolio
project.
