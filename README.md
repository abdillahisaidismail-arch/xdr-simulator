# XDR Simulator

> **An open-source Extended Detection & Response (XDR) lab in pure Python.**
> Simulates a banking SOC under PCI-DSS constraints: 10 000+ events/day across 3 sources, multi-source correlation, automated detection of 3 incident types, and full audit-ready reporting.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen.svg)](#development)

---

## Table of contents

1. [What is this?](#1-what-is-this)
2. [Key features](#2-key-features)
3. [Prerequisites (macOS)](#3-prerequisites-macos)
4. [Quickstart — copy-paste](#4-quickstart--copy-paste)
5. [How it works (for SOC students)](#5-how-it-works-for-soc-students)
6. [Running scenarios and tuning](#6-running-scenarios-and-tuning)
7. [Output files explained](#7-output-files-explained)
8. [Learning exercises](#8-learning-exercises-blue-team)
9. [Development](#9-development)
10. [Project structure](#10-project-structure)
11. [License](#11-license)

---

## 1. What is this?

This project is a **realistic XDR simulator** designed to help SOC / Blue Team students practice the full detection lifecycle without needing a real SIEM stack.

It was built in the context of a **banking information system under PCI-DSS** (Payment Card Industry Data Security Standard), where every authentication, every privileged action, and every anomaly must be logged, correlated, and auditable.

In one command, it will:

1. **Generate 10 000+ events per day** from three different log sources (Linux Syslog, Filebeat-style application logs, and a JSON REST API).
2. **Parse and normalize** all those events into a common schema.
3. **Correlate** events across sources by IP, user, host, and time window.
4. **Detect three incident types**: SSH brute force, abnormal access, and privilege escalation — each mapped to **MITRE ATT&CK**.
5. **Produce audit-ready reports**: an XDR summary, individual incident reports, a tamper-evident audit trail, and a PCI-DSS compliance report.

It is a self-contained **lab in your terminal** — no Docker, no external services, no API keys.

---

## 2. Key features

- **Multi-source telemetry** — Syslog (auth, sudo, ssh), Filebeat-style JSON (web/app servers), JSON REST API (banking transactions).
- **Correlation engine** — Joins events on IP / user / host within a configurable time window, flags multi-source matches.
- **Detection engine** — Three production-style detection rules:
  - **SSH brute force** → MITRE **T1110** (Brute Force)
  - **Abnormal access** (geo / time / volume) → MITRE **T1078** (Valid Accounts)
  - **Privilege escalation** (sudo abuse, role change) → MITRE **T1548** (Abuse Elevation Control)
- **PCI-DSS compliance** — Audit trail (Req. 10), 90-day rotation, structured incident reports, compliance summary.
- **Plain-text dashboard** — Console summary at the end of every run.
- **Reproducible & deterministic-friendly** — Configurable event count and attack probability for repeatable exercises.
- **27 unit & integration tests** — Validate parsers, generators, detection, and the end-to-end pipeline.

---

## 3. Prerequisites (macOS)

You only need three things: **Homebrew**, **Python 3.11**, and **Git**. VS Code is optional but recommended.

### 3.1 Install Homebrew (if you don't have it)

Open **Terminal** (`Cmd + Space` → type `Terminal`) and run:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Then check it works:

```bash
brew --version
```

> If you see something like `Homebrew 4.x.x`, you're good.

### 3.2 Install Python 3.11

```bash
brew install python@3.11
```

Verify:

```bash
python3.11 --version
# expected: Python 3.11.x
```

### 3.3 Install Git

```bash
brew install git
git --version
```

### 3.4 (Optional) Install VS Code

```bash
brew install --cask visual-studio-code
```

---

## 4. Quickstart — copy-paste

> Open a fresh Terminal and run these commands one by one. They are designed to work on a brand-new Mac.

```bash
# 1) Clone the repo
git clone https://github.com/abdillahisaidismail-arch/xdr-simulator.git
cd xdr-simulator

# 2) Create a virtual environment with Python 3.11
python3.11 -m venv .venv
source .venv/bin/activate

# 3) Upgrade build tools (avoids old packaging bugs)
python -m pip install --upgrade pip setuptools wheel

# 4) Install the project + dev tools (pytest, black, flake8, mypy)
pip install -e ".[dev]"

# 5) Run your first simulation (default: 12,000 events, 12% attack rate)
python -m xdr_simulator
```

When the run finishes, you should see something like:

```
======================================================================
  Simulation complete in 0.42s
  Events: 12,153 | Incidents: 87 | Reports: data/
======================================================================
```

### Where are the outputs?

| Folder | What's inside |
|---|---|
| `data/` | XDR summary report, individual incident reports (`IR-*.json`), audit trail, PCI-DSS report |
| `logs/` | Application logs and rotating audit trail (`xdr_simulator.log`, `audit_trail.log`) |

> Both folders are created automatically the first time you run.

### Don't want editable mode?

```bash
pip install .                # plain install
pip install ".[dev]"         # plain install + dev extras
```

---

## 5. How it works (for SOC students)

The simulator is a **6-phase pipeline**. Each phase is a separate Python module so you can read and modify them independently.

```
┌─────────────────────┐
│ 1. Event generators │   Syslog + Filebeat + JSON API
└──────────┬──────────┘   (raw, source-specific formats)
           │
           ▼
┌─────────────────────┐
│ 2. Parser & normaliser │   Common NormalizedEvent schema
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ 3. Correlation engine │   Joins on IP / user / host / time
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ 4. Detection engine │   3 rules, MITRE ATT&CK mapping
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ 5. PCI-DSS reporting │   Audit trail + incident reports
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ 6. Dashboard        │   Console summary + xdr_report.json
└─────────────────────┘
```

### Phase 1 — Event generators

Three independent generators produce realistic logs:

- **Syslog generator** — Linux `/var/log/auth.log` style: `sshd`, `sudo`, `su`, login successes/failures.
- **Filebeat generator** — application logs in JSON envelope, e.g. web/app servers, MFA events.
- **JSON API generator** — banking transactions and admin API calls.

A small percentage of events are **attacker traffic** (controlled by `--attack-prob`). The rest is realistic noise.

### Phase 2 — Parser & normaliser

Each raw event is converted into a single `NormalizedEvent` object with consistent fields: `timestamp`, `source_ip`, `user`, `host`, `action`, `outcome`, `source_type`, etc. This is what makes correlation possible.

### Phase 3 — Correlation engine

Indexes normalised events by **IP**, **user**, and **host**, then walks them in a sliding time window. When several events share the same key across **different sources**, that's a high-value **multi-source correlation** — exactly what real XDR products try to surface.

### Phase 4 — Detection engine

Three detection rules run on the normalised + correlated events:

| Rule | Trigger | MITRE ATT&CK |
|---|---|---|
| SSH brute force | N failed SSH logins from one IP within window | T1110 |
| Abnormal access | Successful login from unusual IP / time / volume | T1078 |
| Privilege escalation | Sudo to root, unusual `su`, role change | T1548 |

Each detection produces an **Incident** with a severity (`critical / high / medium / low`).

### Phase 5 — PCI-DSS reporting

For every run, the simulator produces:

- One **PCI-DSS compliance report** (`PCI-DSS-YYYYMMDD-HHMMSS.json`)
- One **audit trail** (`audit_trail.json`) — tamper-evident, time-stamped, structured (PCI-DSS Req. 10)
- One **incident report per incident** (`IR-<short-uuid>.json`)

### Phase 6 — Dashboard

A clean console summary, plus a single `xdr_report.json` that you can open or pipe into another tool.

---

## 6. Running scenarios and tuning

The CLI is designed to be self-explanatory:

```bash
python -m xdr_simulator --help
```

### Common scenarios

```bash
# Quiet day — low volume, low attack rate
python -m xdr_simulator --events 5000 --attack-prob 0.05

# Default day
python -m xdr_simulator

# Noisy day — high volume, high attack rate
python -m xdr_simulator --events 25000 --attack-prob 0.30

# Custom output directory
python -m xdr_simulator --output reports/ --log-dir reports/logs

# Suppress dashboard (useful for automation / CI)
python -m xdr_simulator --quiet
```

### All flags

| Flag | Default | Meaning |
|---|---|---|
| `-e`, `--events` | `12000` | Events to generate per simulated day |
| `-a`, `--attack-prob` | `0.12` | Attack probability (`0.0` – `1.0`) |
| `-o`, `--output` | `data` | Output directory (auto-created) |
| `--log-dir` | `logs` | Log directory (auto-created) |
| `-q`, `--quiet` | `False` | Skip the console dashboard |

If you pass an invalid value (e.g. `--attack-prob 2.5`), the CLI rejects it with a clear message and exits cleanly.

---

## 7. Output files explained

### `data/xdr_report.json`

The **main XDR report**. Use it as your "single pane of glass":

- Total events / parsed events / parsing success rate
- Top correlations
- All detected incidents with severity, MITRE technique, evidence
- Execution timing per phase

> **A SOC analyst would** open this first to triage the day.

### `data/IR-<short-uuid>.json`

One **Incident Report** per detected incident:

- Incident ID, type, severity, MITRE technique
- Source IP / user / host
- Timeline of correlated events
- Recommended response actions

> **A SOC analyst would** attach these to the ticket / SOAR playbook.

### `data/audit_trail.json` + `logs/audit_trail.log`

PCI-DSS **Requirement 10** audit trail: every security-relevant action is appended with timestamp, action, and structured details. Rotated, retained for 90 days minimum.

> **A SOC analyst (or auditor) would** use this for forensic timelines and compliance evidence.

### `data/PCI-DSS-YYYYMMDD-HHMMSS.json`

Compliance summary report aligned to PCI-DSS controls (logging, access, monitoring).

> **A GRC analyst would** export this monthly to demonstrate continuous compliance.

### `logs/xdr_simulator.log`

Rotating application log in JSON format (10 MB × 30 backups). Useful when something goes wrong.

---

## 8. Learning exercises (Blue Team)

Try these in order — each one teaches a different piece of the SOC mindset.

### Exercise 1 — Identify SSH brute force

```bash
python -m xdr_simulator --events 8000 --attack-prob 0.05
```

Then open `data/xdr_report.json` and find:
- How many incidents are `ssh_brute_force`?
- For one of them, what is the source IP, the number of failed attempts, and the time window?

### Exercise 2 — Tune the noise

Run the same command with `--attack-prob 0.30`. Compare:
- Total incident count.
- Severity distribution.
- Did multi-source correlations increase?

### Exercise 3 — Trace one incident end-to-end

Pick **one** `IR-*.json` file. Find the related raw events in `xdr_report.json`, then re-run with `--events 3000` and try to spot the same pattern with a smaller dataset. This is exactly how a real analyst pivots from alert → events → root cause.

### Exercise 4 — Add a fourth detection rule

Open `xdr_simulator/detection/detection_engine.py`. Add a rule that flags **more than 5 successful logins for the same user from different IPs in 10 minutes**. Run the test suite (`pytest`) to make sure nothing else breaks.

### Exercise 5 — PCI-DSS audit drill

Pretend you're an external auditor. Open `audit_trail.json` and answer:
- Was simulation start logged? With what timestamp?
- Are timestamps in ISO 8601 UTC?
- Could you reconstruct the full sequence of detections from this file alone?

---

## 9. Development

### Run the test suite

```bash
pytest                  # 27 tests, < 1 second
pytest --cov            # with coverage
```

### Lint, format, type-check

```bash
black xdr_simulator tests        # auto-format
flake8 xdr_simulator tests       # style check
mypy xdr_simulator               # static typing
```

### VS Code

Open the folder, then:

1. `Cmd + Shift + P` → **Python: Select Interpreter** → choose `.venv/bin/python`.
2. Open a terminal inside VS Code (`Ctrl + ` `` ` ``) — your venv is activated automatically.
3. Install the **Python** and **Pylance** extensions if not already.

---

## 10. Project structure

```
xdr-simulator/
├── pyproject.toml              # Modern packaging (PEP 621, setuptools backend)
├── README.md
├── LICENSE                     # MIT
├── config/
│   └── default.yaml            # Tunable thresholds and time windows
├── tests/                      # 27 unit + integration tests
│   ├── test_detection.py
│   ├── test_generators.py
│   ├── test_integration.py
│   └── test_parser.py
└── xdr_simulator/
    ├── __init__.py
    ├── __main__.py             # `python -m xdr_simulator`
    ├── main.py                 # CLI + run_simulation()
    ├── generators/             # Syslog / Filebeat / JSON API + orchestrator
    ├── parsers/                # Event normaliser
    ├── correlation/            # Multi-source correlation engine
    ├── detection/              # 3 detection rules + MITRE mapping
    ├── compliance/             # PCI-DSS reports + audit trail
    ├── dashboard/              # Console + JSON reporter
    └── utils/
        ├── logger.py           # JSON logger + AuditLogger (PCI-DSS Req. 10)
        └── models.py           # Dataclasses (NormalizedEvent, Incident, ...)
```

---

## 11. License

MIT — free to use, learn from, and adapt. See [`LICENSE`](LICENSE).

---

### Author

**Abdillahi Saïd Ismaïl**
L3 Computer Science → Master 1 Cybersecurity (CNAM Bruz, France)
Looking for a 24-month cybersecurity apprenticeship — SOC / Blue Team / GRC.
