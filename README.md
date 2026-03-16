# XDR Simulator — Extended Detection & Response

<div align="center">

**Simulateur XDR pour infrastructure bancaire critique sous contrainte PCI-DSS**

*Développé dans le cadre d'un stage à la Banque Centrale de Djibouti (Mai–Juillet 2025)*

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![PCI-DSS](https://img.shields.io/badge/PCI--DSS-v4.0-green)
![License](https://img.shields.io/badge/License-MIT-blue)
![Events](https://img.shields.io/badge/Events-+10%2C000%2Fday-orange)

</div>

---

## Overview

Simulateur **Extended Detection & Response (XDR)** traitant **+10 000 événements/jour** provenant de trois sources hétérogènes (Syslog, Filebeat, JSON API). Le système réalise une **corrélation multi-sources** et une **détection automatisée** de trois types d'incidents dans un environnement bancaire critique.

### Résultats clés

| Métrique | Valeur |
|----------|--------|
| Volume de traitement | **+10 000 événements/jour** |
| Sources corrélées | **3** (Syslog, Filebeat, JSON) |
| Types d'incidents détectés | **3** (brute force SSH, accès anormaux, élévation de privilèges) |
| Réduction temps de détection | **-40%** |
| Conformité | **PCI-DSS v4.0** |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    XDR SIMULATOR                             │
├──────────────┬──────────────┬──────────────────────────────┤
│              │              │                              │
│  ┌────────┐  │  ┌────────┐  │  ┌──────────┐               │
│  │ Syslog │  │  │Filebeat│  │  │ JSON API │  Event Sources │
│  │  40%   │  │  │  35%   │  │  │   25%    │               │
│  └───┬────┘  │  └───┬────┘  │  └────┬─────┘               │
│      │       │      │       │       │                      │
│      └───────┴──────┴───────┴───────┘                      │
│                      │                                     │
│              ┌───────▼────────┐                             │
│              │  Event Parser  │  Normalization Layer        │
│              │  & Normalizer  │                             │
│              └───────┬────────┘                             │
│                      │                                     │
│              ┌───────▼────────┐                             │
│              │  Correlation   │  Multi-Source Correlation   │
│              │    Engine      │  (4 rules, sliding window)  │
│              └───────┬────────┘                             │
│                      │                                     │
│              ┌───────▼────────┐                             │
│              │   Detection    │  Automated Detection        │
│              │    Engine      │  (3 incident types)         │
│              └───────┬────────┘                             │
│                      │                                     │
│         ┌────────────┼────────────┐                        │
│         │            │            │                        │
│  ┌──────▼─────┐ ┌────▼─────┐ ┌───▼──────┐                │
│  │  PCI-DSS   │ │Dashboard │ │ Incident │  Output Layer   │
│  │ Compliance │ │ Reporter │ │ Reports  │                │
│  └────────────┘ └──────────┘ └──────────┘                │
└─────────────────────────────────────────────────────────────┘
```

---

## Fonctionnalités

### Génération d'événements
- **Syslog** : authentification SSH, sudo, PAM, services système, pare-feu
- **Filebeat** : logs HTTP, logs applicatifs, logs pare-feu, événements structurés
- **JSON API** : transactions bancaires, authentification API, monitoring système, audit

### Corrélation multi-sources
- Corrélation par IP source, utilisateur, hostname
- Fenêtre glissante configurable (5 min – 1 heure)
- Détection de patterns multi-sources (attaques cross-platform)
- 4 règles de corrélation prédéfinies

### Détection automatisée

| Type d'incident | MITRE ATT&CK | Seuil |
|-----------------|---------------|-------|
| **Brute Force SSH** | T1110 — Brute Force | 5 échecs / 5 min |
| **Accès Anormaux** | T1078 — Valid Accounts | IP externe + hors heures + chemin sensible |
| **Élévation de Privilèges** | T1548 — Abuse Elevation Control | 2+ tentatives sudo/su échouées |

### Conformité PCI-DSS v4.0
- **Req 10.2** : Pistes d'audit automatisées
- **Req 10.3** : Champs d'audit normalisés (utilisateur, type, timestamp, résultat, origine, ressource)
- **Req 10.5** : Intégrité des logs (rotation, rétention)
- **Req 10.6** : Revue automatisée quotidienne
- **Req 11.4** : Détection d'intrusion (IDS)
- **Req 12.10** : Documentation de réponse aux incidents

---

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/abdillahisaidismail-arch/xdr-simulator.git
cd xdr-simulator

# Installer (Python 3.11+ requis)
pip install -e .

# Ou avec les dépendances de développement
pip install -e ".[dev]"
```

## Utilisation

### Exécution rapide

```bash
# Simulation par défaut (12 000 événements/jour)
python -m xdr_simulator

# Personnaliser le volume
python -m xdr_simulator --events 20000

# Augmenter la probabilité d'attaque
python -m xdr_simulator --attack-prob 0.25

# Sortie silencieuse (pas de dashboard)
python -m xdr_simulator --quiet --output reports/
```

### Utilisation programmatique

```python
from xdr_simulator.main import run_simulation

results = run_simulation(
    events_per_day=15000,
    attack_probability=0.15,
    output_dir="data",
    verbose=True,
)

print(f"Incidents détectés : {results['incidents']}")
print(f"Types : {results['incident_types']}")
```

### Options CLI

| Option | Description | Défaut |
|--------|-------------|--------|
| `--events`, `-e` | Nombre d'événements/jour | 12000 |
| `--attack-prob`, `-a` | Probabilité d'attaque (0.0-1.0) | 0.12 |
| `--output`, `-o` | Répertoire de sortie | `data/` |
| `--log-dir` | Répertoire des logs | `logs/` |
| `--quiet`, `-q` | Désactiver le dashboard | `false` |

---

## Sortie

Le simulateur produit :

```
data/
├── PCI-DSS-YYYYMMDD-HHMMSS.json    # Rapport de conformité PCI-DSS
├── audit_trail.json                  # Piste d'audit complète (Req 10.2)
├── IR-XXXXXXXX.json                  # Rapports d'incidents individuels (Req 12.10)
└── xdr_report.json                   # Rapport de synthèse

logs/
├── xdr_simulator.log                # Logs applicatifs (JSON structuré)
└── audit_trail.log                  # Piste d'audit opérationnelle
```

---

## Tests

```bash
# Exécuter tous les tests
python -m pytest tests/ -v

# Avec couverture de code
python -m pytest tests/ -v --cov=xdr_simulator --cov-report=term-missing

# Tests spécifiques
python -m pytest tests/test_detection.py -v
python -m pytest tests/test_integration.py -v
```

---

## Structure du projet

```
xdr-simulator/
├── xdr_simulator/
│   ├── __init__.py              # Package principal
│   ├── __main__.py              # Point d'entrée CLI
│   ├── main.py                  # Pipeline principal
│   ├── generators/
│   │   ├── syslog_generator.py  # Générateur Syslog
│   │   ├── filebeat_generator.py # Générateur Filebeat
│   │   ├── json_generator.py    # Générateur JSON API
│   │   └── event_orchestrator.py # Orchestrateur multi-sources
│   ├── parsers/
│   │   └── event_parser.py      # Parseur et normalisateur
│   ├── correlation/
│   │   └── correlation_engine.py # Moteur de corrélation
│   ├── detection/
│   │   └── detection_engine.py  # Moteur de détection (3 règles)
│   ├── compliance/
│   │   └── pci_dss.py           # Module conformité PCI-DSS
│   ├── dashboard/
│   │   └── reporter.py          # Dashboard et rapports
│   └── utils/
│       ├── logger.py            # Logging structuré
│       └── models.py            # Modèles de données
├── tests/
│   ├── test_generators.py
│   ├── test_parser.py
│   ├── test_detection.py
│   └── test_integration.py
├── config/
│   └── default.yaml
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Scénario d'attaque simulé

Le simulateur injecte un scénario d'attaque coordonné multi-phase :

| Phase | Heure | Description | Source |
|-------|-------|-------------|--------|
| **1. Reconnaissance** | 02:00–02:30 | Brute-force SSH (30-60 tentatives) | Syslog |
| **2. Accès initial** | 02:30 | Login SSH réussi avec compte compromis | Syslog |
| **3. Escalade** | 03:00–03:30 | Tentatives sudo, modification permissions | Syslog |
| **4. Exfiltration** | 03:30–04:00 | Accès données via API, export bulk | Filebeat |

---

## Technologies

- **Python 3.11+** — Langage principal
- **Architecture modulaire** — Séparation nette génération / parsing / corrélation / détection
- **MITRE ATT&CK** — Mapping des incidents sur le framework ATT&CK
- **PCI-DSS v4.0** — Conformité des pistes d'audit et rapports
- **Structured logging** — Logs JSON pour intégration SIEM

---

## Contexte

Ce projet a été développé lors d'un **stage de trois mois à la Banque Centrale de Djibouti** (Mai–Juillet 2025). L'environnement de déploiement : un SI bancaire critique sous contrainte **PCI-DSS**, avec de vraies exigences de traçabilité et de documentation opérationnelle.

---

## Auteur

**Abdillahi Said Ismail**

## Licence

MIT License — voir [LICENSE](LICENSE)
