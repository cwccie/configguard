# ConfigGuard

**AI-driven network configuration compliance — catch misconfigs before they become breaches.**

[![CI](https://github.com/cwccie/configguard/actions/workflows/ci.yml/badge.svg)](https://github.com/cwccie/configguard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

The average cost of a data breach reached **$4.88 million in 2024** ([IBM Cost of a Data Breach Report](https://www.ibm.com/reports/data-breach)). Network misconfigurations are consistently among the top attack vectors — and they're preventable.

**ConfigGuard** scans your network device configurations against NIST 800-53, CIS Benchmarks, and PCI-DSS frameworks. It explains every violation in plain English, tells you exactly what could go wrong, and generates ready-to-apply remediation configs — validated before you deploy.

## What It Does

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│  Network Configs │────▶│  ConfigGuard │────▶│   Compliance   │
│  (Cisco, JunOS,  │     │              │     │    Report       │
│   Arista, PAN)   │     │  60+ Rules   │     │                │
└─────────────────┘     │  3 Frameworks│     │  Score: 67%    │
                        │  4 Vendors   │     │  12 Findings   │
                        └──────────────┘     │  3 Critical    │
                                              └────────────────┘
```

- **Parse** — Multi-vendor config ingestion (Cisco IOS, JunOS, Arista EOS, Palo Alto PAN-OS)
- **Check** — 60+ compliance rules across three frameworks, with severity scoring
- **Explain** — Plain English descriptions: what's wrong, what could go wrong, business impact
- **Remediate** — Config snippets to fix each violation, with rollback and validation steps
- **Report** — PDF, JSON, CSV reports with executive summary and trend tracking
- **Monitor** — Continuous scanning, drift detection from compliant baselines
- **Integrate** — REST API, web dashboard, CLI

## Compliance Frameworks

| Framework | Controls | Focus |
|-----------|----------|-------|
| **NIST 800-53** | AC, AU, SC families | Access control, audit logging, system protection |
| **CIS Benchmarks** | 20+ checks | Device hardening, service minimization, credential protection |
| **PCI-DSS v4.0** | Requirements 1-10 | Network segmentation, encryption, access control, audit trails |

## Quick Start

### Install

```bash
pip install -e .
```

### Run a Demo

```bash
configguard demo
```

This scans a deliberately misconfigured router and shows findings with explanations.

### Scan Your Configs

```bash
# Scan a single config file
configguard scan router.conf

# Scan a directory of configs
configguard scan /path/to/configs/

# Filter by framework
configguard scan router.conf -f nist_800_53

# Generate a report
configguard scan configs/ -o report.json --format json
```

### Explain Violations

```bash
configguard explain router.conf
```

Output:
```
FINDING: SSH not enforced for remote access
Device: router
Severity: CRITICAL — This must be fixed immediately.

WHAT'S WRONG:
The device does not enforce SSH for management access, allowing unencrypted
protocols like Telnet. All commands, including passwords, are transmitted
in cleartext across the network.

RISK — WHAT COULD GO WRONG:
Any user on the same network segment can capture management traffic with
basic packet sniffing tools (Wireshark, tcpdump). This exposes admin
credentials and all configuration changes in real-time.

BUSINESS IMPACT:
Credential theft leading to full device takeover. Compliance frameworks
universally require encrypted management channels — this finding will
cause automatic audit failure.
```

### Generate Remediation

```bash
configguard remediate router.conf
```

Output includes ready-to-paste config snippets, rollback commands, risk assessment, and validation steps.

### Web Dashboard

```bash
configguard dashboard
# Open http://127.0.0.1:5000
```

### REST API

```bash
# Start the API server
flask --app configguard.api.app:create_app run --port 8080

# Scan a config
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"config": "hostname TEST\nenable password weak\n", "device_name": "test-rtr"}'

# Get findings with explanations
curl http://localhost:8080/api/v1/findings/<finding_id>
```

## Architecture

```
configguard/
├── src/configguard/
│   ├── ingest/        # Multi-vendor config parser
│   │   ├── parser.py      # Cisco IOS, JunOS, Arista EOS, Palo Alto
│   │   ├── scanner.py     # Directory & Git repo scanning
│   │   └── inventory.py   # Config inventory management
│   ├── rules/         # YAML rule engine
│   │   ├── loader.py      # Load rules from YAML files
│   │   └── engine.py      # Rule evaluation engine
│   ├── check/         # Compliance checker
│   │   └── checker.py     # Orchestrates parsing + rule evaluation
│   ├── explain/       # Plain English explainer
│   │   └── explainer.py   # What, risk, impact for each finding
│   ├── remediate/     # Remediation engine
│   │   └── engine.py      # Config generation, rollback, Batfish validation
│   ├── report/        # Report generation
│   │   └── generator.py   # PDF, JSON, CSV, text, trend analysis
│   ├── scan/          # Continuous scanning
│   │   ├── continuous.py  # File watching, scheduled scans
│   │   └── drift.py       # Baseline drift detection
│   ├── api/           # REST API (Flask)
│   ├── dashboard/     # Web dashboard (Flask)
│   ├── cli.py         # Click CLI
│   └── models.py      # Core data models
├── rules/             # Built-in YAML rule sets
│   ├── nist_800_53/       # NIST 800-53 (AC, AU, SC families)
│   ├── cis_benchmarks/    # CIS hardening checks
│   └── pci_dss/           # PCI-DSS requirements
├── sample_configs/    # Sample configs with known violations
├── tests/             # 50+ tests
└── pyproject.toml
```

## Docker

```bash
# Build and run
docker compose up -d

# API available at http://localhost:8080
# Dashboard at http://localhost:5000
```

## Custom Rules

Define your own compliance rules in YAML:

```yaml
framework: custom

rules:
  - id: CUSTOM-001
    title: "OSPF authentication required"
    description: "All OSPF interfaces must use MD5 authentication"
    control_id: NET-001
    severity: high
    check_type: config_match
    match_section: routing
    match_pattern: "ip ospf authentication message-digest"
    must_exist: true
    remediation: |
      interface <INTERFACE>
       ip ospf authentication message-digest
       ip ospf message-digest-key 1 md5 <KEY>
    explanation: "OSPF is running without authentication."
    risk_description: "An attacker on the network can inject rogue routes."
    business_impact: "Traffic interception and black-holing."
```

Load custom rules:

```bash
configguard scan configs/ -r /path/to/custom/rules/
```

## Development

```bash
# Clone and install
git clone https://github.com/cwccie/configguard.git
cd configguard
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/status` | GET | Health check |
| `/api/v1/rules` | GET | List loaded rules |
| `/api/v1/scan` | POST | Scan config text |
| `/api/v1/scan/file` | POST | Upload config file |
| `/api/v1/findings` | GET | List all findings |
| `/api/v1/findings/<id>` | GET | Finding detail with explanation |
| `/api/v1/report/<format>` | GET | Generate report (json, text) |
| `/api/v1/trend` | GET | Compliance score trend data |

## Author

**Corey A. Wade** — CCIE #14124, CISSP

- GitHub: [@cwccie](https://github.com/cwccie)
- 20+ years in network engineering and security

## License

MIT — see [LICENSE](LICENSE)
