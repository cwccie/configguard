# Contributing to ConfigGuard

Thank you for your interest in improving ConfigGuard! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USER/configguard.git`
3. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install in development mode: `pip install -e ".[dev]"`
5. Run tests: `pytest`

## Development Setup

```bash
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest                    # Run all tests
pytest -v                 # Verbose output
pytest tests/test_parser.py  # Specific test file
pytest --cov=configguard  # With coverage
```

## Code Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting:

```bash
ruff check src/
ruff format src/
```

## Adding Compliance Rules

Rules are defined in YAML files under `rules/`. Each rule file follows this structure:

```yaml
framework: nist_800_53  # or cis_benchmark, pci_dss, custom

rules:
  - id: UNIQUE-ID
    title: "Short descriptive title"
    description: "Detailed description"
    control_id: "AC-2"
    severity: critical  # critical, high, medium, low, info
    check_type: config_match
    match_pattern: "regex pattern"
    must_exist: true
    remediation: "Config commands to fix"
    explanation: "Plain English explanation"
    risk_description: "What could go wrong"
    business_impact: "Why the business should care"
```

### Check Types

- `config_match` — Search config for a regex pattern
- `config_absent` — Verify pattern is NOT present
- `service_check` — Check if a service is enabled/disabled
- `interface_check` — Check interface configuration
- `banner_check` — Verify login banner exists
- `password_check` — Check for weak/plaintext passwords
- `snmp_check`, `ntp_check`, `logging_check`, `aaa_check`, etc.

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Write tests for your changes
3. Ensure all tests pass: `pytest`
4. Ensure code is formatted: `ruff check src/ && ruff format src/`
5. Submit a PR with a clear description

## Adding Vendor Support

To add a new vendor parser:

1. Add the vendor to `Vendor` enum in `models.py`
2. Add detection logic in `parser.py:detect_vendor()`
3. Add a parsing method in `ConfigParser`
4. Add sample config in `sample_configs/`
5. Add tests

## Reporting Issues

Please include:
- ConfigGuard version (`configguard --version`)
- Python version (`python --version`)
- Steps to reproduce
- Expected vs actual behavior
- Sample config (sanitized) if applicable

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
