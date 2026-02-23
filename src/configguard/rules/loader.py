"""YAML rule loader — loads compliance rules from YAML files."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from configguard.models import ComplianceRule, Framework, Severity

logger = logging.getLogger(__name__)

FRAMEWORK_MAP = {
    "nist_800_53": Framework.NIST_800_53,
    "cis_benchmark": Framework.CIS_BENCHMARK,
    "pci_dss": Framework.PCI_DSS,
    "custom": Framework.CUSTOM,
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class RuleLoader:
    """Load compliance rules from YAML files."""

    def load_file(self, filepath: str | Path) -> list[ComplianceRule]:
        """Load rules from a single YAML file."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Rule file not found: {filepath}")

        with open(filepath) as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            logger.warning("No rules found in %s", filepath)
            return []

        rules = []
        framework_default = data.get("framework", "custom")
        for rule_data in data["rules"]:
            try:
                rule = self._parse_rule(rule_data, framework_default)
                rules.append(rule)
            except Exception as e:
                logger.warning("Failed to parse rule in %s: %s", filepath, e)

        logger.info("Loaded %d rules from %s", len(rules), filepath.name)
        return rules

    def load_directory(self, dirpath: str | Path) -> list[ComplianceRule]:
        """Load all rule files from a directory."""
        dirpath = Path(dirpath)
        rules = []
        for filepath in sorted(dirpath.rglob("*.yml")):
            rules.extend(self.load_file(filepath))
        for filepath in sorted(dirpath.rglob("*.yaml")):
            rules.extend(self.load_file(filepath))
        return rules

    def load_builtin_rules(self) -> list[ComplianceRule]:
        """Load all built-in rule sets shipped with ConfigGuard."""
        rules_dir = Path(__file__).parent.parent.parent.parent / "rules"
        if rules_dir.exists():
            return self.load_directory(rules_dir)

        # Try relative to package installation
        import importlib.resources
        logger.warning("Built-in rules directory not found at %s", rules_dir)
        return []

    def _parse_rule(self, data: dict[str, Any],
                    framework_default: str) -> ComplianceRule:
        """Parse a single rule from YAML data."""
        framework_str = data.get("framework", framework_default)
        framework = FRAMEWORK_MAP.get(framework_str, Framework.CUSTOM)
        severity = SEVERITY_MAP.get(data.get("severity", "medium"), Severity.MEDIUM)

        vendor = data.get("vendor", ["all"])
        if isinstance(vendor, str):
            vendor = [vendor]

        return ComplianceRule(
            rule_id=data["id"],
            title=data["title"],
            description=data.get("description", ""),
            framework=framework,
            control_id=data.get("control_id", ""),
            severity=severity,
            vendor=vendor,
            check_type=data.get("check_type", "config_match"),
            match_section=data.get("match_section", "global"),
            match_pattern=data.get("match_pattern", ""),
            must_exist=data.get("must_exist", True),
            must_not_exist=data.get("must_not_exist", False),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
            explanation=data.get("explanation", ""),
            risk_description=data.get("risk_description", ""),
            business_impact=data.get("business_impact", ""),
            metadata=data.get("metadata", {}),
        )
