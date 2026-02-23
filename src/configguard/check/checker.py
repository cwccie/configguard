"""Compliance checking engine — orchestrates rule evaluation."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from configguard.ingest.parser import ConfigParser
from configguard.models import (
    ComplianceReport,
    ComplianceRule,
    Finding,
    Framework,
    ParsedConfig,
    Severity,
)
from configguard.rules.engine import RuleEngine
from configguard.rules.loader import RuleLoader

logger = logging.getLogger(__name__)


class ComplianceChecker:
    """Main compliance checking orchestrator.

    Loads rules, parses configs, evaluates compliance, and produces reports.
    """

    def __init__(self, rules_dir: str | Path | None = None,
                 additional_rules: list[ComplianceRule] | None = None) -> None:
        self.parser = ConfigParser()
        self.engine = RuleEngine()
        self.loader = RuleLoader()

        # Load built-in rules
        builtin = self.loader.load_builtin_rules()
        self.engine.add_rules(builtin)

        # Load custom rules directory
        if rules_dir:
            custom = self.loader.load_directory(rules_dir)
            self.engine.add_rules(custom)

        # Add any programmatic rules
        if additional_rules:
            self.engine.add_rules(additional_rules)

        logger.info("ComplianceChecker initialized with %d rules", self.engine.rule_count)

    def check_file(self, filepath: str | Path,
                   frameworks: list[Framework] | None = None) -> ComplianceReport:
        """Check a single configuration file for compliance."""
        config = self.parser.parse_file(filepath)
        return self.check_config(config, frameworks)

    def check_config(self, config: ParsedConfig,
                     frameworks: list[Framework] | None = None) -> ComplianceReport:
        """Check a parsed config for compliance."""
        findings = self.engine.evaluate(config, frameworks)

        # Calculate compliance score
        total_rules = self.engine.rule_count
        violations = len(findings)
        score = max(0.0, (1 - violations / max(total_rules, 1)) * 100)

        report = ComplianceReport(
            devices=[config.device_name],
            frameworks=frameworks or [f for f in Framework],
            findings=findings,
            total_rules_checked=total_rules,
            compliance_score=round(score, 1),
        )

        # Generate summary
        report.summary = self._generate_summary(report)
        return report

    def check_directory(self, directory: str | Path,
                        frameworks: list[Framework] | None = None) -> ComplianceReport:
        """Check all config files in a directory."""
        from configguard.ingest.scanner import DirectoryScanner

        scanner = DirectoryScanner(self.parser)
        configs = scanner.scan(directory)

        all_findings: list[Finding] = []
        devices: list[str] = []

        for config in configs:
            findings = self.engine.evaluate(config, frameworks)
            all_findings.extend(findings)
            devices.append(config.device_name)

        total_rules = self.engine.rule_count * max(len(configs), 1)
        violations = len(all_findings)
        score = max(0.0, (1 - violations / max(total_rules, 1)) * 100)

        report = ComplianceReport(
            devices=devices,
            frameworks=frameworks or [f for f in Framework],
            findings=all_findings,
            total_rules_checked=total_rules,
            compliance_score=round(score, 1),
        )
        report.summary = self._generate_summary(report)
        return report

    def _generate_summary(self, report: ComplianceReport) -> str:
        """Generate an executive summary for a report."""
        lines = [
            f"Compliance Score: {report.compliance_score}%",
            f"Devices Scanned: {len(report.devices)}",
            f"Total Findings: {len(report.findings)}",
            f"  Critical: {report.critical_count}",
            f"  High: {report.high_count}",
            f"  Medium: {report.medium_count}",
            f"  Low: {report.low_count}",
        ]

        if report.critical_count > 0:
            lines.append("\nIMMEDIATE ACTION REQUIRED: Critical findings detected.")
        elif report.high_count > 0:
            lines.append("\nATTENTION: High-severity findings require prompt remediation.")
        elif report.compliance_score >= 90:
            lines.append("\nGood compliance posture. Address remaining findings as scheduled.")
        else:
            lines.append("\nCompliance gaps identified. Review findings and plan remediation.")

        return "\n".join(lines)

    def get_score_breakdown(self, report: ComplianceReport) -> dict[str, float]:
        """Get compliance score broken down by framework."""
        breakdown: dict[str, list[Finding]] = {}
        for finding in report.findings:
            fw = finding.framework.value
            breakdown.setdefault(fw, []).append(finding)

        scores = {}
        rules_per_fw: dict[str, int] = {}
        for rule in self.engine.get_rules():
            fw = rule.framework.value
            rules_per_fw[fw] = rules_per_fw.get(fw, 0) + 1

        for fw, count in rules_per_fw.items():
            violations = len(breakdown.get(fw, []))
            scores[fw] = round(max(0.0, (1 - violations / max(count, 1)) * 100), 1)

        return scores
