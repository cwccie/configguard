"""Tests for the compliance checker."""

import pytest
from pathlib import Path

from configguard.check.checker import ComplianceChecker
from configguard.models import Framework, Severity


class TestComplianceChecker:
    def test_checker_loads_rules(self, rules_dir):
        checker = ComplianceChecker()
        assert checker.engine.rule_count >= 0

    def test_check_noncompliant_config(self, cisco_config, rules_dir):
        checker = ComplianceChecker(rules_dir=rules_dir)
        parsed = checker.parser.parse_text(cisco_config, device_name="test-rtr")
        report = checker.check_config(parsed)
        assert len(report.findings) > 0
        assert report.compliance_score < 100

    def test_check_has_critical_findings(self, cisco_config, rules_dir):
        checker = ComplianceChecker(rules_dir=rules_dir)
        parsed = checker.parser.parse_text(cisco_config, device_name="test-rtr")
        report = checker.check_config(parsed)
        assert report.critical_count > 0

    def test_check_by_framework(self, cisco_config, rules_dir):
        checker = ComplianceChecker(rules_dir=rules_dir)
        parsed = checker.parser.parse_text(cisco_config, device_name="test-rtr")
        report = checker.check_config(parsed, frameworks=[Framework.NIST_800_53])
        # All findings should be NIST
        for finding in report.findings:
            assert finding.framework == Framework.NIST_800_53

    def test_check_generates_summary(self, cisco_config, rules_dir):
        checker = ComplianceChecker(rules_dir=rules_dir)
        parsed = checker.parser.parse_text(cisco_config, device_name="test-rtr")
        report = checker.check_config(parsed)
        assert report.summary
        assert "Compliance Score" in report.summary

    def test_check_directory(self, sample_configs_dir, rules_dir):
        if not sample_configs_dir.exists():
            pytest.skip("Sample configs not found")
        checker = ComplianceChecker(rules_dir=rules_dir)
        report = checker.check_directory(sample_configs_dir)
        assert len(report.devices) > 0
        assert len(report.findings) > 0

    def test_check_file(self, sample_configs_dir, rules_dir):
        config_file = sample_configs_dir / "cisco_core_router.conf"
        if not config_file.exists():
            pytest.skip("Sample config not found")
        checker = ComplianceChecker(rules_dir=rules_dir)
        report = checker.check_file(config_file)
        assert report.devices == ["cisco_core_router"]
        assert len(report.findings) > 0

    def test_score_breakdown(self, cisco_config, rules_dir):
        checker = ComplianceChecker(rules_dir=rules_dir)
        parsed = checker.parser.parse_text(cisco_config, device_name="test-rtr")
        report = checker.check_config(parsed)
        breakdown = checker.get_score_breakdown(report)
        assert isinstance(breakdown, dict)

    def test_compliant_config_higher_score(self, cisco_config, compliant_config, rules_dir):
        checker = ComplianceChecker(rules_dir=rules_dir)
        bad_parsed = checker.parser.parse_text(cisco_config, device_name="bad")
        good_parsed = checker.parser.parse_text(compliant_config, device_name="good")
        bad_report = checker.check_config(bad_parsed)
        good_report = checker.check_config(good_parsed)
        assert good_report.compliance_score >= bad_report.compliance_score
