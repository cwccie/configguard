"""Tests for the rule loader and rule engine."""

import pytest
from pathlib import Path

from configguard.rules.loader import RuleLoader
from configguard.rules.engine import RuleEngine
from configguard.models import ComplianceRule, Framework, Severity


class TestRuleLoader:
    def test_load_nist_rules(self, rules_dir):
        loader = RuleLoader()
        nist_dir = rules_dir / "nist_800_53"
        if nist_dir.exists():
            rules = loader.load_directory(nist_dir)
            assert len(rules) >= 15

    def test_load_cis_rules(self, rules_dir):
        loader = RuleLoader()
        cis_dir = rules_dir / "cis_benchmarks"
        if cis_dir.exists():
            rules = loader.load_directory(cis_dir)
            assert len(rules) >= 15

    def test_load_pci_rules(self, rules_dir):
        loader = RuleLoader()
        pci_dir = rules_dir / "pci_dss"
        if pci_dir.exists():
            rules = loader.load_directory(pci_dir)
            assert len(rules) >= 10

    def test_load_all_builtin(self, rules_dir):
        loader = RuleLoader()
        rules = loader.load_directory(rules_dir)
        assert len(rules) >= 40  # Total across all frameworks

    def test_load_nonexistent_file(self):
        loader = RuleLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_file("/nonexistent/rules.yml")

    def test_rule_has_required_fields(self, rules_dir):
        loader = RuleLoader()
        rules = loader.load_directory(rules_dir)
        for rule in rules:
            assert rule.rule_id
            assert rule.title
            assert isinstance(rule.severity, Severity)
            assert isinstance(rule.framework, Framework)


class TestRuleEngine:
    def test_add_rules(self):
        engine = RuleEngine()
        rules = [
            ComplianceRule(rule_id="TEST-1", title="Test Rule",
                           description="test", framework=Framework.CUSTOM,
                           control_id="T-1", severity=Severity.HIGH),
        ]
        engine.add_rules(rules)
        assert engine.rule_count == 1

    def test_get_rules_by_framework(self):
        engine = RuleEngine()
        rules = [
            ComplianceRule(rule_id="NIST-1", title="NIST Rule",
                           description="", framework=Framework.NIST_800_53,
                           control_id="AC-1", severity=Severity.HIGH),
            ComplianceRule(rule_id="CIS-1", title="CIS Rule",
                           description="", framework=Framework.CIS_BENCHMARK,
                           control_id="1.1", severity=Severity.MEDIUM),
        ]
        engine.add_rules(rules)
        nist_rules = engine.get_rules(Framework.NIST_800_53)
        assert len(nist_rules) == 1
        assert nist_rules[0].rule_id == "NIST-1"

    def test_evaluate_must_exist_violation(self, cisco_config):
        from configguard.ingest.parser import ConfigParser
        engine = RuleEngine()
        engine.add_rules([
            ComplianceRule(
                rule_id="TEST-SSH", title="SSH Required",
                description="SSH must be used", framework=Framework.CUSTOM,
                control_id="T-1", severity=Severity.HIGH,
                check_type="config_match", match_section="line",
                match_pattern="transport input ssh$",
                must_exist=True,
            ),
        ])
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        findings = engine.evaluate(config)
        assert len(findings) >= 1

    def test_evaluate_must_not_exist_violation(self, cisco_config):
        from configguard.ingest.parser import ConfigParser
        engine = RuleEngine()
        engine.add_rules([
            ComplianceRule(
                rule_id="TEST-FINGER", title="Finger Disabled",
                description="Finger must be disabled", framework=Framework.CUSTOM,
                control_id="T-2", severity=Severity.MEDIUM,
                check_type="config_match",
                match_pattern="service finger",
                must_not_exist=True, must_exist=False,
            ),
        ])
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        findings = engine.evaluate(config)
        assert len(findings) >= 1

    def test_evaluate_compliant_config(self, compliant_config):
        from configguard.ingest.parser import ConfigParser
        engine = RuleEngine()
        engine.add_rules([
            ComplianceRule(
                rule_id="TEST-ENCRYPT", title="Password Encryption",
                description="", framework=Framework.CUSTOM,
                control_id="T-3", severity=Severity.HIGH,
                check_type="config_match",
                match_pattern="service password-encryption",
                must_exist=True,
            ),
        ])
        parser = ConfigParser()
        config = parser.parse_text(compliant_config, device_name="test")
        findings = engine.evaluate(config)
        assert len(findings) == 0

    def test_vendor_filtering(self, cisco_config):
        from configguard.ingest.parser import ConfigParser
        engine = RuleEngine()
        engine.add_rules([
            ComplianceRule(
                rule_id="JUNOS-ONLY", title="JunOS Only Rule",
                description="", framework=Framework.CUSTOM,
                control_id="J-1", severity=Severity.HIGH,
                vendor=["junos"],
                check_type="config_match",
                match_pattern="nonexistent",
                must_exist=True,
            ),
        ])
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        findings = engine.evaluate(config)
        assert len(findings) == 0  # Rule should be skipped for Cisco

    def test_finding_deduplication(self, cisco_config):
        from configguard.ingest.parser import ConfigParser
        engine = RuleEngine()
        # Two rules that would produce findings with same dedup key
        engine.add_rules([
            ComplianceRule(
                rule_id="DUP-1", title="Duplicate Check",
                description="", framework=Framework.CUSTOM,
                control_id="D-1", severity=Severity.HIGH,
                check_type="config_match",
                match_pattern="ip ssh version 2",
                must_exist=True,
            ),
            ComplianceRule(
                rule_id="DUP-2", title="Duplicate Check",
                description="", framework=Framework.CUSTOM,
                control_id="D-1", severity=Severity.HIGH,
                check_type="config_match",
                match_pattern="ip ssh version 2",
                must_exist=True,
            ),
        ])
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        findings = engine.evaluate(config)
        # Should be deduplicated (both rules fire but produce same dedup key)
        assert len(findings) == 1
