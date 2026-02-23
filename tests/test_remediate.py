"""Tests for the remediation engine."""

from configguard.remediate.engine import RemediationEngine
from configguard.models import Finding, RemediationPlan, Severity


class TestRemediationEngine:
    def test_generate_ssh_plan(self):
        engine = RemediationEngine()
        finding = Finding(
            title="SSH not enforced",
            description="Telnet allowed",
            severity=Severity.HIGH,
        )
        plan = engine.generate_plan(finding)
        assert isinstance(plan, RemediationPlan)
        assert "ssh" in plan.config_snippet.lower()
        assert plan.rollback_snippet
        assert plan.risk_assessment
        assert len(plan.validation_steps) > 0

    def test_generate_password_plan(self):
        engine = RemediationEngine()
        finding = Finding(
            title="Plaintext password detected",
            severity=Severity.CRITICAL,
        )
        plan = engine.generate_plan(finding)
        assert "password" in plan.config_snippet.lower() or "encrypt" in plan.config_snippet.lower()

    def test_generate_snmp_plan(self):
        engine = RemediationEngine()
        finding = Finding(
            title="Default SNMP community string",
            severity=Severity.CRITICAL,
        )
        plan = engine.generate_plan(finding)
        assert "snmp" in plan.config_snippet.lower()

    def test_generate_logging_plan(self):
        engine = RemediationEngine()
        finding = Finding(
            title="Logging not configured",
            severity=Severity.HIGH,
        )
        plan = engine.generate_plan(finding)
        assert "logging" in plan.config_snippet.lower()

    def test_generate_ntp_plan(self):
        engine = RemediationEngine()
        finding = Finding(
            title="NTP not configured",
            description="Missing time synchronization",
            severity=Severity.HIGH,
        )
        plan = engine.generate_plan(finding)
        assert "ntp" in plan.config_snippet.lower()

    def test_generate_aaa_plan(self):
        engine = RemediationEngine()
        finding = Finding(
            title="AAA not configured",
            description="No TACACS+ authentication",
            severity=Severity.HIGH,
        )
        plan = engine.generate_plan(finding)
        assert "aaa" in plan.config_snippet.lower()

    def test_generate_plans_multiple(self):
        engine = RemediationEngine()
        findings = [
            Finding(title="SSH issue", severity=Severity.HIGH),
            Finding(title="Password issue", severity=Severity.CRITICAL),
        ]
        plans = engine.generate_plans(findings)
        assert len(plans) == 2

    def test_batfish_validation(self):
        engine = RemediationEngine()
        finding = Finding(title="Test", severity=Severity.LOW)
        plan = engine.generate_plan(finding)
        result = engine.validate_with_batfish(plan)
        assert result["validated"] is True
        assert len(result["checks_passed"]) > 0
        assert plan.batfish_validated is True

    def test_batfish_high_risk_warning(self):
        engine = RemediationEngine()
        finding = Finding(title="AAA authentication", severity=Severity.HIGH)
        plan = engine.generate_plan(finding)
        result = engine.validate_with_batfish(plan)
        # AAA changes should generate warnings
        assert len(result["warnings"]) > 0

    def test_format_plan_text(self):
        engine = RemediationEngine()
        finding = Finding(
            title="Banner not configured",
            device_name="rtr-01",
            severity=Severity.MEDIUM,
        )
        plan = engine.generate_plan(finding)
        text = engine.format_plan_text(plan)
        assert "REMEDIATION PLAN" in text
        assert "CONFIGURATION FIX" in text
        assert "ROLLBACK" in text
        assert "RISK ASSESSMENT" in text
        assert "VALIDATION STEPS" in text

    def test_generic_remediation(self):
        engine = RemediationEngine()
        finding = Finding(
            title="Unknown issue type",
            description="Some obscure finding",
            severity=Severity.LOW,
        )
        plan = engine.generate_plan(finding)
        assert plan.config_snippet  # Should still produce something
