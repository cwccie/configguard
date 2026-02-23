"""Tests for the violation explainer."""

from configguard.explain.explainer import ViolationExplainer
from configguard.models import Finding, Framework, Severity


class TestViolationExplainer:
    def test_explain_returns_all_keys(self):
        explainer = ViolationExplainer()
        finding = Finding(
            title="SSH not configured",
            description="SSH is not enabled",
            severity=Severity.HIGH,
            framework=Framework.NIST_800_53,
            control_id="AC-17",
        )
        result = explainer.explain(finding)
        assert "what" in result
        assert "risk" in result
        assert "impact" in result
        assert "recommendation" in result
        assert "severity_context" in result

    def test_explain_password_finding(self):
        explainer = ViolationExplainer()
        finding = Finding(
            title="Plaintext password detected",
            description="Password stored in plaintext",
            severity=Severity.CRITICAL,
        )
        result = explainer.explain(finding)
        assert "password" in result["what"].lower() or "credential" in result["what"].lower()

    def test_explain_ssh_finding(self):
        explainer = ViolationExplainer()
        finding = Finding(
            title="SSH not enforced",
            description="Telnet allowed on VTY",
            severity=Severity.HIGH,
        )
        result = explainer.explain(finding)
        assert len(result["what"]) > 20

    def test_explain_text_format(self):
        explainer = ViolationExplainer()
        finding = Finding(
            title="SNMP default community",
            description="Default SNMP community string",
            severity=Severity.CRITICAL,
            device_name="rtr-01",
            framework=Framework.CIS_BENCHMARK,
            control_id="2.1.1",
        )
        text = explainer.explain_text(finding)
        assert "FINDING:" in text
        assert "rtr-01" in text
        assert "CRITICAL" in text
        assert "WHAT'S WRONG:" in text
        assert "RISK" in text
        assert "BUSINESS IMPACT:" in text

    def test_explain_with_rule_provided_text(self):
        explainer = ViolationExplainer()
        finding = Finding(
            title="Custom finding",
            explanation="Custom what",
            risk_context="Custom risk",
            business_impact="Custom impact",
            severity=Severity.MEDIUM,
        )
        result = explainer.explain(finding)
        assert result["what"] == "Custom what"
        assert result["risk"] == "Custom risk"
        assert result["impact"] == "Custom impact"

    def test_severity_context(self):
        explainer = ViolationExplainer()
        for severity in Severity:
            finding = Finding(title="Test", severity=severity)
            result = explainer.explain(finding)
            assert len(result["severity_context"]) > 20

    def test_explain_banner_finding(self):
        explainer = ViolationExplainer()
        finding = Finding(
            title="No login banner configured",
            severity=Severity.MEDIUM,
        )
        result = explainer.explain(finding)
        assert "banner" in result["what"].lower()

    def test_explain_ntp_finding(self):
        explainer = ViolationExplainer()
        finding = Finding(
            title="NTP not configured",
            description="Missing time synchronization",
            severity=Severity.HIGH,
        )
        result = explainer.explain(finding)
        assert "time" in result["what"].lower() or "ntp" in result["what"].lower()
