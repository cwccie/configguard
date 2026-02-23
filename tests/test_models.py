"""Tests for core data models."""

from configguard.models import (
    ComplianceReport,
    ComplianceRule,
    ConfigBlock,
    Finding,
    Framework,
    ParsedConfig,
    RemediationPlan,
    Severity,
    Vendor,
)


class TestSeverity:
    def test_severity_scores(self):
        assert Severity.CRITICAL.score == 10
        assert Severity.HIGH.score == 8
        assert Severity.MEDIUM.score == 5
        assert Severity.LOW.score == 2
        assert Severity.INFO.score == 0

    def test_severity_comparison(self):
        assert Severity.LOW < Severity.HIGH
        assert Severity.MEDIUM < Severity.CRITICAL

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"


class TestVendor:
    def test_vendor_values(self):
        assert Vendor.CISCO_IOS.value == "cisco_ios"
        assert Vendor.JUNOS.value == "junos"
        assert Vendor.ARISTA_EOS.value == "arista_eos"
        assert Vendor.PALO_ALTO.value == "palo_alto"


class TestFramework:
    def test_framework_values(self):
        assert Framework.NIST_800_53.value == "nist_800_53"
        assert Framework.CIS_BENCHMARK.value == "cis_benchmark"
        assert Framework.PCI_DSS.value == "pci_dss"


class TestFinding:
    def test_finding_dedup_key(self):
        f1 = Finding(device_name="rtr1", control_id="AC-2", title="Test")
        f2 = Finding(device_name="rtr1", control_id="AC-2", title="Test")
        assert f1.dedup_key == f2.dedup_key

    def test_finding_dedup_different(self):
        f1 = Finding(device_name="rtr1", control_id="AC-2", title="Test A")
        f2 = Finding(device_name="rtr1", control_id="AC-3", title="Test B")
        assert f1.dedup_key != f2.dedup_key

    def test_finding_defaults(self):
        f = Finding()
        assert f.status == "open"
        assert f.severity == Severity.INFO
        assert len(f.finding_id) == 12


class TestComplianceReport:
    def test_report_counts(self):
        findings = [
            Finding(severity=Severity.CRITICAL),
            Finding(severity=Severity.CRITICAL),
            Finding(severity=Severity.HIGH),
            Finding(severity=Severity.MEDIUM),
            Finding(severity=Severity.LOW),
        ]
        report = ComplianceReport(findings=findings)
        assert report.critical_count == 2
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 1

    def test_empty_report(self):
        report = ComplianceReport()
        assert report.critical_count == 0
        assert report.compliance_score == 0.0


class TestConfigBlock:
    def test_config_block_creation(self):
        block = ConfigBlock(block_type="interface", name="Gi0/0",
                            lines=["interface Gi0/0", " ip address 10.0.0.1 255.255.255.0"])
        assert block.block_type == "interface"
        assert len(block.lines) == 2


class TestParsedConfig:
    def test_parsed_config_defaults(self):
        config = ParsedConfig(device_name="test", vendor=Vendor.CISCO_IOS, raw_config="")
        assert config.hostname == ""
        assert config.interfaces == []
        assert config.services == {}
