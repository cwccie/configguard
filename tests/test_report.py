"""Tests for report generation."""

import json
import tempfile
from pathlib import Path

from configguard.report.generator import ReportGenerator
from configguard.models import ComplianceReport, Finding, Framework, Severity


def _make_report():
    findings = [
        Finding(finding_id="f1", title="Critical Issue", severity=Severity.CRITICAL,
                device_name="rtr-01", framework=Framework.NIST_800_53,
                control_id="AC-2", description="AAA not configured"),
        Finding(finding_id="f2", title="SSH Not Enforced", severity=Severity.HIGH,
                device_name="rtr-01", framework=Framework.CIS_BENCHMARK,
                control_id="1.3.1", description="Telnet allowed"),
        Finding(finding_id="f3", title="Missing Banner", severity=Severity.MEDIUM,
                device_name="rtr-01", framework=Framework.PCI_DSS,
                control_id="3.1.1", remediation="Add a login banner"),
    ]
    return ComplianceReport(
        devices=["rtr-01"],
        frameworks=[Framework.NIST_800_53, Framework.CIS_BENCHMARK],
        findings=findings,
        total_rules_checked=50,
        compliance_score=72.5,
    )


class TestReportGenerator:
    def test_generate_json(self):
        gen = ReportGenerator()
        report = _make_report()
        json_str = gen.generate_json(report)
        data = json.loads(json_str)
        assert data["compliance_score"] == 72.5
        assert len(data["findings"]) == 3
        assert data["summary"]["critical"] == 1

    def test_generate_json_file(self):
        gen = ReportGenerator()
        report = _make_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            gen.generate_json(report, f.name)
            data = json.loads(Path(f.name).read_text())
            assert data["compliance_score"] == 72.5

    def test_generate_csv(self):
        gen = ReportGenerator()
        report = _make_report()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            gen.generate_csv(report, f.name)
            content = Path(f.name).read_text()
            assert "Critical Issue" in content
            assert "Finding ID" in content

    def test_generate_text(self):
        gen = ReportGenerator()
        report = _make_report()
        text = gen.generate_text(report)
        assert "CONFIGGUARD COMPLIANCE REPORT" in text
        assert "72.5%" in text
        assert "Critical Issue" in text

    def test_generate_text_file(self):
        gen = ReportGenerator()
        report = _make_report()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            gen.generate_text(report, f.name)
            content = Path(f.name).read_text()
            assert "COMPLIANCE REPORT" in content

    def test_trend_recording(self):
        gen = ReportGenerator()
        report = _make_report()
        gen.record_for_trend(report)
        trend = gen.get_trend_data()
        assert len(trend) == 1
        assert trend[0]["score"] == 72.5

    def test_trend_multiple(self):
        gen = ReportGenerator()
        for score in [60.0, 70.0, 80.0]:
            r = ComplianceReport(compliance_score=score, findings=[])
            gen.record_for_trend(r)
        trend = gen.get_trend_data()
        assert len(trend) == 3

    def test_trend_csv_export(self):
        gen = ReportGenerator()
        report = _make_report()
        gen.record_for_trend(report)
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            gen.export_trend_csv(f.name)
            content = Path(f.name).read_text()
            assert "Score" in content
