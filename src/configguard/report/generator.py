"""Report generator — PDF, JSON, CSV, executive summary."""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from configguard.models import ComplianceReport, Finding, Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate compliance reports in multiple formats.

    Supports:
    - PDF reports with executive summary and detailed findings
    - JSON export for integration
    - CSV export for spreadsheet analysis
    - Plain text summary
    - Trend analysis data
    """

    def __init__(self) -> None:
        self._history: list[dict[str, Any]] = []

    def generate_pdf(self, report: ComplianceReport,
                     output_path: str | Path) -> str:
        """Generate a PDF compliance report."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError:
            logger.warning("reportlab not installed, generating text report instead")
            text_path = str(output_path).replace(".pdf", ".txt")
            return self.generate_text(report, text_path)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(str(output_path), pagesize=letter,
                                topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            "CustomTitle", parent=styles["Title"],
            fontSize=24, spaceAfter=12,
        )
        story.append(Paragraph("ConfigGuard Compliance Report", title_style))
        story.append(Spacer(1, 12))

        # Report metadata
        meta_style = styles["Normal"]
        story.append(Paragraph(
            f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
        story.append(Paragraph(
            f"Report ID: {report.report_id}", meta_style))
        story.append(Paragraph(
            f"Devices: {', '.join(report.devices)}", meta_style))
        story.append(Spacer(1, 24))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles["Heading1"]))
        story.append(Spacer(1, 6))

        # Score and summary table
        score_color = (
            colors.green if report.compliance_score >= 80
            else colors.orange if report.compliance_score >= 60
            else colors.red
        )
        summary_data = [
            ["Compliance Score", f"{report.compliance_score}%"],
            ["Total Findings", str(len(report.findings))],
            ["Critical", str(report.critical_count)],
            ["High", str(report.high_count)],
            ["Medium", str(report.medium_count)],
            ["Low", str(report.low_count)],
            ["Rules Checked", str(report.total_rules_checked)],
        ]
        summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 24))

        # Findings
        if report.findings:
            story.append(Paragraph("Detailed Findings", styles["Heading1"]))
            story.append(Spacer(1, 12))

            # Sort by severity
            sorted_findings = sorted(report.findings,
                                     key=lambda f: f.severity.score, reverse=True)

            for finding in sorted_findings:
                sev = finding.severity.value.upper()
                story.append(Paragraph(
                    f"[{sev}] {finding.title}", styles["Heading3"]))
                story.append(Paragraph(
                    f"Device: {finding.device_name} | "
                    f"Framework: {finding.framework.value} | "
                    f"Control: {finding.control_id}",
                    meta_style))
                if finding.description:
                    story.append(Paragraph(finding.description, meta_style))
                if finding.evidence:
                    story.append(Paragraph("Evidence:", styles["Heading4"]))
                    for ev in finding.evidence[:3]:
                        story.append(Paragraph(f"  {ev}", meta_style))
                if finding.remediation:
                    story.append(Paragraph(
                        f"Remediation: {finding.remediation}", meta_style))
                story.append(Spacer(1, 12))

        doc.build(story)
        logger.info("PDF report generated: %s", output_path)
        return str(output_path)

    def generate_json(self, report: ComplianceReport,
                      output_path: str | Path | None = None) -> str:
        """Generate a JSON compliance report."""
        data = {
            "report_id": report.report_id,
            "title": report.title,
            "generated_at": report.generated_at.isoformat(),
            "compliance_score": report.compliance_score,
            "devices": report.devices,
            "frameworks": [f.value for f in report.frameworks],
            "total_rules_checked": report.total_rules_checked,
            "summary": {
                "total_findings": len(report.findings),
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
            },
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "device": f.device_name,
                    "framework": f.framework.value,
                    "control_id": f.control_id,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "status": f.status,
                    "found_at": f.found_at.isoformat(),
                }
                for f in report.findings
            ],
        }

        json_str = json.dumps(data, indent=2)
        if output_path:
            Path(output_path).write_text(json_str)
            logger.info("JSON report generated: %s", output_path)
        return json_str

    def generate_csv(self, report: ComplianceReport,
                     output_path: str | Path) -> str:
        """Generate a CSV export of findings."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Finding ID", "Severity", "Title", "Device", "Framework",
                "Control ID", "Description", "Evidence", "Remediation",
                "Status", "Found At",
            ])
            for finding in report.findings:
                writer.writerow([
                    finding.finding_id,
                    finding.severity.value,
                    finding.title,
                    finding.device_name,
                    finding.framework.value,
                    finding.control_id,
                    finding.description,
                    "; ".join(finding.evidence[:3]),
                    finding.remediation,
                    finding.status,
                    finding.found_at.isoformat(),
                ])

        logger.info("CSV report generated: %s", output_path)
        return str(output_path)

    def generate_text(self, report: ComplianceReport,
                      output_path: str | Path | None = None) -> str:
        """Generate a plain text report."""
        lines = [
            "=" * 70,
            "CONFIGGUARD COMPLIANCE REPORT",
            "=" * 70,
            f"Report ID:        {report.report_id}",
            f"Generated:        {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"Devices:          {', '.join(report.devices)}",
            f"Compliance Score: {report.compliance_score}%",
            "",
            "-" * 70,
            "SUMMARY",
            "-" * 70,
            report.summary or "(no summary)",
            "",
        ]

        if report.findings:
            lines.append("-" * 70)
            lines.append("FINDINGS")
            lines.append("-" * 70)
            sorted_findings = sorted(report.findings,
                                     key=lambda f: f.severity.score, reverse=True)
            for i, f in enumerate(sorted_findings, 1):
                lines.append(f"\n{i}. [{f.severity.value.upper()}] {f.title}")
                lines.append(f"   Device: {f.device_name}")
                lines.append(f"   Framework: {f.framework.value} ({f.control_id})")
                if f.description:
                    lines.append(f"   {f.description}")
                if f.evidence:
                    lines.append(f"   Evidence: {f.evidence[0]}")
                if f.remediation:
                    lines.append(f"   Fix: {f.remediation}")

        lines.append("")
        lines.append("=" * 70)
        lines.append("End of Report")
        lines.append("=" * 70)

        text = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(text)
            logger.info("Text report generated: %s", output_path)
        return text

    def record_for_trend(self, report: ComplianceReport) -> None:
        """Record a report's score for trend analysis."""
        self._history.append({
            "timestamp": report.generated_at.isoformat(),
            "score": report.compliance_score,
            "findings": len(report.findings),
            "critical": report.critical_count,
            "high": report.high_count,
            "devices": report.devices,
        })

    def get_trend_data(self) -> list[dict[str, Any]]:
        """Get compliance score trend data."""
        return list(self._history)

    def export_trend_csv(self, output_path: str | Path) -> str:
        """Export trend data to CSV."""
        output_path = Path(output_path)
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Score", "Findings", "Critical", "High"])
            for entry in self._history:
                writer.writerow([
                    entry["timestamp"], entry["score"],
                    entry["findings"], entry["critical"], entry["high"],
                ])
        return str(output_path)
