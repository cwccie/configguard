"""Flask web dashboard for ConfigGuard.

Provides a web UI for:
- Per-device compliance scores
- Framework coverage visualization
- Finding timeline
- Remediation tracking
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, jsonify

from configguard.check.checker import ComplianceChecker
from configguard.explain.explainer import ViolationExplainer
from configguard.models import ComplianceReport, Framework, Finding
from configguard.remediate.engine import RemediationEngine
from configguard.report.generator import ReportGenerator

logger = logging.getLogger(__name__)


def create_dashboard_app(checker: ComplianceChecker | None = None) -> Flask:
    """Create the dashboard Flask app."""
    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    app = Flask(__name__,
                template_folder=str(template_dir),
                static_folder=str(static_dir))
    app.config["SECRET_KEY"] = "configguard-dashboard-dev"

    _checker = checker or ComplianceChecker()
    _explainer = ViolationExplainer()
    _remediator = RemediationEngine()
    _reporter = ReportGenerator()

    # In-memory state
    _reports: list[ComplianceReport] = []
    _device_scores: dict[str, float] = {}
    _remediation_status: dict[str, str] = {}  # finding_id -> status

    @app.route("/")
    def index():
        """Dashboard home page."""
        total_findings = sum(len(r.findings) for r in _reports)
        avg_score = 0.0
        if _reports:
            avg_score = round(sum(r.compliance_score for r in _reports) / len(_reports), 1)

        # Framework coverage
        fw_coverage = {}
        for fw in Framework:
            rules = _checker.engine.get_rules(fw)
            fw_coverage[fw.value] = len(rules)

        return render_template("index.html",
                               reports=_reports,
                               device_scores=_device_scores,
                               total_findings=total_findings,
                               avg_score=avg_score,
                               fw_coverage=fw_coverage,
                               remediation_status=_remediation_status)

    @app.route("/scan", methods=["GET", "POST"])
    def scan():
        """Scan configuration page."""
        if request.method == "POST":
            config_text = request.form.get("config_text", "")
            device_name = request.form.get("device_name", "manual-scan")

            if config_text.strip():
                parsed = _checker.parser.parse_text(config_text, device_name=device_name)
                report = _checker.check_config(parsed)
                _reports.append(report)
                _device_scores[device_name] = report.compliance_score
                _reporter.record_for_trend(report)
                return redirect(url_for("report_detail", report_id=report.report_id))

        return render_template("scan.html")

    @app.route("/report/<report_id>")
    def report_detail(report_id: str):
        """View a specific report."""
        report = None
        for r in _reports:
            if r.report_id == report_id:
                report = r
                break
        if not report:
            return "Report not found", 404

        # Enrich findings with explanations
        enriched = []
        for finding in report.findings:
            explanation = _explainer.explain(finding)
            plan = _remediator.generate_plan(finding)
            enriched.append({
                "finding": finding,
                "explanation": explanation,
                "plan": plan,
                "status": _remediation_status.get(finding.finding_id, "open"),
            })

        # Sort by severity
        enriched.sort(key=lambda e: e["finding"].severity.score, reverse=True)

        return render_template("report.html", report=report, enriched=enriched)

    @app.route("/findings")
    def findings_list():
        """List all findings across all reports."""
        all_findings = []
        for report in _reports:
            for finding in report.findings:
                explanation = _explainer.explain(finding)
                all_findings.append({
                    "finding": finding,
                    "explanation": explanation,
                    "status": _remediation_status.get(finding.finding_id, "open"),
                    "report_id": report.report_id,
                })
        all_findings.sort(key=lambda e: e["finding"].severity.score, reverse=True)
        return render_template("findings.html", findings=all_findings)

    @app.route("/finding/<finding_id>/remediate", methods=["POST"])
    def mark_remediated(finding_id: str):
        """Mark a finding as remediated."""
        status = request.form.get("status", "remediated")
        _remediation_status[finding_id] = status
        return redirect(request.referrer or url_for("findings_list"))

    @app.route("/api/dashboard/scores")
    def api_scores():
        """API endpoint for device scores (for charts)."""
        return jsonify(_device_scores)

    @app.route("/api/dashboard/trend")
    def api_trend():
        """API endpoint for trend data (for charts)."""
        return jsonify(_reporter.get_trend_data())

    return app
