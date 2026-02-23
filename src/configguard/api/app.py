"""Flask REST API for ConfigGuard.

Endpoints:
  POST /api/v1/scan            — Submit config text for scanning
  POST /api/v1/scan/file       — Upload config file for scanning
  GET  /api/v1/findings        — Query findings
  GET  /api/v1/findings/<id>   — Get a specific finding with explanation
  GET  /api/v1/report/<format> — Generate report (json, csv, text)
  GET  /api/v1/status          — Service health check
  GET  /api/v1/rules           — List loaded rules
"""

from __future__ import annotations

import logging
from flask import Flask, jsonify, request

from configguard.check.checker import ComplianceChecker
from configguard.explain.explainer import ViolationExplainer
from configguard.models import Framework, Vendor
from configguard.remediate.engine import RemediationEngine
from configguard.report.generator import ReportGenerator

logger = logging.getLogger(__name__)


def create_app(checker: ComplianceChecker | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    _checker = checker or ComplianceChecker()
    _explainer = ViolationExplainer()
    _remediator = RemediationEngine()
    _reporter = ReportGenerator()

    # Store findings across requests
    _findings_store: dict[str, dict] = {}

    @app.route("/api/v1/status", methods=["GET"])
    def status():
        """Health check endpoint."""
        return jsonify({
            "status": "healthy",
            "version": "1.0.0",
            "rules_loaded": _checker.engine.rule_count,
        })

    @app.route("/api/v1/rules", methods=["GET"])
    def list_rules():
        """List all loaded rules."""
        framework = request.args.get("framework")
        fw = None
        if framework:
            try:
                fw = Framework(framework)
            except ValueError:
                return jsonify({"error": f"Unknown framework: {framework}"}), 400

        rules = _checker.engine.get_rules(fw)
        return jsonify({
            "count": len(rules),
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "framework": r.framework.value,
                    "control_id": r.control_id,
                    "severity": r.severity.value,
                }
                for r in rules
            ],
        })

    @app.route("/api/v1/scan", methods=["POST"])
    def scan_config():
        """Submit configuration text for compliance scanning."""
        data = request.get_json()
        if not data or "config" not in data:
            return jsonify({"error": "Missing 'config' in request body"}), 400

        config_text = data["config"]
        device_name = data.get("device_name", "unknown")
        vendor = data.get("vendor")
        frameworks_str = data.get("frameworks", [])

        vendor_enum = None
        if vendor:
            try:
                vendor_enum = Vendor(vendor)
            except ValueError:
                return jsonify({"error": f"Unknown vendor: {vendor}"}), 400

        frameworks = []
        for fw_str in frameworks_str:
            try:
                frameworks.append(Framework(fw_str))
            except ValueError:
                return jsonify({"error": f"Unknown framework: {fw_str}"}), 400

        parsed = _checker.parser.parse_text(config_text, vendor_enum, device_name)
        report = _checker.check_config(parsed, frameworks or None)

        # Store findings
        for finding in report.findings:
            _findings_store[finding.finding_id] = {
                "finding": finding,
                "explanation": _explainer.explain(finding),
            }

        _reporter.record_for_trend(report)

        return jsonify({
            "report_id": report.report_id,
            "compliance_score": report.compliance_score,
            "device": device_name,
            "vendor": parsed.vendor.value,
            "total_findings": len(report.findings),
            "summary": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
            },
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "control_id": f.control_id,
                    "framework": f.framework.value,
                }
                for f in report.findings
            ],
        })

    @app.route("/api/v1/scan/file", methods=["POST"])
    def scan_file():
        """Upload a config file for scanning."""
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "Empty filename"}), 400

        config_text = file.read().decode("utf-8", errors="replace")
        device_name = file.filename.rsplit(".", 1)[0]

        parsed = _checker.parser.parse_text(config_text, device_name=device_name)
        report = _checker.check_config(parsed)

        for finding in report.findings:
            _findings_store[finding.finding_id] = {
                "finding": finding,
                "explanation": _explainer.explain(finding),
            }

        return jsonify({
            "report_id": report.report_id,
            "compliance_score": report.compliance_score,
            "device": device_name,
            "vendor": parsed.vendor.value,
            "total_findings": len(report.findings),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity.value,
                    "title": f.title,
                }
                for f in report.findings
            ],
        })

    @app.route("/api/v1/findings", methods=["GET"])
    def list_findings():
        """List all findings."""
        severity = request.args.get("severity")
        findings = list(_findings_store.values())
        if severity:
            findings = [f for f in findings
                        if f["finding"].severity.value == severity]
        return jsonify({
            "count": len(findings),
            "findings": [
                {
                    "finding_id": f["finding"].finding_id,
                    "severity": f["finding"].severity.value,
                    "title": f["finding"].title,
                    "device": f["finding"].device_name,
                    "framework": f["finding"].framework.value,
                    "control_id": f["finding"].control_id,
                }
                for f in findings
            ],
        })

    @app.route("/api/v1/findings/<finding_id>", methods=["GET"])
    def get_finding(finding_id: str):
        """Get a specific finding with full explanation."""
        entry = _findings_store.get(finding_id)
        if not entry:
            return jsonify({"error": "Finding not found"}), 404

        finding = entry["finding"]
        explanation = entry["explanation"]
        plan = _remediator.generate_plan(finding)

        return jsonify({
            "finding_id": finding.finding_id,
            "severity": finding.severity.value,
            "title": finding.title,
            "device": finding.device_name,
            "framework": finding.framework.value,
            "control_id": finding.control_id,
            "evidence": finding.evidence,
            "explanation": explanation,
            "remediation": {
                "config_snippet": plan.config_snippet,
                "rollback_snippet": plan.rollback_snippet,
                "risk_assessment": plan.risk_assessment,
                "validation_steps": plan.validation_steps,
            },
        })

    @app.route("/api/v1/report/<fmt>", methods=["GET"])
    def generate_report(fmt: str):
        """Generate a report in the specified format."""
        if fmt not in ("json", "text"):
            return jsonify({"error": f"Unsupported format: {fmt}. Use json or text."}), 400

        # Build report from stored findings
        from configguard.models import ComplianceReport
        findings = [f["finding"] for f in _findings_store.values()]
        devices = list({f.device_name for f in findings})
        total = _checker.engine.rule_count * max(len(devices), 1)
        score = max(0.0, (1 - len(findings) / max(total, 1)) * 100)

        report = ComplianceReport(
            devices=devices,
            findings=findings,
            total_rules_checked=total,
            compliance_score=round(score, 1),
        )

        if fmt == "json":
            return _reporter.generate_json(report)
        else:
            return _reporter.generate_text(report), 200, {"Content-Type": "text/plain"}

    @app.route("/api/v1/trend", methods=["GET"])
    def trend():
        """Get compliance score trend data."""
        return jsonify({"trend": _reporter.get_trend_data()})

    return app
