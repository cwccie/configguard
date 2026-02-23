"""Tests for the REST API."""

import json
import pytest

from configguard.api.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestAPIStatus:
    def test_health_check(self, client):
        rv = client.get("/api/v1/status")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"


class TestAPIRules:
    def test_list_rules(self, client):
        rv = client.get("/api/v1/rules")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "count" in data
        assert "rules" in data

    def test_filter_rules_by_framework(self, client):
        rv = client.get("/api/v1/rules?framework=nist_800_53")
        assert rv.status_code == 200

    def test_invalid_framework(self, client):
        rv = client.get("/api/v1/rules?framework=invalid")
        assert rv.status_code == 400


class TestAPIScan:
    def test_scan_config(self, client):
        rv = client.post("/api/v1/scan", json={
            "config": "hostname TEST\nenable password weak\nservice finger\n",
            "device_name": "test-rtr",
        })
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "compliance_score" in data
        assert "findings" in data

    def test_scan_missing_config(self, client):
        rv = client.post("/api/v1/scan", json={})
        assert rv.status_code == 400

    def test_scan_with_vendor(self, client):
        rv = client.post("/api/v1/scan", json={
            "config": "hostname TEST\n",
            "device_name": "test",
            "vendor": "cisco_ios",
        })
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert data["vendor"] == "cisco_ios"

    def test_scan_invalid_vendor(self, client):
        rv = client.post("/api/v1/scan", json={
            "config": "hostname TEST\n",
            "vendor": "invalid_vendor",
        })
        assert rv.status_code == 400


class TestAPIFindings:
    def test_list_findings_empty(self, client):
        rv = client.get("/api/v1/findings")
        assert rv.status_code == 200

    def test_finding_not_found(self, client):
        rv = client.get("/api/v1/findings/nonexistent")
        assert rv.status_code == 404

    def test_scan_then_get_findings(self, client):
        # Scan first
        client.post("/api/v1/scan", json={
            "config": "hostname TEST\nenable password weak\n",
            "device_name": "test-rtr",
        })
        # Get findings
        rv = client.get("/api/v1/findings")
        data = json.loads(rv.data)
        if data["count"] > 0:
            # Get specific finding
            finding_id = data["findings"][0]["finding_id"]
            rv2 = client.get(f"/api/v1/findings/{finding_id}")
            assert rv2.status_code == 200
            detail = json.loads(rv2.data)
            assert "explanation" in detail
            assert "remediation" in detail


class TestAPIReport:
    def test_generate_json_report(self, client):
        rv = client.get("/api/v1/report/json")
        assert rv.status_code == 200

    def test_generate_text_report(self, client):
        rv = client.get("/api/v1/report/text")
        assert rv.status_code == 200

    def test_unsupported_format(self, client):
        rv = client.get("/api/v1/report/xml")
        assert rv.status_code == 400


class TestAPITrend:
    def test_trend_empty(self, client):
        rv = client.get("/api/v1/trend")
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "trend" in data
