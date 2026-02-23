"""Tests for drift detection."""

from configguard.scan.drift import DriftDetector


class TestDriftDetector:
    def test_no_drift(self):
        detector = DriftDetector()
        baseline = "hostname RTR-01\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
        detector.set_baseline("rtr-01", baseline)
        result = detector.check_drift("rtr-01", baseline)
        assert result["drifted"] is False

    def test_drift_detected(self):
        detector = DriftDetector()
        baseline = "hostname RTR-01\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
        detector.set_baseline("rtr-01", baseline)
        changed = "hostname RTR-01\ninterface Gi0/0\n ip address 10.0.0.2 255.255.255.0\n"
        result = detector.check_drift("rtr-01", changed)
        assert result["drifted"] is True
        assert result["diff_summary"]["lines_added"] > 0

    def test_no_baseline(self):
        detector = DriftDetector()
        result = detector.check_drift("unknown-device", "some config")
        assert result["drifted"] is False
        assert "error" in result

    def test_baseline_devices(self):
        detector = DriftDetector()
        detector.set_baseline("rtr-01", "config1")
        detector.set_baseline("rtr-02", "config2")
        assert len(detector.baseline_devices) == 2
        assert "rtr-01" in detector.baseline_devices

    def test_check_all(self):
        detector = DriftDetector()
        detector.set_baseline("rtr-01", "original config 1")
        detector.set_baseline("rtr-02", "original config 2")
        results = detector.check_all({
            "rtr-01": "original config 1",  # no drift
            "rtr-02": "changed config 2",   # drift
        })
        assert len(results) == 2
        drifted = [r for r in results if r["drifted"]]
        assert len(drifted) == 1
