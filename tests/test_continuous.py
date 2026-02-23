"""Tests for continuous scanning."""

import tempfile
from pathlib import Path

from configguard.scan.continuous import ContinuousScanner
from configguard.models import ScanResult


class TestContinuousScanner:
    def test_scan_once(self):
        scanner = ContinuousScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "test.conf"
            config_file.write_text("hostname TEST\ninterface Gi0/0\n")
            scanner.add_watch_directory(tmpdir)
            result = scanner.scan_once()
            assert isinstance(result, ScanResult)
            assert result.completed_at is not None

    def test_scan_with_directory(self):
        scanner = ContinuousScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "router.conf"
            config_file.write_text("hostname RTR\ninterface Gi0/0\n")
            result = scanner.scan_once(tmpdir)
            assert result.configs_scanned >= 1

    def test_scan_history(self):
        scanner = ContinuousScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "test.conf"
            config_file.write_text("hostname TEST\n")
            scanner.add_watch_directory(tmpdir)
            scanner.scan_once()
            scanner.scan_once()
            assert len(scanner.scan_history) == 2

    def test_callback(self):
        results = []
        scanner = ContinuousScanner()
        scanner.add_callback(lambda r: results.append(r))
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "test.conf"
            config_file.write_text("hostname TEST\n")
            scanner.scan_once(tmpdir)
        assert len(results) == 1

    def test_stop(self):
        scanner = ContinuousScanner()
        scanner.stop()
        assert scanner._running is False
