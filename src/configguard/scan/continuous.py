"""Continuous configuration scanning with file watching and scheduling."""

from __future__ import annotations

import logging
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from configguard.check.checker import ComplianceChecker
from configguard.models import ComplianceReport, Framework, ScanResult

logger = logging.getLogger(__name__)


class ContinuousScanner:
    """Watches directories for config changes and runs compliance checks.

    Features:
    - File system watching for real-time config change detection
    - Scheduled periodic scans
    - Callback support for notifications
    """

    def __init__(self, checker: ComplianceChecker | None = None,
                 frameworks: list[Framework] | None = None) -> None:
        self.checker = checker or ComplianceChecker()
        self.frameworks = frameworks
        self._watch_dirs: list[Path] = []
        self._callbacks: list[Callable[[ScanResult], None]] = []
        self._running = False
        self._scan_history: list[ScanResult] = []

    def add_watch_directory(self, directory: str | Path) -> None:
        """Add a directory to watch for config changes."""
        self._watch_dirs.append(Path(directory))

    def add_callback(self, callback: Callable[[ScanResult], None]) -> None:
        """Register a callback for scan results."""
        self._callbacks.append(callback)

    def scan_once(self, directory: str | Path | None = None) -> ScanResult:
        """Run a single compliance scan."""
        result = ScanResult(scan_type="manual")

        dirs_to_scan = [Path(directory)] if directory else self._watch_dirs
        all_reports: list[ComplianceReport] = []

        for scan_dir in dirs_to_scan:
            if scan_dir.is_dir():
                report = self.checker.check_directory(scan_dir, self.frameworks)
                all_reports.append(report)
                result.configs_scanned += len(report.devices)
                result.findings_count += len(report.findings)

        result.reports = all_reports
        result.completed_at = datetime.utcnow()

        if all_reports:
            scores = [r.compliance_score for r in all_reports]
            result.compliance_score = round(sum(scores) / len(scores), 1)

        self._scan_history.append(result)

        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(result)
            except Exception as e:
                logger.error("Callback error: %s", e)

        return result

    def watch(self, interval_seconds: int = 300) -> None:
        """Start watching directories for changes (blocking).

        Uses polling-based watching. For production, integrate with
        watchdog's Observer for filesystem events.
        """
        self._running = True
        logger.info("Starting continuous scan (interval: %ds)", interval_seconds)

        while self._running:
            for watch_dir in self._watch_dirs:
                try:
                    result = self.scan_once(watch_dir)
                    logger.info(
                        "Scan complete: %d configs, %d findings, score %.1f%%",
                        result.configs_scanned, result.findings_count,
                        result.compliance_score,
                    )
                except Exception as e:
                    logger.error("Scan error for %s: %s", watch_dir, e)

            time.sleep(interval_seconds)

    def watch_async(self, interval_seconds: int = 300) -> threading.Thread:
        """Start watching in a background thread."""
        thread = threading.Thread(target=self.watch, args=(interval_seconds,),
                                  daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """Stop watching."""
        self._running = False

    @property
    def scan_history(self) -> list[ScanResult]:
        return list(self._scan_history)
