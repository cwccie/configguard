"""Configuration drift detection from compliant baselines."""

from __future__ import annotations

import difflib
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detects configuration drift from a known-compliant baseline.

    Compares current configs against stored baselines and reports
    any changes that may affect compliance posture.
    """

    def __init__(self, baseline_dir: str | Path | None = None) -> None:
        self._baselines: dict[str, str] = {}  # device_name -> config_text
        self._baseline_hashes: dict[str, str] = {}
        if baseline_dir:
            self.load_baselines(baseline_dir)

    def set_baseline(self, device_name: str, config_text: str) -> None:
        """Set the compliant baseline for a device."""
        self._baselines[device_name] = config_text
        self._baseline_hashes[device_name] = hashlib.sha256(
            config_text.encode()).hexdigest()[:16]
        logger.info("Baseline set for %s", device_name)

    def load_baselines(self, directory: str | Path) -> int:
        """Load baseline configs from a directory."""
        directory = Path(directory)
        count = 0
        if directory.is_dir():
            for f in directory.iterdir():
                if f.is_file():
                    self.set_baseline(f.stem, f.read_text(errors="replace"))
                    count += 1
        return count

    def check_drift(self, device_name: str,
                    current_config: str) -> dict[str, Any]:
        """Check if a config has drifted from baseline.

        Returns a dict with drift details.
        """
        if device_name not in self._baselines:
            return {
                "device": device_name,
                "drifted": False,
                "error": "No baseline configured for this device",
            }

        baseline = self._baselines[device_name]
        current_hash = hashlib.sha256(current_config.encode()).hexdigest()[:16]

        if current_hash == self._baseline_hashes[device_name]:
            return {
                "device": device_name,
                "drifted": False,
                "message": "Configuration matches baseline",
            }

        # Generate diff
        diff_lines = list(difflib.unified_diff(
            baseline.splitlines(),
            current_config.splitlines(),
            fromfile=f"{device_name} (baseline)",
            tofile=f"{device_name} (current)",
            lineterm="",
        ))

        additions = [l for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
        removals = [l for l in diff_lines if l.startswith("-") and not l.startswith("---")]

        return {
            "device": device_name,
            "drifted": True,
            "checked_at": datetime.utcnow().isoformat(),
            "baseline_hash": self._baseline_hashes[device_name],
            "current_hash": current_hash,
            "diff_summary": {
                "lines_added": len(additions),
                "lines_removed": len(removals),
                "additions": additions[:20],
                "removals": removals[:20],
            },
            "full_diff": "\n".join(diff_lines),
        }

    def check_all(self, configs: dict[str, str]) -> list[dict[str, Any]]:
        """Check drift for multiple devices."""
        results = []
        for device_name, config_text in configs.items():
            results.append(self.check_drift(device_name, config_text))
        return results

    @property
    def baseline_devices(self) -> list[str]:
        return list(self._baselines.keys())
