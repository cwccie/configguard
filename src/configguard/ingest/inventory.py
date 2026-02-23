"""Configuration inventory management."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from configguard.models import ParsedConfig, Vendor


@dataclass
class InventoryEntry:
    """An entry in the configuration inventory."""

    device_name: str
    vendor: Vendor
    source_file: str
    hostname: str = ""
    last_scanned: datetime = field(default_factory=datetime.utcnow)
    compliance_score: float | None = None
    finding_count: int = 0
    config_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ConfigInventory:
    """Manages an inventory of scanned device configurations.

    Tracks which devices have been scanned, their compliance status,
    and configuration change history.
    """

    def __init__(self) -> None:
        self._entries: dict[str, InventoryEntry] = {}
        self._history: list[dict[str, Any]] = []

    def add(self, config: ParsedConfig, score: float | None = None) -> InventoryEntry:
        """Add or update a device in the inventory."""
        import hashlib

        config_hash = hashlib.sha256(config.raw_config.encode()).hexdigest()[:16]

        entry = InventoryEntry(
            device_name=config.device_name,
            vendor=config.vendor,
            source_file=config.source_file,
            hostname=config.hostname,
            config_hash=config_hash,
            compliance_score=score,
        )

        # Track changes
        if config.device_name in self._entries:
            old = self._entries[config.device_name]
            if old.config_hash != config_hash:
                self._history.append({
                    "device": config.device_name,
                    "event": "config_changed",
                    "old_hash": old.config_hash,
                    "new_hash": config_hash,
                    "timestamp": datetime.utcnow().isoformat(),
                })

        self._entries[config.device_name] = entry
        return entry

    def get(self, device_name: str) -> InventoryEntry | None:
        """Get an inventory entry by device name."""
        return self._entries.get(device_name)

    def list_all(self) -> list[InventoryEntry]:
        """List all inventory entries."""
        return list(self._entries.values())

    def remove(self, device_name: str) -> bool:
        """Remove a device from the inventory."""
        if device_name in self._entries:
            del self._entries[device_name]
            return True
        return False

    @property
    def device_count(self) -> int:
        return len(self._entries)

    def get_history(self, device_name: str | None = None) -> list[dict[str, Any]]:
        """Get change history, optionally filtered by device."""
        if device_name:
            return [h for h in self._history if h["device"] == device_name]
        return list(self._history)

    def export_json(self, filepath: str | Path) -> None:
        """Export inventory to JSON."""
        data = {
            "exported_at": datetime.utcnow().isoformat(),
            "device_count": self.device_count,
            "devices": [
                {
                    "device_name": e.device_name,
                    "vendor": e.vendor.value,
                    "hostname": e.hostname,
                    "source_file": e.source_file,
                    "config_hash": e.config_hash,
                    "compliance_score": e.compliance_score,
                    "finding_count": e.finding_count,
                    "last_scanned": e.last_scanned.isoformat(),
                }
                for e in self._entries.values()
            ],
        }
        Path(filepath).write_text(json.dumps(data, indent=2))
