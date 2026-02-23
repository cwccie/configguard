"""Tests for directory and inventory scanning."""

import tempfile
from pathlib import Path

import pytest

from configguard.ingest.scanner import DirectoryScanner
from configguard.ingest.inventory import ConfigInventory
from configguard.ingest.parser import ConfigParser
from configguard.models import Vendor


class TestDirectoryScanner:
    def test_scan_sample_directory(self, sample_configs_dir):
        if not sample_configs_dir.exists():
            pytest.skip("Sample configs dir not found")
        scanner = DirectoryScanner()
        configs = scanner.scan(sample_configs_dir)
        assert len(configs) >= 1

    def test_scan_nonexistent_directory(self):
        scanner = DirectoryScanner()
        with pytest.raises(NotADirectoryError):
            scanner.scan("/nonexistent/directory")

    def test_scan_empty_directory(self):
        scanner = DirectoryScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            configs = scanner.scan(tmpdir)
            assert len(configs) == 0

    def test_scan_with_config_file(self):
        scanner = DirectoryScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "router.conf"
            config_file.write_text("hostname TEST\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n")
            configs = scanner.scan(tmpdir)
            assert len(configs) == 1
            assert configs[0].hostname == "TEST"


class TestConfigInventory:
    def test_add_device(self):
        from configguard.models import ParsedConfig
        inv = ConfigInventory()
        config = ParsedConfig(
            device_name="rtr-01", vendor=Vendor.CISCO_IOS,
            raw_config="hostname rtr-01\n", hostname="rtr-01",
        )
        entry = inv.add(config)
        assert entry.device_name == "rtr-01"
        assert inv.device_count == 1

    def test_get_device(self):
        from configguard.models import ParsedConfig
        inv = ConfigInventory()
        config = ParsedConfig(
            device_name="rtr-02", vendor=Vendor.CISCO_IOS,
            raw_config="hostname rtr-02\n",
        )
        inv.add(config)
        entry = inv.get("rtr-02")
        assert entry is not None
        assert entry.device_name == "rtr-02"

    def test_list_all(self):
        from configguard.models import ParsedConfig
        inv = ConfigInventory()
        for i in range(3):
            config = ParsedConfig(
                device_name=f"rtr-{i}", vendor=Vendor.CISCO_IOS,
                raw_config=f"hostname rtr-{i}\n",
            )
            inv.add(config)
        assert len(inv.list_all()) == 3

    def test_remove_device(self):
        from configguard.models import ParsedConfig
        inv = ConfigInventory()
        config = ParsedConfig(
            device_name="rtr-del", vendor=Vendor.CISCO_IOS,
            raw_config="hostname rtr-del\n",
        )
        inv.add(config)
        assert inv.remove("rtr-del") is True
        assert inv.device_count == 0
        assert inv.remove("nonexistent") is False

    def test_config_change_tracking(self):
        from configguard.models import ParsedConfig
        inv = ConfigInventory()
        config1 = ParsedConfig(
            device_name="rtr-change", vendor=Vendor.CISCO_IOS,
            raw_config="hostname rtr-v1\n",
        )
        inv.add(config1)

        config2 = ParsedConfig(
            device_name="rtr-change", vendor=Vendor.CISCO_IOS,
            raw_config="hostname rtr-v2\n",
        )
        inv.add(config2)

        history = inv.get_history("rtr-change")
        assert len(history) == 1
        assert history[0]["event"] == "config_changed"

    def test_export_json(self):
        from configguard.models import ParsedConfig
        inv = ConfigInventory()
        config = ParsedConfig(
            device_name="rtr-export", vendor=Vendor.CISCO_IOS,
            raw_config="hostname rtr-export\n",
        )
        inv.add(config)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            inv.export_json(f.name)
            import json
            data = json.loads(Path(f.name).read_text())
            assert data["device_count"] == 1
