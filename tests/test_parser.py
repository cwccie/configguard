"""Tests for the multi-vendor config parser."""

import pytest
from configguard.ingest.parser import ConfigParser, detect_vendor
from configguard.models import Vendor


class TestVendorDetection:
    def test_detect_cisco_ios(self, cisco_config):
        assert detect_vendor(cisco_config) == Vendor.CISCO_IOS

    def test_detect_junos(self, junos_config):
        assert detect_vendor(junos_config) == Vendor.JUNOS

    def test_detect_palo_alto(self, paloalto_config):
        assert detect_vendor(paloalto_config) == Vendor.PALO_ALTO

    def test_detect_arista(self):
        config = "! Arista EOS config\nhostname TEST\ntransceiver qsfp default-mode 4x10G\n"
        assert detect_vendor(config) == Vendor.ARISTA_EOS

    def test_detect_unknown(self):
        assert detect_vendor("random text no config here") == Vendor.UNKNOWN


class TestCiscoParser:
    def test_parse_hostname(self, cisco_config):
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        assert config.hostname == "TEST-RTR-01"

    def test_parse_interfaces(self, cisco_config):
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        assert len(config.interfaces) >= 1

    def test_parse_services(self, cisco_config):
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        assert "finger" in config.services
        assert config.services["finger"] is True

    def test_parse_no_service(self):
        parser = ConfigParser()
        config = parser.parse_text("no service finger\nhostname TEST\n", device_name="test")
        assert config.services.get("finger") is False

    def test_parse_snmp(self, cisco_config):
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        assert len(config.snmp) >= 1

    def test_parse_users(self, cisco_config):
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        assert len(config.users) >= 1

    def test_parse_lines(self, cisco_config):
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        assert len(config.lines) >= 1

    def test_parse_acl(self):
        config_text = "hostname R1\naccess-list extended TEST\n permit ip any any\n"
        parser = ConfigParser()
        config = parser.parse_text(config_text, device_name="test")
        assert len(config.acls) >= 1

    def test_parse_vendor(self, cisco_config):
        parser = ConfigParser()
        config = parser.parse_text(cisco_config, device_name="test")
        assert config.vendor == Vendor.CISCO_IOS


class TestJunosParser:
    def test_parse_junos_set_style(self, junos_config):
        parser = ConfigParser()
        config = parser.parse_text(junos_config, vendor=Vendor.JUNOS, device_name="junos-test")
        assert config.hostname == "JUNOS-TEST-01"
        assert config.vendor == Vendor.JUNOS

    def test_parse_junos_interfaces(self, junos_config):
        parser = ConfigParser()
        config = parser.parse_text(junos_config, vendor=Vendor.JUNOS, device_name="test")
        assert len(config.interfaces) >= 1

    def test_parse_junos_hierarchical(self):
        config_text = """
system {
    host-name JUNOS-HIER;
    services {
        ssh;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.1.1.1/24;
            }
        }
    }
}
"""
        parser = ConfigParser()
        config = parser.parse_text(config_text, vendor=Vendor.JUNOS, device_name="test")
        assert config.hostname == "JUNOS-HIER"


class TestPaloAltoParser:
    def test_parse_palo_hostname(self, paloalto_config):
        parser = ConfigParser()
        config = parser.parse_text(paloalto_config, vendor=Vendor.PALO_ALTO, device_name="test")
        assert config.hostname == "PA-TEST-01"

    def test_parse_palo_vendor(self, paloalto_config):
        parser = ConfigParser()
        config = parser.parse_text(paloalto_config, vendor=Vendor.PALO_ALTO, device_name="test")
        assert config.vendor == Vendor.PALO_ALTO


class TestParserFileOperations:
    def test_parse_file_not_found(self):
        parser = ConfigParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_file("/nonexistent/file.conf")

    def test_parse_sample_file(self, sample_configs_dir):
        parser = ConfigParser()
        config_file = sample_configs_dir / "cisco_core_router.conf"
        if config_file.exists():
            config = parser.parse_file(config_file)
            assert config.hostname == "CORE-RTR-01"
            assert config.device_name == "cisco_core_router"
