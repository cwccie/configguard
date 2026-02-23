"""Multi-vendor network configuration parser."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from configguard.models import (
    ConfigBlock,
    ParsedConfig,
    Vendor,
)


def detect_vendor(config_text: str) -> Vendor:
    """Detect the vendor of a configuration file from its content."""
    lower = config_text.lower()

    # Cisco IOS / IOS-XE markers
    if "ios" in lower and "version" in lower:
        return Vendor.CISCO_IOS
    if re.search(r"^hostname\s+\S+", config_text, re.MULTILINE) and "interface" in lower:
        if "set" not in lower[:200]:
            return Vendor.CISCO_IOS

    # Cisco NX-OS markers
    if "nx-os" in lower or "feature" in lower and "vdc" in lower:
        return Vendor.CISCO_NXOS

    # JunOS markers
    if re.search(r"^(system|interfaces|protocols)\s*\{", config_text, re.MULTILINE):
        return Vendor.JUNOS
    if "set system" in lower or "set interfaces" in lower:
        return Vendor.JUNOS

    # Arista EOS markers
    if "arista" in lower or ("eos" in lower and "transceiver" in lower):
        return Vendor.ARISTA_EOS

    # Palo Alto PAN-OS markers
    if "deviceconfig" in lower or "set deviceconfig" in lower:
        return Vendor.PALO_ALTO
    if "security rules" in lower or "set rulebase" in lower:
        return Vendor.PALO_ALTO

    # Default: try Cisco IOS if it has common Cisco-like config
    if re.search(r"^(interface|router|access-list|line|service)\s", config_text, re.MULTILINE):
        return Vendor.CISCO_IOS

    return Vendor.UNKNOWN


class ConfigParser:
    """Multi-vendor network configuration parser.

    Parses Cisco IOS, JunOS, Arista EOS, and Palo Alto configurations
    into a normalized ParsedConfig structure.
    """

    def parse_file(self, filepath: str | Path) -> ParsedConfig:
        """Parse a configuration file."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        raw = filepath.read_text(encoding="utf-8", errors="replace")
        vendor = detect_vendor(raw)
        device_name = filepath.stem

        config = self._parse_config(raw, vendor, device_name)
        config.source_file = str(filepath)
        return config

    def parse_text(self, text: str, vendor: Vendor | None = None,
                   device_name: str = "unknown") -> ParsedConfig:
        """Parse configuration text directly."""
        if vendor is None:
            vendor = detect_vendor(text)
        return self._parse_config(text, vendor, device_name)

    def _parse_config(self, raw: str, vendor: Vendor,
                      device_name: str) -> ParsedConfig:
        """Route parsing to vendor-specific method."""
        if vendor == Vendor.JUNOS:
            return self._parse_junos(raw, device_name)
        if vendor == Vendor.PALO_ALTO:
            return self._parse_palo_alto(raw, device_name)
        # Cisco IOS, NX-OS, Arista EOS share similar syntax
        return self._parse_cisco_like(raw, vendor, device_name)

    def _parse_cisco_like(self, raw: str, vendor: Vendor,
                          device_name: str) -> ParsedConfig:
        """Parse Cisco IOS / NX-OS / Arista EOS style configurations."""
        config = ParsedConfig(device_name=device_name, vendor=vendor, raw_config=raw)
        lines = raw.splitlines()
        i = 0
        current_block: ConfigBlock | None = None

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped or stripped.startswith("!") or stripped.startswith("#"):
                i += 1
                continue

            # Hostname
            m = re.match(r"^hostname\s+(\S+)", stripped)
            if m:
                config.hostname = m.group(1)
                i += 1
                continue

            # Service lines
            m = re.match(r"^(no\s+)?service\s+(\S+)", stripped)
            if m:
                negated = m.group(1) is not None
                svc = m.group(2)
                config.services[svc] = not negated
                i += 1
                continue

            # Interface block
            m = re.match(r"^interface\s+(.+)", stripped)
            if m:
                block, i = self._read_cisco_block("interface", m.group(1), lines, i)
                config.interfaces.append(block)
                config.blocks.append(block)
                continue

            # ACL
            m = re.match(r"^(ip\s+)?access-list\s+(extended|standard)?\s*(\S+)", stripped)
            if m:
                acl_name = m.group(3)
                block, i = self._read_cisco_block("access-list", acl_name, lines, i)
                config.acls.append(block)
                config.blocks.append(block)
                continue

            # Routing protocols
            m = re.match(r"^router\s+(\S+)\s*(.*)", stripped)
            if m:
                proto = m.group(1)
                extra = m.group(2).strip()
                block, i = self._read_cisco_block("router", f"{proto} {extra}".strip(), lines, i)
                config.routing.append(block)
                config.blocks.append(block)
                continue

            # AAA
            if stripped.startswith("aaa "):
                block = ConfigBlock(block_type="aaa", name=stripped, lines=[stripped],
                                    line_numbers=(i + 1, i + 1))
                config.aaa.append(block)
                config.blocks.append(block)
                i += 1
                continue

            # Crypto
            if stripped.startswith("crypto "):
                block, i = self._read_cisco_block("crypto", stripped, lines, i)
                config.crypto.append(block)
                config.blocks.append(block)
                continue

            # NTP
            if stripped.startswith("ntp "):
                block = ConfigBlock(block_type="ntp", name=stripped, lines=[stripped],
                                    line_numbers=(i + 1, i + 1))
                config.ntp.append(block)
                config.blocks.append(block)
                i += 1
                continue

            # Logging
            if stripped.startswith("logging "):
                block = ConfigBlock(block_type="logging", name=stripped, lines=[stripped],
                                    line_numbers=(i + 1, i + 1))
                config.logging_config.append(block)
                config.blocks.append(block)
                i += 1
                continue

            # SNMP
            if stripped.startswith("snmp-server "):
                block = ConfigBlock(block_type="snmp", name=stripped, lines=[stripped],
                                    line_numbers=(i + 1, i + 1))
                config.snmp.append(block)
                config.blocks.append(block)
                i += 1
                continue

            # Banner
            m = re.match(r"^banner\s+(motd|login|exec)\s+(.)", stripped)
            if m:
                banner_type = m.group(1)
                delimiter = m.group(2)
                banner_lines = [stripped]
                start = i
                i += 1
                while i < len(lines):
                    banner_lines.append(lines[i])
                    if delimiter in lines[i] and i != start:
                        break
                    i += 1
                i += 1
                block = ConfigBlock(block_type="banner", name=banner_type,
                                    lines=banner_lines, line_numbers=(start + 1, i))
                config.banners.append(block)
                config.blocks.append(block)
                continue

            # Username
            if stripped.startswith("username "):
                block = ConfigBlock(block_type="user", name=stripped, lines=[stripped],
                                    line_numbers=(i + 1, i + 1))
                config.users.append(block)
                config.blocks.append(block)
                i += 1
                continue

            # Line (VTY, console)
            m = re.match(r"^line\s+(con|vty|aux)\s*(.*)", stripped)
            if m:
                line_type = f"{m.group(1)} {m.group(2)}".strip()
                block, i = self._read_cisco_block("line", line_type, lines, i)
                config.lines.append(block)
                config.blocks.append(block)
                continue

            # Generic single line
            block = ConfigBlock(block_type="global", name=stripped, lines=[stripped],
                                line_numbers=(i + 1, i + 1))
            config.blocks.append(block)
            i += 1

        return config

    def _read_cisco_block(self, block_type: str, name: str,
                          lines: list[str], start: int) -> tuple[ConfigBlock, int]:
        """Read an indented block from Cisco-style config."""
        block_lines = [lines[start].strip()]
        i = start + 1
        while i < len(lines):
            line = lines[i]
            if line and not line[0].isspace() and line.strip() and not line.strip().startswith("!"):
                break
            if line.strip():
                block_lines.append(line.strip())
            i += 1
        block = ConfigBlock(
            block_type=block_type,
            name=name,
            lines=block_lines,
            line_numbers=(start + 1, i),
        )
        # Parse properties from block lines
        for bline in block_lines[1:]:
            parts = bline.strip().split(None, 1)
            if len(parts) == 2:
                block.properties[parts[0]] = parts[1]
            elif len(parts) == 1:
                block.properties[parts[0]] = True
        return block, i

    def _parse_junos(self, raw: str, device_name: str) -> ParsedConfig:
        """Parse JunOS hierarchical or set-style configuration."""
        config = ParsedConfig(device_name=device_name, vendor=Vendor.JUNOS, raw_config=raw)

        # Detect if set-style
        is_set_style = raw.strip().startswith("set ")

        if is_set_style:
            return self._parse_junos_set(raw, config)
        return self._parse_junos_hierarchical(raw, config)

    def _parse_junos_set(self, raw: str, config: ParsedConfig) -> ParsedConfig:
        """Parse JunOS set-style configuration."""
        for i, line in enumerate(raw.splitlines()):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            m = re.match(r"^set\s+(\S+)\s+(.*)", stripped)
            if not m:
                continue

            section = m.group(1)
            rest = m.group(2)

            block = ConfigBlock(
                block_type=section, name=rest,
                lines=[stripped], line_numbers=(i + 1, i + 1),
            )

            if section == "system":
                if rest.startswith("host-name"):
                    config.hostname = rest.split()[-1]
                config.blocks.append(block)
            elif section == "interfaces":
                config.interfaces.append(block)
                config.blocks.append(block)
            elif section in ("protocols", "routing-options"):
                config.routing.append(block)
                config.blocks.append(block)
            elif section == "security":
                config.acls.append(block)
                config.blocks.append(block)
            elif section == "firewall":
                config.acls.append(block)
                config.blocks.append(block)
            else:
                config.blocks.append(block)

            # Extract NTP
            if "ntp" in stripped.lower():
                config.ntp.append(block)
            if "syslog" in stripped.lower():
                config.logging_config.append(block)
            if "snmp" in stripped.lower():
                config.snmp.append(block)
            if "authentication" in stripped.lower() or "login" in stripped.lower():
                config.aaa.append(block)

        return config

    def _parse_junos_hierarchical(self, raw: str, config: ParsedConfig) -> ParsedConfig:
        """Parse JunOS hierarchical brace-style configuration."""
        lines = raw.splitlines()
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            if not stripped or stripped.startswith("#") or stripped == "}":
                i += 1
                continue

            # Read top-level section
            m = re.match(r"^(\S+)\s*\{", stripped)
            if m:
                section = m.group(1)
                block_lines = [stripped]
                brace_depth = 1
                start = i
                i += 1
                while i < len(lines) and brace_depth > 0:
                    l = lines[i].strip()
                    block_lines.append(l)
                    brace_depth += l.count("{") - l.count("}")
                    i += 1
                block = ConfigBlock(block_type=section, name=section,
                                    lines=block_lines, line_numbers=(start + 1, i))
                config.blocks.append(block)

                if section == "system":
                    hm = re.search(r"host-name\s+(\S+);", "\n".join(block_lines))
                    if hm:
                        config.hostname = hm.group(1)
                elif section == "interfaces":
                    config.interfaces.append(block)
                elif section in ("protocols", "routing-options"):
                    config.routing.append(block)
                elif section in ("security", "firewall"):
                    config.acls.append(block)
                continue

            block = ConfigBlock(block_type="global", name=stripped, lines=[stripped],
                                line_numbers=(i + 1, i + 1))
            config.blocks.append(block)
            i += 1

        return config

    def _parse_palo_alto(self, raw: str, device_name: str) -> ParsedConfig:
        """Parse Palo Alto PAN-OS configuration (set-style)."""
        config = ParsedConfig(device_name=device_name, vendor=Vendor.PALO_ALTO, raw_config=raw)

        for i, line in enumerate(raw.splitlines()):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            m = re.match(r"^set\s+(\S+)\s+(.*)", stripped)
            if not m:
                # Non-set line
                block = ConfigBlock(block_type="global", name=stripped, lines=[stripped],
                                    line_numbers=(i + 1, i + 1))
                config.blocks.append(block)
                continue

            section = m.group(1)
            rest = m.group(2)

            block = ConfigBlock(block_type=section, name=rest,
                                lines=[stripped], line_numbers=(i + 1, i + 1))
            config.blocks.append(block)

            if section == "deviceconfig":
                if "hostname" in rest:
                    parts = rest.split()
                    if parts:
                        config.hostname = parts[-1]
            elif section == "network":
                if "interface" in rest:
                    config.interfaces.append(block)
            elif section == "rulebase":
                config.acls.append(block)

            if "ntp" in stripped.lower():
                config.ntp.append(block)
            if "syslog" in stripped.lower() or "log-settings" in stripped.lower():
                config.logging_config.append(block)
            if "snmp" in stripped.lower():
                config.snmp.append(block)
            if "authentication" in stripped.lower():
                config.aaa.append(block)

        return config
