"""Compliance rule evaluation engine."""

from __future__ import annotations

import logging
import re
from typing import Any

from configguard.models import (
    ComplianceRule,
    Finding,
    Framework,
    ParsedConfig,
    Severity,
)

logger = logging.getLogger(__name__)


class RuleEngine:
    """Evaluates compliance rules against parsed configurations."""

    def __init__(self) -> None:
        self._rules: list[ComplianceRule] = []

    def add_rules(self, rules: list[ComplianceRule]) -> None:
        """Add rules to the engine."""
        self._rules.extend(rules)
        logger.info("Engine now has %d rules", len(self._rules))

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rules(self, framework: Framework | None = None) -> list[ComplianceRule]:
        """Get rules, optionally filtered by framework."""
        if framework:
            return [r for r in self._rules if r.framework == framework]
        return list(self._rules)

    def evaluate(self, config: ParsedConfig,
                 frameworks: list[Framework] | None = None) -> list[Finding]:
        """Evaluate all applicable rules against a parsed config."""
        findings: list[Finding] = []
        seen_dedup: set[str] = set()

        for rule in self._rules:
            # Filter by framework
            if frameworks and rule.framework not in frameworks:
                continue

            # Filter by vendor
            if "all" not in rule.vendor and config.vendor.value not in rule.vendor:
                continue

            # Evaluate the rule
            result = self._evaluate_rule(rule, config)
            if result is not None:
                if result.dedup_key not in seen_dedup:
                    seen_dedup.add(result.dedup_key)
                    findings.append(result)

        return findings

    def _evaluate_rule(self, rule: ComplianceRule,
                       config: ParsedConfig) -> Finding | None:
        """Evaluate a single rule against a config. Returns Finding if violated."""
        check_fn = {
            "config_match": self._check_config_match,
            "config_absent": self._check_config_absent,
            "service_check": self._check_service,
            "interface_check": self._check_interface,
            "acl_check": self._check_acl,
            "line_check": self._check_line,
            "snmp_check": self._check_snmp,
            "ntp_check": self._check_ntp,
            "logging_check": self._check_logging,
            "aaa_check": self._check_aaa,
            "banner_check": self._check_banner,
            "crypto_check": self._check_crypto,
            "user_check": self._check_user,
            "password_check": self._check_password,
        }.get(rule.check_type, self._check_config_match)

        return check_fn(rule, config)

    def _make_finding(self, rule: ComplianceRule, config: ParsedConfig,
                      evidence: list[str],
                      line_numbers: list[int] | None = None) -> Finding:
        """Create a Finding from a rule violation."""
        return Finding(
            rule=rule,
            device_name=config.device_name,
            severity=rule.severity,
            title=rule.title,
            description=rule.description,
            evidence=evidence,
            line_numbers=line_numbers or [],
            remediation=rule.remediation,
            explanation=rule.explanation,
            risk_context=rule.risk_description,
            business_impact=rule.business_impact,
            framework=rule.framework,
            control_id=rule.control_id,
        )

    def _search_config(self, config: ParsedConfig, pattern: str,
                       section: str = "global") -> list[tuple[str, int]]:
        """Search config for lines matching a pattern. Returns (line, line_num) pairs."""
        matches = []
        blocks = self._get_section_blocks(config, section)
        for block in blocks:
            for i, line in enumerate(block.lines):
                if re.search(pattern, line, re.IGNORECASE):
                    line_num = block.line_numbers[0] + i
                    matches.append((line, line_num))

        # Also search raw config if no matches found in blocks (some lines
        # are consumed by the parser into dicts rather than blocks)
        if not matches and section == "global":
            for i, line in enumerate(config.raw_config.splitlines()):
                stripped = line.strip()
                if stripped and re.search(pattern, stripped, re.IGNORECASE):
                    matches.append((stripped, i + 1))
        return matches

    def _get_section_blocks(self, config: ParsedConfig, section: str):
        """Get config blocks for a given section."""
        section_map = {
            "global": config.blocks,
            "interface": config.interfaces,
            "interfaces": config.interfaces,
            "acl": config.acls,
            "routing": config.routing,
            "aaa": config.aaa,
            "crypto": config.crypto,
            "ntp": config.ntp,
            "logging": config.logging_config,
            "snmp": config.snmp,
            "banner": config.banners,
            "user": config.users,
            "line": config.lines,
        }
        return section_map.get(section, config.blocks)

    def _check_config_match(self, rule: ComplianceRule,
                            config: ParsedConfig) -> Finding | None:
        """Check if a pattern exists (or doesn't) in config."""
        if not rule.match_pattern:
            return None

        matches = self._search_config(config, rule.match_pattern, rule.match_section)

        if rule.must_exist and not matches:
            return self._make_finding(rule, config,
                                      [f"Pattern not found: {rule.match_pattern}"])
        if rule.must_not_exist and matches:
            evidence = [line for line, _ in matches]
            line_nums = [num for _, num in matches]
            return self._make_finding(rule, config, evidence, line_nums)

        return None

    def _check_config_absent(self, rule: ComplianceRule,
                             config: ParsedConfig) -> Finding | None:
        """Check that something is absent from config."""
        rule_copy = ComplianceRule(**{
            **rule.__dict__,
            "must_exist": False,
            "must_not_exist": True,
        })
        return self._check_config_match(rule_copy, config)

    def _check_service(self, rule: ComplianceRule,
                       config: ParsedConfig) -> Finding | None:
        """Check service configuration."""
        if not rule.match_pattern:
            return None

        svc_name = rule.match_pattern
        is_enabled = config.services.get(svc_name)

        if rule.must_exist and not is_enabled:
            return self._make_finding(rule, config,
                                      [f"Service '{svc_name}' is not enabled"])
        if rule.must_not_exist and is_enabled:
            return self._make_finding(rule, config,
                                      [f"Service '{svc_name}' is enabled but should be disabled"])
        return None

    def _check_interface(self, rule: ComplianceRule,
                         config: ParsedConfig) -> Finding | None:
        """Check interface configuration."""
        if not config.interfaces:
            return None

        if not rule.match_pattern:
            return None

        for iface in config.interfaces:
            config_text = "\n".join(iface.lines)
            if rule.must_exist and not re.search(rule.match_pattern, config_text, re.IGNORECASE):
                return self._make_finding(
                    rule, config,
                    [f"Interface {iface.name} missing: {rule.match_pattern}"],
                    [iface.line_numbers[0]],
                )
        return None

    def _check_acl(self, rule: ComplianceRule,
                   config: ParsedConfig) -> Finding | None:
        """Check ACL configuration."""
        matches = self._search_config(config, rule.match_pattern or ".", "acl")
        if rule.must_exist and not matches and not config.acls:
            return self._make_finding(rule, config, ["No ACLs configured"])
        if rule.must_not_exist and matches:
            evidence = [line for line, _ in matches]
            return self._make_finding(rule, config, evidence)
        return None

    def _check_line(self, rule: ComplianceRule,
                    config: ParsedConfig) -> Finding | None:
        """Check line (VTY/console) configuration."""
        return self._check_config_match(
            ComplianceRule(**{**rule.__dict__, "match_section": "line"}), config
        )

    def _check_snmp(self, rule: ComplianceRule,
                    config: ParsedConfig) -> Finding | None:
        """Check SNMP configuration."""
        return self._check_config_match(
            ComplianceRule(**{**rule.__dict__, "match_section": "snmp"}), config
        )

    def _check_ntp(self, rule: ComplianceRule,
                   config: ParsedConfig) -> Finding | None:
        """Check NTP configuration."""
        return self._check_config_match(
            ComplianceRule(**{**rule.__dict__, "match_section": "ntp"}), config
        )

    def _check_logging(self, rule: ComplianceRule,
                       config: ParsedConfig) -> Finding | None:
        """Check logging configuration."""
        return self._check_config_match(
            ComplianceRule(**{**rule.__dict__, "match_section": "logging"}), config
        )

    def _check_aaa(self, rule: ComplianceRule,
                   config: ParsedConfig) -> Finding | None:
        """Check AAA configuration."""
        return self._check_config_match(
            ComplianceRule(**{**rule.__dict__, "match_section": "aaa"}), config
        )

    def _check_banner(self, rule: ComplianceRule,
                      config: ParsedConfig) -> Finding | None:
        """Check banner configuration."""
        if rule.must_exist and not config.banners:
            return self._make_finding(rule, config, ["No login banner configured"])
        return None

    def _check_crypto(self, rule: ComplianceRule,
                      config: ParsedConfig) -> Finding | None:
        """Check crypto/encryption configuration."""
        return self._check_config_match(
            ComplianceRule(**{**rule.__dict__, "match_section": "crypto"}), config
        )

    def _check_user(self, rule: ComplianceRule,
                    config: ParsedConfig) -> Finding | None:
        """Check user account configuration."""
        return self._check_config_match(
            ComplianceRule(**{**rule.__dict__, "match_section": "user"}), config
        )

    def _check_password(self, rule: ComplianceRule,
                        config: ParsedConfig) -> Finding | None:
        """Check for weak password configurations."""
        # Look for plaintext passwords in the entire config
        weak_patterns = [
            r"password\s+\d+\s+\S+",  # Type 0 or 7 passwords
            r"password\s+\S+$",  # Plaintext password
            r"enable\s+password\s+",
        ]
        for pattern in weak_patterns:
            matches = self._search_config(config, pattern, "global")
            if matches:
                evidence = [line for line, _ in matches]
                return self._make_finding(rule, config, evidence)
        return None
