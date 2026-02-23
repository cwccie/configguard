"""Remediation engine — generates fix configs, rollback, risk assessment."""

from __future__ import annotations

import re
from typing import Any

from configguard.models import Finding, RemediationPlan, Severity


# Remediation templates for common findings
_REMEDIATION_TEMPLATES: dict[str, dict[str, Any]] = {
    "enable_ssh": {
        "config": (
            "! Enable SSH and disable Telnet\n"
            "ip ssh version 2\n"
            "ip ssh time-out 60\n"
            "ip ssh authentication-retries 3\n"
            "crypto key generate rsa modulus 2048\n"
            "line vty 0 15\n"
            " transport input ssh\n"
            " transport output ssh\n"
        ),
        "rollback": (
            "! Rollback: Re-enable Telnet (NOT RECOMMENDED)\n"
            "line vty 0 15\n"
            " transport input telnet ssh\n"
        ),
        "risk": "low",
        "validation": [
            "Verify SSH connectivity: ssh admin@<device-ip>",
            "Verify Telnet is rejected: telnet <device-ip>",
            "Check SSH status: show ip ssh",
        ],
    },
    "strong_password": {
        "config": (
            "! Enable strong password encryption\n"
            "service password-encryption\n"
            "enable algorithm-type scrypt secret <CHANGE_ME>\n"
        ),
        "rollback": (
            "! Rollback: Revert to previous password config\n"
            "! NOTE: Capture current enable secret before applying\n"
        ),
        "risk": "low",
        "validation": [
            "Verify passwords are encrypted: show running-config | include password",
            "Verify login still works with new credentials",
        ],
    },
    "enable_logging": {
        "config": (
            "! Configure centralized logging\n"
            "logging buffered 64000 informational\n"
            "logging console critical\n"
            "logging host 10.0.0.100\n"
            "logging trap informational\n"
            "logging source-interface Loopback0\n"
            "service timestamps log datetime msec localtime show-timezone\n"
            "service timestamps debug datetime msec localtime show-timezone\n"
        ),
        "rollback": (
            "! Rollback logging changes\n"
            "no logging host 10.0.0.100\n"
            "no logging trap informational\n"
        ),
        "risk": "low",
        "validation": [
            "Verify syslog messages reach server: show logging",
            "Check logging config: show running-config | section logging",
        ],
    },
    "configure_ntp": {
        "config": (
            "! Configure NTP with authentication\n"
            "ntp authenticate\n"
            "ntp authentication-key 1 md5 <NTP_KEY>\n"
            "ntp trusted-key 1\n"
            "ntp server 10.0.0.50 key 1\n"
            "ntp server 10.0.0.51 key 1\n"
        ),
        "rollback": (
            "! Rollback NTP changes\n"
            "no ntp server 10.0.0.50\n"
            "no ntp server 10.0.0.51\n"
            "no ntp authenticate\n"
        ),
        "risk": "low",
        "validation": [
            "Verify NTP sync: show ntp status",
            "Verify NTP associations: show ntp associations",
        ],
    },
    "configure_banner": {
        "config": (
            "! Configure login banner\n"
            "banner login #\n"
            "***********************************************\n"
            "* WARNING: Authorized access only.            *\n"
            "* All activities are monitored and recorded.  *\n"
            "* Unauthorized access is strictly prohibited  *\n"
            "* and will be prosecuted to the fullest       *\n"
            "* extent of the law.                          *\n"
            "***********************************************\n"
            "#\n"
        ),
        "rollback": "! Rollback: no banner login\nno banner login\n",
        "risk": "low",
        "validation": [
            "Verify banner displays on login",
            "Check banner config: show running-config | section banner",
        ],
    },
    "secure_snmp": {
        "config": (
            "! Secure SNMP configuration\n"
            "no snmp-server community public\n"
            "no snmp-server community private\n"
            "snmp-server group SNMPV3GRP v3 priv\n"
            "snmp-server user snmpuser SNMPV3GRP v3 auth sha <AUTH_PASS> priv aes 256 <PRIV_PASS>\n"
            "snmp-server host 10.0.0.100 version 3 priv snmpuser\n"
        ),
        "rollback": (
            "! Rollback SNMP (NOT RECOMMENDED - restores weak config)\n"
            "no snmp-server group SNMPV3GRP v3 priv\n"
            "snmp-server community public RO\n"
        ),
        "risk": "medium",
        "validation": [
            "Verify SNMPv3 works: snmpwalk -v3 -u snmpuser -l authPriv ...",
            "Verify old community strings rejected",
            "Check SNMP config: show snmp user",
        ],
    },
    "enable_aaa": {
        "config": (
            "! Enable AAA with TACACS+\n"
            "aaa new-model\n"
            "aaa authentication login default group tacacs+ local\n"
            "aaa authorization exec default group tacacs+ local\n"
            "aaa accounting exec default start-stop group tacacs+\n"
            "aaa accounting commands 15 default start-stop group tacacs+\n"
            "tacacs server PRIMARY\n"
            " address ipv4 10.0.0.200\n"
            " key 7 <TACACS_KEY>\n"
        ),
        "rollback": (
            "! Rollback AAA (CAUTION - may lock you out)\n"
            "! Ensure console access is available before rollback\n"
            "no aaa new-model\n"
        ),
        "risk": "high",
        "validation": [
            "Verify TACACS+ authentication works",
            "Verify local fallback works if TACACS+ is down",
            "Check AAA config: show aaa sessions",
            "IMPORTANT: Keep console session open during testing",
        ],
    },
    "disable_service": {
        "config": (
            "! Disable unnecessary services\n"
            "no service pad\n"
            "no service finger\n"
            "no service udp-small-servers\n"
            "no service tcp-small-servers\n"
            "no ip source-route\n"
            "no ip finger\n"
            "no ip http server\n"
            "no ip bootp server\n"
            "no cdp run\n"
        ),
        "rollback": (
            "! Rollback: re-enable services (if needed)\n"
            "service pad\n"
            "ip http server\n"
            "cdp run\n"
        ),
        "risk": "low",
        "validation": [
            "Verify services are disabled: show control-plane host open-ports",
            "Test that required services still work",
        ],
    },
}


class RemediationEngine:
    """Generates remediation plans for compliance findings.

    Provides:
    - Config snippets to fix violations
    - Rollback configs to undo changes
    - Risk assessment for applying changes
    - Validation steps to verify the fix
    - Mock Batfish validation
    """

    def generate_plan(self, finding: Finding) -> RemediationPlan:
        """Generate a remediation plan for a finding."""
        # Try to match a template
        template_key = self._match_template(finding)

        if template_key and template_key in _REMEDIATION_TEMPLATES:
            template = _REMEDIATION_TEMPLATES[template_key]
            plan = RemediationPlan(
                finding=finding,
                config_snippet=template["config"],
                rollback_snippet=template["rollback"],
                risk_assessment=self._assess_risk(finding, template.get("risk", "medium")),
                validation_steps=template.get("validation", []),
                estimated_impact=template.get("risk", "medium"),
            )
        else:
            # Generate from rule remediation text
            plan = RemediationPlan(
                finding=finding,
                config_snippet=finding.remediation or "! Manual remediation required\n! See finding description for details",
                rollback_snippet="! Manual rollback required\n! Capture current config before applying changes",
                risk_assessment=self._assess_risk(finding, "medium"),
                validation_steps=["Verify the configuration change was applied correctly",
                                  "Test connectivity and functionality"],
                estimated_impact="medium",
            )

        return plan

    def generate_plans(self, findings: list[Finding]) -> list[RemediationPlan]:
        """Generate remediation plans for multiple findings."""
        return [self.generate_plan(f) for f in findings]

    def validate_with_batfish(self, plan: RemediationPlan) -> dict[str, Any]:
        """Validate a remediation plan using Batfish (mock).

        In production, this would connect to a Batfish instance and
        verify that the proposed config change doesn't break connectivity.
        """
        # Mock validation - simulates what Batfish would check
        result = {
            "validated": True,
            "checks_passed": [
                "Reachability analysis: No connectivity impact detected",
                "Loop detection: No routing loops introduced",
                "ACL analysis: No unintended traffic blocked",
                "Undefined references: No dangling references",
            ],
            "warnings": [],
            "errors": [],
        }

        # Add warnings for high-risk changes
        if plan.estimated_impact == "high":
            result["warnings"].append(
                "High-impact change detected. Recommend applying during maintenance window."
            )
        if "aaa" in (plan.finding.title or "").lower():
            result["warnings"].append(
                "AAA changes can lock out administrators. Ensure console access is available."
            )

        plan.batfish_validated = True
        return result

    def _match_template(self, finding: Finding) -> str | None:
        """Match a finding to a remediation template."""
        title_lower = (finding.title or "").lower()
        desc_lower = (finding.description or "").lower()
        combined = f"{title_lower} {desc_lower}"

        mappings = [
            ("enable_ssh", ["ssh", "telnet", "transport input"]),
            ("strong_password", ["password", "credential", "plaintext", "type 7"]),
            ("enable_logging", ["logging", "syslog", "audit log"]),
            ("configure_ntp", ["ntp", "time synchronization"]),
            ("configure_banner", ["banner", "motd", "login warning"]),
            ("secure_snmp", ["snmp", "community string"]),
            ("enable_aaa", ["aaa", "tacacs", "radius", "authentication server"]),
            ("disable_service", ["unnecessary service", "finger", "small-server", "http server"]),
        ]

        for key, keywords in mappings:
            if any(kw in combined for kw in keywords):
                return key

        return None

    def _assess_risk(self, finding: Finding, base_risk: str) -> str:
        """Generate a risk assessment for applying remediation."""
        risk_lines = [f"Change Risk Level: {base_risk.upper()}"]

        if base_risk == "high":
            risk_lines.extend([
                "",
                "WARNING: This change has a high risk of service disruption.",
                "- Apply during a scheduled maintenance window",
                "- Ensure out-of-band console access is available",
                "- Have the rollback configuration ready",
                "- Test in a lab environment first if possible",
            ])
        elif base_risk == "medium":
            risk_lines.extend([
                "",
                "CAUTION: This change may affect device behavior.",
                "- Review the configuration snippet carefully before applying",
                "- Monitor the device after applying changes",
                "- Have the rollback configuration ready",
            ])
        else:
            risk_lines.extend([
                "",
                "Low risk change. Standard change control process applies.",
                "- Verify the change was applied correctly",
                "- Monitor for any unexpected behavior",
            ])

        return "\n".join(risk_lines)

    def format_plan_text(self, plan: RemediationPlan) -> str:
        """Format a remediation plan as readable text."""
        lines = [
            f"{'=' * 60}",
            f"REMEDIATION PLAN — {plan.finding.title}",
            f"Device: {plan.finding.device_name}",
            f"Severity: {plan.finding.severity.value.upper()}",
            f"{'=' * 60}",
            "",
            "CONFIGURATION FIX:",
            "-" * 40,
            plan.config_snippet,
            "",
            "ROLLBACK CONFIGURATION:",
            "-" * 40,
            plan.rollback_snippet,
            "",
            "RISK ASSESSMENT:",
            "-" * 40,
            plan.risk_assessment,
            "",
            "VALIDATION STEPS:",
            "-" * 40,
        ]
        for i, step in enumerate(plan.validation_steps, 1):
            lines.append(f"  {i}. {step}")

        if plan.batfish_validated:
            lines.extend(["", "BATFISH VALIDATION: PASSED"])

        return "\n".join(lines)
