"""Plain English violation explainer with risk context and business impact."""

from __future__ import annotations

from configguard.models import Finding, Framework, Severity


# Pre-built explanation templates by common violation categories
_EXPLANATION_TEMPLATES = {
    "password": {
        "what": (
            "The device configuration contains passwords stored in a weak or plaintext format. "
            "Anyone with read access to the configuration file can extract these credentials."
        ),
        "risk": (
            "An attacker who obtains a copy of the configuration (through a backup, TFTP "
            "intercept, or unauthorized access) can immediately use these credentials to "
            "gain administrative access to the device."
        ),
        "impact": (
            "Complete device compromise. An attacker with admin credentials can intercept "
            "all traffic traversing the device, modify routing to redirect traffic, create "
            "persistent backdoor accounts, or take the device offline."
        ),
    },
    "ssh": {
        "what": (
            "The device does not enforce SSH for management access, allowing unencrypted "
            "protocols like Telnet. All commands, including passwords, are transmitted "
            "in cleartext across the network."
        ),
        "risk": (
            "Any user on the same network segment can capture management traffic with "
            "basic packet sniffing tools (Wireshark, tcpdump). This exposes admin "
            "credentials and all configuration changes in real-time."
        ),
        "impact": (
            "Credential theft leading to full device takeover. Additionally, compliance "
            "frameworks universally require encrypted management channels — this finding "
            "will cause automatic audit failure."
        ),
    },
    "acl": {
        "what": (
            "Access Control Lists (ACLs) are either missing, incomplete, or too permissive. "
            "This means network traffic is not being properly filtered at this device."
        ),
        "risk": (
            "Without proper ACLs, unauthorized traffic can traverse the network unchecked. "
            "Lateral movement after initial compromise becomes trivial, and network "
            "segmentation controls are effectively bypassed."
        ),
        "impact": (
            "Regulatory non-compliance (PCI-DSS requires network segmentation). Increased "
            "blast radius of any security incident. Failed security audits."
        ),
    },
    "snmp": {
        "what": (
            "SNMP is configured with default or weak community strings (such as 'public' "
            "or 'private'), or is using SNMPv1/v2c which transmits community strings in "
            "cleartext."
        ),
        "risk": (
            "An attacker can use default SNMP community strings to read the entire device "
            "configuration remotely, including interface details, routing tables, and "
            "potentially credentials. With write access, they can modify the configuration."
        ),
        "impact": (
            "Information disclosure of the complete network topology and device "
            "configurations. With write community access, full device compromise "
            "without needing SSH/console credentials."
        ),
    },
    "ntp": {
        "what": (
            "The device lacks proper NTP (time synchronization) configuration or uses "
            "unauthenticated NTP sources."
        ),
        "risk": (
            "Without accurate time synchronization, security logs from different devices "
            "cannot be correlated. An attacker can manipulate device time to hide their "
            "activities in logs or cause certificate validation failures."
        ),
        "impact": (
            "Inability to perform forensic investigation after a security incident. "
            "Compliance violations for audit logging requirements. Potential disruption "
            "of time-dependent protocols (TLS certificates, Kerberos)."
        ),
    },
    "logging": {
        "what": (
            "The device does not have adequate logging configured. Security events, "
            "configuration changes, and access attempts are not being recorded to a "
            "central logging server."
        ),
        "risk": (
            "Without centralized logging, security incidents go undetected. An attacker "
            "who compromises the device can erase local logs to cover their tracks, "
            "with no remote copy preserved."
        ),
        "impact": (
            "Inability to detect, investigate, or respond to security incidents. "
            "Automatic failure of compliance audits requiring audit trail preservation "
            "(NIST AU-*, PCI-DSS 10.x)."
        ),
    },
    "banner": {
        "what": (
            "The device does not display a legal warning banner before or after login. "
            "A login banner provides legal notice that the system is monitored and "
            "unauthorized access is prohibited."
        ),
        "risk": (
            "Without a legal banner, the organization may have limited legal recourse "
            "against unauthorized users. In some jurisdictions, the absence of a warning "
            "can weaken prosecution of computer crimes."
        ),
        "impact": (
            "Reduced legal protection against unauthorized access. Compliance gap for "
            "frameworks requiring access warning banners (NIST AC-8, CIS benchmarks)."
        ),
    },
    "encryption": {
        "what": (
            "The device uses weak or outdated encryption algorithms, or critical "
            "communications channels lack encryption entirely."
        ),
        "risk": (
            "Weak encryption can be broken by modern computing resources. Data in "
            "transit — including credentials and configuration data — can be intercepted "
            "and decrypted by an attacker."
        ),
        "impact": (
            "Data confidentiality breach. Regulatory non-compliance. Exposure of "
            "sensitive data including credentials, routing information, and potentially "
            "customer traffic if the device handles user data."
        ),
    },
    "aaa": {
        "what": (
            "The device does not use centralized Authentication, Authorization, and "
            "Accounting (AAA). Access is managed with local accounts only, without "
            "RADIUS or TACACS+ integration."
        ),
        "risk": (
            "Local-only authentication cannot enforce enterprise password policies, "
            "multi-factor authentication, or centralized account lifecycle management. "
            "Terminated employees may retain access indefinitely."
        ),
        "impact": (
            "Orphaned accounts with persistent access after personnel changes. No "
            "centralized audit trail of who accessed which devices. Failed compliance "
            "for access control requirements."
        ),
    },
    "default": {
        "what": "A configuration compliance violation was detected on this device.",
        "risk": (
            "This violation creates a security gap that could be exploited by "
            "malicious actors to compromise the device or the network."
        ),
        "impact": (
            "Potential regulatory non-compliance and increased security risk. "
            "Review the specific finding details for more information."
        ),
    },
}


class ViolationExplainer:
    """Generates plain English explanations of compliance violations.

    Provides three levels of explanation:
    - What's wrong (technical description in plain language)
    - Risk context (what could go wrong if not fixed)
    - Business impact (why the business should care)
    """

    def explain(self, finding: Finding) -> dict[str, str]:
        """Generate a full explanation for a finding.

        Returns a dict with keys: what, risk, impact, recommendation, severity_context
        """
        # Use rule-provided explanations if available
        if finding.explanation and finding.risk_context and finding.business_impact:
            return {
                "what": finding.explanation,
                "risk": finding.risk_context,
                "impact": finding.business_impact,
                "recommendation": finding.remediation or "Review and remediate this finding.",
                "severity_context": self._severity_context(finding.severity),
            }

        # Auto-generate from templates
        category = self._categorize_finding(finding)
        template = _EXPLANATION_TEMPLATES.get(category, _EXPLANATION_TEMPLATES["default"])

        return {
            "what": finding.explanation or template["what"],
            "risk": finding.risk_context or template["risk"],
            "impact": finding.business_impact or template["impact"],
            "recommendation": finding.remediation or "Review and remediate this finding.",
            "severity_context": self._severity_context(finding.severity),
        }

    def explain_text(self, finding: Finding) -> str:
        """Generate a formatted text explanation."""
        info = self.explain(finding)
        lines = [
            f"FINDING: {finding.title}",
            f"Device: {finding.device_name}",
            f"Severity: {finding.severity.value.upper()} — {info['severity_context']}",
            f"Framework: {finding.framework.value} ({finding.control_id})",
            "",
            "WHAT'S WRONG:",
            info["what"],
            "",
            "RISK — WHAT COULD GO WRONG:",
            info["risk"],
            "",
            "BUSINESS IMPACT:",
            info["impact"],
            "",
            "RECOMMENDATION:",
            info["recommendation"],
        ]

        if finding.evidence:
            lines.append("")
            lines.append("EVIDENCE:")
            for ev in finding.evidence[:5]:
                lines.append(f"  > {ev}")

        return "\n".join(lines)

    def _categorize_finding(self, finding: Finding) -> str:
        """Categorize a finding to select the right explanation template."""
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        combined = f"{title_lower} {desc_lower}"

        categories = [
            ("password", ["password", "credential", "secret", "type 7", "plaintext"]),
            ("ssh", ["ssh", "telnet", "transport input", "management protocol"]),
            ("acl", ["acl", "access-list", "access control", "firewall rule"]),
            ("snmp", ["snmp", "community string"]),
            ("ntp", ["ntp", "time synchronization", "time server"]),
            ("logging", ["logging", "syslog", "audit", "log server"]),
            ("banner", ["banner", "motd", "warning message"]),
            ("encryption", ["encrypt", "cipher", "tls", "ssl", "crypto", "key exchange"]),
            ("aaa", ["aaa", "tacacs", "radius", "authentication", "authorization"]),
        ]

        for cat, keywords in categories:
            if any(kw in combined for kw in keywords):
                return cat

        return "default"

    def _severity_context(self, severity: Severity) -> str:
        """Provide context for what a severity level means."""
        return {
            Severity.CRITICAL: (
                "This must be fixed immediately. Critical findings represent imminent "
                "risk of compromise and will cause automatic compliance audit failure."
            ),
            Severity.HIGH: (
                "Fix within 24-48 hours. High-severity findings indicate significant "
                "security weaknesses that are likely to be exploited."
            ),
            Severity.MEDIUM: (
                "Fix within 30 days. Medium findings represent real risk that should "
                "be addressed in the next maintenance window."
            ),
            Severity.LOW: (
                "Fix within 90 days. Low-severity findings are hardening improvements "
                "that reduce attack surface."
            ),
            Severity.INFO: (
                "Informational. Review for best practice alignment but no immediate "
                "action required."
            ),
        }[severity]
