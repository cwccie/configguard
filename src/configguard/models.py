"""Core data models for ConfigGuard."""

from __future__ import annotations

import enum
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Vendor(enum.Enum):
    """Supported network device vendors."""

    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    JUNOS = "junos"
    ARISTA_EOS = "arista_eos"
    PALO_ALTO = "palo_alto"
    UNKNOWN = "unknown"


class Severity(enum.Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}[self.value]

    def __lt__(self, other: Severity) -> bool:
        return self.score < other.score


class Framework(enum.Enum):
    """Compliance frameworks."""

    NIST_800_53 = "nist_800_53"
    CIS_BENCHMARK = "cis_benchmark"
    PCI_DSS = "pci_dss"
    CUSTOM = "custom"


@dataclass
class ConfigBlock:
    """A parsed configuration block."""

    block_type: str
    name: str
    lines: list[str] = field(default_factory=list)
    children: list[ConfigBlock] = field(default_factory=list)
    line_numbers: tuple[int, int] = (0, 0)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedConfig:
    """A fully parsed network device configuration."""

    device_name: str
    vendor: Vendor
    raw_config: str
    blocks: list[ConfigBlock] = field(default_factory=list)
    hostname: str = ""
    interfaces: list[ConfigBlock] = field(default_factory=list)
    acls: list[ConfigBlock] = field(default_factory=list)
    routing: list[ConfigBlock] = field(default_factory=list)
    services: dict[str, bool] = field(default_factory=dict)
    aaa: list[ConfigBlock] = field(default_factory=list)
    crypto: list[ConfigBlock] = field(default_factory=list)
    ntp: list[ConfigBlock] = field(default_factory=list)
    logging_config: list[ConfigBlock] = field(default_factory=list)
    snmp: list[ConfigBlock] = field(default_factory=list)
    banners: list[ConfigBlock] = field(default_factory=list)
    users: list[ConfigBlock] = field(default_factory=list)
    lines: list[ConfigBlock] = field(default_factory=list)
    source_file: str = ""
    parsed_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceRule:
    """A single compliance rule definition."""

    rule_id: str
    title: str
    description: str
    framework: Framework
    control_id: str  # e.g., AC-2, 1.1.1
    severity: Severity
    vendor: list[str] = field(default_factory=lambda: ["all"])
    check_type: str = "config_match"
    match_section: str = "global"
    match_pattern: str = ""
    must_exist: bool = True
    must_not_exist: bool = False
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    explanation: str = ""
    risk_description: str = ""
    business_impact: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A compliance violation finding."""

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    rule: ComplianceRule | None = None
    device_name: str = ""
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    line_numbers: list[int] = field(default_factory=list)
    remediation: str = ""
    explanation: str = ""
    risk_context: str = ""
    business_impact: str = ""
    framework: Framework = Framework.CUSTOM
    control_id: str = ""
    status: str = "open"
    found_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def dedup_key(self) -> str:
        raw = f"{self.device_name}:{self.control_id}:{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class RemediationPlan:
    """A remediation plan for a finding."""

    finding: Finding
    config_snippet: str = ""
    rollback_snippet: str = ""
    risk_assessment: str = ""
    validation_steps: list[str] = field(default_factory=list)
    batfish_validated: bool = False
    estimated_impact: str = "low"


@dataclass
class ComplianceReport:
    """A compliance report for one or more devices."""

    report_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    title: str = "ConfigGuard Compliance Report"
    generated_at: datetime = field(default_factory=datetime.utcnow)
    devices: list[str] = field(default_factory=list)
    frameworks: list[Framework] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_rules_checked: int = 0
    compliance_score: float = 0.0
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)


@dataclass
class ScanResult:
    """Result of a configuration scan."""

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    scan_type: str = "manual"
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    configs_scanned: int = 0
    findings_count: int = 0
    compliance_score: float = 0.0
    reports: list[ComplianceReport] = field(default_factory=list)
    drift_detected: bool = False
    drift_details: list[str] = field(default_factory=list)
