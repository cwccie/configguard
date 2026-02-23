"""ConfigGuard CLI — Click-based command-line interface.

Commands:
  scan       Scan config files or directories for compliance
  check      Check a single config file
  report     Generate compliance reports
  explain    Explain a finding in plain English
  remediate  Generate remediation plans
  dashboard  Launch the web dashboard
  demo       Run a demo with sample configs
  rules      List loaded compliance rules
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from configguard import __version__


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


@click.group()
@click.version_option(version=__version__, prog_name="ConfigGuard")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
def cli(verbose: bool) -> None:
    """ConfigGuard — AI-driven network configuration compliance.

    Scan network configs against NIST 800-53, CIS Benchmarks, and PCI-DSS.
    Get plain English explanations and actionable remediation.
    """
    _setup_logging(verbose)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-f", "--framework", multiple=True,
              type=click.Choice(["nist_800_53", "cis_benchmark", "pci_dss"]),
              help="Filter by compliance framework")
@click.option("-o", "--output", type=click.Path(), help="Output report file")
@click.option("--format", "fmt", type=click.Choice(["text", "json", "csv", "pdf"]),
              default="text", help="Report format")
@click.option("-r", "--rules-dir", type=click.Path(exists=True),
              help="Additional rules directory")
def scan(path: str, framework: tuple[str], output: str | None,
         fmt: str, rules_dir: str | None) -> None:
    """Scan config file(s) or directory for compliance violations."""
    from configguard.check.checker import ComplianceChecker
    from configguard.models import Framework
    from configguard.report.generator import ReportGenerator

    frameworks = [Framework(f) for f in framework] if framework else None
    checker = ComplianceChecker(rules_dir=rules_dir)
    reporter = ReportGenerator()

    target = Path(path)
    if target.is_dir():
        click.echo(f"Scanning directory: {target}")
        report = checker.check_directory(target, frameworks)
    else:
        click.echo(f"Scanning file: {target}")
        report = checker.check_file(target, frameworks)

    # Display results
    _display_score(report.compliance_score)
    click.echo(f"\nDevices: {', '.join(report.devices)}")
    click.echo(f"Rules checked: {report.total_rules_checked}")
    click.echo(f"Findings: {len(report.findings)}")
    click.echo(f"  Critical: {report.critical_count}")
    click.echo(f"  High:     {report.high_count}")
    click.echo(f"  Medium:   {report.medium_count}")
    click.echo(f"  Low:      {report.low_count}")

    # Show findings summary
    if report.findings:
        click.echo("\nFindings:")
        for f in sorted(report.findings, key=lambda x: x.severity.score, reverse=True):
            sev_color = {"critical": "red", "high": "red", "medium": "yellow",
                         "low": "blue", "info": "white"}
            click.echo(
                click.style(f"  [{f.severity.value.upper():8s}] ", fg=sev_color.get(f.severity.value, "white"))
                + f"{f.title}"
            )

    # Generate report file
    if output:
        if fmt == "json":
            reporter.generate_json(report, output)
        elif fmt == "csv":
            reporter.generate_csv(report, output)
        elif fmt == "pdf":
            reporter.generate_pdf(report, output)
        else:
            reporter.generate_text(report, output)
        click.echo(f"\nReport saved: {output}")


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-f", "--framework", multiple=True,
              type=click.Choice(["nist_800_53", "cis_benchmark", "pci_dss"]))
def check(filepath: str, framework: tuple[str]) -> None:
    """Check a single config file and show detailed findings."""
    from configguard.check.checker import ComplianceChecker
    from configguard.explain.explainer import ViolationExplainer
    from configguard.models import Framework

    frameworks = [Framework(f) for f in framework] if framework else None
    checker = ComplianceChecker()
    explainer = ViolationExplainer()

    report = checker.check_file(filepath, frameworks)
    _display_score(report.compliance_score)

    if not report.findings:
        click.echo(click.style("\nNo compliance violations found!", fg="green"))
        return

    click.echo(f"\n{len(report.findings)} findings:\n")
    for finding in sorted(report.findings, key=lambda x: x.severity.score, reverse=True):
        explanation = explainer.explain_text(finding)
        click.echo(explanation)
        click.echo()


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), required=True)
@click.option("--format", "fmt", type=click.Choice(["text", "json", "csv", "pdf"]),
              default="text")
def report(filepath: str, output: str, fmt: str) -> None:
    """Generate a compliance report."""
    from configguard.check.checker import ComplianceChecker
    from configguard.report.generator import ReportGenerator

    checker = ComplianceChecker()
    reporter = ReportGenerator()

    target = Path(filepath)
    if target.is_dir():
        result = checker.check_directory(filepath)
    else:
        result = checker.check_file(filepath)

    if fmt == "json":
        reporter.generate_json(result, output)
    elif fmt == "csv":
        reporter.generate_csv(result, output)
    elif fmt == "pdf":
        reporter.generate_pdf(result, output)
    else:
        reporter.generate_text(result, output)

    click.echo(f"Report generated: {output}")
    click.echo(f"Compliance score: {result.compliance_score}%")


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
def explain(filepath: str) -> None:
    """Explain violations in plain English with risk context."""
    from configguard.check.checker import ComplianceChecker
    from configguard.explain.explainer import ViolationExplainer

    checker = ComplianceChecker()
    explainer = ViolationExplainer()
    report = checker.check_file(filepath)

    if not report.findings:
        click.echo(click.style("No violations to explain — config is compliant!", fg="green"))
        return

    for finding in sorted(report.findings, key=lambda x: x.severity.score, reverse=True):
        click.echo("=" * 70)
        click.echo(explainer.explain_text(finding))
        click.echo()


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
def remediate(filepath: str) -> None:
    """Generate remediation plans for violations."""
    from configguard.check.checker import ComplianceChecker
    from configguard.remediate.engine import RemediationEngine

    checker = ComplianceChecker()
    remediator = RemediationEngine()
    report = checker.check_file(filepath)

    if not report.findings:
        click.echo(click.style("No violations to remediate!", fg="green"))
        return

    plans = remediator.generate_plans(report.findings)
    for plan in plans:
        click.echo(remediator.format_plan_text(plan))
        click.echo()


@cli.command()
@click.option("-p", "--port", default=5000, help="Dashboard port")
@click.option("-h", "--host", default="127.0.0.1", help="Dashboard host")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def dashboard(port: int, host: str, debug: bool) -> None:
    """Launch the ConfigGuard web dashboard."""
    from configguard.dashboard.app import create_dashboard_app

    app = create_dashboard_app()
    click.echo(f"ConfigGuard Dashboard: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


@cli.command()
def demo() -> None:
    """Run a demo scan on sample configurations."""
    from configguard.check.checker import ComplianceChecker
    from configguard.explain.explainer import ViolationExplainer
    from configguard.remediate.engine import RemediationEngine

    click.echo(click.style("=" * 70, fg="blue"))
    click.echo(click.style("  ConfigGuard Demo — AI-Driven Configuration Compliance", fg="blue", bold=True))
    click.echo(click.style("=" * 70, fg="blue"))

    # Sample config with deliberate violations
    sample_config = """!
hostname DEMO-ROUTER
!
enable password cisco123
!
service finger
service pad
no service password-encryption
!
username admin password 0 admin123
!
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
snmp-server community public RO
snmp-server community private RW
!
line con 0
 password console123
 login
!
line vty 0 4
 password vty123
 transport input telnet
!
"""

    checker = ComplianceChecker()
    explainer = ViolationExplainer()
    remediator = RemediationEngine()

    click.echo("\nScanning demo router configuration...")
    click.echo(f"Rules loaded: {checker.engine.rule_count}\n")

    parsed = checker.parser.parse_text(sample_config, device_name="DEMO-ROUTER")
    report = checker.check_config(parsed)

    _display_score(report.compliance_score)
    click.echo(f"\nFindings: {len(report.findings)}")
    click.echo(f"  Critical: {report.critical_count}")
    click.echo(f"  High:     {report.high_count}")
    click.echo(f"  Medium:   {report.medium_count}")
    click.echo(f"  Low:      {report.low_count}")

    if report.findings:
        click.echo("\n" + "=" * 70)
        click.echo(click.style("  DETAILED FINDINGS WITH EXPLANATIONS", bold=True))
        click.echo("=" * 70)

        for i, finding in enumerate(sorted(report.findings,
                                           key=lambda x: x.severity.score, reverse=True), 1):
            click.echo(f"\n--- Finding {i} ---")
            click.echo(explainer.explain_text(finding))

            plan = remediator.generate_plan(finding)
            click.echo(f"\nSuggested Fix:")
            click.echo(click.style(plan.config_snippet, fg="green"))

    click.echo("\n" + click.style("Demo complete. Run 'configguard scan <config-file>' on your own configs.", fg="blue"))


@cli.command()
@click.option("-f", "--framework",
              type=click.Choice(["nist_800_53", "cis_benchmark", "pci_dss"]),
              help="Filter by framework")
def rules(framework: str | None) -> None:
    """List loaded compliance rules."""
    from configguard.check.checker import ComplianceChecker
    from configguard.models import Framework

    checker = ComplianceChecker()
    fw = Framework(framework) if framework else None
    rule_list = checker.engine.get_rules(fw)

    click.echo(f"Loaded rules: {len(rule_list)}")
    click.echo()
    for rule in sorted(rule_list, key=lambda r: (r.framework.value, r.rule_id)):
        sev_color = {"critical": "red", "high": "red", "medium": "yellow",
                     "low": "blue", "info": "white"}
        click.echo(
            f"  {rule.rule_id:20s} "
            + click.style(f"[{rule.severity.value:8s}]", fg=sev_color.get(rule.severity.value, "white"))
            + f" {rule.title}"
        )


def _display_score(score: float) -> None:
    """Display compliance score with color."""
    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    else:
        color = "red"
    click.echo(click.style(f"\nCompliance Score: {score}%", fg=color, bold=True))


if __name__ == "__main__":
    cli()
