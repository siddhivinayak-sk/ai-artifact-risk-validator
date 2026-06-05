"""Text output formatter for scan reports.

Formats a ScanReport as rich-formatted terminal text using
rich.console.Console with record=True for string capture.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ai_artifact_risk_validator.models.enums import GateAction, SeverityLabel
from ai_artifact_risk_validator.models.report import ScanReport


_GATE_STYLE = {
    GateAction.BLOCK: "bold red",
    GateAction.WARN: "bold yellow",
    GateAction.INFO: "bold green",
}

_SEVERITY_STYLE = {
    SeverityLabel.CRITICAL: "bold red",
    SeverityLabel.HIGH: "red",
    SeverityLabel.MEDIUM: "yellow",
    SeverityLabel.LOW: "cyan",
    SeverityLabel.INFORMATIONAL: "dim",
}


def format_text(report: ScanReport) -> str:
    """Format a ScanReport as rich-formatted terminal text.

    Includes a summary section with gate decision and finding counts,
    followed by a table listing each finding with severity, risk ID,
    title, file path, and line number.

    Args:
        report: The ScanReport to format.

    Returns:
        A string containing the formatted terminal output.
    """
    console = Console(record=True, width=120)

    # Header
    console.print()
    console.rule("[bold]AI Artifact Risk Validator — Scan Report[/bold]")
    console.print()

    # Summary section
    gate = report.summary.gate_decision
    gate_style = _GATE_STYLE.get(gate, "bold")
    console.print(f"  [bold]Scan ID:[/bold]     {report.scan_id}")
    console.print(f"  [bold]Path:[/bold]        {report.artifact_path}")
    console.print(f"  [bold]Timestamp:[/bold]   {report.scan_timestamp.isoformat()}")
    console.print(f"  [bold]Version:[/bold]     {report.scanner_version}")
    console.print()

    gate_text = Text(f"  Gate Decision: {gate.value}", style=gate_style)
    console.print(gate_text)
    console.print()

    # Counts summary
    summary = report.summary
    console.print(f"  [bold]Total Findings:[/bold]  {summary.total_findings}")
    console.print(f"  [red]Blocking:[/red]        {summary.blocking_findings}")
    console.print(f"  [yellow]Warnings:[/yellow]        {summary.warning_findings}")
    console.print(f"  [green]Info:[/green]            {summary.info_findings}")
    console.print()

    # Findings table
    if report.findings:
        table = Table(title="Findings", show_lines=True, expand=True)
        table.add_column("Severity", width=14)
        table.add_column("Risk ID", width=10)
        table.add_column("Title", min_width=20)
        table.add_column("File", min_width=20)
        table.add_column("Line", width=6, justify="right")

        for finding in report.findings:
            sev_style = _SEVERITY_STYLE.get(finding.severity_label, "")
            severity_text = Text(
                f"{finding.severity_label.value} (S{finding.severity_score})",
                style=sev_style,
            )

            line_str = str(finding.location.line) if finding.location.line else "—"

            fp_marker = " [dim](suppressed)[/dim]" if finding.false_positive else ""
            title_str = f"{finding.title}{fp_marker}"

            table.add_row(
                severity_text,
                finding.id,
                title_str,
                finding.artifact_path,
                line_str,
            )

        console.print(table)
    else:
        console.print("  [green]No findings detected.[/green]")

    # Errors section
    if report.errors:
        console.print()
        console.print("[bold yellow]Errors:[/bold yellow]")
        for error in report.errors:
            console.print(f"  • {error}")

    console.print()
    return console.export_text()
