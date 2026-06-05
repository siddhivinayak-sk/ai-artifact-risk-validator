"""list-risks command implementation for the AI Artifact Validator CLI.

Displays the risk catalog with optional filtering by category, artifact type,
severity, and scanner module. Supports JSON and text output formats.

Requirements: 16.1, 16.10
"""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.risks.registry import RiskRegistry


def _severity_label_from_score(score: int) -> SeverityLabel:
    """Map a severity score to the minimum matching severity label."""
    if score >= 9:
        return SeverityLabel.CRITICAL
    if score >= 7:
        return SeverityLabel.HIGH
    if score >= 5:
        return SeverityLabel.MEDIUM
    if score >= 3:
        return SeverityLabel.LOW
    return SeverityLabel.INFORMATIONAL


@click.command("list-risks")
@click.option(
    "--category",
    type=click.Choice([c.value for c in RiskCategory], case_sensitive=False),
    default=None,
    help="Filter by risk category.",
)
@click.option(
    "--artifact-type",
    type=click.Choice([a.value for a in ArtifactType], case_sensitive=False),
    default=None,
    help="Filter by artifact type.",
)
@click.option(
    "--severity",
    type=click.Choice(
        [s.value for s in SeverityLabel],
        case_sensitive=False,
    ),
    default=None,
    help="Filter by severity label.",
)
@click.option(
    "--scanner",
    type=click.Choice([s.value for s in ScannerModule], case_sensitive=False),
    default=None,
    help="Filter by scanner module.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "text"], case_sensitive=False),
    default="text",
    help="Output format (default: text).",
)
def list_risks(
    category: str | None,
    artifact_type: str | None,
    severity: str | None,
    scanner: str | None,
    output_format: str,
) -> None:
    """Display the risk catalog with optional filters."""
    registry = RiskRegistry()

    # Convert string filter values to enum types
    category_enum = RiskCategory(category) if category else None
    artifact_type_enum = ArtifactType(artifact_type) if artifact_type else None
    severity_enum = SeverityLabel(severity) if severity else None
    scanner_enum = ScannerModule(scanner) if scanner else None

    # Query the registry
    risks = registry.query(
        category=category_enum,
        artifact_type=artifact_type_enum,
        severity=severity_enum,
        scanner_module=scanner_enum,
    )

    # Sort by severity score descending, then by ID
    risks.sort(key=lambda r: (-r.severity_score, r.id))

    if output_format == "json":
        _output_json(risks)
    else:
        _output_text(risks)


def _output_json(risks: list) -> None:
    """Output risks as JSON to stdout."""
    output = []
    for risk in risks:
        output.append(
            {
                "id": risk.id,
                "title": risk.title,
                "category": risk.category.value,
                "severity_score": risk.severity_score,
                "severity_label": risk.severity_label.value,
                "gate_action": risk.gate_action.value,
                "artifact_types": [a.value for a in risk.artifact_types],
                "scanner_modules": [s.value for s in risk.scanner_modules],
            }
        )
    click.echo(json.dumps(output, indent=2))


def _output_text(risks: list) -> None:
    """Output risks as a rich formatted table."""
    console = Console()

    if not risks:
        console.print("[yellow]No risks found matching the specified filters.[/yellow]")
        return

    table = Table(title=f"Risk Catalog ({len(risks)} risks)", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Category", style="magenta")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Gate", no_wrap=True)
    table.add_column("Scanners", style="dim")

    for risk in risks:
        # Color severity based on label
        severity_style = _get_severity_style(risk.severity_label)
        severity_text = f"[{severity_style}]{risk.severity_label.value} (S{risk.severity_score})[/{severity_style}]"

        # Color gate action
        gate_style = _get_gate_style(risk.gate_action.value)
        gate_text = f"[{gate_style}]{risk.gate_action.value}[/{gate_style}]"

        scanners_text = ", ".join(s.value for s in risk.scanner_modules)

        table.add_row(
            risk.id,
            risk.title,
            risk.category.value,
            severity_text,
            gate_text,
            scanners_text,
        )

    console.print(table)


def _get_severity_style(severity: SeverityLabel) -> str:
    """Return a rich style string for the given severity label."""
    styles = {
        SeverityLabel.CRITICAL: "bold red",
        SeverityLabel.HIGH: "red",
        SeverityLabel.MEDIUM: "yellow",
        SeverityLabel.LOW: "blue",
        SeverityLabel.INFORMATIONAL: "dim",
    }
    return styles.get(severity, "white")


def _get_gate_style(gate: str) -> str:
    """Return a rich style string for the given gate action."""
    styles = {
        "BLOCK": "bold red",
        "WARN": "yellow",
        "INFO": "dim",
    }
    return styles.get(gate, "white")
