"""Click CLI application entry point for ai-artifact-validator.

Provides the `verify` command with options for output, format, config,
scanners, severity threshold, log level, and parallel execution.

Exit codes:
    0 - PASS/INFO (no blocking or warning findings)
    1 - BLOCK (at least one finding requires blocking)
    2 - WARN (at least one warning-level finding, no blocking)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)

# Exit code mapping per gate decision
_EXIT_CODES: dict[GateAction, int] = {
    GateAction.INFO: 0,
    GateAction.WARN: 2,
    GateAction.BLOCK: 1,
}


@click.group()
@click.version_option(package_name="ai-artifact-risk-validator")
def cli() -> None:
    """AI Artifact Risk Validator - Validate AI artifacts for risks."""


@cli.command()
@click.argument("path", type=click.Path(exists=False))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Write report to file instead of stdout.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "text", "html"], case_sensitive=False),
    default="text",
    help="Output format for the report.",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML configuration file.",
)
@click.option(
    "--scanners",
    type=str,
    default=None,
    help="Comma-separated list of scanner module names to enable.",
)
@click.option(
    "--severity-threshold",
    type=click.IntRange(1, 10),
    default=None,
    help="Minimum severity score to include in report (1-10).",
)
@click.option(
    "--log-level",
    type=click.Choice(
        ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        case_sensitive=False,
    ),
    default=None,
    help="Logging level.",
)
@click.option(
    "--no-ignore",
    is_flag=True,
    default=False,
    help="Override all suppression rules and report all findings.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Disable scan result caching.",
)
@click.option(
    "--parallel",
    type=click.IntRange(1, 32),
    default=None,
    help="Number of parallel file workers (1-32).",
)
@click.option(
    "--allow-dynamic-scan",
    is_flag=True,
    default=False,
    help="Allow dynamic scanning of live MCP servers. Required in CI/CD mode.",
)
@click.option(
    "--semantic/--no-semantic",
    "semantic_enabled",
    default=None,
    help="Enable or disable semantic (embedding-based) analysis.",
)
@click.option(
    "--semantic-model",
    type=str,
    default=None,
    help="Sentence-transformer model name for semantic analysis.",
)
@click.option(
    "--semantic-threshold",
    type=click.FloatRange(0.0, 1.0),
    default=None,
    help="Minimum similarity score for semantic matches (0.0-1.0).",
)
def verify(
    path: str,
    output: str | None,
    output_format: str,
    config_path: str | None,
    scanners: str | None,
    severity_threshold: int | None,
    log_level: str | None,
    no_ignore: bool,
    no_cache: bool,
    parallel: int | None,
    allow_dynamic_scan: bool,
    semantic_enabled: bool | None,
    semantic_model: str | None,
    semantic_threshold: float | None,
) -> None:
    """Scan PATH for AI artifact risks and produce a validation report.

    PATH can be a directory (recursive scan) or a single file.

    Exit codes: 0=PASS/INFO, 1=BLOCK, 2=WARN
    """
    from ai_artifact_risk_validator.config.manager import ConfigManager
    from ai_artifact_risk_validator.models.config import ValidatorConfig
    from ai_artifact_risk_validator.models.enums import ScannerModule
    from ai_artifact_risk_validator.reporting.formatters.html_formatter import format_html
    from ai_artifact_risk_validator.reporting.formatters.text_formatter import format_text
    from ai_artifact_risk_validator.reporting.serializer import ReportSerializer
    from ai_artifact_risk_validator.validator import Validator

    console = Console(stderr=True)

    # Build CLI overrides dict
    cli_overrides: dict[str, object] = {}

    if log_level is not None:
        cli_overrides["log_level"] = log_level.upper()

    if severity_threshold is not None:
        cli_overrides["severity_threshold"] = severity_threshold

    if parallel is not None:
        cli_overrides["parallel_files"] = parallel

    if scanners is not None:
        scanner_names = [s.strip() for s in scanners.split(",") if s.strip()]
        try:
            cli_overrides["enabled_scanners"] = [ScannerModule(s) for s in scanner_names]
        except ValueError as exc:
            console.print(f"[red]Error:[/red] Invalid scanner name: {exc}")
            sys.exit(1)

    if no_cache:
        # Disable caching by not setting a cache directory
        cli_overrides["cache_dir"] = None

    if allow_dynamic_scan:
        cli_overrides["allow_dynamic_scan"] = True

    # Semantic CLI overrides
    semantic_overrides: dict[str, object] = {}
    if semantic_enabled is not None:
        semantic_overrides["enabled"] = semantic_enabled
    if semantic_model is not None:
        semantic_overrides["model_name"] = semantic_model
    if semantic_threshold is not None:
        semantic_overrides["threshold"] = semantic_threshold
    if semantic_overrides:
        cli_overrides["semantic"] = semantic_overrides

    # Also honour the AI_VALIDATOR_SEMANTIC_ENABLED env var
    env_semantic = os.environ.get("AI_VALIDATOR_SEMANTIC_ENABLED")
    if env_semantic is not None and "semantic" not in cli_overrides:
        cli_overrides["semantic"] = {"enabled": env_semantic.lower() in ("1", "true", "yes")}

    # Load configuration using ConfigManager with proper precedence
    config_manager = ConfigManager()
    try:
        config = config_manager.load(
            config_path=config_path,
            scan_path=path,
            cli_overrides=cli_overrides,
        )
    except Exception as exc:
        console.print(f"[red]Error loading configuration:[/red] {exc}")
        sys.exit(1)

    # Handle --no-ignore: clear suppression rules
    if no_ignore:
        config = ValidatorConfig(
            **{
                **config.model_dump(),
                "suppression_rules": [],
            }
        )

    # Create Validator and run the scan
    validator = Validator(config=config)
    report = validator.verify(path)

    # Handle --no-ignore post-processing: mark all findings as not false-positive
    if no_ignore:
        for finding in report.findings:
            finding.false_positive = False

    # Apply severity threshold filtering to the output
    if config.severity_threshold > 1:
        report.findings = [
            f for f in report.findings if f.severity_score >= config.severity_threshold
        ]
        # Recompute summary counts after filtering
        from ai_artifact_risk_validator.models.enums import GateAction

        non_fp = [f for f in report.findings if not f.false_positive]
        report.summary.total_findings = len(report.findings)
        report.summary.blocking_findings = sum(
            1 for f in non_fp if f.gate_action == GateAction.BLOCK
        )
        report.summary.warning_findings = sum(1 for f in non_fp if f.gate_action == GateAction.WARN)
        report.summary.info_findings = sum(1 for f in non_fp if f.gate_action == GateAction.INFO)

    # Format the report
    if output_format == "text":
        report_output = format_text(report)
    elif output_format == "html":
        report_output = format_html(report)
    else:
        serializer = ReportSerializer()
        report_output = serializer.serialize(report)

    # Output the report
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_output, encoding="utf-8")
        console.print(f"Report written to: {output}")
    else:
        # Write to stdout (not stderr)
        click.echo(report_output)

    # Side-effect: write HTML report to configured path if set
    html_side_effect_path = config.html_report_path or os.environ.get("AAV_HTML_REPORT_PATH")
    if html_side_effect_path:
        # Only write side-effect if it's a different path than --output
        # (or if --format is not html, since --output already received non-HTML content)
        should_write_side_effect = True
        if output and output_format == "html":
            # When --format html --output <path> and AAV_HTML_REPORT_PATH are set,
            # write to both locations (--output already handled above)
            resolved_output = str(Path(output).resolve())
            resolved_side = str(Path(html_side_effect_path).resolve())
            if resolved_output == resolved_side:
                should_write_side_effect = False

        if should_write_side_effect:
            try:
                side_effect_path = Path(html_side_effect_path)
                side_effect_path.parent.mkdir(parents=True, exist_ok=True)
                html_content = format_html(report) if output_format != "html" else report_output
                side_effect_path.write_text(html_content, encoding="utf-8")
                console.print(f"HTML report written to: {html_side_effect_path}")
            except OSError as exc:
                console.print(
                    f"[yellow]Warning:[/yellow] Failed to write HTML report to "
                    f"{html_side_effect_path}: {exc}"
                )

    # Determine exit code from gate decision
    exit_code = _EXIT_CODES.get(report.summary.gate_decision, 0)
    sys.exit(exit_code)


@cli.command("list-risks")
@click.option(
    "--category",
    type=click.Choice(
        [c.value for c in RiskCategory],
        case_sensitive=False,
    ),
    default=None,
    help="Filter risks by category.",
)
@click.option(
    "--artifact-type",
    type=click.Choice(
        [a.value for a in ArtifactType],
        case_sensitive=False,
    ),
    default=None,
    help="Filter risks by artifact type.",
)
@click.option(
    "--severity",
    type=click.Choice(
        [s.value for s in SeverityLabel],
        case_sensitive=False,
    ),
    default=None,
    help="Filter risks by severity label.",
)
@click.option(
    "--scanner",
    type=click.Choice(
        [m.value for m in ScannerModule],
        case_sensitive=False,
    ),
    default=None,
    help="Filter risks by scanner module.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format (text table or JSON).",
)
def list_risks(
    category: str | None,
    artifact_type: str | None,
    severity: str | None,
    scanner: str | None,
    output_format: str,
) -> None:
    """List all known risk definitions with optional filters."""
    import json

    from rich.table import Table

    from ai_artifact_risk_validator.models.enums import (
        ArtifactType,
        RiskCategory,
        ScannerModule,
        SeverityLabel,
    )
    from ai_artifact_risk_validator.risks.registry import RiskRegistry

    console = Console()

    registry = RiskRegistry()

    # Build query kwargs from filters
    query_kwargs: dict[str, object] = {}
    if category is not None:
        query_kwargs["category"] = RiskCategory(category)
    if artifact_type is not None:
        query_kwargs["artifact_type"] = ArtifactType(artifact_type)
    if severity is not None:
        query_kwargs["severity"] = SeverityLabel(severity)
    if scanner is not None:
        query_kwargs["scanner_module"] = ScannerModule(scanner)

    risks = registry.query(**query_kwargs)  # type: ignore[arg-type]

    # Sort by severity score (descending) then by ID
    risks.sort(key=lambda r: (-r.severity_score, r.id))

    if output_format == "json":
        data = [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity_label.value,
                "severity_score": r.severity_score,
                "category": r.category.value,
                "artifact_types": [at.value for at in r.artifact_types],
                "scanner_modules": [sm.value for sm in r.scanner_modules],
            }
            for r in risks
        ]
        click.echo(json.dumps(data, indent=2))
    else:
        table = Table(title=f"Risk Definitions ({len(risks)} results)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Title", style="white")
        table.add_column("Severity", style="bold")
        table.add_column("Category", style="green")
        table.add_column("Artifact Types", style="blue")
        table.add_column("Scanners", style="magenta")

        for r in risks:
            severity_style = {
                SeverityLabel.CRITICAL: "bold red",
                SeverityLabel.HIGH: "red",
                SeverityLabel.MEDIUM: "yellow",
                SeverityLabel.LOW: "blue",
                SeverityLabel.INFORMATIONAL: "dim",
            }.get(r.severity_label, "")

            table.add_row(
                r.id,
                r.title,
                f"[{severity_style}]{r.severity_label.value} ({r.severity_score})[/{severity_style}]",
                r.category.value,
                ", ".join(at.value for at in r.artifact_types),
                ", ".join(sm.value for sm in r.scanner_modules),
            )

        console.print(table)


@cli.command()
@click.option(
    "--path",
    "target_path",
    type=click.Path(),
    default=".",
    help="Directory where .aav.yaml will be created (defaults to current directory).",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing .aav.yaml file if it exists.",
)
def init(target_path: str, force: bool) -> None:
    """Generate a default .aav.yaml configuration file."""
    from rich.panel import Panel

    from ai_artifact_risk_validator.config.defaults import DEFAULT_CONFIG

    console = Console()

    target_dir = Path(target_path).resolve()
    config_file = target_dir / ".aav.yaml"

    if config_file.exists() and not force:
        console.print(
            Panel(
                f"[red]Configuration file already exists:[/red] {config_file}\n"
                "Use [bold]--force[/bold] to overwrite.",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)

    # Build YAML content from defaults
    import yaml

    # Prepare a user-friendly config with comments via ordered structure
    config_data: dict[str, object] = {
        "log_level": DEFAULT_CONFIG["log_level"],
        "severity_threshold": DEFAULT_CONFIG["severity_threshold"],
        "max_file_size_bytes": DEFAULT_CONFIG["max_file_size_bytes"],
        "parallel_files": DEFAULT_CONFIG["parallel_files"],
        "parallel_scanners": DEFAULT_CONFIG["parallel_scanners"],
        "file_include_patterns": DEFAULT_CONFIG["file_include_patterns"],
        "file_exclude_patterns": DEFAULT_CONFIG["file_exclude_patterns"],
        "enabled_scanners": DEFAULT_CONFIG["enabled_scanners"],
        "disabled_scanners": DEFAULT_CONFIG["disabled_scanners"],
        "custom_plugin_dirs": DEFAULT_CONFIG["custom_plugin_dirs"],
        "suppression_rules": DEFAULT_CONFIG["suppression_rules"],
        "gate_overrides": DEFAULT_CONFIG["gate_overrides"],
        "custom_artifact_patterns": DEFAULT_CONFIG["custom_artifact_patterns"],
    }

    target_dir.mkdir(parents=True, exist_ok=True)
    yaml_content = yaml.dump(config_data, default_flow_style=False, sort_keys=False)
    config_file.write_text(yaml_content, encoding="utf-8")

    console.print(
        Panel(
            f"[green]Configuration file created:[/green] {config_file}",
            title="Success",
            border_style="green",
        )
    )


if __name__ == "__main__":
    cli()
