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

from ai_artifact_risk_validator.models.enums import GateAction

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
    default="json",
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


if __name__ == "__main__":
    cli()
