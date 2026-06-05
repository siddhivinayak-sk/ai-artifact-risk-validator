"""Click CLI application entry point for ai-artifact-validator."""

import click


@click.group()
@click.version_option(package_name="ai-artifact-risk-validator")
def cli() -> None:
    """AI Artifact Risk Validator - Validate AI artifacts for risks."""


if __name__ == "__main__":
    cli()
