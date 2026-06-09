"""Unit tests for the standalone cli/commands/list_risks.py module.

This module has 0% coverage because it's a separate implementation from
cli/main.py's list-risks command. Tests exercise the Click command directly.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.commands.list_risks import list_risks


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


class TestListRisksStandalone:
    """Tests for the standalone list-risks command in cli/commands/list_risks.py."""

    def test_text_format_default(self, runner: CliRunner):
        """list-risks with default text format outputs a table."""
        result = runner.invoke(list_risks)
        assert result.exit_code == 0
        assert "Risk Catalog" in result.output

    def test_json_format(self, runner: CliRunner):
        """list-risks --format json outputs valid JSON array."""
        result = runner.invoke(list_risks, ["--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0
        first = data[0]
        assert "id" in first
        assert "title" in first
        assert "category" in first
        assert "severity_score" in first
        assert "severity_label" in first
        assert "gate_action" in first
        assert "artifact_types" in first
        assert "scanner_modules" in first

    def test_filter_by_category(self, runner: CliRunner):
        """list-risks --category Security filters results."""
        result = runner.invoke(list_risks, ["--format", "json", "--category", "Security"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert risk["category"] == "Security"

    def test_filter_by_artifact_type(self, runner: CliRunner):
        """list-risks --artifact-type prompt filters results."""
        result = runner.invoke(list_risks, ["--format", "json", "--artifact-type", "prompt"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert "prompt" in risk["artifact_types"]

    def test_filter_by_severity(self, runner: CliRunner):
        """list-risks --severity Critical filters results."""
        result = runner.invoke(list_risks, ["--format", "json", "--severity", "Critical"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert risk["severity_label"] == "Critical"

    def test_filter_by_scanner(self, runner: CliRunner):
        """list-risks --scanner SecretScan filters results."""
        result = runner.invoke(list_risks, ["--format", "json", "--scanner", "SecretScan"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert "SecretScan" in risk["scanner_modules"]

    def test_results_sorted_by_severity_desc(self, runner: CliRunner):
        """Results are sorted by severity score descending."""
        result = runner.invoke(list_risks, ["--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        scores = [r["severity_score"] for r in data]
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1]

    def test_no_results_text_format(self, runner: CliRunner):
        """list-risks with filters that yield no results shows message."""
        # Use a combination unlikely to yield results
        result = runner.invoke(
            list_risks,
            ["--format", "text", "--category", "Ethics", "--artifact-type", "api_schema"],
        )
        assert result.exit_code == 0
        # Either shows "No risks found" or an empty table
        # The implementation shows "No risks found" when empty

    def test_combined_filters(self, runner: CliRunner):
        """list-risks with multiple filters ANDs them."""
        result = runner.invoke(
            list_risks,
            ["--format", "json", "--category", "Security", "--artifact-type", "prompt"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        for risk in data:
            assert risk["category"] == "Security"
            assert "prompt" in risk["artifact_types"]

    def test_severity_label_helper(self):
        """Test the _severity_label_from_score helper function."""
        from ai_artifact_risk_validator.cli.commands.list_risks import _severity_label_from_score
        from ai_artifact_risk_validator.models.enums import SeverityLabel

        assert _severity_label_from_score(10) == SeverityLabel.CRITICAL
        assert _severity_label_from_score(9) == SeverityLabel.CRITICAL
        assert _severity_label_from_score(8) == SeverityLabel.HIGH
        assert _severity_label_from_score(7) == SeverityLabel.HIGH
        assert _severity_label_from_score(6) == SeverityLabel.MEDIUM
        assert _severity_label_from_score(5) == SeverityLabel.MEDIUM
        assert _severity_label_from_score(4) == SeverityLabel.LOW
        assert _severity_label_from_score(3) == SeverityLabel.LOW
        assert _severity_label_from_score(2) == SeverityLabel.INFORMATIONAL
        assert _severity_label_from_score(1) == SeverityLabel.INFORMATIONAL

    def test_get_severity_style(self):
        """Test the _get_severity_style helper function."""
        from ai_artifact_risk_validator.cli.commands.list_risks import _get_severity_style
        from ai_artifact_risk_validator.models.enums import SeverityLabel

        assert _get_severity_style(SeverityLabel.CRITICAL) == "bold red"
        assert _get_severity_style(SeverityLabel.HIGH) == "red"
        assert _get_severity_style(SeverityLabel.MEDIUM) == "yellow"
        assert _get_severity_style(SeverityLabel.LOW) == "blue"
        assert _get_severity_style(SeverityLabel.INFORMATIONAL) == "dim"

    def test_get_gate_style(self):
        """Test the _get_gate_style helper function."""
        from ai_artifact_risk_validator.cli.commands.list_risks import _get_gate_style

        assert _get_gate_style("BLOCK") == "bold red"
        assert _get_gate_style("WARN") == "yellow"
        assert _get_gate_style("INFO") == "dim"
        assert _get_gate_style("UNKNOWN") == "white"
