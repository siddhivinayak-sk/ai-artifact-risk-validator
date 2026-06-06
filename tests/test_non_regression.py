"""Non-regression tests for existing JSON and text formats.

Ensures that the addition of HTML report format does not alter the behavior
of existing `--format json` and `--format text` outputs, and that the
`Validator.verify()` signature and return type remain unchanged.

Validates: Requirements 5.1, 5.2, 5.3, 5.4
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import get_type_hints

import pytest
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.main import cli
from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.models.report import ScanReport, ScanSummary
from ai_artifact_risk_validator.reporting.formatters import format_json, format_text
from ai_artifact_risk_validator.reporting.serializer import ReportSerializer
from ai_artifact_risk_validator.validator import Validator

# Common CLI args to suppress log output
_QUIET_ARGS = ["--log-level", "CRITICAL"]


@pytest.fixture
def sample_finding() -> ScanFinding:
    """Create a deterministic sample finding for non-regression testing."""
    return ScanFinding(
        id="P-S1",
        artifact_type=ArtifactType.PROMPT,
        artifact_path="prompts/system.prompt.md",
        severity_score=9,
        severity_label=SeverityLabel.CRITICAL,
        priority=Priority.P0,
        gate_action=GateAction.BLOCK,
        category=RiskCategory.SECURITY,
        title="Prompt Injection Detected",
        description="Direct injection pattern found in system prompt",
        location=FindingLocation(line=5, end_line=7, section="System Prompt"),
        evidence="ignore previous instructions",
        confidence=0.95,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Remove or sanitize the injection pattern",
        references=["https://owasp.org/llm-top-10"],
        false_positive=False,
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


@pytest.fixture
def sample_report(sample_finding: ScanFinding) -> ScanReport:
    """Create a deterministic sample report for non-regression testing."""
    return ScanReport(
        scan_id="non-regression-001",
        artifact_path="/project/artifacts",
        artifact_type=None,
        scan_timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        scanner_version="0.1.0",
        findings=[sample_finding],
        summary=ScanSummary(
            total_findings=1,
            by_severity={"Critical": 1},
            by_category={"Security": 1},
            gate_decision=GateAction.BLOCK,
            blocking_findings=1,
            warning_findings=0,
            info_findings=0,
        ),
        errors=[],
    )


@pytest.fixture
def empty_report() -> ScanReport:
    """Create a deterministic empty report for non-regression testing."""
    return ScanReport(
        scan_id="non-regression-empty-001",
        artifact_path="/project/clean",
        artifact_type=None,
        scan_timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        scanner_version="0.1.0",
        findings=[],
        summary=ScanSummary(
            total_findings=0,
            by_severity={},
            by_category={},
            gate_decision=GateAction.INFO,
            blocking_findings=0,
            warning_findings=0,
            info_findings=0,
        ),
        errors=[],
    )


class TestJsonFormatNonRegression:
    """Verify --format json output schema and content remain unchanged."""

    def test_json_output_is_valid_json(self, sample_report: ScanReport):
        """JSON output must be parseable as valid JSON."""
        output = format_json(sample_report)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_json_schema_has_required_top_level_keys(self, sample_report: ScanReport):
        """JSON output must contain all expected top-level keys."""
        output = format_json(sample_report)
        parsed = json.loads(output)
        expected_keys = {
            "scan_id",
            "artifact_path",
            "artifact_type",
            "scan_timestamp",
            "scanner_version",
            "findings",
            "summary",
            "errors",
        }
        assert expected_keys == set(parsed.keys())

    def test_json_summary_schema_unchanged(self, sample_report: ScanReport):
        """JSON summary section must contain all expected keys."""
        output = format_json(sample_report)
        parsed = json.loads(output)
        summary = parsed["summary"]
        expected_summary_keys = {
            "total_findings",
            "by_severity",
            "by_category",
            "gate_decision",
            "blocking_findings",
            "warning_findings",
            "info_findings",
        }
        assert expected_summary_keys == set(summary.keys())

    def test_json_finding_schema_unchanged(self, sample_report: ScanReport):
        """JSON finding objects must contain all expected keys."""
        output = format_json(sample_report)
        parsed = json.loads(output)
        finding = parsed["findings"][0]
        expected_finding_keys = {
            "id",
            "artifact_type",
            "artifact_path",
            "severity_score",
            "severity_label",
            "priority",
            "gate_action",
            "category",
            "title",
            "description",
            "location",
            "evidence",
            "confidence",
            "scanner_module",
            "remediation",
            "references",
            "false_positive",
            "timestamp",
        }
        assert expected_finding_keys == set(finding.keys())

    def test_json_finding_location_schema_unchanged(self, sample_report: ScanReport):
        """JSON finding location must contain all expected keys."""
        output = format_json(sample_report)
        parsed = json.loads(output)
        location = parsed["findings"][0]["location"]
        expected_location_keys = {"line", "end_line", "section", "offset"}
        assert expected_location_keys == set(location.keys())

    def test_json_content_values_unchanged(self, sample_report: ScanReport):
        """JSON output preserves exact field values from the ScanReport."""
        output = format_json(sample_report)
        parsed = json.loads(output)

        assert parsed["scan_id"] == "non-regression-001"
        assert parsed["artifact_path"] == "/project/artifacts"
        assert parsed["artifact_type"] is None
        assert parsed["scanner_version"] == "0.1.0"
        assert parsed["errors"] == []

        # Timestamp serialized as ISO 8601
        assert "2024-01-01" in parsed["scan_timestamp"]

        # Summary values
        assert parsed["summary"]["total_findings"] == 1
        assert parsed["summary"]["blocking_findings"] == 1
        assert parsed["summary"]["warning_findings"] == 0
        assert parsed["summary"]["info_findings"] == 0
        assert parsed["summary"]["gate_decision"] == "BLOCK"

        # Finding values
        finding = parsed["findings"][0]
        assert finding["id"] == "P-S1"
        assert finding["artifact_type"] == "prompt"
        assert finding["severity_score"] == 9
        assert finding["severity_label"] == "Critical"
        assert finding["priority"] == "P0"
        assert finding["gate_action"] == "BLOCK"
        assert finding["category"] == "Security"
        assert finding["title"] == "Prompt Injection Detected"
        assert finding["confidence"] == 0.95
        assert finding["false_positive"] is False

    def test_json_pretty_printed_with_indent(self, sample_report: ScanReport):
        """JSON output is pretty-printed (contains newlines and indentation)."""
        output = format_json(sample_report)
        assert "\n" in output
        assert "  " in output

    def test_json_empty_report_schema(self, empty_report: ScanReport):
        """Empty report JSON maintains the same schema with empty findings list."""
        output = format_json(empty_report)
        parsed = json.loads(output)
        assert parsed["findings"] == []
        assert parsed["summary"]["total_findings"] == 0
        assert parsed["summary"]["gate_decision"] == "INFO"

    def test_report_serializer_produces_same_as_format_json(self, sample_report: ScanReport):
        """ReportSerializer.serialize() and format_json() produce identical output."""
        serializer = ReportSerializer()
        serializer_output = serializer.serialize(sample_report)
        formatter_output = format_json(sample_report)
        assert serializer_output == formatter_output

    def test_cli_json_format_output_schema(self, tmp_path: Path):
        """CLI --format json produces valid JSON with correct schema via CliRunner."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tmp_path), "--format", "json", *_QUIET_ARGS])
        assert result.exit_code in (0, 1, 2)
        parsed = json.loads(result.output.strip())
        # Verify top-level schema
        expected_keys = {
            "scan_id",
            "artifact_path",
            "artifact_type",
            "scan_timestamp",
            "scanner_version",
            "findings",
            "summary",
            "errors",
        }
        assert expected_keys == set(parsed.keys())


class TestTextFormatNonRegression:
    """Verify --format text output format remains unchanged."""

    def test_text_output_is_string(self, sample_report: ScanReport):
        """Text output must be a non-empty string."""
        output = format_text(sample_report)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_text_contains_header(self, sample_report: ScanReport):
        """Text output must contain the report header."""
        output = format_text(sample_report)
        assert "AI Artifact Risk Validator" in output
        assert "Scan Report" in output

    def test_text_contains_scan_metadata(self, sample_report: ScanReport):
        """Text output must contain scan metadata fields."""
        output = format_text(sample_report)
        assert "Scan ID:" in output
        assert "non-regression-001" in output
        assert "Path:" in output
        assert "/project/artifacts" in output
        assert "Timestamp:" in output
        assert "Version:" in output
        assert "0.1.0" in output

    def test_text_contains_gate_decision(self, sample_report: ScanReport):
        """Text output must display the gate decision."""
        output = format_text(sample_report)
        assert "Gate Decision:" in output
        assert "BLOCK" in output

    def test_text_contains_summary_counts(self, sample_report: ScanReport):
        """Text output must display finding count labels."""
        output = format_text(sample_report)
        assert "Total Findings:" in output
        assert "Blocking:" in output
        assert "Warnings:" in output
        assert "Info:" in output

    def test_text_contains_finding_details(self, sample_report: ScanReport):
        """Text output must include finding risk ID, title, and severity."""
        output = format_text(sample_report)
        assert "P-S1" in output
        assert "Prompt Injection Detected" in output
        assert "Critical" in output

    def test_text_contains_finding_path(self, sample_report: ScanReport):
        """Text output must include the finding artifact path."""
        output = format_text(sample_report)
        assert "prompts/system.prompt.md" in output

    def test_text_empty_report_shows_no_findings(self, empty_report: ScanReport):
        """Empty report text output displays 'No findings detected' message."""
        output = format_text(empty_report)
        assert "No findings detected" in output

    def test_text_format_includes_findings_table(self, sample_report: ScanReport):
        """Text output with findings includes a 'Findings' table header."""
        output = format_text(sample_report)
        assert "Findings" in output

    def test_cli_text_format_output(self, tmp_path: Path):
        """CLI --format text produces non-empty text output via CliRunner."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(tmp_path), "--format", "text", *_QUIET_ARGS])
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        assert len(output) > 0
        assert "AI Artifact Risk Validator" in output
        assert "Scan Report" in output


class TestValidatorVerifySignature:
    """Verify Validator.verify() method signature and return type are unchanged."""

    def test_verify_method_exists(self):
        """Validator class has a verify() method."""
        assert hasattr(Validator, "verify")
        assert callable(Validator.verify)

    def test_verify_accepts_path_parameter(self):
        """verify() method accepts a 'path' parameter of type str | Path."""
        sig = inspect.signature(Validator.verify)
        params = list(sig.parameters.keys())
        # First param is 'self', second is 'path'
        assert "self" in params
        assert "path" in params
        assert len(params) == 2  # Only self and path

    def test_verify_path_parameter_annotation(self):
        """verify() path parameter is annotated as str | Path."""
        hints = get_type_hints(Validator.verify)
        # The path parameter should accept str or Path
        assert "path" in hints
        # Check it includes Path (str | Path)
        path_hint = hints["path"]
        # str | Path becomes typing.Union[str, Path] in get_type_hints
        assert Path in path_hint.__args__
        assert str in path_hint.__args__

    def test_verify_return_type_is_scan_report(self):
        """verify() return type is annotated as ScanReport."""
        hints = get_type_hints(Validator.verify)
        assert "return" in hints
        assert hints["return"] is ScanReport

    def test_verify_returns_scan_report_instance(self, tmp_path: Path):
        """verify() actually returns a ScanReport instance at runtime."""
        validator = Validator()
        report = validator.verify(str(tmp_path))
        assert isinstance(report, ScanReport)

    def test_verify_return_has_expected_attributes(self, tmp_path: Path):
        """ScanReport returned by verify() has all expected attributes."""
        validator = Validator()
        report = validator.verify(str(tmp_path))
        assert hasattr(report, "scan_id")
        assert hasattr(report, "artifact_path")
        assert hasattr(report, "artifact_type")
        assert hasattr(report, "scan_timestamp")
        assert hasattr(report, "scanner_version")
        assert hasattr(report, "findings")
        assert hasattr(report, "summary")
        assert hasattr(report, "errors")


class TestNoHtmlSideEffectWithoutConfig:
    """Verify no HTML output is produced when no HTML config is provided.

    Validates: Requirement 5.4
    """

    def test_json_format_produces_no_html_file(self, tmp_path: Path):
        """--format json without HTML config produces no HTML side-effect files."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS])
        assert result.exit_code in (0, 1, 2)
        # No .html files should be created anywhere in tmp_path
        html_files = list(tmp_path.rglob("*.html"))
        assert html_files == []

    def test_text_format_produces_no_html_file(self, tmp_path: Path):
        """--format text without HTML config produces no HTML side-effect files."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["verify", str(scan_dir), "--format", "text", *_QUIET_ARGS])
        assert result.exit_code in (0, 1, 2)
        # No .html files should be created anywhere in tmp_path
        html_files = list(tmp_path.rglob("*.html"))
        assert html_files == []
