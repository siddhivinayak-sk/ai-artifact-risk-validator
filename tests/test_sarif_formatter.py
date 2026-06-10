"""Unit tests for SARIF formatter edge cases.

Validates specific example-based behaviors: empty report output, 2-space
indentation, and known-good snapshot validation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

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
from ai_artifact_risk_validator.reporting.formatters.sarif_formatter import format_sarif


def _empty_report() -> ScanReport:
    """Create a ScanReport with zero findings for testing."""
    return ScanReport(
        scan_id="test-001",
        artifact_path="src/test.py",
        artifact_type=ArtifactType.PROMPT,
        scan_timestamp=datetime(2025, 6, 5, 12, 0, 0, tzinfo=timezone.utc),
        scanner_version="0.6.0",
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


def _report_with_one_finding() -> ScanReport:
    """Create a ScanReport with one known finding for snapshot testing."""
    finding = ScanFinding(
        id="P-S1",
        artifact_type=ArtifactType.PROMPT,
        artifact_path="src/prompts/main.txt",
        severity_score=7,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        category=RiskCategory.SECURITY,
        title="Hardcoded secret detected",
        description="Found a hardcoded API key in the prompt template",
        location=FindingLocation(line=42, end_line=42),
        evidence="sk-abc123secret",
        confidence=0.95,
        scanner_module=ScannerModule.SECRET_SCAN,
        remediation="Move the secret to an environment variable or secrets manager.",
        references=["https://owasp.org/secrets"],
        false_positive=False,
        timestamp=datetime(2025, 6, 5, 12, 0, 0, tzinfo=timezone.utc),
    )
    return ScanReport(
        scan_id="snapshot-scan-001",
        artifact_path="src/prompts/main.txt",
        artifact_type=ArtifactType.PROMPT,
        scan_timestamp=datetime(2025, 6, 5, 12, 0, 0, tzinfo=timezone.utc),
        scanner_version="0.6.0",
        findings=[finding],
        summary=ScanSummary(
            total_findings=1,
            by_severity={"High": 1},
            by_category={"Security": 1},
            gate_decision=GateAction.BLOCK,
            blocking_findings=1,
            warning_findings=0,
            info_findings=0,
        ),
        errors=[],
    )


class TestEmptyReportProducesValidSarif:
    """Test: empty report (zero findings) produces valid SARIF with empty results array.

    Validates: Requirement 2.10
    """

    def test_empty_report_has_empty_results_array(self) -> None:
        """An empty ScanReport produces a SARIF document with an empty results array."""
        report = _empty_report()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        assert run["results"] == []

    def test_empty_report_has_valid_sarif_structure(self) -> None:
        """An empty ScanReport still produces a structurally valid SARIF document."""
        report = _empty_report()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        # Check required top-level fields
        assert "$schema" in doc
        assert doc["version"] == "2.1.0"
        assert "runs" in doc
        assert len(doc["runs"]) == 1

        run = doc["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "name" in run["tool"]["driver"]
        assert "version" in run["tool"]["driver"]

    def test_empty_report_has_empty_rules_array(self) -> None:
        """An empty ScanReport produces an empty tool.driver.rules array."""
        report = _empty_report()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        assert run["tool"]["driver"]["rules"] == []


class TestOutputUsesTwoSpaceIndentation:
    """Test: output uses 2-space indentation.

    Validates: Requirement 6.2
    """

    def test_output_uses_2_space_indent(self) -> None:
        """The SARIF output uses 2-space indentation, not 4-space."""
        report = _empty_report()
        sarif_output = format_sarif(report)

        # Lines should be indented with 2 spaces for first-level keys
        lines = sarif_output.split("\n")
        indented_lines = [line for line in lines if line.startswith("  ")]
        assert len(indented_lines) > 0, "Expected lines indented with 2 spaces"

        # Verify 2-space indent: first-level keys start with exactly "  " (2 spaces)
        # and NOT "    " (4 spaces) at the first indentation level
        assert any(line.startswith('  "') and not line.startswith('    "') for line in lines), (
            "Expected 2-space indentation at first level"
        )

    def test_output_does_not_use_4_space_indent_at_first_level(self) -> None:
        """The first indentation level uses exactly 2 spaces, never 4."""
        report = _empty_report()
        sarif_output = format_sarif(report)

        lines = sarif_output.split("\n")
        # Find lines at the first indentation level (direct children of root object)
        # These should start with exactly 2 spaces
        first_level_lines = [
            line for line in lines if line.startswith("  ") and not line.startswith("    ")
        ]
        assert len(first_level_lines) > 0, (
            "Expected first-level indented lines with exactly 2 spaces"
        )

        # Verify the known top-level keys appear at 2-space indent
        first_level_text = "\n".join(first_level_lines)
        assert '"version"' in first_level_text or '"runs"' in first_level_text


class TestKnownScanReportProducesExpectedSarif:
    """Test: specific known ScanReport produces expected SARIF output (snapshot test).

    Validates: Requirement 1.7
    """

    def test_known_report_contains_expected_rule_id(self) -> None:
        """The SARIF output contains the expected ruleId from the finding."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "P-S1"

    def test_known_report_contains_expected_message(self) -> None:
        """The SARIF output contains the expected message text."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        result = doc["runs"][0]["results"][0]
        assert result["message"]["text"] == "Found a hardcoded API key in the prompt template"

    def test_known_report_contains_expected_level(self) -> None:
        """The SARIF output maps BLOCK gate_action to 'error' level."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        result = doc["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_known_report_contains_expected_location(self) -> None:
        """The SARIF output contains expected artifact location and region."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        result = doc["runs"][0]["results"][0]
        location = result["locations"][0]
        assert location["artifactLocation"]["uri"] == "src/prompts/main.txt"
        assert location["region"]["startLine"] == 42
        assert location["region"]["endLine"] == 42

    def test_known_report_contains_expected_properties(self) -> None:
        """The SARIF output contains expected properties bag values."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        result = doc["runs"][0]["results"][0]
        props = result["properties"]
        assert props["severity_score"] == 7
        assert props["confidence"] == 0.95
        assert props["category"] == "Security"
        assert props["scanner_module"] == "SecretScan"
        assert props["evidence"] == "sk-abc123secret"

    def test_known_report_contains_expected_rule_metadata(self) -> None:
        """The SARIF output contains expected rule descriptor metadata."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert rule["id"] == "P-S1"
        assert rule["shortDescription"]["text"] == "Hardcoded secret detected"
        assert rule["fullDescription"]["text"] == (
            "Found a hardcoded API key in the prompt template"
        )
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["help"]["text"] == (
            "Move the secret to an environment variable or secrets manager."
        )

    def test_known_report_contains_expected_invocation(self) -> None:
        """The SARIF output contains expected invocation metadata."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        invocation = doc["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        assert invocation["commandLine"] == "ai-artifact-validator verify src/prompts/main.txt"
        assert invocation["startTimeUtc"] == "2025-06-05T12:00:00Z"

    def test_known_report_automation_details(self) -> None:
        """The SARIF output contains the scan_id in automationDetails."""
        report = _report_with_one_finding()
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        automation = doc["runs"][0]["automationDetails"]
        assert automation["id"] == "snapshot-scan-001"
