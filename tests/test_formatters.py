"""Tests for output formatters (JSON, text, HTML)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

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
from ai_artifact_risk_validator.reporting.formatters import format_html, format_json, format_text


@pytest.fixture
def sample_finding() -> ScanFinding:
    """Create a sample finding for testing."""
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
        location=FindingLocation(line=5, end_line=7),
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
    """Create a sample report with one finding."""
    return ScanReport(
        scan_id="test-scan-001",
        artifact_path="/project/artifacts",
        artifact_type=None,
        scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
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
    )


@pytest.fixture
def empty_report() -> ScanReport:
    """Create a report with no findings."""
    return ScanReport(
        scan_id="empty-scan-001",
        artifact_path="/project/clean",
        artifact_type=None,
        scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
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
    )


@pytest.fixture
def report_with_errors(sample_finding: ScanFinding) -> ScanReport:
    """Create a report with error messages."""
    return ScanReport(
        scan_id="error-scan-001",
        artifact_path="/project/broken",
        artifact_type=None,
        scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
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
        errors=["Permission denied: /project/broken/secret.txt", "Scanner timeout: SecretScan"],
    )


class TestJsonFormatter:
    """Tests for the JSON formatter."""

    def test_returns_valid_json(self, sample_report: ScanReport):
        output = format_json(sample_report)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_scan_id(self, sample_report: ScanReport):
        output = format_json(sample_report)
        parsed = json.loads(output)
        assert parsed["scan_id"] == "test-scan-001"

    def test_contains_findings(self, sample_report: ScanReport):
        output = format_json(sample_report)
        parsed = json.loads(output)
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["id"] == "P-S1"

    def test_datetime_serialized_as_iso8601(self, sample_report: ScanReport):
        output = format_json(sample_report)
        parsed = json.loads(output)
        # Pydantic serializes to ISO 8601
        assert "2024-01-01" in parsed["scan_timestamp"]

    def test_empty_report(self, empty_report: ScanReport):
        output = format_json(empty_report)
        parsed = json.loads(output)
        assert parsed["findings"] == []
        assert parsed["summary"]["total_findings"] == 0

    def test_pretty_printed(self, sample_report: ScanReport):
        output = format_json(sample_report)
        # Pretty-printed JSON has newlines and indentation
        assert "\n" in output
        assert "  " in output


class TestTextFormatter:
    """Tests for the rich text formatter."""

    def test_contains_scan_id(self, sample_report: ScanReport):
        output = format_text(sample_report)
        assert "test-scan-001" in output

    def test_contains_gate_decision(self, sample_report: ScanReport):
        output = format_text(sample_report)
        assert "BLOCK" in output

    def test_contains_finding_risk_id(self, sample_report: ScanReport):
        output = format_text(sample_report)
        assert "P-S1" in output

    def test_contains_finding_title(self, sample_report: ScanReport):
        output = format_text(sample_report)
        assert "Prompt Injection Detected" in output

    def test_contains_artifact_path(self, sample_report: ScanReport):
        output = format_text(sample_report)
        assert "prompts/system.prompt.md" in output

    def test_contains_summary_counts(self, sample_report: ScanReport):
        output = format_text(sample_report)
        assert "Total Findings" in output
        assert "Blocking" in output

    def test_empty_report_shows_no_findings(self, empty_report: ScanReport):
        output = format_text(empty_report)
        assert "No findings detected" in output

    def test_returns_string(self, sample_report: ScanReport):
        output = format_text(sample_report)
        assert isinstance(output, str)

    def test_report_with_errors(self, report_with_errors: ScanReport):
        output = format_text(report_with_errors)
        assert "Permission denied" in output
        assert "Scanner timeout" in output


class TestHtmlFormatter:
    """Tests for the HTML formatter."""

    def test_is_complete_html_document(self, sample_report: ScanReport):
        output = format_html(sample_report)
        assert "<!DOCTYPE html>" in output
        assert "<html" in output
        assert "</html>" in output
        assert "<head>" in output
        assert "</head>" in output
        assert "<body>" in output
        assert "</body>" in output

    def test_contains_inline_css(self, sample_report: ScanReport):
        output = format_html(sample_report)
        assert "<style>" in output
        assert "</style>" in output

    def test_contains_scan_id(self, sample_report: ScanReport):
        output = format_html(sample_report)
        assert "test-scan-001" in output

    def test_contains_gate_decision(self, sample_report: ScanReport):
        output = format_html(sample_report)
        assert "BLOCK" in output

    def test_contains_finding_risk_id(self, sample_report: ScanReport):
        output = format_html(sample_report)
        assert "P-S1" in output

    def test_contains_finding_title(self, sample_report: ScanReport):
        output = format_html(sample_report)
        assert "Prompt Injection Detected" in output

    def test_contains_severity_badge(self, sample_report: ScanReport):
        output = format_html(sample_report)
        assert "severity-badge" in output
        assert "Critical (S9)" in output

    def test_empty_report_shows_no_findings(self, empty_report: ScanReport):
        output = format_html(empty_report)
        assert "No findings detected" in output

    def test_html_escapes_special_characters(self):
        """Test that special characters in findings are properly escaped."""
        finding = ScanFinding(
            id="P-S1",
            artifact_type=ArtifactType.PROMPT,
            artifact_path="path/<script>alert('xss')</script>",
            severity_score=9,
            severity_label=SeverityLabel.CRITICAL,
            priority=Priority.P0,
            gate_action=GateAction.BLOCK,
            category=RiskCategory.SECURITY,
            title='Test <b>bold</b> & "quotes"',
            description="Test description",
            location=FindingLocation(line=1),
            evidence="test evidence",
            confidence=0.95,
            scanner_module=ScannerModule.INJECTION_DET,
            remediation="Fix it",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        report = ScanReport(
            scan_id="xss-test",
            artifact_path="/project/<script>",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            scanner_version="0.1.0",
            findings=[finding],
            summary=ScanSummary(
                total_findings=1,
                by_severity={"Critical": 1},
                by_category={"Security": 1},
                gate_decision=GateAction.BLOCK,
                blocking_findings=1,
                warning_findings=0,
                info_findings=0,
            ),
        )
        output = format_html(report)
        # Should be escaped, not raw HTML
        assert "<script>" not in output
        assert "&lt;script&gt;" in output
        assert "&amp;" in output

    def test_report_with_errors(self, report_with_errors: ScanReport):
        output = format_html(report_with_errors)
        assert "Permission denied" in output
        assert "Scanner timeout" in output

    def test_suppressed_finding_has_class(self):
        """Test that suppressed findings get the suppressed class."""
        finding = ScanFinding(
            id="P-S1",
            artifact_type=ArtifactType.PROMPT,
            artifact_path="test.md",
            severity_score=5,
            severity_label=SeverityLabel.MEDIUM,
            priority=Priority.P2,
            gate_action=GateAction.WARN,
            category=RiskCategory.SECURITY,
            title="Suppressed Finding",
            description="This was suppressed",
            location=FindingLocation(line=1),
            evidence="test",
            confidence=0.9,
            scanner_module=ScannerModule.INJECTION_DET,
            remediation="N/A",
            false_positive=True,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        report = ScanReport(
            scan_id="supp-test",
            artifact_path="/project",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            scanner_version="0.1.0",
            findings=[finding],
            summary=ScanSummary(
                total_findings=1,
                by_severity={"Medium": 1},
                by_category={"Security": 1},
                gate_decision=GateAction.INFO,
                blocking_findings=0,
                warning_findings=0,
                info_findings=0,
            ),
        )
        output = format_html(report)
        assert 'class="suppressed"' in output
