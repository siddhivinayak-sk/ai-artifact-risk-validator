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
        assert "suppressed" in output
        assert 'class="finding-card suppressed"' in output

    def test_summary_section_contains_all_fields(self, sample_report: ScanReport):
        """Verify summary section includes all required metadata fields."""
        output = format_html(sample_report)
        # scan_id
        assert "test-scan-001" in output
        # artifact_path
        assert "/project/artifacts" in output
        # scan_timestamp in ISO format
        assert "2024-01-01T00:00:00" in output
        # scanner_version
        assert "0.1.0" in output
        # gate_decision value
        assert "BLOCK" in output
        # total_findings count
        assert ">1<" in output  # total_findings = 1 in a table cell
        # blocking_findings count
        assert "Blocking" in output
        # warning_findings count
        assert "Warnings" in output
        # info_findings count
        assert "Info" in output

    def test_errors_section_renders_ul_list(self, report_with_errors: ScanReport):
        """Verify errors section uses a <ul> list structure."""
        output = format_html(report_with_errors)
        assert "<ul>" in output
        assert "<li>" in output
        assert "Permission denied: /project/broken/secret.txt" in output
        assert "Scanner timeout: SecretScan" in output

    def test_errors_section_absent_when_no_errors(self, sample_report: ScanReport):
        """Verify errors section is not rendered when no errors exist."""
        output = format_html(sample_report)
        assert 'class="errors"' not in output

    def test_errors_section_escapes_html_in_messages(self):
        """Verify error messages with HTML chars are escaped."""
        report = ScanReport(
            scan_id="esc-test",
            artifact_path="/project",
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
            errors=["<script>alert('xss')</script>", "a & b < c"],
        )
        output = format_html(report)
        assert "&lt;script&gt;" in output
        assert "<script>" not in output
        assert "&amp;" in output

    def test_html5_document_structure(self, sample_report: ScanReport):
        """Verify the HTML5 document structure is complete."""
        output = format_html(sample_report)
        assert output.startswith("<!DOCTYPE html>")
        assert '<html lang="en">' in output
        assert "<head>" in output
        assert "</head>" in output
        assert "<style>" in output
        assert "</style>" in output
        assert "<body>" in output
        assert "</body>" in output
        assert "</html>" in output

    def test_no_external_resource_references(self, sample_report: ScanReport):
        """Verify no external resources are referenced."""
        output = format_html(sample_report)
        assert 'href="http' not in output
        assert 'src="http' not in output
        assert "url(http" not in output
        assert '<link rel="stylesheet" href=' not in output

    # --- Task 4.2: Edge case unit tests ---

    def test_zero_findings_produces_valid_html_with_no_findings_message(
        self, empty_report: ScanReport
    ):
        """Verify zero findings produces valid HTML5 with 'no findings' message.

        Requirements: 4.2, 6.2
        """
        output = format_html(empty_report)
        # Valid HTML5 structure
        assert "<!DOCTYPE html>" in output
        assert '<html lang="en">' in output
        assert "<head>" in output
        assert "</head>" in output
        assert "<body>" in output
        assert "</body>" in output
        assert "</html>" in output
        assert "<style>" in output
        # No findings message
        assert "No findings detected" in output
        # No finding cards present
        assert 'class="finding-card' not in output

    def test_single_finding_renders_all_detail_fields(self, sample_report: ScanReport):
        """Verify single finding renders every detail field in its card.

        Requirements: 4.1, 6.2
        """
        output = format_html(sample_report)
        finding = sample_report.findings[0]

        # Risk ID
        assert finding.id in output
        # Artifact Type
        assert finding.artifact_type.value in output
        # Artifact Path
        assert finding.artifact_path in output
        # Severity Score
        assert f"S{finding.severity_score}" in output
        # Severity Label
        assert finding.severity_label.value in output
        # Priority
        assert finding.priority.value in output
        # Gate Action
        assert finding.gate_action.value in output
        # Category
        assert finding.category.value in output
        # Title
        assert finding.title in output
        # Description
        assert finding.description in output
        # Location: line
        assert str(finding.location.line) in output
        # Location: end_line
        assert str(finding.location.end_line) in output
        # Evidence in code block
        assert finding.evidence in output
        assert "<pre><code>" in output
        # Confidence
        assert str(finding.confidence) in output
        # Scanner Module
        assert finding.scanner_module.value in output
        # Remediation
        assert finding.remediation in output
        # References
        assert finding.references[0] in output
        # False Positive status
        assert "No" in output  # false_positive=False shows "No"

    def test_multiple_findings_render_each_in_own_card(self):
        """Verify multiple findings are each rendered in separate cards.

        Requirements: 6.2
        """
        finding1 = ScanFinding(
            id="P-S1",
            artifact_type=ArtifactType.PROMPT,
            artifact_path="prompts/a.md",
            severity_score=9,
            severity_label=SeverityLabel.CRITICAL,
            priority=Priority.P0,
            gate_action=GateAction.BLOCK,
            category=RiskCategory.SECURITY,
            title="First Finding",
            description="First description",
            location=FindingLocation(line=1),
            evidence="evidence one",
            confidence=0.95,
            scanner_module=ScannerModule.INJECTION_DET,
            remediation="Fix first",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        finding2 = ScanFinding(
            id="P-S2",
            artifact_type=ArtifactType.SKILL,
            artifact_path="skills/b.yaml",
            severity_score=5,
            severity_label=SeverityLabel.MEDIUM,
            priority=Priority.P2,
            gate_action=GateAction.WARN,
            category=RiskCategory.QUALITY,
            title="Second Finding",
            description="Second description",
            location=FindingLocation(line=10, end_line=12),
            evidence="evidence two",
            confidence=0.7,
            scanner_module=ScannerModule.QUALITY_LINT,
            remediation="Fix second",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        finding3 = ScanFinding(
            id="P-S3",
            artifact_type=ArtifactType.AGENT,
            artifact_path="agents/c.json",
            severity_score=3,
            severity_label=SeverityLabel.LOW,
            priority=Priority.P4,
            gate_action=GateAction.INFO,
            category=RiskCategory.RELIABILITY,
            title="Third Finding",
            description="Third description",
            location=FindingLocation(line=20),
            evidence="evidence three",
            confidence=0.5,
            scanner_module=ScannerModule.COMPOSE_ANALYZE,
            remediation="Fix third",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        report = ScanReport(
            scan_id="multi-test",
            artifact_path="/project/multi",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            scanner_version="0.1.0",
            findings=[finding1, finding2, finding3],
            summary=ScanSummary(
                total_findings=3,
                by_severity={"Critical": 1, "Medium": 1, "Low": 1},
                by_category={"Security": 1, "Quality": 1, "Reliability": 1},
                gate_decision=GateAction.BLOCK,
                blocking_findings=1,
                warning_findings=1,
                info_findings=1,
            ),
        )
        output = format_html(report)

        # Each finding gets its own card
        assert output.count('class="finding-card') == 3
        # Each finding's unique title and ID appear
        assert "First Finding" in output
        assert "Second Finding" in output
        assert "Third Finding" in output
        assert "P-S1" in output
        assert "P-S2" in output
        assert "P-S3" in output
        # Each finding's evidence appears
        assert "evidence one" in output
        assert "evidence two" in output
        assert "evidence three" in output

    def test_html_entity_escaping_all_special_chars(self):
        """Verify HTML entity escaping of <, >, &, double-quote, and single-quote.

        Requirements: 6.3
        """
        finding = ScanFinding(
            id="P-S1",
            artifact_type=ArtifactType.PROMPT,
            artifact_path='path/with"quotes&amps',
            severity_score=5,
            severity_label=SeverityLabel.MEDIUM,
            priority=Priority.P2,
            gate_action=GateAction.WARN,
            category=RiskCategory.SECURITY,
            title="Title with <angle> & \"double\" and 'single' quotes",
            description="Desc has <tag> & \"val\" and 'apos'",
            location=FindingLocation(line=1),
            evidence="<script>alert('xss')</script> & \"test\"",
            confidence=0.8,
            scanner_module=ScannerModule.INJECTION_DET,
            remediation="Use &amp; and 'escape'",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        report = ScanReport(
            scan_id="escape-test",
            artifact_path="/project/<dir>&'test'",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            scanner_version="0.1.0",
            findings=[finding],
            summary=ScanSummary(
                total_findings=1,
                by_severity={"Medium": 1},
                by_category={"Security": 1},
                gate_decision=GateAction.WARN,
                blocking_findings=0,
                warning_findings=1,
                info_findings=0,
            ),
        )
        output = format_html(report)

        # < is escaped
        assert "&lt;" in output
        # > is escaped
        assert "&gt;" in output
        # & is escaped (but not the already-escaped &amp; or &lt; etc.)
        assert "&amp;" in output
        # Double quote is escaped
        assert "&quot;" in output
        # Single quote is escaped (html.escape with quote=True escapes to &#x27;)
        assert "&#x27;" in output
        # Raw special chars must NOT appear in content positions
        assert "<script>" not in output
        assert "<tag>" not in output

    def test_false_positive_true_has_suppressed_indicator(self):
        """Verify findings with false_positive=True have suppressed visual indicator.

        Requirements: 4.2, 6.2
        """
        suppressed_finding = ScanFinding(
            id="P-S1",
            artifact_type=ArtifactType.PROMPT,
            artifact_path="test.md",
            severity_score=7,
            severity_label=SeverityLabel.HIGH,
            priority=Priority.P1,
            gate_action=GateAction.BLOCK,
            category=RiskCategory.SECURITY,
            title="Suppressed Issue",
            description="This is suppressed",
            location=FindingLocation(line=3),
            evidence="suppressed evidence",
            confidence=0.85,
            scanner_module=ScannerModule.INJECTION_DET,
            remediation="Already handled",
            false_positive=True,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        active_finding = ScanFinding(
            id="P-S2",
            artifact_type=ArtifactType.SKILL,
            artifact_path="skill.yaml",
            severity_score=5,
            severity_label=SeverityLabel.MEDIUM,
            priority=Priority.P2,
            gate_action=GateAction.WARN,
            category=RiskCategory.QUALITY,
            title="Active Issue",
            description="This is active",
            location=FindingLocation(line=10),
            evidence="active evidence",
            confidence=0.7,
            scanner_module=ScannerModule.QUALITY_LINT,
            remediation="Needs fixing",
            false_positive=False,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        report = ScanReport(
            scan_id="fp-test",
            artifact_path="/project",
            scan_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            scanner_version="0.1.0",
            findings=[suppressed_finding, active_finding],
            summary=ScanSummary(
                total_findings=2,
                by_severity={"High": 1, "Medium": 1},
                by_category={"Security": 1, "Quality": 1},
                gate_decision=GateAction.BLOCK,
                blocking_findings=1,
                warning_findings=1,
                info_findings=0,
            ),
        )
        output = format_html(report)

        # Suppressed finding has the 'suppressed' class
        assert 'class="finding-card suppressed"' in output
        # Active finding does NOT have the 'suppressed' class
        # Count: one card with suppressed, one without
        assert output.count('class="finding-card suppressed"') == 1
        assert output.count('class="finding-card"') == 1
