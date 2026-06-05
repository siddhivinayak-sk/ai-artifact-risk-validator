"""Unit tests for ReportSerializer and ReportParser.

Tests JSON serialization/deserialization of ScanReport objects,
datetime→ISO 8601 handling, and validation error reporting.
"""

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
from ai_artifact_risk_validator.reporting.parser import ReportParser
from ai_artifact_risk_validator.reporting.serializer import ReportSerializer


@pytest.fixture
def serializer() -> ReportSerializer:
    return ReportSerializer()


@pytest.fixture
def parser() -> ReportParser:
    return ReportParser()


@pytest.fixture
def sample_finding() -> ScanFinding:
    return ScanFinding(
        id="P-S1",
        artifact_type=ArtifactType.PROMPT,
        artifact_path="/test/prompt.md",
        severity_score=9,
        severity_label=SeverityLabel.CRITICAL,
        priority=Priority.P0,
        gate_action=GateAction.BLOCK,
        category=RiskCategory.SECURITY,
        title="Prompt Injection Detected",
        description="Direct prompt injection pattern found.",
        location=FindingLocation(line=5, end_line=7, section="system"),
        evidence="ignore previous instructions",
        confidence=0.95,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Remove or sanitize the injection pattern.",
        references=["https://owasp.org/llm-top-10"],
        false_positive=False,
        timestamp=datetime(2025, 6, 5, 12, 0, 0, tzinfo=timezone.utc),
    )


@pytest.fixture
def sample_report(sample_finding: ScanFinding) -> ScanReport:
    return ScanReport(
        scan_id="test-scan-001",
        artifact_path="/test/project",
        artifact_type=ArtifactType.PROMPT,
        scan_timestamp=datetime(2025, 6, 5, 12, 0, 0, tzinfo=timezone.utc),
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


class TestReportSerializer:
    """Tests for ReportSerializer."""

    def test_serialize_produces_valid_json(
        self, serializer: ReportSerializer, sample_report: ScanReport
    ) -> None:
        result = serializer.serialize(sample_report)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_serialize_datetime_as_iso8601(
        self, serializer: ReportSerializer, sample_report: ScanReport
    ) -> None:
        result = serializer.serialize(sample_report)
        parsed = json.loads(result)
        # scan_timestamp should be ISO 8601 string
        ts = parsed["scan_timestamp"]
        assert isinstance(ts, str)
        # Should be parseable as ISO 8601
        dt = datetime.fromisoformat(ts)
        assert dt.year == 2025
        assert dt.month == 6
        assert dt.day == 5

    def test_serialize_finding_timestamp_as_iso8601(
        self, serializer: ReportSerializer, sample_report: ScanReport
    ) -> None:
        result = serializer.serialize(sample_report)
        parsed = json.loads(result)
        finding_ts = parsed["findings"][0]["timestamp"]
        assert isinstance(finding_ts, str)
        dt = datetime.fromisoformat(finding_ts)
        assert dt.year == 2025

    def test_serialize_pretty_printed(
        self, serializer: ReportSerializer, sample_report: ScanReport
    ) -> None:
        result = serializer.serialize(sample_report)
        # Pretty-printed JSON has newlines and indentation
        assert "\n" in result
        # Check for 2-space indentation
        lines = result.split("\n")
        indented_lines = [l for l in lines if l.startswith("  ")]
        assert len(indented_lines) > 0

    def test_serialize_empty_findings(self, serializer: ReportSerializer) -> None:
        report = ScanReport(
            scan_id="empty-scan",
            artifact_path="/empty",
            artifact_type=None,
            scan_timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
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
        result = serializer.serialize(report)
        parsed = json.loads(result)
        assert parsed["findings"] == []
        assert parsed["artifact_type"] is None


class TestReportParser:
    """Tests for ReportParser."""

    def test_parse_valid_json(
        self, serializer: ReportSerializer, parser: ReportParser, sample_report: ScanReport
    ) -> None:
        json_str = serializer.serialize(sample_report)
        restored = parser.parse(json_str)
        assert isinstance(restored, ScanReport)
        assert restored.scan_id == sample_report.scan_id
        assert restored.artifact_path == sample_report.artifact_path

    def test_round_trip_preserves_data(
        self, serializer: ReportSerializer, parser: ReportParser, sample_report: ScanReport
    ) -> None:
        json_str = serializer.serialize(sample_report)
        restored = parser.parse(json_str)

        assert restored.scan_id == sample_report.scan_id
        assert restored.artifact_path == sample_report.artifact_path
        assert restored.artifact_type == sample_report.artifact_type
        assert restored.scanner_version == sample_report.scanner_version
        assert len(restored.findings) == len(sample_report.findings)
        assert restored.summary.total_findings == sample_report.summary.total_findings
        assert restored.summary.gate_decision == sample_report.summary.gate_decision

    def test_round_trip_preserves_finding_details(
        self, serializer: ReportSerializer, parser: ReportParser, sample_report: ScanReport
    ) -> None:
        json_str = serializer.serialize(sample_report)
        restored = parser.parse(json_str)

        original_finding = sample_report.findings[0]
        restored_finding = restored.findings[0]

        assert restored_finding.id == original_finding.id
        assert restored_finding.severity_score == original_finding.severity_score
        assert restored_finding.confidence == original_finding.confidence
        assert restored_finding.evidence == original_finding.evidence
        assert restored_finding.location.line == original_finding.location.line
        assert restored_finding.location.end_line == original_finding.location.end_line

    def test_parse_malformed_json_raises_valueerror(self, parser: ReportParser) -> None:
        with pytest.raises(ValueError, match="Invalid ScanReport JSON|Invalid JSON"):
            parser.parse("not valid json {{{")

    def test_parse_missing_fields_raises_valueerror(self, parser: ReportParser) -> None:
        incomplete_json = json.dumps({"scan_id": "test"})
        with pytest.raises(ValueError, match="Invalid ScanReport JSON"):
            parser.parse(incomplete_json)

    def test_parse_invalid_field_values_raises_valueerror(self, parser: ReportParser) -> None:
        invalid_json = json.dumps(
            {
                "scan_id": "test",
                "artifact_path": "/test",
                "artifact_type": "invalid_type",
                "scan_timestamp": "2025-01-01T00:00:00Z",
                "scanner_version": "0.1.0",
                "findings": [],
                "summary": {
                    "total_findings": 0,
                    "gate_decision": "BLOCK",
                    "blocking_findings": 0,
                    "warning_findings": 0,
                    "info_findings": 0,
                },
            }
        )
        with pytest.raises(ValueError, match="Invalid ScanReport JSON"):
            parser.parse(invalid_json)

    def test_parse_error_includes_field_details(self, parser: ReportParser) -> None:
        incomplete_json = json.dumps({"scan_id": "test"})
        with pytest.raises(ValueError) as exc_info:
            parser.parse(incomplete_json)
        error_message = str(exc_info.value)
        # Should mention missing fields
        assert "artifact_path" in error_message or "validation error" in error_message
