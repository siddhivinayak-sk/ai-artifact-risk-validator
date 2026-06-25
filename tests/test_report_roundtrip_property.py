"""Property-based tests for report serialization round-trip.

**Validates: Requirements 13.1, 13.2, 13.3**

Property 1: Report Serialization Round-Trip
Tests that for any valid ScanReport, serializing to JSON then parsing back
produces an equivalent object. Uses Hypothesis strategies to generate valid
ScanReport objects with random findings.
"""

import string
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models import (
    ArtifactType,
    FindingLocation,
    GateAction,
    Priority,
    RiskCategory,
    ScanFinding,
    ScannerModule,
    ScanReport,
    ScanSummary,
    SeverityLabel,
)
from ai_artifact_risk_validator.reporting.parser import ReportParser
from ai_artifact_risk_validator.reporting.serializer import ReportSerializer

# --- Strategies for generating valid components ---

valid_id_strategy = st.from_regex(r"^[A-Z]+-[A-Z]?[0-9]+$", fullmatch=True)

valid_severity_score_strategy = st.integers(min_value=1, max_value=10)

valid_confidence_strategy = st.floats(
    min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False
)

valid_artifact_type_strategy = st.sampled_from(list(ArtifactType))

valid_severity_label_strategy = st.sampled_from(list(SeverityLabel))

valid_priority_strategy = st.sampled_from(list(Priority))

valid_gate_action_strategy = st.sampled_from(list(GateAction))

valid_category_strategy = st.sampled_from(list(RiskCategory))

valid_scanner_module_strategy = st.sampled_from(list(ScannerModule))

valid_non_empty_text = st.text(
    alphabet=string.ascii_letters + string.digits + " _-./",
    min_size=1,
    max_size=50,
)

# Datetime strategy: generate aware datetimes that serialize cleanly to ISO 8601
# Pydantic v2 serializes datetimes as ISO 8601; we use UTC-aware timestamps
# to ensure deterministic round-trip.
valid_datetime_strategy = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31),
).map(lambda dt: dt.replace(microsecond=0, tzinfo=timezone.utc))


@st.composite
def valid_finding_location(draw: st.DrawFn) -> FindingLocation:
    """Generate a valid FindingLocation with optional fields."""
    return FindingLocation(
        line=draw(st.one_of(st.none(), st.integers(min_value=1, max_value=10000))),
        end_line=draw(st.one_of(st.none(), st.integers(min_value=1, max_value=10000))),
        section=draw(st.one_of(st.none(), valid_non_empty_text)),
        offset=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=100000))),
    )


@st.composite
def valid_scan_finding(draw: st.DrawFn) -> ScanFinding:
    """Generate a valid ScanFinding object."""
    return ScanFinding(
        id=draw(valid_id_strategy),
        artifact_type=draw(valid_artifact_type_strategy),
        artifact_path=draw(valid_non_empty_text),
        severity_score=draw(valid_severity_score_strategy),
        severity_label=draw(valid_severity_label_strategy),
        priority=draw(valid_priority_strategy),
        gate_action=draw(valid_gate_action_strategy),
        category=draw(valid_category_strategy),
        title=draw(valid_non_empty_text),
        description=draw(valid_non_empty_text),
        location=draw(valid_finding_location()),
        evidence=draw(valid_non_empty_text),
        confidence=draw(valid_confidence_strategy),
        scanner_module=draw(valid_scanner_module_strategy),
        remediation=draw(valid_non_empty_text),
        references=draw(st.lists(valid_non_empty_text, min_size=0, max_size=5)),
        false_positive=draw(st.booleans()),
        timestamp=draw(valid_datetime_strategy),
    )


@st.composite
def valid_scan_summary(draw: st.DrawFn, findings: list[ScanFinding]) -> ScanSummary:
    """Generate a valid ScanSummary computed from findings."""
    total_findings = len(findings)

    # Compute by_severity counts
    by_severity: dict[str, int] = {}
    for f in findings:
        label = f.severity_label.value
        by_severity[label] = by_severity.get(label, 0) + 1

    # Compute by_category counts
    by_category: dict[str, int] = {}
    for f in findings:
        cat = f.category.value
        by_category[cat] = by_category.get(cat, 0) + 1

    # Compute gate counts (excluding false positives)
    blocking = sum(
        1 for f in findings if f.gate_action == GateAction.BLOCK and not f.false_positive
    )
    warning = sum(1 for f in findings if f.gate_action == GateAction.WARN and not f.false_positive)
    info = sum(1 for f in findings if f.gate_action == GateAction.INFO and not f.false_positive)

    # Overall gate decision
    if blocking > 0:
        gate_decision = GateAction.BLOCK
    elif warning > 0:
        gate_decision = GateAction.WARN
    else:
        gate_decision = GateAction.INFO

    return ScanSummary(
        total_findings=total_findings,
        by_severity=by_severity,
        by_category=by_category,
        gate_decision=gate_decision,
        blocking_findings=blocking,
        warning_findings=warning,
        info_findings=info,
    )


@st.composite
def valid_scan_report(draw: st.DrawFn) -> ScanReport:
    """Generate a valid ScanReport with random findings and computed summary."""
    findings = draw(st.lists(valid_scan_finding(), min_size=0, max_size=10))
    summary = draw(valid_scan_summary(findings))

    return ScanReport(
        scan_id=draw(st.uuids().map(str)),
        artifact_path=draw(valid_non_empty_text),
        artifact_type=draw(st.one_of(st.none(), valid_artifact_type_strategy)),
        scan_timestamp=draw(valid_datetime_strategy),
        scanner_version=draw(st.from_regex(r"^[0-9]+\.[0-9]+\.[0-9]+$", fullmatch=True)),
        findings=findings,
        summary=summary,
        errors=draw(st.lists(valid_non_empty_text, min_size=0, max_size=3)),
    )


# --- Property Tests ---


class TestReportSerializationRoundTrip:
    """Property 1: Report Serialization Round-Trip.

    **Validates: Requirements 13.1, 13.2, 13.3**
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_serialize_then_parse_produces_equivalent_report(self, report: ScanReport) -> None:
        """For all valid ScanReport r, parse(serialize(r)) == r (structurally).

        Serializing a ScanReport to JSON with ReportSerializer.serialize() and
        then parsing it back with ReportParser.parse() should produce a
        ScanReport object with all fields matching the original.
        """
        serializer = ReportSerializer()
        parser = ReportParser()

        # Serialize to JSON
        json_str = serializer.serialize(report)

        # Parse back to ScanReport
        parsed_report = parser.parse(json_str)

        # Verify structural equivalence
        assert parsed_report.scan_id == report.scan_id
        assert parsed_report.artifact_path == report.artifact_path
        assert parsed_report.artifact_type == report.artifact_type
        assert parsed_report.scan_timestamp == report.scan_timestamp
        assert parsed_report.scanner_version == report.scanner_version
        assert parsed_report.errors == report.errors

        # Verify summary equivalence
        assert parsed_report.summary.total_findings == report.summary.total_findings
        assert parsed_report.summary.by_severity == report.summary.by_severity
        assert parsed_report.summary.by_category == report.summary.by_category
        assert parsed_report.summary.gate_decision == report.summary.gate_decision
        assert parsed_report.summary.blocking_findings == report.summary.blocking_findings
        assert parsed_report.summary.warning_findings == report.summary.warning_findings
        assert parsed_report.summary.info_findings == report.summary.info_findings

        # Verify findings count and content
        assert len(parsed_report.findings) == len(report.findings)
        for original, parsed in zip(report.findings, parsed_report.findings):
            assert parsed.id == original.id
            assert parsed.artifact_type == original.artifact_type
            assert parsed.artifact_path == original.artifact_path
            assert parsed.severity_score == original.severity_score
            assert parsed.severity_label == original.severity_label
            assert parsed.priority == original.priority
            assert parsed.gate_action == original.gate_action
            assert parsed.category == original.category
            assert parsed.title == original.title
            assert parsed.description == original.description
            assert parsed.evidence == original.evidence
            assert parsed.confidence == original.confidence
            assert parsed.scanner_module == original.scanner_module
            assert parsed.remediation == original.remediation
            assert parsed.references == original.references
            assert parsed.false_positive == original.false_positive
            assert parsed.timestamp == original.timestamp
            # Verify location
            assert parsed.location.line == original.location.line
            assert parsed.location.end_line == original.location.end_line
            assert parsed.location.section == original.location.section
            assert parsed.location.offset == original.location.offset
