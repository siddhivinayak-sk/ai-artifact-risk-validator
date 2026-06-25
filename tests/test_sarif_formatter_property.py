"""Property-based tests for the SARIF formatter.

Uses Hypothesis to verify correctness properties of format_sarif()
across randomly generated ScanReport inputs.
"""

from __future__ import annotations

import json
import string
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

import ai_artifact_risk_validator
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

# --- Hypothesis strategies for generating valid model instances ---

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

# Paths that may include backslashes (Windows-style)
valid_path_strategy = st.one_of(
    # Forward-slash paths
    st.text(
        alphabet=string.ascii_letters + string.digits + "_-./",
        min_size=1,
        max_size=60,
    ),
    # Backslash paths (Windows-style)
    st.text(
        alphabet=string.ascii_letters + string.digits + "_-.\\",
        min_size=1,
        max_size=60,
    ),
)

valid_datetime_strategy = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31),
).map(lambda dt: dt.replace(microsecond=0, tzinfo=timezone.utc))

# Remediation strategy: empty, whitespace-only, or non-empty text
valid_remediation_strategy = st.one_of(
    st.just(""),
    st.just("   "),
    st.just("\t\n"),
    valid_non_empty_text,
)


@st.composite
def valid_finding_location(draw: st.DrawFn) -> FindingLocation:
    """Generate a valid FindingLocation with optional line numbers."""
    line = draw(st.one_of(st.none(), st.integers(min_value=1, max_value=10000)))
    end_line = draw(st.one_of(st.none(), st.integers(min_value=1, max_value=10000)))
    return FindingLocation(
        line=line,
        end_line=end_line,
        section=draw(st.one_of(st.none(), valid_non_empty_text)),
        offset=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=100000))),
    )


@st.composite
def valid_scan_finding(draw: st.DrawFn) -> ScanFinding:
    """Generate a valid ScanFinding object with all field variants."""
    return ScanFinding(
        id=draw(valid_id_strategy),
        artifact_type=draw(valid_artifact_type_strategy),
        artifact_path=draw(valid_path_strategy),
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
        remediation=draw(valid_remediation_strategy),
        references=draw(st.lists(valid_non_empty_text, min_size=0, max_size=5)),
        false_positive=draw(st.booleans()),
        timestamp=draw(valid_datetime_strategy),
    )


def _build_scan_summary(findings: list[ScanFinding]) -> ScanSummary:
    """Build a valid ScanSummary computed from findings."""
    total_findings = len(findings)

    by_severity: dict[str, int] = {}
    for f in findings:
        label = f.severity_label.value
        by_severity[label] = by_severity.get(label, 0) + 1

    by_category: dict[str, int] = {}
    for f in findings:
        cat = f.category.value
        by_category[cat] = by_category.get(cat, 0) + 1

    blocking = sum(
        1 for f in findings if f.gate_action == GateAction.BLOCK and not f.false_positive
    )
    warning = sum(1 for f in findings if f.gate_action == GateAction.WARN and not f.false_positive)
    info = sum(1 for f in findings if f.gate_action == GateAction.INFO and not f.false_positive)

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
    """Generate a valid ScanReport with random findings (0 to 20) and computed summary.

    Covers:
    - Variable numbers of findings (0 to 20)
    - All GateAction variants (BLOCK, WARN, INFO)
    - All RiskCategory variants
    - All ScannerModule variants
    - Paths with/without backslashes
    - Findings with/without line numbers (location.line = None or integer)
    - Empty and non-empty remediation strings
    - false_positive = True/False
    - Duplicate finding IDs with different metadata
    - Empty and non-empty error lists
    """
    findings = draw(st.lists(valid_scan_finding(), min_size=0, max_size=20))
    summary = _build_scan_summary(findings)

    return ScanReport(
        scan_id=draw(st.uuids().map(str)),
        artifact_path=draw(valid_path_strategy),
        artifact_type=draw(st.one_of(st.none(), valid_artifact_type_strategy)),
        scan_timestamp=draw(valid_datetime_strategy),
        scanner_version=draw(st.from_regex(r"^[0-9]+\.[0-9]+\.[0-9]+$", fullmatch=True)),
        findings=findings,
        summary=summary,
        errors=draw(st.lists(valid_non_empty_text, min_size=0, max_size=5)),
    )


# --- Property Tests ---


# Feature: sarif-report-format, Property 1: SARIF Document Structural Invariants
class TestSarifDocumentStructuralInvariants:
    """Property 1: SARIF Document Structural Invariants.

    **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 5.1**

    For any valid ScanReport, formatting it to SARIF SHALL produce a JSON document
    where: $schema equals the SARIF v2.1.0 schema URL, version equals "2.1.0",
    runs contains exactly one element, tool.driver.name equals
    "ai-artifact-risk-validator", tool.driver.version equals the package __version__,
    tool.driver.informationUri is a non-empty valid URL, and invocations contains
    exactly one element.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_schema_field_is_sarif_v2_1_0_url(self, report: ScanReport) -> None:
        """$schema equals the SARIF v2.1.0 schema URL."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        expected_schema = (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        )
        assert doc["$schema"] == expected_schema

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_version_field_is_2_1_0(self, report: ScanReport) -> None:
        """version equals "2.1.0"."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        assert doc["version"] == "2.1.0"

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_runs_contains_exactly_one_element(self, report: ScanReport) -> None:
        """runs contains exactly one element."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        assert len(doc["runs"]) == 1

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_tool_driver_name_is_correct(self, report: ScanReport) -> None:
        """tool.driver.name equals "ai-artifact-risk-validator"."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "ai-artifact-risk-validator"

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_tool_driver_version_matches_package(self, report: ScanReport) -> None:
        """tool.driver.version equals ai_artifact_risk_validator.__version__."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        assert run["tool"]["driver"]["version"] == ai_artifact_risk_validator.__version__

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_tool_driver_information_uri_is_valid_url(self, report: ScanReport) -> None:
        """tool.driver.informationUri is a non-empty string containing "http"."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        info_uri = run["tool"]["driver"]["informationUri"]
        assert isinstance(info_uri, str)
        assert len(info_uri) > 0
        assert "http" in info_uri

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_invocations_contains_exactly_one_element(self, report: ScanReport) -> None:
        """invocations contains exactly one element."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        assert len(run["invocations"]) == 1


# Feature: sarif-report-format, Property 2: Finding-to-Result Count and Order Preservation
class TestFindingToResultCountAndOrder:
    """Property 2: Finding-to-Result Count and Order Preservation.

    **Validates: Requirements 2.1**

    For any valid ScanReport with N findings, formatting it to SARIF SHALL produce
    a results array with exactly N elements, where the i-th result corresponds to
    the i-th finding in the original report (same ruleId as finding id).
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_results_count_equals_findings_count(self, report: ScanReport) -> None:
        """The SARIF results array has exactly N elements for N findings."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        assert len(run["results"]) == len(report.findings)

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_results_rule_ids_match_findings_in_order(self, report: ScanReport) -> None:
        """For each index i, results[i].ruleId equals findings[i].id."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        for i, finding in enumerate(report.findings):
            assert run["results"][i]["ruleId"] == finding.id


# Feature: sarif-report-format, Property 3: GateAction to SARIF Level Mapping
class TestGateActionToSarifLevelMapping:
    """Property 3: GateAction to SARIF Level Mapping.

    **Validates: Requirements 2.2, 2.3, 2.4, 3.5**

    For any ScanFinding, the result level and rule defaultConfiguration.level
    match the gate_action mapping: BLOCK→error, WARN→warning, INFO→note.
    """

    _EXPECTED_LEVEL: dict[GateAction, str] = {
        GateAction.BLOCK: "error",
        GateAction.WARN: "warning",
        GateAction.INFO: "note",
    }

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_result_level_matches_gate_action(self, report: ScanReport) -> None:
        """Each result's level matches the expected SARIF level for the finding's gate_action."""
        if not report.findings:
            return

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            expected_level = self._EXPECTED_LEVEL[finding.gate_action]
            assert results[i]["level"] == expected_level, (
                f"Finding {i} with gate_action={finding.gate_action.value} "
                f"expected level='{expected_level}', got '{results[i]['level']}'"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_rule_default_configuration_level_matches_first_finding_gate_action(
        self, report: ScanReport
    ) -> None:
        """Each rule's defaultConfiguration.level matches the gate_action of the first finding with that id."""
        if not report.findings:
            return

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        # Build expected: first occurrence of each id determines the rule's level
        first_occurrence: dict[str, GateAction] = {}
        for finding in report.findings:
            if finding.id not in first_occurrence:
                first_occurrence[finding.id] = finding.gate_action

        for rule in rules:
            rule_id = rule["id"]
            expected_gate_action = first_occurrence[rule_id]
            expected_level = self._EXPECTED_LEVEL[expected_gate_action]
            actual_level = rule["defaultConfiguration"]["level"]
            assert actual_level == expected_level, (
                f"Rule '{rule_id}' with first gate_action={expected_gate_action.value} "
                f"expected defaultConfiguration.level='{expected_level}', got '{actual_level}'"
            )


# Feature: sarif-report-format, Property 4: Finding Field Mapping to SARIF Result
class TestFindingFieldMappingToSarifResult:
    """Property 4: Finding Field Mapping to SARIF Result.

    **Validates: Requirements 2.5, 2.6, 2.7, 2.8, 2.9, 2.11**

    For any ScanFinding, the corresponding SARIF result SHALL have: ruleId equal
    to the finding id, message.text equal to the finding description,
    artifactLocation.uri equal to artifact_path with backslashes replaced by
    forward slashes, region.startLine equal to location.line when line is not None,
    region.endLine equal to location.end_line when end_line is not None, and no
    region object when location.line is None.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_finding_field_mapping(self, report: ScanReport) -> None:
        """Each finding maps correctly to its SARIF result fields."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]
        findings = report.findings

        for i, finding in enumerate(findings):
            result = results[i]

            # ruleId equals finding id
            assert result["ruleId"] == finding.id

            # message.text equals finding description
            assert result["message"]["text"] == finding.description

            # artifactLocation.uri equals artifact_path with backslashes replaced
            location = result["locations"][0]
            expected_uri = finding.artifact_path.replace("\\", "/")
            assert location["artifactLocation"]["uri"] == expected_uri

            # region fields match location
            if finding.location.line is not None:
                assert location["region"]["startLine"] == finding.location.line
                if finding.location.end_line is not None:
                    assert location["region"]["endLine"] == finding.location.end_line
            else:
                assert "region" not in location


# Feature: sarif-report-format, Property 12: Round-Trip Serialization Preservation
class TestRoundTripSerializationPreservation:
    """Property 12: Round-Trip Serialization Preservation.

    **Validates: Requirements 6.6, 8.1, 8.2, 8.3, 8.7**

    For any valid ScanReport, formatting it to SARIF via format_sarif then parsing
    the output via SarifParser.parse SHALL produce a ScanReport where: the findings
    count equals the original, each finding's id matches the corresponding original
    finding's id, each finding's gate_action matches the original, each finding's
    description matches the original, each finding's artifact_path matches the original
    (normalized to forward slashes), and summary.gate_decision equals the original.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_round_trip_findings_count_preserved(self, report: ScanReport) -> None:
        """The round-tripped report has the same number of findings as the original."""
        from ai_artifact_risk_validator.reporting.sarif_parser import SarifParser

        sarif_output = format_sarif(report)
        parsed_report = SarifParser().parse(sarif_output)

        assert len(parsed_report.findings) == len(report.findings)

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_round_trip_finding_ids_match(self, report: ScanReport) -> None:
        """Each finding's id matches the original after round-trip."""
        from ai_artifact_risk_validator.reporting.sarif_parser import SarifParser

        sarif_output = format_sarif(report)
        parsed_report = SarifParser().parse(sarif_output)

        for i, (original, parsed) in enumerate(
            zip(report.findings, parsed_report.findings, strict=True)
        ):
            assert parsed.id == original.id, (
                f"Finding[{i}] id mismatch: expected {original.id!r}, got {parsed.id!r}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_round_trip_finding_gate_actions_match(self, report: ScanReport) -> None:
        """Each finding's gate_action matches the original after round-trip."""
        from ai_artifact_risk_validator.reporting.sarif_parser import SarifParser

        sarif_output = format_sarif(report)
        parsed_report = SarifParser().parse(sarif_output)

        for i, (original, parsed) in enumerate(
            zip(report.findings, parsed_report.findings, strict=True)
        ):
            assert parsed.gate_action == original.gate_action, (
                f"Finding[{i}] gate_action mismatch: "
                f"expected {original.gate_action!r}, got {parsed.gate_action!r}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_round_trip_finding_descriptions_match(self, report: ScanReport) -> None:
        """Each finding's description matches the original after round-trip."""
        from ai_artifact_risk_validator.reporting.sarif_parser import SarifParser

        sarif_output = format_sarif(report)
        parsed_report = SarifParser().parse(sarif_output)

        for i, (original, parsed) in enumerate(
            zip(report.findings, parsed_report.findings, strict=True)
        ):
            assert parsed.description == original.description, (
                f"Finding[{i}] description mismatch: "
                f"expected {original.description!r}, got {parsed.description!r}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_round_trip_finding_artifact_paths_match(self, report: ScanReport) -> None:
        """Each finding's artifact_path matches the original (normalized to forward slashes)."""
        from ai_artifact_risk_validator.reporting.sarif_parser import SarifParser

        sarif_output = format_sarif(report)
        parsed_report = SarifParser().parse(sarif_output)

        for i, (original, parsed) in enumerate(
            zip(report.findings, parsed_report.findings, strict=True)
        ):
            expected_path = original.artifact_path.replace("\\", "/")
            parsed_path = parsed.artifact_path.replace("\\", "/")
            assert parsed_path == expected_path, (
                f"Finding[{i}] artifact_path mismatch: "
                f"expected {expected_path!r}, got {parsed_path!r}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_round_trip_gate_decision_matches(self, report: ScanReport) -> None:
        """The summary.gate_decision matches the original after round-trip."""
        from ai_artifact_risk_validator.reporting.sarif_parser import SarifParser

        sarif_output = format_sarif(report)
        parsed_report = SarifParser().parse(sarif_output)

        assert parsed_report.summary.gate_decision == report.summary.gate_decision, (
            f"gate_decision mismatch: "
            f"expected {report.summary.gate_decision!r}, "
            f"got {parsed_report.summary.gate_decision!r}"
        )


# Feature: sarif-report-format, Property 5: Rule Descriptor Correctness
class TestRuleDescriptorCorrectness:
    """Property 5: Rule Descriptor Correctness.

    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.8, 3.9**

    For any valid ScanReport, the tool.driver.rules array SHALL contain exactly one
    entry per distinct finding id, ordered by first appearance in the findings list.
    Each rule descriptor SHALL have: id matching the finding id, shortDescription.text
    matching the finding title, fullDescription.text matching the finding description,
    and each result's ruleIndex pointing to the correct zero-based position in the
    rules array.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_rules_count_equals_distinct_finding_ids(self, report: ScanReport) -> None:
        """The rules array has exactly one entry per distinct finding id."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]

        distinct_ids = list(dict.fromkeys(f.id for f in report.findings))
        assert len(rules) == len(distinct_ids)

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_rules_ordered_by_first_appearance(self, report: ScanReport) -> None:
        """Rules are ordered by first appearance of each distinct id in the findings list."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]

        seen_ids: list[str] = []
        for finding in report.findings:
            if finding.id not in seen_ids:
                seen_ids.append(finding.id)

        rule_ids = [rule["id"] for rule in rules]
        assert rule_ids == seen_ids

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_each_rule_id_matches_finding_id(self, report: ScanReport) -> None:
        """Each rule has id matching the finding id."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]

        seen_ids: list[str] = []
        for finding in report.findings:
            if finding.id not in seen_ids:
                seen_ids.append(finding.id)

        for i, rule in enumerate(rules):
            assert rule["id"] == seen_ids[i]

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_each_rule_short_description_matches_first_finding_title(
        self, report: ScanReport
    ) -> None:
        """Each rule has shortDescription.text matching the first finding with that id's title."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]

        first_occurrence: dict[str, ScanFinding] = {}
        for finding in report.findings:
            if finding.id not in first_occurrence:
                first_occurrence[finding.id] = finding

        for rule in rules:
            expected_title = first_occurrence[rule["id"]].title
            assert rule["shortDescription"]["text"] == expected_title

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_each_rule_full_description_matches_first_finding_description(
        self, report: ScanReport
    ) -> None:
        """Each rule has fullDescription.text matching the first finding with that id's description."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]

        first_occurrence: dict[str, ScanFinding] = {}
        for finding in report.findings:
            if finding.id not in first_occurrence:
                first_occurrence[finding.id] = finding

        for rule in rules:
            expected_description = first_occurrence[rule["id"]].description
            assert rule["fullDescription"]["text"] == expected_description

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_each_result_rule_index_points_to_correct_rule(self, report: ScanReport) -> None:
        """Each result's ruleIndex correctly points to the zero-based position of its rule."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]

        # Build expected rule index map
        seen_ids: list[str] = []
        for finding in report.findings:
            if finding.id not in seen_ids:
                seen_ids.append(finding.id)
        expected_index_map = {rule_id: idx for idx, rule_id in enumerate(seen_ids)}

        for i, result in enumerate(results):
            rule_index = result["ruleIndex"]
            rule_id = result["ruleId"]
            # ruleIndex should point to the correct position
            assert rule_index == expected_index_map[rule_id]
            # The rule at that index should have the same id
            assert rules[rule_index]["id"] == rule_id


# Strategy that generates a ScanReport guaranteed to have duplicate finding IDs
@st.composite
def valid_scan_report_with_duplicate_ids(draw: st.DrawFn) -> ScanReport:
    """Generate a valid ScanReport guaranteed to have at least 2 findings sharing the same ID."""
    # Pick a shared ID that will appear at least twice
    shared_id = draw(valid_id_strategy)

    # Generate at least 2 findings with the shared ID but potentially different metadata
    num_duplicates = draw(st.integers(min_value=2, max_value=5))
    duplicate_findings: list[ScanFinding] = []
    for _ in range(num_duplicates):
        finding = draw(valid_scan_finding())
        # Override the id to ensure duplication
        duplicate_findings.append(finding.model_copy(update={"id": shared_id}))

    # Optionally add other findings with unique IDs
    other_findings = draw(st.lists(valid_scan_finding(), min_size=0, max_size=10))

    # Combine and shuffle via drawing an order
    all_findings = duplicate_findings + other_findings
    # Use hypothesis to generate a permutation order
    indices = list(range(len(all_findings)))
    shuffled = draw(st.permutations(indices))
    findings = [all_findings[i] for i in shuffled]

    summary = _build_scan_summary(findings)

    return ScanReport(
        scan_id=draw(st.uuids().map(str)),
        artifact_path=draw(valid_path_strategy),
        artifact_type=draw(st.one_of(st.none(), valid_artifact_type_strategy)),
        scan_timestamp=draw(valid_datetime_strategy),
        scanner_version=draw(st.from_regex(r"^[0-9]+\.[0-9]+\.[0-9]+$", fullmatch=True)),
        findings=findings,
        summary=summary,
        errors=draw(st.lists(valid_non_empty_text, min_size=0, max_size=5)),
    )


# Feature: sarif-report-format, Property 6: Duplicate Finding ID Rule Deduplication
class TestDuplicateFindingIdRuleDeduplication:
    """Property 6: Duplicate Finding ID Rule Deduplication.

    **Validates: Requirements 3.10**

    For any ScanReport containing multiple findings with the same id but different
    metadata (title, description, remediation, gate_action), the rule descriptor
    SHALL use the metadata from the first occurrence of that id in the findings list.
    """

    _EXPECTED_LEVEL: dict[GateAction, str] = {
        GateAction.BLOCK: "error",
        GateAction.WARN: "warning",
        GateAction.INFO: "note",
    }

    @given(report=valid_scan_report_with_duplicate_ids())
    @settings(max_examples=100, deadline=None)
    def test_rule_short_description_uses_first_occurrence_title(self, report: ScanReport) -> None:
        """When multiple findings share the same id, shortDescription.text uses the first title."""
        from collections import Counter

        from hypothesis import assume

        id_counts = Counter(f.id for f in report.findings)
        assume(any(count > 1 for count in id_counts.values()))

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        # Build first occurrence map
        first_occurrence: dict[str, ScanFinding] = {}
        for finding in report.findings:
            if finding.id not in first_occurrence:
                first_occurrence[finding.id] = finding

        for rule in rules:
            rule_id = rule["id"]
            expected_title = first_occurrence[rule_id].title
            assert rule["shortDescription"]["text"] == expected_title, (
                f"Rule '{rule_id}' shortDescription.text should be "
                f"'{expected_title}' (from first occurrence), "
                f"got '{rule['shortDescription']['text']}'"
            )

    @given(report=valid_scan_report_with_duplicate_ids())
    @settings(max_examples=100, deadline=None)
    def test_rule_full_description_uses_first_occurrence_description(
        self, report: ScanReport
    ) -> None:
        """When multiple findings share the same id, fullDescription.text uses the first description."""
        from collections import Counter

        from hypothesis import assume

        id_counts = Counter(f.id for f in report.findings)
        assume(any(count > 1 for count in id_counts.values()))

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        # Build first occurrence map
        first_occurrence: dict[str, ScanFinding] = {}
        for finding in report.findings:
            if finding.id not in first_occurrence:
                first_occurrence[finding.id] = finding

        for rule in rules:
            rule_id = rule["id"]
            expected_description = first_occurrence[rule_id].description
            assert rule["fullDescription"]["text"] == expected_description, (
                f"Rule '{rule_id}' fullDescription.text should be "
                f"'{expected_description}' (from first occurrence), "
                f"got '{rule['fullDescription']['text']}'"
            )

    @given(report=valid_scan_report_with_duplicate_ids())
    @settings(max_examples=100, deadline=None)
    def test_rule_default_configuration_level_uses_first_occurrence_gate_action(
        self, report: ScanReport
    ) -> None:
        """When multiple findings share the same id, defaultConfiguration.level uses the first gate_action."""
        from collections import Counter

        from hypothesis import assume

        id_counts = Counter(f.id for f in report.findings)
        assume(any(count > 1 for count in id_counts.values()))

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        # Build first occurrence map
        first_occurrence: dict[str, ScanFinding] = {}
        for finding in report.findings:
            if finding.id not in first_occurrence:
                first_occurrence[finding.id] = finding

        for rule in rules:
            rule_id = rule["id"]
            expected_level = self._EXPECTED_LEVEL[first_occurrence[rule_id].gate_action]
            actual_level = rule["defaultConfiguration"]["level"]
            assert actual_level == expected_level, (
                f"Rule '{rule_id}' defaultConfiguration.level should be "
                f"'{expected_level}' (from first occurrence gate_action="
                f"{first_occurrence[rule_id].gate_action.value}), "
                f"got '{actual_level}'"
            )


# Feature: sarif-report-format, Property 8: Invocation Metadata Correctness
class TestInvocationMetadataCorrectness:
    """Property 8: Invocation Metadata Correctness.

    **Validates: Requirements 5.2, 5.3, 5.4, 5.5**

    For any valid ScanReport, the SARIF invocation object SHALL have:
    executionSuccessful equal to True when the report's errors list is empty and
    False otherwise, commandLine equal to "ai-artifact-validator verify <path>"
    where <path> is artifact_path with backslashes converted to forward slashes,
    and startTimeUtc equal to the scan_timestamp serialized as ISO 8601 UTC.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_execution_successful_true_when_no_errors(self, report: ScanReport) -> None:
        """executionSuccessful is True when report.errors is empty."""
        from hypothesis import assume

        assume(len(report.errors) == 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        invocation = doc["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_execution_successful_false_when_errors_present(self, report: ScanReport) -> None:
        """executionSuccessful is False when report.errors has one or more entries."""
        from hypothesis import assume

        assume(len(report.errors) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        invocation = doc["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_command_line_matches_artifact_path(self, report: ScanReport) -> None:
        """commandLine equals 'ai-artifact-validator verify <normalized_path>'."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        invocation = doc["runs"][0]["invocations"][0]
        normalized_path = report.artifact_path.replace("\\", "/")
        expected_command_line = f"ai-artifact-validator verify {normalized_path}"
        assert invocation["commandLine"] == expected_command_line

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_start_time_utc_matches_scan_timestamp(self, report: ScanReport) -> None:
        """startTimeUtc equals scan_timestamp formatted as ISO 8601 UTC."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        invocation = doc["runs"][0]["invocations"][0]
        expected_timestamp = report.scan_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert invocation["startTimeUtc"] == expected_timestamp


# Feature: sarif-report-format, Property 7: Remediation to Help Mapping
class TestRemediationToHelpMapping:
    """Property 7: Remediation to Help Mapping.

    **Validates: Requirements 3.6, 3.7**

    For any valid ScanReport with findings, each rule descriptor SHALL have:
    help.text equal to the first finding's remediation when remediation.strip()
    is non-empty, and no help property when remediation.strip() is empty or
    whitespace-only.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_non_empty_remediation_produces_help_text(self, report: ScanReport) -> None:
        """Non-empty remediation produces help.text; empty/whitespace omits help."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        # Build first occurrence map
        first_occurrence: dict[str, ScanFinding] = {}
        for finding in report.findings:
            if finding.id not in first_occurrence:
                first_occurrence[finding.id] = finding

        for rule in rules:
            first_finding = first_occurrence[rule["id"]]
            if first_finding.remediation.strip():
                assert "help" in rule, (
                    f"Rule '{rule['id']}' with non-empty remediation "
                    f"{first_finding.remediation!r} should have help property"
                )
                assert rule["help"]["text"] == first_finding.remediation, (
                    f"Rule '{rule['id']}' help.text mismatch: "
                    f"expected {first_finding.remediation!r}, got {rule['help']['text']!r}"
                )
            else:
                assert "help" not in rule, (
                    f"Rule '{rule['id']}' with empty/whitespace remediation "
                    f"{first_finding.remediation!r} should NOT have help property"
                )


# Feature: sarif-report-format, Property 10: Properties Bag Enrichment
class TestPropertiesBagEnrichment:
    """Property 10: Properties Bag Enrichment.

    **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.7**

    For any ScanFinding, the corresponding SARIF result's properties bag SHALL
    contain: severity_score as the integer value (1-10), confidence as the float
    value (0.0-1.0), category as the enum's string value, scanner_module as the
    enum's string value, and evidence as the string value.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_properties_bag_severity_score_matches_finding(self, report: ScanReport) -> None:
        """Each result's properties.severity_score equals the finding's severity_score."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            assert results[i]["properties"]["severity_score"] == finding.severity_score, (
                f"Finding[{i}] severity_score mismatch: "
                f"expected {finding.severity_score}, "
                f"got {results[i]['properties']['severity_score']}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_properties_bag_confidence_matches_finding(self, report: ScanReport) -> None:
        """Each result's properties.confidence equals the finding's confidence."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            assert results[i]["properties"]["confidence"] == finding.confidence, (
                f"Finding[{i}] confidence mismatch: "
                f"expected {finding.confidence}, "
                f"got {results[i]['properties']['confidence']}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_properties_bag_category_matches_finding(self, report: ScanReport) -> None:
        """Each result's properties.category equals the finding's category.value."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            assert results[i]["properties"]["category"] == finding.category.value, (
                f"Finding[{i}] category mismatch: "
                f"expected {finding.category.value!r}, "
                f"got {results[i]['properties']['category']!r}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_properties_bag_scanner_module_matches_finding(self, report: ScanReport) -> None:
        """Each result's properties.scanner_module equals the finding's scanner_module.value."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            assert results[i]["properties"]["scanner_module"] == finding.scanner_module.value, (
                f"Finding[{i}] scanner_module mismatch: "
                f"expected {finding.scanner_module.value!r}, "
                f"got {results[i]['properties']['scanner_module']!r}"
            )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_properties_bag_evidence_matches_finding(self, report: ScanReport) -> None:
        """Each result's properties.evidence equals the finding's evidence."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            assert results[i]["properties"]["evidence"] == finding.evidence, (
                f"Finding[{i}] evidence mismatch: "
                f"expected {finding.evidence!r}, "
                f"got {results[i]['properties']['evidence']!r}"
            )


# Feature: sarif-report-format, Property 9: Deterministic Valid JSON Output
class TestDeterministicValidJsonOutput:
    """Property 9: Deterministic Valid JSON Output.

    **Validates: Requirements 6.1, 6.3, 6.4**

    For any valid ScanReport, formatting it to SARIF SHALL produce output that:
    is parseable as valid JSON, has all object keys in lexicographic (sorted) order
    at every nesting level, and has all datetime values formatted as ISO 8601 UTC
    strings (YYYY-MM-DDTHH:MM:SSZ).
    """

    @staticmethod
    def _check_keys_sorted(obj: object) -> None:
        """Recursively verify all object keys are in lexicographic order."""
        if isinstance(obj, dict):
            keys = list(obj.keys())
            assert keys == sorted(keys), f"Keys not sorted: {keys}"
            for value in obj.values():
                TestDeterministicValidJsonOutput._check_keys_sorted(value)
        elif isinstance(obj, list):
            for item in obj:
                TestDeterministicValidJsonOutput._check_keys_sorted(item)

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_output_is_parseable_json(self, report: ScanReport) -> None:
        """The SARIF output is parseable as valid JSON (RFC 8259 compliant)."""
        sarif_output = format_sarif(report)
        # json.loads raises ValueError/JSONDecodeError if not valid JSON
        doc = json.loads(sarif_output)
        assert isinstance(doc, dict)

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_all_keys_in_lexicographic_order(self, report: ScanReport) -> None:
        """All object keys at every nesting level are in lexicographic (sorted) order."""
        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        self._check_keys_sorted(doc)

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_datetime_values_are_iso_8601_utc(self, report: ScanReport) -> None:
        """All datetime values (startTimeUtc) are formatted as ISO 8601 UTC: YYYY-MM-DDTHH:MM:SSZ."""
        import re

        iso_utc_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)

        run = doc["runs"][0]
        invocations = run["invocations"]
        for invocation in invocations:
            start_time = invocation["startTimeUtc"]
            assert iso_utc_pattern.match(start_time), (
                f"startTimeUtc '{start_time}' does not match ISO 8601 UTC format YYYY-MM-DDTHH:MM:SSZ"
            )


# Feature: sarif-report-format, Property 11: False Positive to Suppressions Mapping
class TestFalsePositiveToSuppressionsMapping:
    """Property 11: False Positive to Suppressions Mapping.

    **Validates: Requirements 7.5, 7.6**

    For any ScanFinding where false_positive is True, the corresponding SARIF result
    SHALL have a suppressions array with one entry containing kind="inSource" and
    justification="Marked as false positive by validator". For findings where
    false_positive is False, the result SHALL NOT have a suppressions key.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_false_positive_produces_suppressions(self, report: ScanReport) -> None:
        """Findings with false_positive=True produce a suppressions array with correct entry."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            if finding.false_positive:
                assert "suppressions" in results[i], (
                    f"Finding[{i}] has false_positive=True but result has no suppressions key"
                )
                suppressions = results[i]["suppressions"]
                assert isinstance(suppressions, list)
                assert len(suppressions) == 1, (
                    f"Finding[{i}] suppressions should have exactly 1 entry, "
                    f"got {len(suppressions)}"
                )
                assert suppressions[0]["kind"] == "inSource", (
                    f"Finding[{i}] suppression kind should be 'inSource', "
                    f"got {suppressions[0]['kind']!r}"
                )
                assert suppressions[0]["justification"] == (
                    "Marked as false positive by validator"
                ), (
                    f"Finding[{i}] suppression justification mismatch: "
                    f"got {suppressions[0]['justification']!r}"
                )

    @given(report=valid_scan_report())
    @settings(max_examples=100, deadline=None)
    def test_non_false_positive_has_no_suppressions(self, report: ScanReport) -> None:
        """Findings with false_positive=False do NOT have a suppressions key."""
        from hypothesis import assume

        assume(len(report.findings) > 0)

        sarif_output = format_sarif(report)
        doc = json.loads(sarif_output)
        results = doc["runs"][0]["results"]

        for i, finding in enumerate(report.findings):
            if not finding.false_positive:
                assert "suppressions" not in results[i], (
                    f"Finding[{i}] has false_positive=False but result has suppressions key"
                )
