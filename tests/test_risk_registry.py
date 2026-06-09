"""Unit tests for RiskRegistry class and loading infrastructure."""

import pytest

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.risk import RiskDefinition
from ai_artifact_risk_validator.risks import RiskRegistry
from ai_artifact_risk_validator.risks.definitions import load_all_risks


def _make_risk(
    risk_id: str = "TEST-1",
    title: str = "Test Risk",
    artifact_types: list[ArtifactType] | None = None,
    category: RiskCategory = RiskCategory.SECURITY,
    severity_score: int = 8,
    severity_label: SeverityLabel = SeverityLabel.HIGH,
    priority: Priority = Priority.P1,
    gate_action: GateAction = GateAction.BLOCK,
    scanner_modules: list[ScannerModule] | None = None,
) -> RiskDefinition:
    """Helper to create a RiskDefinition with sensible defaults."""
    return RiskDefinition(
        id=risk_id,
        title=title,
        artifact_types=artifact_types or [ArtifactType.PROMPT],
        category=category,
        severity_score=severity_score,
        severity_label=severity_label,
        priority=priority,
        gate_action=gate_action,
        description="Test description",
        examples=["Example 1"],
        mitigation=["Mitigation 1"],
        detection_mechanisms=["Detection 1"],
        scanner_modules=scanner_modules or [ScannerModule.SECRET_SCAN],
    )


class TestRiskRegistryInit:
    """Tests for RiskRegistry initialization."""

    def test_creates_registry_with_builtin_definitions(self):
        reg = RiskRegistry()
        assert reg.total_count == 198

    def test_registry_is_importable_from_risks_package(self):
        from ai_artifact_risk_validator.risks import RiskRegistry as Imported

        assert Imported is RiskRegistry


class TestRiskRegistryGet:
    """Tests for RiskRegistry.get() method."""

    def test_get_returns_none_for_nonexistent_id(self):
        reg = RiskRegistry()
        assert reg.get("NONEXISTENT-99") is None

    def test_get_returns_risk_after_add_custom(self):
        reg = RiskRegistry()
        risk = _make_risk("CUSTOM-1")
        reg.add_custom(risk)
        result = reg.get("CUSTOM-1")
        assert result is not None
        assert result.id == "CUSTOM-1"
        assert result.title == "Test Risk"

    def test_get_returns_exact_risk_object(self):
        reg = RiskRegistry()
        risk = _make_risk("EXACT-1")
        reg.add_custom(risk)
        assert reg.get("EXACT-1") is risk

    def test_get_builtin_risk_by_id(self):
        reg = RiskRegistry()
        result = reg.get("P-S1")
        assert result is not None
        assert result.id == "P-S1"
        assert result.category == RiskCategory.SECURITY


class TestRiskRegistryQuery:
    """Tests for RiskRegistry.query() method."""

    def test_query_no_filters_returns_all(self):
        reg = RiskRegistry()
        results = reg.query()
        assert len(results) == 198

    def test_query_by_artifact_type(self):
        reg = RiskRegistry()
        results = reg.query(artifact_type=ArtifactType.PROMPT)
        # All prompt-applicable risks should be returned
        assert len(results) > 0
        for r in results:
            assert ArtifactType.PROMPT in r.artifact_types

    def test_query_by_artifact_type_matches_multi_type_risks(self):
        reg = RiskRegistry()
        reg.add_custom(
            _make_risk("ZMULTI-1", artifact_types=[ArtifactType.PROMPT, ArtifactType.SKILL])
        )
        results = reg.query(artifact_type=ArtifactType.SKILL)
        result_ids = [r.id for r in results]
        assert "ZMULTI-1" in result_ids

    def test_query_by_category(self):
        reg = RiskRegistry()
        results = reg.query(category=RiskCategory.SECURITY)
        assert len(results) > 0
        for r in results:
            assert r.category == RiskCategory.SECURITY

    def test_query_by_severity(self):
        reg = RiskRegistry()
        results = reg.query(severity=SeverityLabel.CRITICAL)
        assert len(results) > 0
        for r in results:
            assert r.severity_label == SeverityLabel.CRITICAL

    def test_query_by_priority(self):
        reg = RiskRegistry()
        results = reg.query(priority=Priority.P0)
        assert len(results) > 0
        for r in results:
            assert r.priority == Priority.P0

    def test_query_by_scanner_module(self):
        reg = RiskRegistry()
        results = reg.query(scanner_module=ScannerModule.SECRET_SCAN)
        assert len(results) > 0
        for r in results:
            assert ScannerModule.SECRET_SCAN in r.scanner_modules

    def test_query_by_scanner_module_matches_multi_scanner_risks(self):
        reg = RiskRegistry()
        # MCP-S3 uses both INJECTION_DET and SECRET_SCAN
        results = reg.query(scanner_module=ScannerModule.SECRET_SCAN)
        result_ids = [r.id for r in results]
        assert "MCP-S3" in result_ids

    def test_query_multiple_filters_are_anded(self):
        reg = RiskRegistry()
        results = reg.query(artifact_type=ArtifactType.PROMPT, category=RiskCategory.SECURITY)
        assert len(results) > 0
        for r in results:
            assert ArtifactType.PROMPT in r.artifact_types
            assert r.category == RiskCategory.SECURITY

    def test_query_no_match_returns_empty(self):
        reg = RiskRegistry()
        # Query for a combination that doesn't exist
        results = reg.query(
            artifact_type=ArtifactType.API_SCHEMA, category=RiskCategory.RELIABILITY
        )
        assert results == []

    def test_query_custom_risk_included_in_results(self):
        reg = RiskRegistry()
        reg.add_custom(
            _make_risk(
                "ZCUSTOM-Q1",
                category=RiskCategory.PERFORMANCE,
                artifact_types=[ArtifactType.EVAL_HARNESS],
            )
        )
        results = reg.query(
            artifact_type=ArtifactType.EVAL_HARNESS, category=RiskCategory.PERFORMANCE
        )
        result_ids = [r.id for r in results]
        assert "ZCUSTOM-Q1" in result_ids


class TestRiskRegistryAddCustom:
    """Tests for RiskRegistry.add_custom() method."""

    def test_add_custom_increases_total_count(self):
        reg = RiskRegistry()
        initial = reg.total_count
        reg.add_custom(_make_risk("ZNEW-1"))
        assert reg.total_count == initial + 1
        reg.add_custom(_make_risk("ZNEW-2"))
        assert reg.total_count == initial + 2

    def test_add_custom_overwrites_existing_id(self):
        reg = RiskRegistry()
        initial = reg.total_count
        reg.add_custom(_make_risk("ZOVER-1", title="Original"))
        reg.add_custom(_make_risk("ZOVER-1", title="Updated"))
        # Adding same ID twice should only add 1 net risk
        assert reg.total_count == initial + 1
        result = reg.get("ZOVER-1")
        assert result is not None
        assert result.title == "Updated"


class TestRiskRegistryTotalCount:
    """Tests for RiskRegistry.total_count property."""

    def test_total_count_is_198_initially(self):
        reg = RiskRegistry()
        assert reg.total_count == 198

    def test_total_count_reflects_added_risks(self):
        reg = RiskRegistry()
        initial = reg.total_count
        for i in range(5):
            reg.add_custom(_make_risk(f"ZCUSTOM-{i}"))
        assert reg.total_count == initial + 5


class TestSeverityToGateAction:
    """Tests for severity_to_gate_action static method."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (10, GateAction.BLOCK),
            (9, GateAction.BLOCK),
            (8, GateAction.BLOCK),
            (7, GateAction.BLOCK),
            (6, GateAction.WARN),
            (5, GateAction.WARN),
            (4, GateAction.INFO),
            (3, GateAction.INFO),
            (2, GateAction.INFO),
            (1, GateAction.INFO),
        ],
    )
    def test_severity_maps_to_correct_gate_action(self, score, expected):
        assert RiskRegistry.severity_to_gate_action(score) == expected


class TestLoadAllRisks:
    """Tests for load_all_risks() function."""

    def test_returns_all_198_risks(self):
        risks = load_all_risks()
        assert isinstance(risks, list)
        assert len(risks) == 198

    def test_returns_list_type(self):
        result = load_all_risks()
        assert isinstance(result, list)

    def test_all_risks_have_unique_ids(self):
        risks = load_all_risks()
        ids = [r.id for r in risks]
        assert len(ids) == len(set(ids)), (
            f"Duplicate IDs found: {[x for x in ids if ids.count(x) > 1]}"
        )

    def test_all_risks_are_risk_definition_instances(self):
        risks = load_all_risks()
        for risk in risks:
            assert isinstance(risk, RiskDefinition)
