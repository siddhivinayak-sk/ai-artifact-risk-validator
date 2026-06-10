"""Property test for Risk Registry completeness and consistency.

**Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5**

Property 7: Risk Registry Completeness and Consistency
- Total risk count is exactly 190
- Each risk has severity_score between 1-10
- severity_label matches severity_score (CRITICAL=9-10, HIGH=7-8, MEDIUM=5-6, LOW=3-4, INFORMATIONAL=1-2)
- Each risk has at least one scanner_module
- Each risk has at least one artifact_type
- All risk IDs are unique
- gate_action matches severity (BLOCK for >=7, WARN for 5-6, INFO for <=4)
"""

import pytest

from ai_artifact_risk_validator.models.enums import (
    GateAction,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.risk import RiskDefinition
from ai_artifact_risk_validator.risks import RiskRegistry

# Load the registry once for all tests
_registry = RiskRegistry()
_all_risks: list[RiskDefinition] = list(_registry.query())


# --- Property 7: Risk Registry Completeness and Consistency ---


class TestRiskRegistryCompleteness:
    """Tests that the risk registry contains exactly 200 risks with unique IDs."""

    def test_total_risk_count_is_exactly_200(self):
        """**Validates: Requirements 11.1, 11.2**"""
        assert _registry.total_count == 200, (
            f"Expected 200 total risks, got {_registry.total_count}"
        )

    def test_all_risk_ids_are_unique(self):
        """**Validates: Requirements 11.1, 11.2**"""
        ids = [r.id for r in _all_risks]
        duplicates = [rid for rid in ids if ids.count(rid) > 1]
        assert len(ids) == len(set(ids)), f"Duplicate risk IDs found: {sorted(set(duplicates))}"


class TestRiskRegistrySeverityScoreValidity:
    """Tests that every risk has a valid severity_score between 1 and 10."""

    @pytest.mark.parametrize(
        "risk",
        _all_risks,
        ids=[r.id for r in _all_risks],
    )
    def test_severity_score_in_valid_range(self, risk: RiskDefinition):
        """**Validates: Requirements 11.1, 11.2**"""
        assert 1 <= risk.severity_score <= 10, (
            f"Risk {risk.id} has invalid severity_score={risk.severity_score}, expected 1-10"
        )


class TestRiskRegistrySeverityLabelConsistency:
    """Tests that severity_label is consistent with severity_score for all risks."""

    _EXPECTED_LABEL_FOR_SCORE = {
        10: SeverityLabel.CRITICAL,
        9: SeverityLabel.CRITICAL,
        8: SeverityLabel.HIGH,
        7: SeverityLabel.HIGH,
        6: SeverityLabel.MEDIUM,
        5: SeverityLabel.MEDIUM,
        4: SeverityLabel.LOW,
        3: SeverityLabel.LOW,
        2: SeverityLabel.INFORMATIONAL,
        1: SeverityLabel.INFORMATIONAL,
    }

    @pytest.mark.parametrize(
        "risk",
        _all_risks,
        ids=[r.id for r in _all_risks],
    )
    def test_severity_label_matches_score(self, risk: RiskDefinition):
        """**Validates: Requirements 11.1, 11.2, 11.4**"""
        expected_label = self._EXPECTED_LABEL_FOR_SCORE[risk.severity_score]
        assert risk.severity_label == expected_label, (
            f"Risk {risk.id}: severity_score={risk.severity_score} should have "
            f"severity_label={expected_label.value}, got {risk.severity_label.value}"
        )


class TestRiskRegistryScannerModuleAssignment:
    """Tests that every risk has at least one scanner_module assigned."""

    @pytest.mark.parametrize(
        "risk",
        _all_risks,
        ids=[r.id for r in _all_risks],
    )
    def test_has_at_least_one_scanner_module(self, risk: RiskDefinition):
        """**Validates: Requirements 11.3**"""
        assert len(risk.scanner_modules) >= 1, f"Risk {risk.id} has no scanner_modules assigned"


class TestRiskRegistryArtifactTypeAssignment:
    """Tests that every risk has at least one artifact_type assigned."""

    @pytest.mark.parametrize(
        "risk",
        _all_risks,
        ids=[r.id for r in _all_risks],
    )
    def test_has_at_least_one_artifact_type(self, risk: RiskDefinition):
        """**Validates: Requirements 11.1, 11.2**"""
        assert len(risk.artifact_types) >= 1, f"Risk {risk.id} has no artifact_types assigned"


class TestRiskRegistryGateActionConsistency:
    """Tests that gate_action matches severity mapping.

    Per Requirement 11.4:
    - S9-S10 -> BLOCK (mandatory, not overridable)
    - S7-S8  -> BLOCK (overridable to WARN)
    - S5-S6  -> WARN
    - S3-S4  -> INFO
    - S1-S2  -> INFO
    """

    # Allowed gate_actions per severity score
    # S7-S8 can be BLOCK or WARN since the spec says "overridable"
    _ALLOWED_GATES_FOR_SCORE: dict[int, set[GateAction]] = {
        10: {GateAction.BLOCK},
        9: {GateAction.BLOCK},
        8: {GateAction.BLOCK, GateAction.WARN},
        7: {GateAction.BLOCK, GateAction.WARN},
        6: {GateAction.WARN},
        5: {GateAction.WARN},
        4: {GateAction.INFO},
        3: {GateAction.INFO},
        2: {GateAction.INFO},
        1: {GateAction.INFO},
    }

    @pytest.mark.parametrize(
        "risk",
        _all_risks,
        ids=[r.id for r in _all_risks],
    )
    def test_gate_action_matches_severity(self, risk: RiskDefinition):
        """**Validates: Requirements 11.4, 11.5**"""
        allowed_gates = self._ALLOWED_GATES_FOR_SCORE[risk.severity_score]
        assert risk.gate_action in allowed_gates, (
            f"Risk {risk.id}: severity_score={risk.severity_score} should have "
            f"gate_action in {[g.value for g in allowed_gates]}, "
            f"got {risk.gate_action.value}"
        )
