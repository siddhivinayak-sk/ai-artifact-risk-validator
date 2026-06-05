"""Unit tests for gate decision logic."""

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.pipeline.gate import (
    assign_gate_action,
    compute_overall_gate,
    should_suppress,
)


def _make_finding(
    severity_score: int = 5,
    confidence: float = 0.90,
    false_positive: bool = False,
    risk_id: str = "P-S1",
) -> ScanFinding:
    """Create a minimal ScanFinding for testing."""
    # Map severity to label
    if severity_score >= 9:
        label = SeverityLabel.CRITICAL
    elif severity_score >= 7:
        label = SeverityLabel.HIGH
    elif severity_score >= 5:
        label = SeverityLabel.MEDIUM
    elif severity_score >= 3:
        label = SeverityLabel.LOW
    else:
        label = SeverityLabel.INFORMATIONAL

    return ScanFinding(
        id=risk_id,
        artifact_type=ArtifactType.PROMPT,
        artifact_path="/test/file.md",
        severity_score=severity_score,
        severity_label=label,
        priority=Priority.P1,
        gate_action=GateAction.INFO,  # This field on the model is separate from effective gate
        category=RiskCategory.SECURITY,
        title="Test finding",
        description="A test finding for gate logic",
        location=FindingLocation(),
        evidence="test evidence",
        confidence=confidence,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Fix it",
        false_positive=false_positive,
    )


class TestSeverityToGateMapping:
    """Tests for severity-based gate action mapping."""

    def test_s10_maps_to_block(self):
        finding = _make_finding(severity_score=10, confidence=0.95)
        assert assign_gate_action(finding) == GateAction.BLOCK

    def test_s9_maps_to_block(self):
        finding = _make_finding(severity_score=9, confidence=0.95)
        assert assign_gate_action(finding) == GateAction.BLOCK

    def test_s8_maps_to_block(self):
        finding = _make_finding(severity_score=8, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.BLOCK

    def test_s7_maps_to_block(self):
        finding = _make_finding(severity_score=7, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.BLOCK

    def test_s6_maps_to_warn(self):
        finding = _make_finding(severity_score=6, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.WARN

    def test_s5_maps_to_warn(self):
        finding = _make_finding(severity_score=5, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.WARN

    def test_s4_maps_to_info(self):
        finding = _make_finding(severity_score=4, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.INFO

    def test_s3_maps_to_info(self):
        finding = _make_finding(severity_score=3, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.INFO

    def test_s2_maps_to_info(self):
        finding = _make_finding(severity_score=2, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.INFO

    def test_s1_maps_to_info(self):
        finding = _make_finding(severity_score=1, confidence=0.90)
        assert assign_gate_action(finding) == GateAction.INFO


class TestLowConfidenceDowngrade:
    """Tests for low-confidence gate downgrade logic."""

    def test_confidence_below_060_downgrades_block_to_info(self):
        finding = _make_finding(severity_score=9, confidence=0.59)
        assert assign_gate_action(finding) == GateAction.INFO

    def test_confidence_below_060_downgrades_warn_to_info(self):
        finding = _make_finding(severity_score=6, confidence=0.50)
        assert assign_gate_action(finding) == GateAction.INFO

    def test_confidence_at_060_does_not_downgrade(self):
        finding = _make_finding(severity_score=9, confidence=0.60)
        assert assign_gate_action(finding) == GateAction.BLOCK

    def test_confidence_above_060_does_not_downgrade(self):
        finding = _make_finding(severity_score=7, confidence=0.80)
        assert assign_gate_action(finding) == GateAction.BLOCK

    def test_low_confidence_info_stays_info(self):
        finding = _make_finding(severity_score=2, confidence=0.50)
        assert assign_gate_action(finding) == GateAction.INFO


class TestGateOverrides:
    """Tests for config-based gate overrides."""

    def test_override_downgrades_block_to_warn(self):
        finding = _make_finding(severity_score=9, confidence=0.95, risk_id="P-S1")
        overrides = {"P-S1": GateAction.WARN}
        assert assign_gate_action(finding, overrides) == GateAction.WARN

    def test_override_downgrades_block_to_info(self):
        finding = _make_finding(severity_score=10, confidence=0.95, risk_id="P-S1")
        overrides = {"P-S1": GateAction.INFO}
        assert assign_gate_action(finding, overrides) == GateAction.INFO

    def test_override_upgrades_info_to_block(self):
        finding = _make_finding(severity_score=2, confidence=0.90, risk_id="P-S2")
        overrides = {"P-S2": GateAction.BLOCK}
        assert assign_gate_action(finding, overrides) == GateAction.BLOCK

    def test_override_does_not_apply_to_other_risk_ids(self):
        finding = _make_finding(severity_score=9, confidence=0.95, risk_id="P-S1")
        overrides = {"P-S2": GateAction.INFO}
        assert assign_gate_action(finding, overrides) == GateAction.BLOCK

    def test_no_overrides_uses_severity_mapping(self):
        finding = _make_finding(severity_score=9, confidence=0.95)
        assert assign_gate_action(finding, None) == GateAction.BLOCK

    def test_low_confidence_overrides_gate_override(self):
        """Low-confidence downgrade applies AFTER gate override."""
        finding = _make_finding(severity_score=2, confidence=0.50, risk_id="P-S1")
        overrides = {"P-S1": GateAction.BLOCK}
        # Override sets BLOCK, but low confidence downgrades to INFO
        assert assign_gate_action(finding, overrides) == GateAction.INFO


class TestComputeOverallGate:
    """Tests for overall gate decision computation."""

    def test_empty_findings_returns_info(self):
        assert compute_overall_gate([]) == GateAction.INFO

    def test_single_block_finding_returns_block(self):
        findings = [_make_finding(severity_score=9, confidence=0.95)]
        assert compute_overall_gate(findings) == GateAction.BLOCK

    def test_single_warn_finding_returns_warn(self):
        findings = [_make_finding(severity_score=5, confidence=0.90)]
        assert compute_overall_gate(findings) == GateAction.WARN

    def test_single_info_finding_returns_info(self):
        findings = [_make_finding(severity_score=2, confidence=0.90)]
        assert compute_overall_gate(findings) == GateAction.INFO

    def test_block_dominates_warn_and_info(self):
        findings = [
            _make_finding(severity_score=2, confidence=0.90),  # INFO
            _make_finding(severity_score=5, confidence=0.90),  # WARN
            _make_finding(severity_score=9, confidence=0.95),  # BLOCK
        ]
        assert compute_overall_gate(findings) == GateAction.BLOCK

    def test_warn_dominates_info(self):
        findings = [
            _make_finding(severity_score=2, confidence=0.90),  # INFO
            _make_finding(severity_score=6, confidence=0.90),  # WARN
        ]
        assert compute_overall_gate(findings) == GateAction.WARN

    def test_all_false_positives_returns_info(self):
        findings = [
            _make_finding(severity_score=9, confidence=0.95, false_positive=True),
            _make_finding(severity_score=8, confidence=0.90, false_positive=True),
        ]
        assert compute_overall_gate(findings) == GateAction.INFO

    def test_false_positive_excluded_from_gate(self):
        findings = [
            _make_finding(severity_score=9, confidence=0.95, false_positive=True),  # Excluded
            _make_finding(severity_score=5, confidence=0.90, false_positive=False),  # WARN
        ]
        assert compute_overall_gate(findings) == GateAction.WARN

    def test_overrides_applied_in_overall_computation(self):
        findings = [
            _make_finding(severity_score=9, confidence=0.95, risk_id="P-S1"),
        ]
        overrides = {"P-S1": GateAction.WARN}
        assert compute_overall_gate(findings, overrides) == GateAction.WARN

    def test_low_confidence_findings_downgraded_in_overall(self):
        findings = [
            _make_finding(severity_score=9, confidence=0.50),  # Downgraded to INFO
            _make_finding(severity_score=5, confidence=0.50),  # Downgraded to INFO
        ]
        assert compute_overall_gate(findings) == GateAction.INFO


class TestShouldSuppress:
    """Tests for confidence-based suppression logic."""

    def test_confidence_below_040_suppressed_at_info_level(self):
        finding = _make_finding(confidence=0.39)
        assert should_suppress(finding, "INFO") is True

    def test_confidence_below_040_suppressed_at_warning_level(self):
        finding = _make_finding(confidence=0.30)
        assert should_suppress(finding, "WARNING") is True

    def test_confidence_below_040_not_suppressed_at_debug_level(self):
        finding = _make_finding(confidence=0.30)
        assert should_suppress(finding, "DEBUG") is False

    def test_confidence_at_040_not_suppressed(self):
        finding = _make_finding(confidence=0.40)
        assert should_suppress(finding, "INFO") is False

    def test_confidence_above_040_not_suppressed(self):
        finding = _make_finding(confidence=0.90)
        assert should_suppress(finding, "INFO") is False

    def test_high_confidence_not_suppressed_at_any_level(self):
        finding = _make_finding(confidence=0.95)
        assert should_suppress(finding, "INFO") is False
        assert should_suppress(finding, "DEBUG") is False
        assert should_suppress(finding, "WARNING") is False

    def test_debug_level_case_insensitive(self):
        finding = _make_finding(confidence=0.30)
        assert should_suppress(finding, "debug") is False

    def test_default_log_level_is_info(self):
        finding = _make_finding(confidence=0.30)
        assert should_suppress(finding) is True
