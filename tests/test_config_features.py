"""Unit tests for .aav.yaml configuration features.

Verifies:
1. gate_overrides correctly downgrade gate actions in the report
2. suppression_rules correctly mark findings as false_positive
3. suppression_rules with file_pattern work with absolute/relative paths
4. Gate decision computation respects overrides and suppressions
"""

from __future__ import annotations

from ai_artifact_risk_validator.models import ArtifactType
from ai_artifact_risk_validator.models.config import SuppressionRule
from ai_artifact_risk_validator.models.enums import (
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.pipeline.aggregator import Aggregator
from ai_artifact_risk_validator.pipeline.gate import assign_gate_action, compute_overall_gate
from ai_artifact_risk_validator.reporting.generator import ReportGenerator


def _make_finding(
    risk_id: str = "SK-S7",
    severity: int = 7,
    confidence: float = 0.95,
    artifact_path: str = "skills/my-skill/SKILL.md",
    gate_action: GateAction = GateAction.BLOCK,
) -> ScanFinding:
    """Create a test finding with sensible defaults."""
    return ScanFinding(
        id=risk_id,
        artifact_type=ArtifactType.SKILL,
        artifact_path=artifact_path,
        severity_score=severity,
        severity_label=SeverityLabel.HIGH if severity >= 7 else SeverityLabel.MEDIUM,
        priority=Priority.P1,
        gate_action=gate_action,
        category=RiskCategory.SECURITY,
        title=f"Test finding {risk_id}",
        description="Test description",
        location=FindingLocation(line=1),
        evidence="test evidence",
        confidence=confidence,
        scanner_module=ScannerModule.PROVENANCE_CHK,
        remediation="Fix it.",
    )


# ===========================================================================
# 1. gate_overrides tests
# ===========================================================================


class TestGateOverrides:
    """Tests for gate_overrides configuration feature."""

    def test_gate_override_downgrades_block_to_info(self) -> None:
        """gate_overrides: SK-S7: INFO should downgrade BLOCK findings to INFO."""
        finding = _make_finding(risk_id="SK-S7", severity=7)
        overrides = {"SK-S7": GateAction.INFO}
        effective = assign_gate_action(finding, overrides)
        assert effective == GateAction.INFO

    def test_gate_override_downgrades_block_to_warn(self) -> None:
        """gate_overrides can downgrade BLOCK to WARN."""
        finding = _make_finding(risk_id="SK-S7", severity=7)
        overrides = {"SK-S7": GateAction.WARN}
        effective = assign_gate_action(finding, overrides)
        assert effective == GateAction.WARN

    def test_gate_override_not_applied_to_other_ids(self) -> None:
        """gate_overrides only applies to matching risk IDs."""
        finding = _make_finding(risk_id="SK-S8", severity=7)
        overrides = {"SK-S7": GateAction.INFO}
        effective = assign_gate_action(finding, overrides)
        assert effective == GateAction.BLOCK  # SK-S8 not overridden

    def test_overall_gate_respects_overrides(self) -> None:
        """compute_overall_gate should respect gate_overrides."""
        findings = [
            _make_finding(risk_id="SK-S7", severity=7),
            _make_finding(risk_id="SK-Q1", severity=4),
        ]
        # Without override: BLOCK (SK-S7 is severity 7)
        assert compute_overall_gate(findings) == GateAction.BLOCK
        # With override: INFO (SK-S7 downgraded, SK-Q1 is INFO)
        overrides = {"SK-S7": GateAction.INFO}
        assert compute_overall_gate(findings, overrides) == GateAction.INFO

    def test_report_generator_applies_gate_overrides(self) -> None:
        """ReportGenerator.generate() should apply gate_overrides to findings."""
        findings = [_make_finding(risk_id="SK-S7", severity=7)]
        gen = ReportGenerator()
        overrides = {"SK-S7": GateAction.INFO}

        report = gen.generate(
            findings=findings,
            artifact_path="test/path",
            gate_overrides=overrides,
        )

        # The finding's gate_action in the report should be INFO
        assert report.findings[0].gate_action == GateAction.INFO
        # The overall gate decision should be INFO
        assert report.summary.gate_decision == GateAction.INFO
        assert report.summary.blocking_findings == 0

    def test_report_generator_without_overrides_preserves_block(self) -> None:
        """Without gate_overrides, severity-7 findings remain BLOCK."""
        findings = [_make_finding(risk_id="SK-S7", severity=7)]
        gen = ReportGenerator()

        report = gen.generate(findings=findings, artifact_path="test/path")

        assert report.findings[0].gate_action == GateAction.BLOCK
        assert report.summary.gate_decision == GateAction.BLOCK
        assert report.summary.blocking_findings == 1


# ===========================================================================
# 2. suppression_rules tests
# ===========================================================================


class TestSuppressionRules:
    """Tests for suppression_rules configuration feature."""

    def test_suppression_by_risk_id_no_file_pattern(self) -> None:
        """A suppression rule with risk_id and no file_pattern suppresses all matches."""
        findings = [
            _make_finding(risk_id="SK-S7", artifact_path="skills/a/SKILL.md"),
            _make_finding(risk_id="SK-S7", artifact_path="skills/b/SKILL.md"),
            _make_finding(risk_id="SK-S8", artifact_path="skills/a/SKILL.md"),
        ]
        rules = [SuppressionRule(risk_id="SK-S7", reason="Accepted")]

        aggregator = Aggregator()
        result = aggregator.aggregate(findings, suppression_rules=rules)

        # SK-S7 findings should be marked as false_positive
        sk_s7 = [f for f in result if f.id == "SK-S7"]
        assert all(f.false_positive is True for f in sk_s7)
        # SK-S8 should NOT be suppressed
        sk_s8 = [f for f in result if f.id == "SK-S8"]
        assert all(f.false_positive is False for f in sk_s8)

    def test_suppression_with_file_pattern_relative(self) -> None:
        """A suppression rule with file_pattern matches relative paths."""
        findings = [
            _make_finding(risk_id="P-S3", artifact_path="tests/fixtures/secret.md"),
            _make_finding(risk_id="P-S3", artifact_path="src/main.py"),
        ]
        rules = [SuppressionRule(risk_id="P-S3", file_pattern="tests/**", reason="Test fixture")]

        aggregator = Aggregator()
        result = aggregator.aggregate(findings, suppression_rules=rules)

        tests_finding = next(f for f in result if "tests" in f.artifact_path)
        src_finding = next(f for f in result if "src" in f.artifact_path)
        assert tests_finding.false_positive is True
        assert src_finding.false_positive is False

    def test_suppression_with_absolute_windows_path(self) -> None:
        """Suppression rules work with absolute Windows paths."""
        findings = [
            _make_finding(
                risk_id="P-S3",
                artifact_path="C:\\Users\\dev\\project\\tests\\fixtures\\secret.md",
            ),
            _make_finding(
                risk_id="P-S3",
                artifact_path="C:\\Users\\dev\\project\\src\\main.py",
            ),
        ]
        rules = [SuppressionRule(risk_id="P-S3", file_pattern="tests/**", reason="Test fixture")]

        aggregator = Aggregator()
        result = aggregator.aggregate(findings, suppression_rules=rules)

        tests_finding = next(f for f in result if "tests" in f.artifact_path)
        src_finding = next(f for f in result if "src" in f.artifact_path)
        assert tests_finding.false_positive is True
        assert src_finding.false_positive is False

    def test_suppression_with_absolute_unix_path(self) -> None:
        """Suppression rules work with absolute Unix paths."""
        findings = [
            _make_finding(
                risk_id="P-S3",
                artifact_path="/home/dev/project/tests/fixtures/secret.md",
            ),
        ]
        rules = [SuppressionRule(risk_id="P-S3", file_pattern="tests/**", reason="Test")]

        aggregator = Aggregator()
        result = aggregator.aggregate(findings, suppression_rules=rules)

        assert result[0].false_positive is True

    def test_suppressed_findings_excluded_from_gate_decision(self) -> None:
        """Suppressed (false_positive) findings don't affect the overall gate."""
        findings = [
            _make_finding(risk_id="SK-S7", severity=7),
        ]
        # Mark as false_positive
        findings[0] = findings[0].model_copy(update={"false_positive": True})

        gate = compute_overall_gate(findings)
        assert gate == GateAction.INFO  # Not BLOCK because it's suppressed

    def test_no_suppression_rules_leaves_findings_unchanged(self) -> None:
        """With no suppression rules, findings are unchanged."""
        findings = [_make_finding(risk_id="SK-S7")]

        aggregator = Aggregator()
        result = aggregator.aggregate(findings, suppression_rules=None)

        assert result[0].false_positive is False


# ===========================================================================
# 3. Combined gate_overrides + suppression_rules
# ===========================================================================


class TestCombinedOverridesAndSuppression:
    """Tests for gate_overrides and suppression_rules working together."""

    def test_overrides_and_suppressions_both_applied(self) -> None:
        """Both gate_overrides and suppression_rules can be active simultaneously."""
        findings = [
            _make_finding(risk_id="SK-S7", severity=7),
            _make_finding(risk_id="SK-S8", severity=7),
            _make_finding(risk_id="SK-Q1", severity=4),
        ]

        # Suppress SK-S8
        rules = [SuppressionRule(risk_id="SK-S8", reason="Accepted")]
        aggregator = Aggregator()
        processed = aggregator.aggregate(findings, suppression_rules=rules)

        # Override SK-S7 gate to INFO
        overrides = {"SK-S7": GateAction.INFO}
        gen = ReportGenerator()
        report = gen.generate(
            findings=processed,
            artifact_path="test",
            gate_overrides=overrides,
        )

        # SK-S7 should have gate_action=INFO (overridden)
        sk_s7 = next(f for f in report.findings if f.id == "SK-S7")
        assert sk_s7.gate_action == GateAction.INFO

        # SK-S8 should be false_positive (suppressed)
        sk_s8 = next(f for f in report.findings if f.id == "SK-S8")
        assert sk_s8.false_positive is True

        # Overall gate should be INFO (SK-S7 overridden, SK-S8 suppressed, SK-Q1 is INFO)
        assert report.summary.gate_decision == GateAction.INFO
