"""Tests for the Aggregator finding deduplication and suppression logic."""

from datetime import datetime

from ai_artifact_risk_validator.models.config import SuppressionRule
from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.pipeline.aggregator import Aggregator


def _make_finding(
    risk_id: str = "P-S1",
    artifact_path: str = "prompts/test.prompt.md",
    line: int | None = 10,
    confidence: float = 0.9,
    false_positive: bool = False,
) -> ScanFinding:
    """Helper to create a ScanFinding with sensible defaults."""
    return ScanFinding(
        id=risk_id,
        artifact_type=ArtifactType.PROMPT,
        artifact_path=artifact_path,
        severity_score=8,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        category=RiskCategory.SECURITY,
        title="Test finding",
        description="A test finding for aggregation tests",
        location=FindingLocation(line=line),
        evidence="some evidence",
        confidence=confidence,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Fix the issue",
        false_positive=false_positive,
        timestamp=datetime(2025, 1, 1, 0, 0, 0),
    )


class TestAggregatorDeduplication:
    """Tests for finding deduplication logic."""

    def test_empty_findings_returns_empty(self) -> None:
        aggregator = Aggregator()
        result = aggregator.aggregate([])
        assert result == []

    def test_single_finding_passes_through(self) -> None:
        aggregator = Aggregator()
        finding = _make_finding()
        result = aggregator.aggregate([finding])
        assert len(result) == 1
        assert result[0] == finding

    def test_duplicate_same_risk_id_and_location_keeps_highest_confidence(self) -> None:
        aggregator = Aggregator()
        low_conf = _make_finding(confidence=0.7)
        high_conf = _make_finding(confidence=0.95)
        result = aggregator.aggregate([low_conf, high_conf])
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_duplicate_reversed_order_keeps_highest_confidence(self) -> None:
        aggregator = Aggregator()
        high_conf = _make_finding(confidence=0.95)
        low_conf = _make_finding(confidence=0.7)
        result = aggregator.aggregate([high_conf, low_conf])
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_different_risk_ids_not_deduplicated(self) -> None:
        aggregator = Aggregator()
        finding1 = _make_finding(risk_id="P-S1")
        finding2 = _make_finding(risk_id="P-S2")
        result = aggregator.aggregate([finding1, finding2])
        assert len(result) == 2

    def test_different_locations_not_deduplicated(self) -> None:
        aggregator = Aggregator()
        finding1 = _make_finding(line=10)
        finding2 = _make_finding(line=20)
        result = aggregator.aggregate([finding1, finding2])
        assert len(result) == 2

    def test_different_artifact_paths_not_deduplicated(self) -> None:
        aggregator = Aggregator()
        finding1 = _make_finding(artifact_path="file1.md")
        finding2 = _make_finding(artifact_path="file2.md")
        result = aggregator.aggregate([finding1, finding2])
        assert len(result) == 2

    def test_none_line_deduplication(self) -> None:
        """Two findings with the same risk_id, same path, and both line=None are duplicates."""
        aggregator = Aggregator()
        finding1 = _make_finding(line=None, confidence=0.6)
        finding2 = _make_finding(line=None, confidence=0.8)
        result = aggregator.aggregate([finding1, finding2])
        assert len(result) == 1
        assert result[0].confidence == 0.8

    def test_multiple_duplicates_across_different_groups(self) -> None:
        aggregator = Aggregator()
        findings = [
            _make_finding(risk_id="P-S1", line=10, confidence=0.7),
            _make_finding(risk_id="P-S1", line=10, confidence=0.9),
            _make_finding(risk_id="P-S2", line=10, confidence=0.8),
            _make_finding(risk_id="P-S2", line=10, confidence=0.6),
        ]
        result = aggregator.aggregate(findings)
        assert len(result) == 2
        risk_ids_and_conf = {(f.id, f.confidence) for f in result}
        assert ("P-S1", 0.9) in risk_ids_and_conf
        assert ("P-S2", 0.8) in risk_ids_and_conf


class TestAggregatorSuppression:
    """Tests for suppression rule application."""

    def test_no_suppression_rules_passes_through(self) -> None:
        aggregator = Aggregator()
        finding = _make_finding()
        result = aggregator.aggregate([finding], suppression_rules=None)
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_empty_suppression_rules_passes_through(self) -> None:
        aggregator = Aggregator()
        finding = _make_finding()
        result = aggregator.aggregate([finding], suppression_rules=[])
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_matching_risk_id_with_no_file_pattern_suppresses(self) -> None:
        """A rule with file_pattern=None matches ALL files for that risk_id."""
        aggregator = Aggregator()
        finding = _make_finding(risk_id="P-S1")
        rule = SuppressionRule(risk_id="P-S1", file_pattern=None, reason="Known false positive")
        result = aggregator.aggregate([finding], suppression_rules=[rule])
        assert len(result) == 1
        assert result[0].false_positive is True

    def test_matching_risk_id_with_matching_file_pattern_suppresses(self) -> None:
        aggregator = Aggregator()
        finding = _make_finding(risk_id="P-S1", artifact_path="prompts/test.prompt.md")
        rule = SuppressionRule(risk_id="P-S1", file_pattern="prompts/*.md")
        result = aggregator.aggregate([finding], suppression_rules=[rule])
        assert len(result) == 1
        assert result[0].false_positive is True

    def test_matching_risk_id_with_non_matching_file_pattern_does_not_suppress(self) -> None:
        aggregator = Aggregator()
        finding = _make_finding(risk_id="P-S1", artifact_path="skills/test.md")
        rule = SuppressionRule(risk_id="P-S1", file_pattern="prompts/*.md")
        result = aggregator.aggregate([finding], suppression_rules=[rule])
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_non_matching_risk_id_does_not_suppress(self) -> None:
        aggregator = Aggregator()
        finding = _make_finding(risk_id="P-S1")
        rule = SuppressionRule(risk_id="P-S2")
        result = aggregator.aggregate([finding], suppression_rules=[rule])
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_wildcard_file_pattern(self) -> None:
        """Test glob-style wildcard patterns via fnmatch."""
        aggregator = Aggregator()
        finding = _make_finding(risk_id="P-S1", artifact_path="src/prompts/deep/nested/file.md")
        _rule_no_match = SuppressionRule(risk_id="P-S1", file_pattern="src/prompts/**/file.md")
        # fnmatch doesn't support **, so this won't match with fnmatch
        # Use a simpler glob pattern
        rule2 = SuppressionRule(risk_id="P-S1", file_pattern="*file.md")
        result = aggregator.aggregate([finding], suppression_rules=[rule2])
        assert len(result) == 1
        assert result[0].false_positive is True

    def test_suppression_preserves_original_finding_data(self) -> None:
        """Suppressed finding retains all fields except false_positive."""
        aggregator = Aggregator()
        finding = _make_finding(risk_id="P-S1", confidence=0.85)
        rule = SuppressionRule(risk_id="P-S1")
        result = aggregator.aggregate([finding], suppression_rules=[rule])
        assert result[0].false_positive is True
        assert result[0].id == "P-S1"
        assert result[0].confidence == 0.85
        assert result[0].artifact_path == finding.artifact_path

    def test_multiple_rules_first_match_wins(self) -> None:
        aggregator = Aggregator()
        finding = _make_finding(risk_id="P-S1")
        rules = [
            SuppressionRule(risk_id="P-S1", reason="First rule"),
            SuppressionRule(risk_id="P-S1", reason="Second rule"),
        ]
        result = aggregator.aggregate([finding], suppression_rules=rules)
        assert len(result) == 1
        assert result[0].false_positive is True

    def test_deduplication_happens_before_suppression(self) -> None:
        """Suppression should apply to already-deduplicated findings."""
        aggregator = Aggregator()
        findings = [
            _make_finding(risk_id="P-S1", confidence=0.7),
            _make_finding(risk_id="P-S1", confidence=0.9),
        ]
        rule = SuppressionRule(risk_id="P-S1")
        result = aggregator.aggregate(findings, suppression_rules=[rule])
        # After dedup, only highest confidence remains; then it gets suppressed
        assert len(result) == 1
        assert result[0].confidence == 0.9
        assert result[0].false_positive is True
