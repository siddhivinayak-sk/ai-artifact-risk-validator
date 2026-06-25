"""Property-based tests for suppression rule application.

**Validates: Requirements 18.1, 18.2, 18.3**

Property 8: Suppression Rule Application
Tests that any finding matching a suppression rule (risk_id + file_pattern)
has false_positive set to True.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator._internal.suppression import apply_config_suppressions
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

# --- Strategies ---

# Valid risk IDs for property testing
_RISK_IDS = ["P-S1", "P-S2", "P-S3", "SK-S1", "MCP-S1", "H-S1", "A-S1", "I-S1"]

# File path patterns that can be used in suppression rules (glob style)
_FILE_PATTERNS = [
    "*.md",
    "prompts/*.md",
    "skills/*",
    "agents/**",
    "src/*.py",
    "*.yaml",
]

# Artifact paths that will match the above patterns
_ARTIFACT_PATHS_BY_PATTERN = {
    "*.md": ["readme.md", "test.md", "doc.md"],
    "prompts/*.md": ["prompts/system.md", "prompts/user.md"],
    "skills/*": ["skills/search.md", "skills/code.yaml"],
    "agents/**": ["agents/main.md", "agents/sub/helper.md"],
    "src/*.py": ["src/main.py", "src/utils.py"],
    "*.yaml": ["config.yaml", "rules.yaml"],
}

# Artifact paths that will NOT match the above patterns
_NON_MATCHING_PATHS = [
    "other/file.txt",
    "data/records.json",
    "lib/module.rs",
]


def _severity_to_label(score: int) -> SeverityLabel:
    """Map severity score to the corresponding label."""
    if score >= 9:
        return SeverityLabel.CRITICAL
    elif score >= 7:
        return SeverityLabel.HIGH
    elif score >= 5:
        return SeverityLabel.MEDIUM
    elif score >= 3:
        return SeverityLabel.LOW
    else:
        return SeverityLabel.INFORMATIONAL


@st.composite
def finding_strategy(
    draw: st.DrawFn,
    risk_id: str | None = None,
    artifact_path: str | None = None,
) -> ScanFinding:
    """Generate a ScanFinding with optional fixed risk_id and artifact_path."""
    rid = risk_id if risk_id is not None else draw(st.sampled_from(_RISK_IDS))
    path = (
        artifact_path
        if artifact_path is not None
        else draw(st.sampled_from(_NON_MATCHING_PATHS + ["prompts/test.md", "src/main.py"]))
    )
    severity_score = draw(st.integers(min_value=1, max_value=10))
    confidence = draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False))

    return ScanFinding(
        id=rid,
        artifact_type=ArtifactType.PROMPT,
        artifact_path=path,
        severity_score=severity_score,
        severity_label=_severity_to_label(severity_score),
        priority=Priority.P1,
        gate_action=GateAction.INFO,
        category=RiskCategory.SECURITY,
        title="Test finding",
        description="Generated for property test",
        location=FindingLocation(),
        evidence="test evidence",
        confidence=confidence,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Fix it",
        false_positive=False,
    )


@st.composite
def matching_finding_and_rule_strategy(draw: st.DrawFn) -> tuple[ScanFinding, SuppressionRule]:
    """Generate a finding and a suppression rule that are guaranteed to match.

    The rule's risk_id matches the finding's id, and the rule's file_pattern
    matches the finding's artifact_path via fnmatch.
    """
    risk_id = draw(st.sampled_from(_RISK_IDS))
    file_pattern = draw(st.sampled_from(_FILE_PATTERNS))
    matching_paths = _ARTIFACT_PATHS_BY_PATTERN[file_pattern]
    artifact_path = draw(st.sampled_from(matching_paths))

    finding = draw(finding_strategy(risk_id=risk_id, artifact_path=artifact_path))
    rule = SuppressionRule(risk_id=risk_id, file_pattern=file_pattern)

    return finding, rule


@st.composite
def non_matching_finding_and_rule_strategy(draw: st.DrawFn) -> tuple[ScanFinding, SuppressionRule]:
    """Generate a finding and a suppression rule that do NOT match.

    Either the risk_id doesn't match or the file_pattern doesn't match.
    """
    # Strategy: use different risk IDs for finding vs rule
    finding_risk_id = draw(st.sampled_from(_RISK_IDS[:4]))  # First half
    rule_risk_id = draw(st.sampled_from(_RISK_IDS[4:]))  # Second half (disjoint)
    file_pattern = draw(st.sampled_from(_FILE_PATTERNS))

    artifact_path = draw(st.sampled_from(_NON_MATCHING_PATHS))

    finding = draw(finding_strategy(risk_id=finding_risk_id, artifact_path=artifact_path))
    rule = SuppressionRule(risk_id=rule_risk_id, file_pattern=file_pattern)

    return finding, rule


# --- Property Tests ---


class TestSuppressionRuleApplication:
    """Property 8: Suppression Rule Application.

    **Validates: Requirements 18.1, 18.2, 18.3**
    """

    @given(data=st.data())
    @settings(max_examples=200, deadline=None)
    def test_matching_finding_marked_false_positive_via_suppression_module(
        self, data: st.DataObject
    ) -> None:
        """Any finding whose risk_id and artifact_path match a suppression rule
        has false_positive set to True after apply_config_suppressions."""
        finding, rule = data.draw(matching_finding_and_rule_strategy())

        result = apply_config_suppressions([finding], [rule])

        assert len(result) == 1
        assert result[0].false_positive is True

    @given(data=st.data())
    @settings(max_examples=200, deadline=None)
    def test_matching_finding_marked_false_positive_via_aggregator(
        self, data: st.DataObject
    ) -> None:
        """Any finding whose risk_id and artifact_path match a suppression rule
        has false_positive set to True after Aggregator.aggregate."""
        finding, rule = data.draw(matching_finding_and_rule_strategy())

        aggregator = Aggregator()
        result = aggregator.aggregate([finding], suppression_rules=[rule])

        assert len(result) == 1
        assert result[0].false_positive is True

    @given(data=st.data())
    @settings(max_examples=200, deadline=None)
    def test_non_matching_finding_not_marked_false_positive(self, data: st.DataObject) -> None:
        """Findings that do NOT match any suppression rule retain false_positive=False."""
        finding, rule = data.draw(non_matching_finding_and_rule_strategy())

        result = apply_config_suppressions([finding], [rule])

        assert len(result) == 1
        assert result[0].false_positive is False

    @given(data=st.data())
    @settings(max_examples=200, deadline=None)
    def test_rule_with_no_file_pattern_matches_all_paths(self, data: st.DataObject) -> None:
        """A suppression rule with file_pattern=None matches any finding with
        the same risk_id, regardless of artifact_path."""
        risk_id = data.draw(st.sampled_from(_RISK_IDS))
        artifact_path = data.draw(
            st.sampled_from(_NON_MATCHING_PATHS + ["prompts/test.md", "src/main.py"])
        )
        finding = data.draw(finding_strategy(risk_id=risk_id, artifact_path=artifact_path))
        rule = SuppressionRule(risk_id=risk_id, file_pattern=None)

        result = apply_config_suppressions([finding], [rule])

        assert len(result) == 1
        assert result[0].false_positive is True

    @given(data=st.data())
    @settings(max_examples=200, deadline=None)
    def test_suppression_preserves_finding_data(self, data: st.DataObject) -> None:
        """Suppression only changes false_positive; all other fields remain unchanged."""
        finding, rule = data.draw(matching_finding_and_rule_strategy())

        result = apply_config_suppressions([finding], [rule])

        suppressed = result[0]
        assert suppressed.false_positive is True
        assert suppressed.id == finding.id
        assert suppressed.artifact_path == finding.artifact_path
        assert suppressed.severity_score == finding.severity_score
        assert suppressed.confidence == finding.confidence
        assert suppressed.scanner_module == finding.scanner_module
        assert suppressed.title == finding.title
        assert suppressed.description == finding.description

    @given(
        findings=st.lists(finding_strategy(), min_size=1, max_size=10),
        rules=st.lists(
            st.builds(
                SuppressionRule,
                risk_id=st.sampled_from(_RISK_IDS),
                file_pattern=st.sampled_from(_FILE_PATTERNS + [None]),
            ),
            min_size=1,
            max_size=5,
        ),
    )
    @settings(max_examples=200, deadline=None)
    def test_all_matching_findings_are_suppressed_in_bulk(
        self, findings: list[ScanFinding], rules: list[SuppressionRule]
    ) -> None:
        """For any list of findings and rules, every finding that matches at least
        one rule has false_positive=True in the output."""
        from fnmatch import fnmatch

        result = apply_config_suppressions(findings, rules)

        assert len(result) == len(findings)

        for original, suppressed in zip(findings, result):
            should_be_suppressed = any(
                original.id == rule.risk_id
                and (
                    rule.file_pattern is None or fnmatch(original.artifact_path, rule.file_pattern)
                )
                for rule in rules
            )
            if should_be_suppressed:
                assert suppressed.false_positive is True
            else:
                # Original was not false_positive, so it should stay that way
                assert suppressed.false_positive == original.false_positive
