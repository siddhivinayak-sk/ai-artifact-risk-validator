"""Tests for the suppression logic module.

Tests inline suppression comment parsing across multiple comment styles,
config-based suppression matching, and the --no-ignore override behavior.
"""

from datetime import datetime

from ai_artifact_risk_validator._internal.suppression import (
    apply_config_suppressions,
    apply_inline_suppressions,
    clear_suppressions,
    parse_inline_suppressions,
)
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


def _make_finding(
    risk_id: str = "P-S1",
    artifact_path: str = "prompts/test.prompt.md",
    line: int | None = 5,
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
        description="A test finding for suppression tests",
        location=FindingLocation(line=line),
        evidence="some evidence",
        confidence=confidence,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Fix the issue",
        false_positive=false_positive,
        timestamp=datetime(2025, 1, 1, 0, 0, 0),
    )


class TestParseInlineSuppressions:
    """Tests for parse_inline_suppressions function."""

    def test_empty_content_returns_empty(self) -> None:
        result = parse_inline_suppressions("")
        assert result == {}

    def test_no_suppression_comments_returns_empty(self) -> None:
        content = "line 1\nline 2\nline 3\n"
        result = parse_inline_suppressions(content)
        assert result == {}

    def test_hash_style_comment(self) -> None:
        content = "# aav-ignore: P-S1\nsome code here"
        result = parse_inline_suppressions(content)
        # Suppression on line 1 applies to line 2
        assert result == {2: ["P-S1"]}

    def test_double_slash_style_comment(self) -> None:
        content = "// aav-ignore: P-S3\nsome code here"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S3"]}

    def test_html_comment_style(self) -> None:
        content = "<!-- aav-ignore: P-S1 -->\n<div>content</div>"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1"]}

    def test_c_block_comment_style(self) -> None:
        content = "/* aav-ignore: MCP-S3 */\nsome code;"
        result = parse_inline_suppressions(content)
        assert result == {2: ["MCP-S3"]}

    def test_multiple_risk_ids_comma_separated(self) -> None:
        content = "# aav-ignore: P-S1, P-S3\nsome code"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1", "P-S3"]}

    def test_multiple_risk_ids_with_extra_whitespace(self) -> None:
        content = "# aav-ignore:  P-S1 ,  P-S3 , SK-S5 \nsome code"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1", "P-S3", "SK-S5"]}

    def test_suppression_applies_to_next_line(self) -> None:
        content = "normal line\n# aav-ignore: P-S1\ntarget line\nanother line"
        result = parse_inline_suppressions(content)
        # Comment on line 2 suppresses line 3
        assert result == {3: ["P-S1"]}

    def test_multiple_suppression_comments(self) -> None:
        content = "# aav-ignore: P-S1\nline 2\n# aav-ignore: P-S3\nline 4"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1"], 4: ["P-S3"]}

    def test_case_insensitive(self) -> None:
        content = "# AAV-IGNORE: P-S1\nsome code"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1"]}

    def test_suppression_at_last_line_targets_beyond_file(self) -> None:
        """Suppression at the last line targets a non-existent next line."""
        content = "line 1\n# aav-ignore: P-S1"
        result = parse_inline_suppressions(content)
        # Comment on line 2 targets line 3 (which doesn't exist, but that's fine)
        assert result == {3: ["P-S1"]}

    def test_indented_comment(self) -> None:
        content = "    # aav-ignore: P-S1\n    code here"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1"]}

    def test_html_comment_with_extra_whitespace(self) -> None:
        content = "  <!--   aav-ignore:   P-S1   -->  \nhtml content"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1"]}

    def test_c_block_comment_with_extra_whitespace(self) -> None:
        content = "  /*   aav-ignore:   P-S1   */  \ncode"
        result = parse_inline_suppressions(content)
        assert result == {2: ["P-S1"]}


class TestApplyInlineSuppressions:
    """Tests for apply_inline_suppressions function."""

    def test_no_suppressions_passes_through(self) -> None:
        finding = _make_finding(line=5)
        content = "line 1\nline 2\nline 3\nline 4\nline 5"
        result = apply_inline_suppressions([finding], content)
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_matching_suppression_marks_false_positive(self) -> None:
        finding = _make_finding(risk_id="P-S1", line=2)
        content = "# aav-ignore: P-S1\ntarget line"
        result = apply_inline_suppressions([finding], content)
        assert len(result) == 1
        assert result[0].false_positive is True

    def test_non_matching_risk_id_not_suppressed(self) -> None:
        finding = _make_finding(risk_id="P-S2", line=2)
        content = "# aav-ignore: P-S1\ntarget line"
        result = apply_inline_suppressions([finding], content)
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_non_matching_line_not_suppressed(self) -> None:
        finding = _make_finding(risk_id="P-S1", line=5)
        content = "# aav-ignore: P-S1\ntarget line\nline 3\nline 4\nline 5"
        result = apply_inline_suppressions([finding], content)
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_finding_with_no_line_not_suppressed(self) -> None:
        finding = _make_finding(risk_id="P-S1", line=None)
        content = "# aav-ignore: P-S1\ntarget line"
        result = apply_inline_suppressions([finding], content)
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_multiple_findings_selective_suppression(self) -> None:
        findings = [
            _make_finding(risk_id="P-S1", line=2),
            _make_finding(risk_id="P-S3", line=2),
            _make_finding(risk_id="P-S1", line=4),
        ]
        content = "# aav-ignore: P-S1, P-S3\ntarget\nline 3\nline 4"
        result = apply_inline_suppressions(findings, content)
        assert result[0].false_positive is True  # P-S1 on line 2 - suppressed
        assert result[1].false_positive is True  # P-S3 on line 2 - suppressed
        assert result[2].false_positive is False  # P-S1 on line 4 - not suppressed

    def test_empty_findings_returns_empty(self) -> None:
        content = "# aav-ignore: P-S1\ntarget line"
        result = apply_inline_suppressions([], content)
        assert result == []

    def test_suppressed_finding_preserves_other_fields(self) -> None:
        finding = _make_finding(risk_id="P-S1", line=2, confidence=0.85)
        content = "# aav-ignore: P-S1\ntarget line"
        result = apply_inline_suppressions([finding], content)
        assert result[0].false_positive is True
        assert result[0].id == "P-S1"
        assert result[0].confidence == 0.85
        assert result[0].location.line == 2


class TestApplyConfigSuppressions:
    """Tests for apply_config_suppressions function."""

    def test_empty_rules_passes_through(self) -> None:
        finding = _make_finding()
        result = apply_config_suppressions([finding], [])
        assert len(result) == 1
        assert result[0].false_positive is False

    def test_matching_risk_id_no_file_pattern_suppresses(self) -> None:
        finding = _make_finding(risk_id="P-S1")
        rules = [SuppressionRule(risk_id="P-S1", reason="test")]
        result = apply_config_suppressions([finding], rules)
        assert result[0].false_positive is True

    def test_matching_risk_id_with_matching_file_pattern(self) -> None:
        finding = _make_finding(risk_id="P-S1", artifact_path="prompts/test.prompt.md")
        rules = [SuppressionRule(risk_id="P-S1", file_pattern="prompts/*.md", reason="test")]
        result = apply_config_suppressions([finding], rules)
        assert result[0].false_positive is True

    def test_matching_risk_id_with_non_matching_file_pattern(self) -> None:
        finding = _make_finding(risk_id="P-S1", artifact_path="skills/test.md")
        rules = [SuppressionRule(risk_id="P-S1", file_pattern="prompts/*.md", reason="test")]
        result = apply_config_suppressions([finding], rules)
        assert result[0].false_positive is False

    def test_non_matching_risk_id(self) -> None:
        finding = _make_finding(risk_id="P-S1")
        rules = [SuppressionRule(risk_id="P-S2", reason="test")]
        result = apply_config_suppressions([finding], rules)
        assert result[0].false_positive is False

    def test_wildcard_file_pattern(self) -> None:
        finding = _make_finding(risk_id="P-S1", artifact_path="prompts/deep/file.md")
        rules = [SuppressionRule(risk_id="P-S1", file_pattern="*file.md", reason="test")]
        result = apply_config_suppressions([finding], rules)
        assert result[0].false_positive is True

    def test_multiple_rules_first_match(self) -> None:
        finding = _make_finding(risk_id="P-S1")
        rules = [
            SuppressionRule(risk_id="P-S1", reason="First"),
            SuppressionRule(risk_id="P-S1", reason="Second"),
        ]
        result = apply_config_suppressions([finding], rules)
        assert result[0].false_positive is True

    def test_multiple_findings_selective_suppression(self) -> None:
        findings = [
            _make_finding(risk_id="P-S1", artifact_path="prompts/a.md"),
            _make_finding(risk_id="P-S2", artifact_path="prompts/b.md"),
        ]
        rules = [SuppressionRule(risk_id="P-S1", reason="test")]
        result = apply_config_suppressions(findings, rules)
        assert result[0].false_positive is True
        assert result[1].false_positive is False


class TestClearSuppressions:
    """Tests for clear_suppressions function (--no-ignore support)."""

    def test_clears_false_positive_flags(self) -> None:
        findings = [
            _make_finding(false_positive=True),
            _make_finding(risk_id="P-S2", false_positive=True),
        ]
        result = clear_suppressions(findings)
        assert all(f.false_positive is False for f in result)

    def test_already_false_findings_unchanged(self) -> None:
        findings = [_make_finding(false_positive=False)]
        result = clear_suppressions(findings)
        assert result[0].false_positive is False

    def test_mixed_findings(self) -> None:
        findings = [
            _make_finding(risk_id="P-S1", false_positive=True),
            _make_finding(risk_id="P-S2", false_positive=False),
        ]
        result = clear_suppressions(findings)
        assert result[0].false_positive is False
        assert result[1].false_positive is False

    def test_empty_findings_returns_empty(self) -> None:
        result = clear_suppressions([])
        assert result == []

    def test_preserves_other_fields(self) -> None:
        finding = _make_finding(risk_id="P-S1", confidence=0.85, false_positive=True)
        result = clear_suppressions([finding])
        assert result[0].id == "P-S1"
        assert result[0].confidence == 0.85
        assert result[0].false_positive is False
