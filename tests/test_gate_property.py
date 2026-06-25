"""Property-based tests for gate decision logic — false positive exclusion.

**Validates: Requirements 14.5**

Property 6: False Positive Exclusion from Counts
Tests that blocking/warning/info counts exclude false_positive findings
while total_findings includes all.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

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
)

# --- Strategies ---

valid_severity_strategy = st.integers(min_value=1, max_value=10)
valid_confidence_strategy = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)


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
def finding_strategy(draw: st.DrawFn, false_positive: bool | None = None) -> ScanFinding:
    """Generate a ScanFinding with a random or fixed false_positive flag."""
    severity_score = draw(valid_severity_strategy)
    confidence = draw(valid_confidence_strategy)
    fp = draw(st.booleans()) if false_positive is None else false_positive

    return ScanFinding(
        id="P-S1",
        artifact_type=ArtifactType.PROMPT,
        artifact_path="/test/artifact.md",
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
        false_positive=fp,
    )


@st.composite
def findings_list_strategy(
    draw: st.DrawFn,
    min_size: int = 1,
    max_size: int = 20,
    false_positive: bool | None = None,
) -> list[ScanFinding]:
    """Generate a list of ScanFindings with random or fixed false_positive flags."""
    return draw(
        st.lists(
            finding_strategy(false_positive=false_positive),
            min_size=min_size,
            max_size=max_size,
        )
    )


def compute_summary_counts(
    findings: list[ScanFinding],
    gate_overrides: dict[str, GateAction] | None = None,
) -> dict:
    """Compute summary counts matching the logic from Requirements 14.5.

    total_findings includes ALL findings.
    blocking/warning/info counts EXCLUDE false_positive findings.
    """
    total_findings = len(findings)
    blocking = 0
    warning = 0
    info = 0

    for f in findings:
        if f.false_positive:
            continue
        effective_gate = assign_gate_action(f, gate_overrides)
        if effective_gate == GateAction.BLOCK:
            blocking += 1
        elif effective_gate == GateAction.WARN:
            warning += 1
        else:
            info += 1

    return {
        "total_findings": total_findings,
        "blocking_findings": blocking,
        "warning_findings": warning,
        "info_findings": info,
    }


# --- Property Tests ---


class TestFalsePositiveExclusionFromCounts:
    """Property 6: False Positive Exclusion from Counts.

    **Validates: Requirements 14.5**
    """

    @given(findings=findings_list_strategy(min_size=1, max_size=15, false_positive=True))
    @settings(max_examples=100, deadline=None)
    def test_all_false_positive_findings_returns_info_gate(
        self, findings: list[ScanFinding]
    ) -> None:
        """When ALL findings are false_positive, compute_overall_gate returns INFO."""
        result = compute_overall_gate(findings)
        assert result == GateAction.INFO

    @given(findings=findings_list_strategy(min_size=1, max_size=15, false_positive=True))
    @settings(max_examples=100, deadline=None)
    def test_all_false_positive_findings_have_zero_blocking_warning_counts(
        self, findings: list[ScanFinding]
    ) -> None:
        """When ALL findings are false_positive, blocking and warning counts are zero
        but total_findings still counts all."""
        counts = compute_summary_counts(findings)

        assert counts["total_findings"] == len(findings)
        assert counts["blocking_findings"] == 0
        assert counts["warning_findings"] == 0
        assert counts["info_findings"] == 0

    @given(findings=findings_list_strategy(min_size=1, max_size=20))
    @settings(max_examples=200, deadline=None)
    def test_total_findings_includes_all_regardless_of_false_positive(
        self, findings: list[ScanFinding]
    ) -> None:
        """total_findings always equals len(findings), including false positives."""
        counts = compute_summary_counts(findings)
        assert counts["total_findings"] == len(findings)

    @given(findings=findings_list_strategy(min_size=1, max_size=20))
    @settings(max_examples=200, deadline=None)
    def test_gate_counts_exclude_false_positive_findings(self, findings: list[ScanFinding]) -> None:
        """blocking + warning + info counts only include non-false-positive findings."""
        counts = compute_summary_counts(findings)

        non_fp_count = sum(1 for f in findings if not f.false_positive)
        gate_count_sum = (
            counts["blocking_findings"] + counts["warning_findings"] + counts["info_findings"]
        )

        assert gate_count_sum == non_fp_count

    @given(findings=findings_list_strategy(min_size=1, max_size=20))
    @settings(max_examples=200, deadline=None)
    def test_overall_gate_only_considers_non_false_positive_findings(
        self, findings: list[ScanFinding]
    ) -> None:
        """compute_overall_gate result matches what we'd get from only
        non-false-positive findings."""
        # Compute overall gate from the full list (implementation skips fp)
        overall = compute_overall_gate(findings)

        # Manually compute from non-fp findings only
        non_fp_findings = [f for f in findings if not f.false_positive]
        if not non_fp_findings:
            expected = GateAction.INFO
        else:
            _gate_severity = {
                GateAction.INFO: 0,
                GateAction.WARN: 1,
                GateAction.BLOCK: 2,
            }
            expected = GateAction.INFO
            for f in non_fp_findings:
                effective = assign_gate_action(f)
                if _gate_severity[effective] > _gate_severity[expected]:
                    expected = effective

        assert overall == expected
