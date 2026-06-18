"""Tests for the risk score computation pipeline (scorer.py)."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import SeverityLabel
from ai_artifact_risk_validator.pipeline.scorer import (
    compute_risk_score,
    detect_executable_scripts,
    severity_band,
)

# ---------------------------------------------------------------------------
# Fixtures: minimal ScanFinding-like objects
# ---------------------------------------------------------------------------


def _make_finding(severity_label: SeverityLabel, severity_score: int) -> object:
    """Create a minimal finding-like object for scorer tests."""

    class _Finding:
        false_positive: bool = False

    f = _Finding()
    f.severity_label = severity_label  # type: ignore[attr-defined]
    f.severity_score = severity_score  # type: ignore[attr-defined]
    return f


# ---------------------------------------------------------------------------
# Unit tests: compute_risk_score
# ---------------------------------------------------------------------------


class TestComputeRiskScore:
    def test_empty_findings_returns_zero(self) -> None:
        assert compute_risk_score([], False) == 0

    def test_single_critical_finding_high_score(self) -> None:
        f = _make_finding(SeverityLabel.CRITICAL, 10)
        score = compute_risk_score([f], False)  # type: ignore[arg-type]
        assert score > 0

    def test_executable_multiplier_increases_score(self) -> None:
        f = _make_finding(SeverityLabel.HIGH, 8)
        score_no_exec = compute_risk_score([f], False)  # type: ignore[arg-type]
        score_with_exec = compute_risk_score([f], True)  # type: ignore[arg-type]
        assert score_with_exec >= score_no_exec

    def test_score_clamped_to_100(self) -> None:
        # Many critical findings should still cap at 100
        findings = [_make_finding(SeverityLabel.CRITICAL, 10) for _ in range(20)]
        score = compute_risk_score(findings, True)  # type: ignore[arg-type]
        assert score <= 100

    def test_score_clamped_to_zero(self) -> None:
        assert compute_risk_score([], False) >= 0

    def test_low_severity_produces_low_score(self) -> None:
        f = _make_finding(SeverityLabel.LOW, 2)
        score = compute_risk_score([f], False)  # type: ignore[arg-type]
        assert score < 20


# ---------------------------------------------------------------------------
# Unit tests: severity_band
# ---------------------------------------------------------------------------


class TestSeverityBand:
    def test_score_0_is_low_safe(self) -> None:
        label, rec = severity_band(0)
        assert label == "LOW"
        assert rec == "SAFE"

    def test_score_20_is_low_safe(self) -> None:
        label, rec = severity_band(20)
        assert label == "LOW"
        assert rec == "SAFE"

    def test_score_21_is_medium_caution(self) -> None:
        label, rec = severity_band(21)
        assert label == "MEDIUM"
        assert rec == "CAUTION"

    def test_score_50_is_medium_caution(self) -> None:
        label, rec = severity_band(50)
        assert label == "MEDIUM"
        assert rec == "CAUTION"

    def test_score_51_is_high_do_not_install(self) -> None:
        label, rec = severity_band(51)
        assert label == "HIGH"
        assert rec == "DO_NOT_INSTALL"

    def test_score_81_is_critical_do_not_install(self) -> None:
        label, rec = severity_band(81)
        assert label == "CRITICAL"
        assert rec == "DO_NOT_INSTALL"

    def test_score_100_is_critical(self) -> None:
        label, rec = severity_band(100)
        assert label == "CRITICAL"
        assert rec == "DO_NOT_INSTALL"


# ---------------------------------------------------------------------------
# Unit tests: detect_executable_scripts
# ---------------------------------------------------------------------------


class TestDetectExecutableScripts:
    def test_python_file_detected(self) -> None:
        assert detect_executable_scripts(["main.py"]) is True

    def test_shell_script_detected(self) -> None:
        assert detect_executable_scripts(["setup.sh"]) is True

    def test_js_file_detected(self) -> None:
        assert detect_executable_scripts(["index.js"]) is True

    def test_markdown_not_detected(self) -> None:
        assert detect_executable_scripts(["README.md"]) is False

    def test_yaml_not_detected(self) -> None:
        assert detect_executable_scripts(["config.yaml"]) is False

    def test_empty_list_returns_false(self) -> None:
        assert detect_executable_scripts([]) is False

    def test_mixed_list_with_executable(self) -> None:
        assert detect_executable_scripts(["README.md", "run.sh", "config.json"]) is True

    def test_mixed_list_without_executable(self) -> None:
        assert detect_executable_scripts(["README.md", "schema.json", "config.yaml"]) is False


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------


@given(score=st.integers(min_value=0, max_value=100))
@settings(max_examples=50)
def test_severity_band_always_returns_valid(score: int) -> None:
    label, rec = severity_band(score)
    assert label in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert rec in {"SAFE", "CAUTION", "DO_NOT_INSTALL"}


@given(
    labels=st.lists(
        st.sampled_from(list(SeverityLabel)),
        min_size=0,
        max_size=50,
    ),
    has_exec=st.booleans(),
)
@settings(max_examples=100)
def test_compute_risk_score_always_valid_range(labels: list[SeverityLabel], has_exec: bool) -> None:
    findings = [_make_finding(lbl, 5) for lbl in labels]
    score = compute_risk_score(findings, has_exec)  # type: ignore[arg-type]
    assert 0 <= score <= 100
