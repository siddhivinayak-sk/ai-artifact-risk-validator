"""Property-based tests for model validation consistency.

**Validates: Requirements 10.2, 10.6**

Property 2: Model Validation Consistency
Tests that ScanFinding construction succeeds with valid data and raises
ValidationError with invalid data (severity out of range, confidence out
of range, id pattern mismatch).
"""

import string

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    FindingLocation,
    GateAction,
    Priority,
    RiskCategory,
    ScanFinding,
    ScannerModule,
    SeverityLabel,
)


# --- Strategies for valid data ---

valid_id_strategy = st.from_regex(r"^[A-Z]+-[A-Z]?[0-9]+$", fullmatch=True)

valid_severity_score_strategy = st.integers(min_value=1, max_value=10)

valid_confidence_strategy = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)

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


@st.composite
def valid_scan_finding_data(draw: st.DrawFn) -> dict:
    """Generate valid data for constructing a ScanFinding."""
    return {
        "id": draw(valid_id_strategy),
        "artifact_type": draw(valid_artifact_type_strategy),
        "artifact_path": draw(valid_non_empty_text),
        "severity_score": draw(valid_severity_score_strategy),
        "severity_label": draw(valid_severity_label_strategy),
        "priority": draw(valid_priority_strategy),
        "gate_action": draw(valid_gate_action_strategy),
        "category": draw(valid_category_strategy),
        "title": draw(valid_non_empty_text),
        "description": draw(valid_non_empty_text),
        "location": FindingLocation(),
        "evidence": draw(valid_non_empty_text),
        "confidence": draw(valid_confidence_strategy),
        "scanner_module": draw(valid_scanner_module_strategy),
        "remediation": draw(valid_non_empty_text),
    }


# --- Strategies for invalid data ---

invalid_severity_too_low_strategy = st.integers(max_value=0)

invalid_severity_too_high_strategy = st.integers(min_value=11)

invalid_confidence_too_low_strategy = st.floats(max_value=-0.01, allow_nan=False, allow_infinity=False)

invalid_confidence_too_high_strategy = st.floats(min_value=1.01, allow_nan=False, allow_infinity=False)

# IDs that do NOT match the pattern ^[A-Z]+-[A-Z]?[0-9]+$
invalid_id_strategy = st.one_of(
    st.just(""),                           # empty string
    st.just("lowercase-1"),                # lowercase letters
    st.just("123-456"),                    # starts with digits
    st.just("ABC"),                        # no hyphen or digits
    st.just("A-"),                         # no digits after hyphen
    st.just("A-BC"),                       # no digits, two letters after hyphen
    st.just("a-1"),                        # lowercase prefix
    st.just("-A1"),                        # starts with hyphen
    st.just("AB-CD-1"),                    # multiple hyphens
    st.text(
        alphabet=string.ascii_lowercase + string.digits + " !@#",
        min_size=1,
        max_size=20,
    ).filter(lambda s: not __import__("re").match(r"^[A-Z]+-[A-Z]?[0-9]+$", s)),
)


# --- Property Tests ---


class TestModelValidationConsistency:
    """Property 2: Model Validation Consistency.

    **Validates: Requirements 10.2, 10.6**
    """

    @given(data=valid_scan_finding_data())
    @settings(max_examples=100)
    def test_valid_scan_finding_constructs_successfully(self, data: dict) -> None:
        """Valid ScanFinding data with severity_score 1-10, confidence 0.0-1.0,
        and id matching ^[A-Z]+-[A-Z]?[0-9]+$ should construct successfully."""
        finding = ScanFinding(**data)

        assert finding.severity_score == data["severity_score"]
        assert finding.confidence == data["confidence"]
        assert finding.id == data["id"]
        assert 1 <= finding.severity_score <= 10
        assert 0.0 <= finding.confidence <= 1.0

    @given(
        invalid_severity=st.one_of(
            invalid_severity_too_low_strategy,
            invalid_severity_too_high_strategy,
        ),
        base_data=valid_scan_finding_data(),
    )
    @settings(max_examples=100)
    def test_invalid_severity_score_raises_validation_error(
        self, invalid_severity: int, base_data: dict
    ) -> None:
        """ScanFinding with severity_score < 1 or > 10 should raise ValidationError."""
        base_data["severity_score"] = invalid_severity

        with pytest.raises(ValidationError):
            ScanFinding(**base_data)

    @given(
        invalid_confidence=st.one_of(
            invalid_confidence_too_low_strategy,
            invalid_confidence_too_high_strategy,
        ),
        base_data=valid_scan_finding_data(),
    )
    @settings(max_examples=100)
    def test_invalid_confidence_raises_validation_error(
        self, invalid_confidence: float, base_data: dict
    ) -> None:
        """ScanFinding with confidence < 0.0 or > 1.0 should raise ValidationError."""
        base_data["confidence"] = invalid_confidence

        with pytest.raises(ValidationError):
            ScanFinding(**base_data)

    @given(
        invalid_id=invalid_id_strategy,
        base_data=valid_scan_finding_data(),
    )
    @settings(max_examples=100)
    def test_invalid_id_pattern_raises_validation_error(
        self, invalid_id: str, base_data: dict
    ) -> None:
        """ScanFinding with id not matching ^[A-Z]+-[A-Z]?[0-9]+$ should raise ValidationError."""
        base_data["id"] = invalid_id

        with pytest.raises(ValidationError):
            ScanFinding(**base_data)
