"""Tests for the LLM meta-analyzer."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ai_artifact_risk_validator.llm.budget import TokenBudget
from ai_artifact_risk_validator.llm.meta_analyzer import LLMMetaAnalyzer, _build_enrichment_prompt
from ai_artifact_risk_validator.llm.provider import LLMProvider
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
    severity: SeverityLabel = SeverityLabel.HIGH,
    score: int = 8,
) -> ScanFinding:
    from datetime import datetime

    return ScanFinding(
        id=risk_id,
        artifact_type=ArtifactType.PROMPT,
        artifact_path="test.md",
        severity_score=score,
        severity_label=severity,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        category=RiskCategory.SECURITY,
        title="Test Finding",
        description="Test description",
        location=FindingLocation(line=10),
        evidence="some evidence",
        confidence=0.90,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Fix it",
        timestamp=datetime(2025, 1, 1),
    )


class TestLLMProviderDisabled:
    def test_is_available_false_when_disabled(self) -> None:
        provider = LLMProvider(allow_llm=False)
        assert provider.is_available() is False

    def test_complete_returns_empty_when_disabled(self) -> None:
        provider = LLMProvider(allow_llm=False)
        result = provider.complete("test message")
        assert result == {"explanation": "", "remediation_detail": ""}


class TestLLMProviderEnabled:
    def test_is_available_false_when_openai_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        monkeypatch.setitem(sys.modules, "openai", None)  # type: ignore[arg-type]
        provider = LLMProvider(allow_llm=True)
        assert provider.is_available() is False


class TestTokenBudget:
    def test_initial_remaining_equals_max(self) -> None:
        budget = TokenBudget(max_tokens=1000)
        assert budget.remaining == 1000

    def test_is_not_exhausted_initially(self) -> None:
        budget = TokenBudget(max_tokens=1000)
        assert budget.is_exhausted is False

    def test_record_usage_reduces_remaining(self) -> None:
        budget = TokenBudget(max_tokens=1000)
        budget.record_usage(200)
        assert budget.remaining == 800

    def test_is_exhausted_after_full_consumption(self) -> None:
        budget = TokenBudget(max_tokens=100)
        budget.record_usage(100)
        assert budget.is_exhausted is True

    def test_remaining_clamped_to_zero(self) -> None:
        budget = TokenBudget(max_tokens=100)
        budget.record_usage(200)
        assert budget.remaining == 0

    def test_estimate_tokens_nonzero(self) -> None:
        budget = TokenBudget()
        estimate = budget.estimate_tokens("Hello world, this is a test message.")
        assert estimate > 0

    def test_can_afford_within_budget(self) -> None:
        budget = TokenBudget(max_tokens=10_000)
        assert budget.can_afford("short text") is True

    def test_cannot_afford_when_exhausted(self) -> None:
        budget = TokenBudget(max_tokens=0)
        assert budget.can_afford("any text") is False

    def test_reset_clears_consumption(self) -> None:
        budget = TokenBudget(max_tokens=1000)
        budget.record_usage(500)
        budget.reset()
        assert budget.remaining == 1000


class TestLLMMetaAnalyzer:
    @pytest.fixture
    def disabled_provider(self) -> LLMProvider:
        return LLMProvider(allow_llm=False)

    def test_enrich_noop_when_unavailable(self, disabled_provider: LLMProvider) -> None:
        analyzer = LLMMetaAnalyzer(disabled_provider)
        findings = [_make_finding()]
        result = analyzer.enrich(findings)
        # Findings unchanged
        assert result[0].explanation is None
        assert result[0].remediation_detail is None

    def test_enrich_skips_low_severity(self) -> None:
        mock_provider = MagicMock(spec=LLMProvider)
        mock_provider.is_available.return_value = True
        mock_provider.complete.return_value = {
            "explanation": "enriched",
            "remediation_detail": "fix",
        }
        analyzer = LLMMetaAnalyzer(mock_provider)

        low_finding = _make_finding(severity=SeverityLabel.LOW, score=2)
        result = analyzer.enrich([low_finding])

        # Low severity should NOT be enriched
        mock_provider.complete.assert_not_called()
        assert result[0].explanation is None

    def test_enrich_enriches_high_severity(self) -> None:
        mock_provider = MagicMock(spec=LLMProvider)
        mock_provider.is_available.return_value = True
        mock_provider.complete.return_value = {
            "explanation": "This is risky because...",
            "remediation_detail": "Fix by doing X",
        }
        budget = TokenBudget(max_tokens=10_000)
        analyzer = LLMMetaAnalyzer(mock_provider, budget)

        high_finding = _make_finding(severity=SeverityLabel.HIGH, score=8)
        result = analyzer.enrich([high_finding])

        mock_provider.complete.assert_called_once()
        assert result[0].explanation == "This is risky because..."
        assert result[0].remediation_detail == "Fix by doing X"

    def test_enrich_respects_budget(self) -> None:
        mock_provider = MagicMock(spec=LLMProvider)
        mock_provider.is_available.return_value = True
        mock_provider.complete.return_value = {
            "explanation": "test",
            "remediation_detail": "fix",
        }
        # Tiny budget that can't afford any calls
        budget = TokenBudget(max_tokens=0)
        analyzer = LLMMetaAnalyzer(mock_provider, budget)

        finding = _make_finding(severity=SeverityLabel.CRITICAL, score=10)
        result = analyzer.enrich([finding])

        # Budget exhausted; complete should not be called
        mock_provider.complete.assert_not_called()
        assert result[0].explanation is None


class TestBuildEnrichmentPrompt:
    def test_prompt_contains_risk_id(self) -> None:
        finding = _make_finding(risk_id="P-S7")
        prompt = _build_enrichment_prompt(finding)
        assert "P-S7" in prompt

    def test_prompt_contains_severity(self) -> None:
        finding = _make_finding(severity=SeverityLabel.CRITICAL)
        prompt = _build_enrichment_prompt(finding)
        # The prompt uses severity_label.value which is "Critical" (not "CRITICAL")
        assert "CRITICAL" in prompt or "Critical" in prompt

    def test_prompt_contains_adversarial_warning(self) -> None:
        finding = _make_finding()
        prompt = _build_enrichment_prompt(finding)
        # Must warn about adversarial content to prevent jailbreak
        assert "adversarial" in prompt.lower() or "do not follow" in prompt.lower()

    def test_prompt_evidence_truncated(self) -> None:
        long_evidence = "x" * 1000
        finding = _make_finding()
        finding.evidence = long_evidence  # type: ignore[attr-defined]
        prompt = _build_enrichment_prompt(finding)
        # Evidence should be truncated to 500 chars
        assert len(prompt) < 2000
