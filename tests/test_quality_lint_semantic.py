"""Tests for QualityLint semantic ambiguity and readability detection."""

from __future__ import annotations

from unittest.mock import MagicMock

import numpy as np
import pytest

from ai_artifact_risk_validator.models import ArtifactType
from ai_artifact_risk_validator.scanners.quality_lint import (
    QualityLintScanner,
    SemanticQualityAnalyzer,
    _count_syllables,
    _flesch_kincaid_score,
)


@pytest.fixture
def scanner() -> QualityLintScanner:
    return QualityLintScanner()


# ---- Readability helpers ----


class TestCountSyllables:
    def test_one_syllable(self):
        assert _count_syllables("cat") == 1

    def test_two_syllables(self):
        assert _count_syllables("open") == 2

    def test_three_syllables(self):
        assert _count_syllables("banana") == 3

    def test_silent_e(self):
        assert _count_syllables("cake") == 1

    def test_empty_after_strip(self):
        assert _count_syllables("e") == 1


class TestFleschKincaidScore:
    def test_short_text_returns_100(self):
        assert _flesch_kincaid_score("Hello.") == 100.0

    def test_empty_text_returns_100(self):
        assert _flesch_kincaid_score("") == 100.0

    def test_simple_text_high_score(self):
        text = "The cat sat on the mat. " * 10
        score = _flesch_kincaid_score(text)
        assert score > 80  # Very simple text

    def test_complex_text_lower_score(self):
        text = (
            "The unprecedented implementation of multifaceted epistemological "
            "frameworks necessitates comprehensive methodological considerations. "
        ) * 5
        score = _flesch_kincaid_score(text)
        assert score < 40

    def test_score_clamped_to_range(self):
        for text in ["A b c d. " * 20, "Incomprehensibility. " * 20]:
            score = _flesch_kincaid_score(text)
            assert 0.0 <= score <= 100.0


# ---- Readability check via scanner ----


class TestReadabilityCheck:
    def test_no_finding_for_simple_text(self, scanner: QualityLintScanner):
        text = "The cat sat on the mat. " * 10
        findings = scanner._check_readability(text, ArtifactType.PROMPT, "p.md")
        assert len(findings) == 0

    def test_finding_for_complex_text(self, scanner: QualityLintScanner):
        text = (
            "The unprecedented implementation of multifaceted epistemological "
            "frameworks necessitates comprehensive methodological considerations "
            "for establishing interdisciplinary collaboration. "
        ) * 5
        findings = scanner._check_readability(text, ArtifactType.PROMPT, "p.md")
        assert len(findings) == 1
        assert findings[0].id == "P-Q9"
        assert "readability" in findings[0].description.lower()

    def test_no_finding_when_no_risk_id(self, scanner: QualityLintScanner):
        text = "Complex text. " * 30
        # SKILL doesn't have a low_readability risk ID
        findings = scanner._check_readability(text, ArtifactType.SKILL, "s.md")
        assert len(findings) == 0


# ---- SemanticQualityAnalyzer ----


class TestSemanticQualityAnalyzer:
    def test_not_available_without_deps(self):
        analyzer = SemanticQualityAnalyzer()
        # On CI without sentence-transformers, is_available will be False
        # This test just verifies the property doesn't crash
        _ = analyzer.is_available

    def test_score_sentences_empty_when_unavailable(self):
        analyzer = SemanticQualityAnalyzer()
        analyzer._available = False
        result = analyzer.score_sentences(["do whatever you want"])
        assert result == []

    def test_score_sentences_with_mock(self):
        analyzer = SemanticQualityAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._corpus_embeddings = np.array([[1.0, 0.0]])

        # High similarity for vague sentence
        mock_scorer.score_against_corpus.return_value = 0.75

        results = analyzer.score_sentences(["Do whatever seems best for the situation"])
        assert len(results) == 1
        assert results[0][0] == 0  # sentence index
        assert results[0][1] == 0.75

    def test_score_sentences_skips_short(self):
        analyzer = SemanticQualityAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._corpus_embeddings = np.array([[1.0]])
        mock_scorer.score_against_corpus.return_value = 0.90

        results = analyzer.score_sentences(["short"])
        assert results == []

    def test_score_sentences_below_threshold(self):
        analyzer = SemanticQualityAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._corpus_embeddings = np.array([[1.0]])
        mock_scorer.score_against_corpus.return_value = 0.30

        results = analyzer.score_sentences(["Respond with exactly three bullet points in markdown"])
        assert results == []

    def test_score_sentences_handles_error(self):
        analyzer = SemanticQualityAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._corpus_embeddings = np.array([[1.0]])
        mock_scorer.score_against_corpus.side_effect = RuntimeError("boom")

        results = analyzer.score_sentences(["A long enough sentence to pass the length filter"])
        assert results == []

    def test_ensure_loaded_false_when_unavailable(self):
        analyzer = SemanticQualityAnalyzer()
        analyzer._available = False
        assert analyzer._ensure_loaded() is False

    def test_ensure_loaded_true_when_already_loaded(self):
        analyzer = SemanticQualityAnalyzer()
        analyzer._available = True
        analyzer._scorer = MagicMock()
        analyzer._corpus_embeddings = np.array([[1.0]])
        assert analyzer._ensure_loaded() is True


# ---- Semantic ambiguity check via scanner ----


class TestSemanticAmbiguityCheck:
    def test_no_finding_when_unavailable(self, scanner: QualityLintScanner):
        scanner._semantic._available = False
        findings = scanner._check_semantic_ambiguity(
            "Do whatever seems best", ArtifactType.PROMPT, "p.md"
        )
        assert len(findings) == 0

    def test_no_finding_when_no_risk_id(self, scanner: QualityLintScanner):
        findings = scanner._check_semantic_ambiguity("test", ArtifactType.SKILL, "s.md")
        assert len(findings) == 0

    def test_finding_when_semantic_hits(self, scanner: QualityLintScanner):
        mock_analyzer = MagicMock(spec=SemanticQualityAnalyzer)
        mock_analyzer.score_sentences.return_value = [(0, 0.72)]
        scanner._semantic = mock_analyzer

        content = "Do whatever you think is appropriate for this task."
        findings = scanner._check_semantic_ambiguity(content, ArtifactType.PROMPT, "p.md")
        assert len(findings) == 1
        assert findings[0].id == "P-Q8"
        assert "semantic" in findings[0].description.lower()

    def test_no_finding_when_no_hits(self, scanner: QualityLintScanner):
        mock_analyzer = MagicMock(spec=SemanticQualityAnalyzer)
        mock_analyzer.score_sentences.return_value = []
        scanner._semantic = mock_analyzer

        findings = scanner._check_semantic_ambiguity(
            "Return exactly three bullet points.", ArtifactType.PROMPT, "p.md"
        )
        assert len(findings) == 0


# ---- Risk ID coverage ----


class TestNewRiskIds:
    def test_p_q8_in_detected_ids(self, scanner: QualityLintScanner):
        assert "P-Q8" in scanner.detected_risk_ids

    def test_p_q9_in_detected_ids(self, scanner: QualityLintScanner):
        assert "P-Q9" in scanner.detected_risk_ids


# ---- Integration: scan() wires new checks ----


class TestScanIntegration:
    def test_scan_includes_readability(self, scanner: QualityLintScanner):
        # Ensure readability check is called via scan()
        text = (
            "The unprecedented implementation of multifaceted epistemological "
            "frameworks necessitates comprehensive methodological considerations "
            "for establishing interdisciplinary collaboration. "
        ) * 5
        findings = scanner.scan(text, ArtifactType.PROMPT, "p.md")
        readability = [f for f in findings if f.id == "P-Q9"]
        assert len(readability) == 1
