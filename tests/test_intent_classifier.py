"""Tests for the IntentClassifier module."""

from __future__ import annotations

from unittest.mock import MagicMock

import numpy as np

from ai_artifact_risk_validator.semantic.intent_classifier import (
    _INTENT_CORPORA,
    ContentIntent,
    IntentClassifier,
)


class TestContentIntentEnum:
    def test_values(self):
        assert ContentIntent.INSTRUCTION.value == "instruction"
        assert ContentIntent.DOCUMENTATION.value == "documentation"
        assert ContentIntent.EXAMPLE.value == "example"
        assert ContentIntent.CONFIGURATION.value == "configuration"
        assert ContentIntent.CONVERSATION.value == "conversation"
        assert ContentIntent.UNKNOWN.value == "unknown"

    def test_all_values_unique(self):
        values = [e.value for e in ContentIntent]
        assert len(values) == len(set(values))


class TestIntentCorpora:
    def test_corpora_has_all_intents(self):
        for intent in ContentIntent:
            if intent == ContentIntent.UNKNOWN:
                continue
            assert intent in _INTENT_CORPORA
            assert len(_INTENT_CORPORA[intent]) >= 5

    def test_unknown_not_in_corpora(self):
        assert ContentIntent.UNKNOWN not in _INTENT_CORPORA


class TestIntentClassifierUnavailable:
    def test_is_available_no_crash(self):
        clf = IntentClassifier()
        _ = clf.is_available  # Should not crash

    def test_classify_returns_unknown_when_unavailable(self):
        clf = IntentClassifier()
        clf._available = False
        assert clf.classify("Follow these steps carefully") == ContentIntent.UNKNOWN

    def test_classify_lines_empty_when_unavailable(self):
        clf = IntentClassifier()
        clf._available = False
        result = clf.classify_lines(["Follow these steps carefully"])
        assert result == []

    def test_ensure_loaded_false_when_unavailable(self):
        clf = IntentClassifier()
        clf._available = False
        assert clf._ensure_loaded() is False


class TestIntentClassifierWithMock:
    def _make_classifier(self) -> tuple[IntentClassifier, MagicMock]:
        clf = IntentClassifier(min_confidence=0.40)
        clf._available = True
        mock_scorer = MagicMock()
        clf._scorer = mock_scorer

        # Create fake embeddings for each intent
        clf._corpus_embeddings = {
            ContentIntent.INSTRUCTION: np.array([[1.0, 0.0]]),
            ContentIntent.DOCUMENTATION: np.array([[0.0, 1.0]]),
        }
        return clf, mock_scorer

    def test_classify_instruction(self):
        clf, mock_scorer = self._make_classifier()
        # Instruction gets high score, documentation low
        mock_scorer.score_against_corpus.side_effect = [0.80, 0.20]

        result = clf.classify("You must always respond in JSON format")
        assert result == ContentIntent.INSTRUCTION

    def test_classify_documentation(self):
        clf, mock_scorer = self._make_classifier()
        mock_scorer.score_against_corpus.side_effect = [0.20, 0.85]

        result = clf.classify("This section describes the API endpoints")
        assert result == ContentIntent.DOCUMENTATION

    def test_classify_unknown_below_threshold(self):
        clf, mock_scorer = self._make_classifier()
        mock_scorer.score_against_corpus.side_effect = [0.10, 0.15]

        result = clf.classify("Some random text with no clear intent at all")
        assert result == ContentIntent.UNKNOWN

    def test_classify_short_text_returns_unknown(self):
        clf, mock_scorer = self._make_classifier()
        result = clf.classify("hi")
        assert result == ContentIntent.UNKNOWN
        mock_scorer.score_against_corpus.assert_not_called()

    def test_classify_handles_scorer_error(self):
        clf, mock_scorer = self._make_classifier()
        mock_scorer.score_against_corpus.side_effect = RuntimeError("boom")

        result = clf.classify("A valid instruction that should be classified")
        assert result == ContentIntent.UNKNOWN

    def test_classify_lines_returns_results(self):
        clf, mock_scorer = self._make_classifier()
        # Two lines, first is instruction (high), second is documentation (high)
        mock_scorer.score_against_corpus.side_effect = [
            0.80,
            0.20,  # line 0: instruction=0.80, doc=0.20
            0.15,
            0.85,  # line 1: instruction=0.15, doc=0.85
        ]

        results = clf.classify_lines(
            [
                "Always respond with JSON output only",
                "This document describes the deployment process",
            ]
        )
        assert len(results) == 2
        assert results[0][1] == ContentIntent.INSTRUCTION
        assert results[1][1] == ContentIntent.DOCUMENTATION

    def test_classify_lines_skips_short(self):
        clf, mock_scorer = self._make_classifier()
        results = clf.classify_lines(["hi", ""])
        assert results == []

    def test_classify_lines_handles_error(self):
        clf, mock_scorer = self._make_classifier()
        mock_scorer.score_against_corpus.side_effect = RuntimeError("fail")

        results = clf.classify_lines(["A long enough sentence for classification testing"])
        assert results == []

    def test_ensure_loaded_returns_true_when_loaded(self):
        clf, _ = self._make_classifier()
        assert clf._ensure_loaded() is True

    def test_min_confidence_respected(self):
        clf, mock_scorer = self._make_classifier()
        clf._min_confidence = 0.90
        mock_scorer.score_against_corpus.side_effect = [0.80, 0.50]

        result = clf.classify("Follow these steps to complete the task")
        assert result == ContentIntent.UNKNOWN  # 0.80 < 0.90 threshold
