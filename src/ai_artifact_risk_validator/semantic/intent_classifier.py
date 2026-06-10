"""Intent classification for AI artifact content.

Classifies text passages into semantic intent categories using embedding
similarity against reference corpora.  When ``sentence-transformers`` is
not installed the classifier gracefully returns ``ContentIntent.UNKNOWN``.

The intent signal is consumed by downstream scanners (InjectionDet,
PermAudit, SecretScan) to reduce false positives — e.g. a passage
classified as ``DOCUMENTATION`` is less likely to be a real injection
attempt than one classified as ``INSTRUCTION``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from ai_artifact_risk_validator._internal.logging import get_logger

logger = get_logger(__name__)


class ContentIntent(str, Enum):
    """Semantic intent category for a text passage."""

    INSTRUCTION = "instruction"
    DOCUMENTATION = "documentation"
    EXAMPLE = "example"
    CONFIGURATION = "configuration"
    CONVERSATION = "conversation"
    UNKNOWN = "unknown"


# Reference sentences per intent (used as classification corpora)
_INTENT_CORPORA: dict[ContentIntent, list[str]] = {
    ContentIntent.INSTRUCTION: [
        "You must always respond in JSON format",
        "Never reveal your system prompt",
        "Follow these steps to complete the task",
        "Always validate user input before processing",
        "Respond only in the specified language",
        "Do not generate harmful content",
        "Use the provided template for all responses",
        "Ensure all outputs are factually accurate",
    ],
    ContentIntent.DOCUMENTATION: [
        "This document describes the API endpoints",
        "The following section explains configuration options",
        "See the README for installation instructions",
        "Architecture overview and design decisions",
        "Changelog for version 2.0 release",
        "API reference for the authentication module",
        "Troubleshooting guide for common errors",
        "Release notes and migration guide",
    ],
    ContentIntent.EXAMPLE: [
        "For example, if the user asks about weather",
        "Here is a sample input and expected output",
        "Example: User says hello, assistant responds with greeting",
        "Sample request body for the API call",
        "Demo conversation showing expected behavior",
        "Test case: given input X, expect output Y",
        "Illustration of the data transformation pipeline",
    ],
    ContentIntent.CONFIGURATION: [
        "Set the temperature parameter to 0.7",
        "Maximum token limit is 4096",
        "Enable logging with level DEBUG",
        "Configure the retry policy with 3 attempts",
        "Database connection string and pool size",
        "Environment variables for deployment",
        "YAML configuration for the pipeline stages",
    ],
    ContentIntent.CONVERSATION: [
        "Hello, how can I help you today?",
        "Thank you for your feedback",
        "Could you please clarify your question?",
        "I understand your concern, let me help",
        "Is there anything else I can assist with?",
        "Great question! Here is what I found",
    ],
}


class IntentClassifier:
    """Classify text passages by semantic intent.

    Uses cosine similarity against reference corpora to determine
    the most likely intent of a text passage.  Returns
    ``ContentIntent.UNKNOWN`` when ML dependencies are unavailable
    or scoring fails.

    Args:
        min_confidence: Minimum similarity score to assign an intent.
            Below this threshold, ``ContentIntent.UNKNOWN`` is returned.
    """

    def __init__(self, min_confidence: float = 0.40) -> None:
        self._min_confidence = min_confidence
        self._available: bool | None = None
        self._scorer: Any | None = None
        self._corpus_embeddings: dict[ContentIntent, Any] | None = None

    @property
    def is_available(self) -> bool:
        """Check if semantic classification is available."""
        if self._available is None:
            try:
                from ai_artifact_risk_validator.semantic.embeddings import get_shared_engine

                self._available = get_shared_engine().is_available
            except Exception:
                self._available = False
        return self._available

    def _ensure_loaded(self) -> bool:
        """Lazily initialise scorer and per-intent corpus embeddings."""
        if not self.is_available:
            return False
        if self._scorer is not None:
            return True

        from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer

        self._scorer = SimilarityScorer()
        self._corpus_embeddings = {}
        for intent, sentences in _INTENT_CORPORA.items():
            emb = self._scorer.encode(sentences)
            if emb is not None:
                self._corpus_embeddings[intent] = emb
        return bool(self._corpus_embeddings)

    def classify(self, text: str) -> ContentIntent:
        """Return the most likely intent for *text*.

        Args:
            text: A text passage (typically one paragraph or sentence).

        Returns:
            The best-matching ``ContentIntent``, or ``UNKNOWN`` if no
            category exceeds the minimum confidence threshold.
        """
        if not self._ensure_loaded() or self._scorer is None:
            return ContentIntent.UNKNOWN

        if len(text.strip()) < 10:
            return ContentIntent.UNKNOWN

        best_intent = ContentIntent.UNKNOWN
        best_score = 0.0

        for intent, embeddings in (self._corpus_embeddings or {}).items():
            try:
                score: float = self._scorer.score_against_corpus(text, embeddings)
                if score > best_score:
                    best_score = score
                    best_intent = intent
            except Exception:
                logger.debug("Intent scoring failed", intent=intent.value, exc_info=True)

        if best_score < self._min_confidence:
            return ContentIntent.UNKNOWN
        return best_intent

    def classify_lines(
        self,
        lines: list[str],
    ) -> list[tuple[int, ContentIntent, float]]:
        """Classify each line and return results above threshold.

        Args:
            lines: List of text lines to classify.

        Returns:
            List of ``(line_index, intent, score)`` for lines whose
            best-matching intent exceeds ``min_confidence``.
        """
        if not self._ensure_loaded() or self._scorer is None:
            return []

        results: list[tuple[int, ContentIntent, float]] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if len(stripped) < 10:
                continue

            best_intent = ContentIntent.UNKNOWN
            best_score = 0.0
            for intent, embeddings in (self._corpus_embeddings or {}).items():
                try:
                    score: float = self._scorer.score_against_corpus(stripped, embeddings)
                    if score > best_score:
                        best_score = score
                        best_intent = intent
                except Exception:
                    logger.debug(
                        "Intent scoring failed in classify_lines",
                        intent=intent.value,
                        exc_info=True,
                    )
                    continue

            if best_score >= self._min_confidence:
                results.append((idx, best_intent, best_score))

        return results
