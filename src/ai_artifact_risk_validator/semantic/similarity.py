"""Cosine similarity scoring against reference corpora.

Wraps ``EmbeddingEngine`` to provide high-level scoring methods:
corpus-based scoring, pairwise similarity, and batch scoring.
Gracefully degrades when ML dependencies are unavailable.
"""

from __future__ import annotations

from typing import Any

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.semantic.embeddings import EmbeddingEngine, get_shared_engine

logger = get_logger(__name__)


class SimilarityScorer:
    """High-level similarity scoring using embeddings.

    Provides convenience methods for comparing text against pre-computed
    corpus embeddings, pairwise comparison, and batch scoring.

    Args:
        engine: An ``EmbeddingEngine`` instance. If ``None``, a default
            engine is created.
    """

    def __init__(self, engine: EmbeddingEngine | None = None) -> None:
        self._engine = engine or get_shared_engine()

    @property
    def is_available(self) -> bool:
        """Whether the underlying embedding engine is available."""
        return self._engine.is_available

    def score_against_corpus(
        self,
        text: str,
        corpus_embeddings: Any,
    ) -> float:
        """Score text against a pre-computed corpus, returning max similarity.

        Args:
            text: The text to score.
            corpus_embeddings: Pre-computed corpus embeddings (numpy array
                of shape ``(N, dim)``).

        Returns:
            Maximum cosine similarity across all corpus entries.
            Returns ``0.0`` if the engine is unavailable or corpus is empty.
        """
        if not self.is_available:
            return 0.0

        import numpy as np

        if not isinstance(corpus_embeddings, np.ndarray) or corpus_embeddings.size == 0:
            return 0.0

        try:
            similarities = self._engine.similarity_to_corpus(text, corpus_embeddings)
            return float(np.max(similarities))
        except RuntimeError:
            return 0.0

    def score_pairwise(self, text_a: str, text_b: str) -> float:
        """Compute cosine similarity between two texts.

        Args:
            text_a: First text.
            text_b: Second text.

        Returns:
            Cosine similarity in ``[-1.0, 1.0]``.
            Returns ``0.0`` if the engine is unavailable.
        """
        if not self.is_available:
            return 0.0

        try:
            return self._engine.similarity(text_a, text_b)
        except RuntimeError:
            return 0.0

    def batch_score(
        self,
        texts: list[str],
        corpus_embeddings: Any,
    ) -> list[float]:
        """Score multiple texts against a corpus, returning max similarity per text.

        Args:
            texts: List of texts to score.
            corpus_embeddings: Pre-computed corpus embeddings (numpy array
                of shape ``(N, dim)``).

        Returns:
            List of maximum cosine similarities, one per input text.
            Returns list of ``0.0`` values if the engine is unavailable.
        """
        if not self.is_available or not texts:
            return [0.0] * len(texts)

        import numpy as np

        if not isinstance(corpus_embeddings, np.ndarray) or corpus_embeddings.size == 0:
            return [0.0] * len(texts)

        try:
            text_embeddings = self._engine.encode(texts)  # (M, dim)
            # (M, dim) @ (dim, N) => (M, N)
            similarity_matrix = np.dot(text_embeddings, corpus_embeddings.T)
            return [float(np.max(row)) for row in similarity_matrix]
        except RuntimeError:
            return [0.0] * len(texts)

    def encode(self, texts: list[str]) -> Any:
        """Encode texts into embedding vectors (pass-through to engine).

        Args:
            texts: List of texts to encode.

        Returns:
            Numpy array of shape ``(len(texts), dim)``, or ``None`` if
            the engine is unavailable.
        """
        if not self.is_available:
            return None

        try:
            return self._engine.encode(texts)
        except RuntimeError:
            return None
