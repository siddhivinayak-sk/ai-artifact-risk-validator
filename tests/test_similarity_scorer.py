"""Unit tests for the SimilarityScorer class."""

from __future__ import annotations

from unittest.mock import MagicMock

import numpy as np
import pytest

from ai_artifact_risk_validator.semantic.embeddings import EmbeddingEngine
from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer


@pytest.fixture
def mock_engine() -> EmbeddingEngine:
    """Create a mock EmbeddingEngine."""
    engine = EmbeddingEngine()
    engine._available = True
    engine._model = MagicMock()
    return engine


@pytest.fixture
def unavailable_engine() -> EmbeddingEngine:
    """Create an EmbeddingEngine that is unavailable."""
    engine = EmbeddingEngine()
    engine._available = False
    return engine


@pytest.fixture
def sample_corpus() -> np.ndarray:
    """Create a sample corpus embedding matrix."""
    return np.array(
        [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
            [0.0, 0.0, 1.0],
        ],
        dtype=np.float32,
    )


class TestSimilarityScorerProperties:
    """Test scorer metadata and availability."""

    def test_is_available_delegates_to_engine(self, mock_engine: EmbeddingEngine) -> None:
        scorer = SimilarityScorer(engine=mock_engine)
        assert scorer.is_available is True

    def test_is_unavailable_delegates_to_engine(self, unavailable_engine: EmbeddingEngine) -> None:
        scorer = SimilarityScorer(engine=unavailable_engine)
        assert scorer.is_available is False

    def test_default_engine_created_when_none(self) -> None:
        scorer = SimilarityScorer(engine=None)
        assert scorer._engine is not None


class TestScoreAgainstCorpus:
    """Test corpus-based scoring."""

    def test_returns_max_similarity(
        self, mock_engine: EmbeddingEngine, sample_corpus: np.ndarray
    ) -> None:
        """Should return the maximum cosine similarity across corpus."""
        mock_engine._model.encode.return_value = np.array(
            [[1.0, 0.0, 0.0]], dtype=np.float32
        )  # Matches first corpus entry

        scorer = SimilarityScorer(engine=mock_engine)
        score = scorer.score_against_corpus("test", sample_corpus)
        assert abs(score - 1.0) < 1e-6

    def test_returns_zero_when_unavailable(
        self, unavailable_engine: EmbeddingEngine, sample_corpus: np.ndarray
    ) -> None:
        scorer = SimilarityScorer(engine=unavailable_engine)
        score = scorer.score_against_corpus("test", sample_corpus)
        assert score == 0.0

    def test_returns_zero_for_empty_corpus(self, mock_engine: EmbeddingEngine) -> None:
        scorer = SimilarityScorer(engine=mock_engine)
        empty = np.empty((0, 0), dtype=np.float32)
        score = scorer.score_against_corpus("test", empty)
        assert score == 0.0

    def test_returns_zero_for_non_array_corpus(self, mock_engine: EmbeddingEngine) -> None:
        scorer = SimilarityScorer(engine=mock_engine)
        score = scorer.score_against_corpus("test", "not_an_array")
        assert score == 0.0

    def test_handles_runtime_error_gracefully(self, mock_engine: EmbeddingEngine) -> None:
        """RuntimeError from engine is caught and returns 0.0."""
        mock_engine._model.encode.side_effect = RuntimeError("model failed")

        scorer = SimilarityScorer(engine=mock_engine)
        corpus = np.random.rand(3, 384).astype(np.float32)
        score = scorer.score_against_corpus("test", corpus)
        assert score == 0.0


class TestScorePairwise:
    """Test pairwise text similarity."""

    def test_returns_similarity(self, mock_engine: EmbeddingEngine) -> None:
        """Should return cosine similarity between two texts."""
        # Return identical vectors for both texts
        vec = np.array([[0.5, 0.5, 0.0]], dtype=np.float32)
        mock_engine._model.encode.return_value = np.vstack([vec, vec])

        scorer = SimilarityScorer(engine=mock_engine)
        score = scorer.score_pairwise("hello", "hello")
        assert abs(score - 0.5) < 1e-6  # dot product of [0.5,0.5,0] · [0.5,0.5,0]

    def test_returns_zero_when_unavailable(self, unavailable_engine: EmbeddingEngine) -> None:
        scorer = SimilarityScorer(engine=unavailable_engine)
        score = scorer.score_pairwise("hello", "world")
        assert score == 0.0

    def test_handles_runtime_error(self, mock_engine: EmbeddingEngine) -> None:
        mock_engine._model.encode.side_effect = RuntimeError("fail")
        scorer = SimilarityScorer(engine=mock_engine)
        score = scorer.score_pairwise("hello", "world")
        assert score == 0.0


class TestBatchScore:
    """Test batch scoring of multiple texts."""

    def test_returns_per_text_max(
        self, mock_engine: EmbeddingEngine, sample_corpus: np.ndarray
    ) -> None:
        """Should return max similarity per text."""
        # Two texts: first matches corpus[0], second matches corpus[1]
        mock_engine._model.encode.return_value = np.array(
            [
                [1.0, 0.0, 0.0],
                [0.0, 1.0, 0.0],
            ],
            dtype=np.float32,
        )

        scorer = SimilarityScorer(engine=mock_engine)
        scores = scorer.batch_score(["text1", "text2"], sample_corpus)
        assert len(scores) == 2
        assert abs(scores[0] - 1.0) < 1e-6
        assert abs(scores[1] - 1.0) < 1e-6

    def test_returns_zeros_when_unavailable(
        self, unavailable_engine: EmbeddingEngine, sample_corpus: np.ndarray
    ) -> None:
        scorer = SimilarityScorer(engine=unavailable_engine)
        scores = scorer.batch_score(["a", "b", "c"], sample_corpus)
        assert scores == [0.0, 0.0, 0.0]

    def test_empty_texts(self, mock_engine: EmbeddingEngine, sample_corpus: np.ndarray) -> None:
        scorer = SimilarityScorer(engine=mock_engine)
        scores = scorer.batch_score([], sample_corpus)
        assert scores == []

    def test_empty_corpus(self, mock_engine: EmbeddingEngine) -> None:
        scorer = SimilarityScorer(engine=mock_engine)
        empty = np.empty((0, 0), dtype=np.float32)
        scores = scorer.batch_score(["a", "b"], empty)
        assert scores == [0.0, 0.0]

    def test_handles_runtime_error(
        self, mock_engine: EmbeddingEngine, sample_corpus: np.ndarray
    ) -> None:
        mock_engine._model.encode.side_effect = RuntimeError("fail")
        scorer = SimilarityScorer(engine=mock_engine)
        scores = scorer.batch_score(["a", "b"], sample_corpus)
        assert scores == [0.0, 0.0]


class TestEncode:
    """Test the encode pass-through method."""

    def test_encode_delegates_to_engine(self, mock_engine: EmbeddingEngine) -> None:
        expected = np.random.rand(2, 384).astype(np.float32)
        mock_engine._model.encode.return_value = expected

        scorer = SimilarityScorer(engine=mock_engine)
        result = scorer.encode(["a", "b"])
        assert result is expected

    def test_encode_returns_none_when_unavailable(
        self, unavailable_engine: EmbeddingEngine
    ) -> None:
        scorer = SimilarityScorer(engine=unavailable_engine)
        result = scorer.encode(["a", "b"])
        assert result is None

    def test_encode_handles_runtime_error(self, mock_engine: EmbeddingEngine) -> None:
        mock_engine._model.encode.side_effect = RuntimeError("fail")
        scorer = SimilarityScorer(engine=mock_engine)
        result = scorer.encode(["a", "b"])
        assert result is None
