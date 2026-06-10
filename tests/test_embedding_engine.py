"""Unit tests for the EmbeddingEngine class."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ai_artifact_risk_validator.semantic.embeddings import EmbeddingEngine


class TestEmbeddingEngineProperties:
    """Test EmbeddingEngine metadata and configuration."""

    def test_default_model_name(self) -> None:
        engine = EmbeddingEngine()
        assert engine.model_name == "all-MiniLM-L6-v2"

    def test_custom_model_name(self) -> None:
        engine = EmbeddingEngine(model_name="paraphrase-MiniLM-L3-v2")
        assert engine.model_name == "paraphrase-MiniLM-L3-v2"

    def test_text_hash_deterministic(self) -> None:
        h1 = EmbeddingEngine.text_hash("hello world")
        h2 = EmbeddingEngine.text_hash("hello world")
        assert h1 == h2
        assert len(h1) == 64

    def test_text_hash_different_inputs(self) -> None:
        h1 = EmbeddingEngine.text_hash("hello")
        h2 = EmbeddingEngine.text_hash("world")
        assert h1 != h2


class TestEmbeddingEngineAvailability:
    """Test graceful degradation when sentence-transformers is missing."""

    def test_is_available_when_installed(self) -> None:
        """When sentence_transformers can be imported, is_available is True."""
        engine = EmbeddingEngine()
        # We can't guarantee the library is installed in the test env,
        # so we mock the import check.
        with patch.dict("sys.modules", {"sentence_transformers": MagicMock()}):
            engine._available = None  # Reset cached value
            assert engine.is_available is True

    def test_is_available_when_not_installed(self) -> None:
        """When sentence_transformers is not importable, is_available is False."""
        engine = EmbeddingEngine()
        engine._available = None  # Reset cached value

        import builtins

        original_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "sentence_transformers":
                raise ImportError("No module named 'sentence_transformers'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            assert engine.is_available is False

    def test_is_available_cached(self) -> None:
        """is_available result is cached after first probe."""
        engine = EmbeddingEngine()
        engine._available = True
        assert engine.is_available is True  # Uses cached value

        engine._available = False
        assert engine.is_available is False  # Uses cached value


class TestEmbeddingEngineEncode:
    """Test encoding methods with mocked models."""

    def test_encode_empty_list(self) -> None:
        """Encoding empty list returns empty array even when unavailable."""
        engine = EmbeddingEngine()
        engine._available = False

        # Empty list short-circuits without checking availability
        result = engine.encode([])
        assert result.shape == (0, 0)

    def test_encode_raises_when_unavailable(self) -> None:
        """encode() raises RuntimeError when ML deps are missing."""
        engine = EmbeddingEngine()
        engine._available = False

        with pytest.raises(RuntimeError, match="sentence-transformers is required"):
            engine.encode(["test text"])

    def test_get_model_raises_when_unavailable(self) -> None:
        """_get_model() raises RuntimeError when ML deps are missing."""
        engine = EmbeddingEngine()
        engine._available = False

        with pytest.raises(RuntimeError, match="sentence-transformers is required"):
            engine._get_model()

    def test_similarity_raises_when_unavailable(self) -> None:
        """similarity() raises RuntimeError when ML deps are missing."""
        engine = EmbeddingEngine()
        engine._available = False

        with pytest.raises(RuntimeError, match="sentence-transformers is required"):
            engine.similarity("hello", "world")

    def test_similarity_to_corpus_raises_when_unavailable(self) -> None:
        """similarity_to_corpus() raises RuntimeError when unavailable."""
        engine = EmbeddingEngine()
        engine._available = False

        import numpy as np

        corpus = np.random.rand(5, 384).astype(np.float32)
        with pytest.raises(RuntimeError, match="sentence-transformers is required"):
            engine.similarity_to_corpus("test", corpus)

    def test_encode_with_mock_model(self) -> None:
        """encode() delegates to the model when available."""
        import numpy as np

        engine = EmbeddingEngine()
        engine._available = True

        mock_model = MagicMock()
        expected = np.random.rand(2, 384).astype(np.float32)
        mock_model.encode.return_value = expected
        engine._model = mock_model

        result = engine.encode(["hello", "world"])
        mock_model.encode.assert_called_once_with(
            ["hello", "world"],
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        assert result is expected

    def test_similarity_with_mock_model(self) -> None:
        """similarity() returns cosine similarity between two texts."""
        import numpy as np

        engine = EmbeddingEngine()
        engine._available = True

        mock_model = MagicMock()
        # Return two identical normalized vectors → similarity = 1.0
        vec = np.array([[1.0, 0.0, 0.0]], dtype=np.float32)
        mock_model.encode.return_value = np.vstack([vec, vec])
        engine._model = mock_model

        result = engine.similarity("same", "same")
        assert abs(result - 1.0) < 1e-6

    def test_similarity_to_corpus_with_mock(self) -> None:
        """similarity_to_corpus() returns per-entry similarities."""
        import numpy as np

        engine = EmbeddingEngine()
        engine._available = True

        mock_model = MagicMock()
        query_vec = np.array([[1.0, 0.0, 0.0]], dtype=np.float32)
        mock_model.encode.return_value = query_vec
        engine._model = mock_model

        corpus = np.array(
            [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
            dtype=np.float32,
        )

        result = engine.similarity_to_corpus("test", corpus)
        assert result.shape == (3,)
        assert abs(result[0] - 1.0) < 1e-6  # Same direction
        assert abs(result[1]) < 1e-6  # Orthogonal
        assert abs(result[2]) < 1e-6  # Orthogonal

    def test_encode_empty_returns_empty_when_available(self) -> None:
        """encode([]) returns empty array shape (0, 0) even when available."""
        engine = EmbeddingEngine()
        engine._available = True
        engine._model = MagicMock()  # Model exists but won't be called

        result = engine.encode([])
        assert result.shape == (0, 0)
        engine._model.encode.assert_not_called()
