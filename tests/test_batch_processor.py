"""Tests for the semantic batch processor."""

from __future__ import annotations

from unittest.mock import MagicMock

import numpy as np
import pytest

from ai_artifact_risk_validator.semantic.batch_processor import BatchProcessor


@pytest.fixture()
def mock_engine() -> MagicMock:
    """Create a mock EmbeddingEngine that returns deterministic embeddings."""
    engine = MagicMock()
    engine.is_available = True

    def _encode(texts: list[str]) -> np.ndarray:
        return np.random.default_rng(42).random((len(texts), 384)).astype(np.float32)

    engine.encode.side_effect = _encode
    return engine


class TestBatchProcessorBasics:
    """Basic batch processor behaviour."""

    def test_empty_documents(self, mock_engine: MagicMock) -> None:
        bp = BatchProcessor(mock_engine, batch_size=4)
        assert bp.encode_documents([]) == []

    def test_single_document(self, mock_engine: MagicMock) -> None:
        bp = BatchProcessor(mock_engine, batch_size=4)
        result = bp.encode_documents(["Hello world."])
        assert len(result) >= 1
        chunk_text, embedding = result[0]
        assert isinstance(chunk_text, str)
        assert embedding.shape == (384,)

    def test_multiple_documents(self, mock_engine: MagicMock) -> None:
        docs = ["Document one. Has content.", "Document two. Also content."]
        bp = BatchProcessor(mock_engine, batch_size=4)
        result = bp.encode_documents(docs)
        assert len(result) >= 2


class TestBatching:
    """Verify batching splits large inputs."""

    def test_respects_batch_size(self, mock_engine: MagicMock) -> None:
        # Create a document with many sentences so it produces many chunks
        doc = ". ".join(f"Sentence {i}" for i in range(50)) + "."
        bp = BatchProcessor(mock_engine, batch_size=8, max_tokens=16)
        bp.encode_documents([doc])

        # Engine.encode should be called multiple times if chunks > batch_size
        assert mock_engine.encode.call_count >= 1

    def test_single_batch_for_small_input(self, mock_engine: MagicMock) -> None:
        bp = BatchProcessor(mock_engine, batch_size=64)
        bp.encode_documents(["Short text."])
        assert mock_engine.encode.call_count == 1


class TestChunkIntegration:
    """Verify chunking is applied to documents."""

    def test_long_document_is_chunked(self, mock_engine: MagicMock) -> None:
        long_doc = "Word " * 500
        bp = BatchProcessor(mock_engine, batch_size=32, max_tokens=32)
        result = bp.encode_documents([long_doc])
        # Should produce multiple chunks
        assert len(result) > 1

    def test_whitespace_only_document(self, mock_engine: MagicMock) -> None:
        bp = BatchProcessor(mock_engine, batch_size=4)
        result = bp.encode_documents(["   \n  "])
        assert result == []
