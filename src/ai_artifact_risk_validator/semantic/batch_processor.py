"""Batch embedding processor for efficient GPU/CPU utilization.

Groups text chunks into batches and encodes them in a single pass
through the embedding model, avoiding per-text overhead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.semantic.chunker import chunk_text

if TYPE_CHECKING:
    import numpy as np

    from ai_artifact_risk_validator.semantic.embeddings import EmbeddingEngine

logger = get_logger(__name__)

_DEFAULT_BATCH_SIZE = 64


class BatchProcessor:
    """Encodes many text chunks in efficient batches.

    Args:
        engine: The :class:`EmbeddingEngine` to use for encoding.
        batch_size: Number of texts to encode per model call.
        max_tokens: Maximum tokens per chunk passed to :func:`chunk_text`.
    """

    def __init__(
        self,
        engine: EmbeddingEngine,
        *,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        max_tokens: int = 128,
    ) -> None:
        self._engine = engine
        self._batch_size = batch_size
        self._max_tokens = max_tokens

    def encode_documents(
        self,
        documents: list[str],
    ) -> list[tuple[str, np.ndarray]]:
        """Chunk and encode multiple documents.

        Each document is split with :func:`chunk_text` and the resulting
        chunks are batched for efficient encoding.

        Args:
            documents: List of full document texts.

        Returns:
            List of ``(chunk_text, embedding_vector)`` tuples in
            document order.
        """
        if not documents:
            return []

        # Chunk all documents
        all_chunks: list[str] = []
        for doc in documents:
            chunks = chunk_text(doc, max_tokens=self._max_tokens)
            all_chunks.extend(chunks)

        if not all_chunks:
            return []

        # Batch encode
        all_embeddings = self._batch_encode(all_chunks)

        return list(zip(all_chunks, all_embeddings))

    def _batch_encode(self, texts: list[str]) -> list[np.ndarray]:
        """Encode texts in batches, returning a list of embedding vectors."""
        results: list[np.ndarray] = []
        for start in range(0, len(texts), self._batch_size):
            batch = texts[start : start + self._batch_size]
            embeddings = self._engine.encode(batch)
            for i in range(len(batch)):
                results.append(embeddings[i])
        logger.debug(
            "Batch-encoded texts",
            total=len(texts),
            batches=(len(texts) + self._batch_size - 1) // self._batch_size,
        )
        return results
