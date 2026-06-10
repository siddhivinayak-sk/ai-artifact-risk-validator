"""Embedding model management with graceful degradation.

Uses sentence-transformers with a lightweight model for fast inference.
Falls back gracefully when ML dependencies are unavailable — all methods
raise ``RuntimeError`` and ``is_available`` returns ``False``.
"""

from __future__ import annotations

import hashlib
import threading
from typing import TYPE_CHECKING, Any

from ai_artifact_risk_validator._internal.logging import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    import numpy as np

logger = get_logger(__name__)

# Default embedding model — 384-dim, ~80MB, fast CPU inference
_DEFAULT_MODEL = "all-MiniLM-L6-v2"


class EmbeddingEngine:
    """Manages embedding model lifecycle and provides text encoding.

    Uses ``sentence-transformers`` with a lightweight model for fast inference.
    Supports graceful degradation to unavailable state when ML dependencies
    are not installed.

    Args:
        model_name: Name of the sentence-transformers model to use.
            Defaults to ``all-MiniLM-L6-v2`` (384-dim, ~80MB).
        cache_dir: Optional directory for model file caching.
    """

    def __init__(
        self,
        model_name: str | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        self._model_name: str = model_name or _DEFAULT_MODEL
        self._model: Any = None
        self._cache_dir = cache_dir
        self._available: bool | None = None

    @property
    def model_name(self) -> str:
        """Return the configured model name."""
        return self._model_name

    @property
    def is_available(self) -> bool:
        """Check if sentence-transformers is installed.

        Lazily probes for the import on first access and caches the result.
        """
        if self._available is None:
            try:
                import sentence_transformers  # noqa: F401

                self._available = True
            except ImportError:
                self._available = False
                logger.info(
                    "sentence-transformers not installed; semantic features disabled."
                    " Install with: pip install ai-artifact-risk-validator[ml]"
                )
        return self._available

    def _get_model(self) -> Any:
        """Lazily load the sentence-transformers model.

        Returns:
            A ``SentenceTransformer`` model instance.

        Raises:
            RuntimeError: If sentence-transformers is not installed.
        """
        if self._model is not None:
            return self._model

        if not self.is_available:
            msg = (
                "sentence-transformers is required for semantic analysis. "
                "Install with: pip install ai-artifact-risk-validator[ml]"
            )
            raise RuntimeError(msg)

        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(
            self._model_name,
            cache_folder=str(self._cache_dir) if self._cache_dir else None,
        )
        logger.info("Loaded embedding model", model_name=self._model_name)
        return self._model

    def encode(self, texts: list[str]) -> np.ndarray:
        """Encode texts into normalized embedding vectors.

        Args:
            texts: List of text strings to encode.

        Returns:
            Numpy array of shape ``(len(texts), dim)`` with L2-normalized
            embeddings.

        Raises:
            RuntimeError: If sentence-transformers is not installed.
        """
        import numpy as np

        if not texts:
            return np.empty((0, 0), dtype=np.float32)

        model = self._get_model()
        embeddings: np.ndarray = model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return embeddings

    def similarity(self, text_a: str, text_b: str) -> float:
        """Compute cosine similarity between two texts.

        Args:
            text_a: First text.
            text_b: Second text.

        Returns:
            Cosine similarity in range ``[-1.0, 1.0]``.

        Raises:
            RuntimeError: If sentence-transformers is not installed.
        """
        import numpy as np

        embeddings = self.encode([text_a, text_b])
        return float(np.dot(embeddings[0], embeddings[1]))

    def similarity_to_corpus(
        self,
        text: str,
        corpus_embeddings: np.ndarray,
    ) -> np.ndarray:
        """Compute similarity of a text against a pre-encoded corpus.

        Args:
            text: The query text to compare.
            corpus_embeddings: Pre-computed corpus embeddings of shape
                ``(N, dim)``.

        Returns:
            Numpy array of shape ``(N,)`` with cosine similarities.

        Raises:
            RuntimeError: If sentence-transformers is not installed.
        """
        import numpy as np

        text_embedding = self.encode([text])  # (1, dim)
        result: np.ndarray[tuple[Any, ...], np.dtype[Any]] = np.dot(
            corpus_embeddings,
            text_embedding.T,
        ).flatten()
        return result

    @staticmethod
    def text_hash(text: str) -> str:
        """Compute SHA-256 hex digest of text for cache keying.

        Args:
            text: The text to hash.

        Returns:
            64-character hex string.
        """
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- Module-level singleton ---
_shared_engine: EmbeddingEngine | None = None
_engine_lock = threading.Lock()


def get_shared_engine() -> EmbeddingEngine:
    """Return a module-level singleton ``EmbeddingEngine``.

    Ensures the model is loaded at most once per process, avoiding
    repeated weight loading when multiple scanners use embeddings.
    Thread-safe via double-checked locking.
    """
    global _shared_engine
    if _shared_engine is None:
        with _engine_lock:
            if _shared_engine is None:
                _shared_engine = EmbeddingEngine()
    return _shared_engine
