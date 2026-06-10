"""Reference corpus management for semantic similarity scoring.

Loads JSON corpus files containing reference sentences for injection,
jailbreak, bias, and guardrail-weakening detection.  Pre-computes and
caches corpus embeddings on first use for fast repeated scoring.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.semantic.embeddings import EmbeddingEngine

if TYPE_CHECKING:
    import numpy as np

logger = get_logger(__name__)

# Directory containing the built-in corpus JSON files
_CORPORA_DIR = Path(__file__).parent / "corpora"

# Known corpus names mapped to their JSON filenames
_CORPUS_FILES: dict[str, str] = {
    "injection": "injection_corpus.json",
    "jailbreak": "jailbreak_corpus.json",
    "bias": "bias_corpus.json",
    "guardrail_weakening": "guardrail_weakening_corpus.json",
}


class CorpusManager:
    """Manages reference corpora for semantic similarity detection.

    Loads corpus sentences from JSON files, computes their embeddings
    using the provided ``EmbeddingEngine``, and caches the result for
    the lifetime of the manager instance.

    Args:
        engine: An ``EmbeddingEngine`` for computing embeddings.
            If ``None``, a default engine is created.
        corpora_dir: Optional directory override for corpus files.
            Defaults to the built-in ``corpora/`` directory.
    """

    def __init__(
        self,
        engine: EmbeddingEngine | None = None,
        corpora_dir: Path | None = None,
    ) -> None:
        self._engine = engine or EmbeddingEngine()
        self._corpora_dir = corpora_dir or _CORPORA_DIR
        self._sentences: dict[str, list[str]] = {}
        self._embeddings: dict[str, np.ndarray[tuple[Any, ...], np.dtype[Any]]] = {}

    @property
    def available_corpora(self) -> list[str]:
        """Return the list of known corpus names."""
        return list(_CORPUS_FILES.keys())

    def load_corpus(self, corpus_name: str) -> list[str]:
        """Load sentences from a named corpus JSON file.

        The JSON file must contain a top-level list of strings.

        Args:
            corpus_name: One of the known corpus names
                (``injection``, ``jailbreak``, ``bias``,
                ``guardrail_weakening``).

        Returns:
            List of corpus sentences.

        Raises:
            ValueError: If the corpus name is unknown.
            FileNotFoundError: If the corpus JSON file does not exist.
        """
        if corpus_name in self._sentences:
            return self._sentences[corpus_name]

        filename = _CORPUS_FILES.get(corpus_name)
        if filename is None:
            msg = f"Unknown corpus '{corpus_name}'. Available: {list(_CORPUS_FILES.keys())}"
            raise ValueError(msg)

        corpus_path = self._corpora_dir / filename
        if not corpus_path.exists():
            msg = f"Corpus file not found: {corpus_path}"
            raise FileNotFoundError(msg)

        data = json.loads(corpus_path.read_text(encoding="utf-8"))
        if not isinstance(data, list) or not all(isinstance(s, str) for s in data):
            msg = f"Corpus file must contain a JSON list of strings: {corpus_path}"
            raise ValueError(msg)

        self._sentences[corpus_name] = data
        logger.info(
            "Loaded corpus",
            corpus_name=corpus_name,
            num_sentences=len(data),
        )
        return data

    def get_corpus_embeddings(self, corpus_name: str) -> np.ndarray:
        """Get pre-computed embeddings for a named corpus.

        Computes and caches embeddings on first call.

        Args:
            corpus_name: One of the known corpus names.

        Returns:
            Numpy array of shape ``(N, dim)`` with L2-normalized embeddings.

        Raises:
            ValueError: If the corpus name is unknown.
            FileNotFoundError: If the corpus JSON file does not exist.
            RuntimeError: If the embedding engine is unavailable.
        """
        if corpus_name in self._embeddings:
            return self._embeddings[corpus_name]

        sentences = self.load_corpus(corpus_name)
        embeddings = self._engine.encode(sentences)
        self._embeddings[corpus_name] = embeddings
        logger.info(
            "Computed corpus embeddings",
            corpus_name=corpus_name,
            shape=str(embeddings.shape),
        )
        return embeddings

    def clear_cache(self) -> None:
        """Clear all cached sentences and embeddings."""
        self._sentences.clear()
        self._embeddings.clear()
