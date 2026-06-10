"""SQLite-backed embedding cache for persisting computed embeddings.

Stores embeddings keyed by SHA-256(model_name + text) with configurable
TTL. This avoids re-computing embeddings for unchanged content across
runs, providing significant speedup on repeated scans.
"""

from __future__ import annotations

import hashlib
import io
import sqlite3
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ai_artifact_risk_validator._internal.logging import get_logger

if TYPE_CHECKING:
    import numpy as np

logger = get_logger(__name__)

# Default cache location
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "ai-artifact-validator"
_DEFAULT_DB_NAME = "embeddings.db"
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 days


class EmbeddingCache:
    """SQLite-backed cache for embedding vectors.

    Stores serialized numpy arrays keyed by a SHA-256 hash of
    ``(model_name, text)``.  Entries expire after a configurable TTL.

    If ``cache_dir`` is ``None``, caching is disabled and all operations
    are safe no-ops.

    Args:
        cache_dir: Directory for the SQLite database file.  If ``None``,
            caching is disabled.
        ttl_seconds: Time-to-live for cache entries in seconds.
            Defaults to 7 days.
    """

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        if cache_dir is not None:
            self._cache_dir: Path | None = Path(cache_dir)
        else:
            self._cache_dir = None
        self._ttl_seconds = ttl_seconds
        self._conn: sqlite3.Connection | None = None

    @property
    def enabled(self) -> bool:
        """Whether caching is enabled."""
        return self._cache_dir is not None

    def _get_connection(self) -> sqlite3.Connection | None:
        """Lazily open the SQLite connection and create the table.

        Returns:
            A ``sqlite3.Connection`` or ``None`` if caching is disabled.
        """
        if self._cache_dir is None:
            return None

        if self._conn is not None:
            return self._conn

        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = self._cache_dir / _DEFAULT_DB_NAME
            self._conn = sqlite3.connect(str(db_path), timeout=5.0)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS embeddings ("
                "  cache_key TEXT PRIMARY KEY,"
                "  embedding BLOB NOT NULL,"
                "  created_at REAL NOT NULL"
                ")"
            )
            self._conn.commit()
        except (sqlite3.Error, OSError) as exc:
            logger.warning("Failed to initialize embedding cache", error=str(exc))
            self._conn = None

        return self._conn

    @staticmethod
    def compute_key(model_name: str, text: str) -> str:
        """Compute a cache key from model name and text.

        Args:
            model_name: The embedding model name.
            text: The text that was embedded.

        Returns:
            64-character hex SHA-256 digest.
        """
        key_material = f"{model_name}\x00{text}"
        return hashlib.sha256(key_material.encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> np.ndarray | None:
        """Retrieve a cached embedding by key.

        Returns ``None`` on cache miss, expiry, corruption, or if caching
        is disabled.

        Args:
            cache_key: The SHA-256 cache key.

        Returns:
            Numpy array of the embedding, or ``None``.
        """
        conn = self._get_connection()
        if conn is None:
            return None

        try:
            cursor = conn.execute(
                "SELECT embedding, created_at FROM embeddings WHERE cache_key = ?",
                (cache_key,),
            )
            row = cursor.fetchone()
            if row is None:
                return None

            blob, created_at = row
            if (time.time() - created_at) > self._ttl_seconds:
                # Expired — delete and return miss
                conn.execute("DELETE FROM embeddings WHERE cache_key = ?", (cache_key,))
                conn.commit()
                return None

            return self._deserialize(blob)
        except (sqlite3.Error, OSError) as exc:
            logger.warning("Failed to read from embedding cache", error=str(exc))
            return None

    def put(self, cache_key: str, embedding: np.ndarray) -> None:
        """Store an embedding in the cache.

        Overwrites any existing entry with the same key.

        Args:
            cache_key: The SHA-256 cache key.
            embedding: The numpy array to cache.
        """
        conn = self._get_connection()
        if conn is None:
            return

        try:
            blob = self._serialize(embedding)
            conn.execute(
                "INSERT OR REPLACE INTO embeddings (cache_key, embedding, created_at) "
                "VALUES (?, ?, ?)",
                (cache_key, blob, time.time()),
            )
            conn.commit()
        except (sqlite3.Error, OSError) as exc:
            logger.warning("Failed to write to embedding cache", error=str(exc))

    def clear(self) -> None:
        """Delete all entries from the cache."""
        conn = self._get_connection()
        if conn is None:
            return

        try:
            conn.execute("DELETE FROM embeddings")
            conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Failed to clear embedding cache", error=str(exc))

    def evict_expired(self) -> int:
        """Remove all expired entries and return the count removed.

        Returns:
            Number of entries evicted, or ``0`` if caching is disabled.
        """
        conn = self._get_connection()
        if conn is None:
            return 0

        try:
            cutoff = time.time() - self._ttl_seconds
            cursor = conn.execute(
                "DELETE FROM embeddings WHERE created_at < ?",
                (cutoff,),
            )
            conn.commit()
            return cursor.rowcount
        except sqlite3.Error as exc:
            logger.warning("Failed to evict expired embeddings", error=str(exc))
            return 0

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    @staticmethod
    def _serialize(arr: np.ndarray) -> bytes:
        """Serialize a numpy array to bytes using numpy's native format.

        Args:
            arr: The numpy array to serialize.

        Returns:
            Bytes representation.
        """
        import numpy as np

        buf = io.BytesIO()
        np.save(buf, arr, allow_pickle=False)
        return buf.getvalue()

    @staticmethod
    def _deserialize(data: bytes) -> np.ndarray:
        """Deserialize bytes back to a numpy array.

        Args:
            data: Bytes produced by ``_serialize``.

        Returns:
            The reconstructed numpy array.
        """
        import numpy as np

        buf = io.BytesIO(data)
        result: np.ndarray[tuple[Any, ...], np.dtype[Any]] = np.load(
            buf,
            allow_pickle=False,
        )
        return result
