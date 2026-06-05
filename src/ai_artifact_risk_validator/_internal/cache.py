"""Scan result caching with content-hash based keys.

Provides ScanCache for storing and retrieving scan findings keyed by
content hash, enabling unchanged files to skip re-scanning.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ai_artifact_risk_validator.models.findings import ScanFinding

logger = logging.getLogger(__name__)


class ScanCache:
    """Cache for scan results stored as JSON files.

    Each cache entry is a JSON file named ``{cache_key}.json`` containing
    a serialized list of ScanFinding objects. If ``cache_dir`` is None,
    caching is disabled and all operations are no-ops.
    """

    def __init__(self, cache_dir: str | None) -> None:
        """Initialize the scan cache.

        Args:
            cache_dir: Directory path for cache storage. If None, caching
                is disabled and get/put/invalidate/clear are no-ops.
        """
        if cache_dir is not None:
            self._cache_dir: Path | None = Path(cache_dir)
        else:
            self._cache_dir = None

    @property
    def enabled(self) -> bool:
        """Whether caching is enabled."""
        return self._cache_dir is not None

    def _cache_path(self, cache_key: str) -> Path | None:
        """Get the file path for a cache key, or None if disabled."""
        if self._cache_dir is None:
            return None
        return self._cache_dir / f"{cache_key}.json"

    def get(self, cache_key: str) -> list[ScanFinding] | None:
        """Read cached findings for a cache key.

        Args:
            cache_key: The content-based cache key.

        Returns:
            List of ScanFinding objects if cache hit, None if miss or disabled.
            Returns None for corrupted/unreadable cache entries.
        """
        path = self._cache_path(cache_key)
        if path is None or not path.exists():
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                logger.warning("Cache entry %s is not a list, treating as miss", cache_key)
                return None
            return [ScanFinding.model_validate(item) for item in data]
        except (json.JSONDecodeError, OSError, ValueError, TypeError) as exc:
            logger.warning("Failed to read cache entry %s: %s", cache_key, exc)
            return None

    def put(self, cache_key: str, findings: list[ScanFinding]) -> None:
        """Store findings for a cache key.

        Creates the cache directory if it doesn't exist on first write.

        Args:
            cache_key: The content-based cache key.
            findings: List of ScanFinding objects to cache.
        """
        if self._cache_dir is None:
            return

        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            path = self._cache_dir / f"{cache_key}.json"
            data = [finding.model_dump(mode="json") for finding in findings]
            path.write_text(json.dumps(data, default=str), encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to write cache entry %s: %s", cache_key, exc)

    def invalidate(self, cache_key: str) -> None:
        """Remove a specific cache entry.

        Args:
            cache_key: The cache key to invalidate.
        """
        path = self._cache_path(cache_key)
        if path is None:
            return

        try:
            if path.exists():
                path.unlink()
        except OSError as exc:
            logger.warning("Failed to invalidate cache entry %s: %s", cache_key, exc)

    def clear(self) -> None:
        """Remove all cache entries.

        Only removes .json files in the cache directory.
        """
        if self._cache_dir is None:
            return

        try:
            if self._cache_dir.exists():
                for cache_file in self._cache_dir.glob("*.json"):
                    cache_file.unlink()
        except OSError as exc:
            logger.warning("Failed to clear cache: %s", exc)
