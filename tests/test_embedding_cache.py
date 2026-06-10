"""Unit tests for the EmbeddingCache class."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import numpy as np
import pytest

from ai_artifact_risk_validator.semantic.cache import EmbeddingCache


@pytest.fixture
def cache_dir() -> Path:
    """Create a temporary directory for cache testing."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def cache(cache_dir: Path) -> EmbeddingCache:
    """Create an EmbeddingCache with a temporary directory."""
    c = EmbeddingCache(cache_dir=cache_dir, ttl_seconds=3600)
    yield c
    c.close()


@pytest.fixture
def disabled_cache() -> EmbeddingCache:
    """Create a disabled EmbeddingCache (cache_dir=None)."""
    return EmbeddingCache(cache_dir=None)


class TestCacheProperties:
    """Test cache configuration and state."""

    def test_enabled_with_dir(self, cache: EmbeddingCache) -> None:
        assert cache.enabled is True

    def test_disabled_with_none(self, disabled_cache: EmbeddingCache) -> None:
        assert disabled_cache.enabled is False


class TestComputeKey:
    """Test cache key computation."""

    def test_deterministic(self) -> None:
        k1 = EmbeddingCache.compute_key("model", "text")
        k2 = EmbeddingCache.compute_key("model", "text")
        assert k1 == k2
        assert len(k1) == 64

    def test_different_model_different_key(self) -> None:
        k1 = EmbeddingCache.compute_key("model-a", "text")
        k2 = EmbeddingCache.compute_key("model-b", "text")
        assert k1 != k2

    def test_different_text_different_key(self) -> None:
        k1 = EmbeddingCache.compute_key("model", "text-a")
        k2 = EmbeddingCache.compute_key("model", "text-b")
        assert k1 != k2


class TestCachePutGet:
    """Test storing and retrieving embeddings."""

    def test_round_trip(self, cache: EmbeddingCache) -> None:
        """Stored embedding should be retrievable and identical."""
        key = "test_key_001"
        original = np.random.rand(384).astype(np.float32)

        cache.put(key, original)
        result = cache.get(key)

        assert result is not None
        np.testing.assert_array_almost_equal(result, original)

    def test_round_trip_2d(self, cache: EmbeddingCache) -> None:
        """2D embedding arrays should round-trip correctly."""
        key = "test_key_2d"
        original = np.random.rand(5, 384).astype(np.float32)

        cache.put(key, original)
        result = cache.get(key)

        assert result is not None
        assert result.shape == (5, 384)
        np.testing.assert_array_almost_equal(result, original)

    def test_cache_miss(self, cache: EmbeddingCache) -> None:
        """Non-existent key returns None."""
        result = cache.get("nonexistent_key")
        assert result is None

    def test_overwrite(self, cache: EmbeddingCache) -> None:
        """Overwriting a key with new data should return the new data."""
        key = "overwrite_key"
        v1 = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        v2 = np.array([4.0, 5.0, 6.0], dtype=np.float32)

        cache.put(key, v1)
        cache.put(key, v2)
        result = cache.get(key)

        assert result is not None
        np.testing.assert_array_almost_equal(result, v2)


class TestCacheDisabled:
    """Test that disabled cache operations are safe no-ops."""

    def test_get_returns_none(self, disabled_cache: EmbeddingCache) -> None:
        assert disabled_cache.get("any_key") is None

    def test_put_no_error(self, disabled_cache: EmbeddingCache) -> None:
        arr = np.array([1.0, 2.0], dtype=np.float32)
        disabled_cache.put("any_key", arr)  # Should not raise

    def test_clear_no_error(self, disabled_cache: EmbeddingCache) -> None:
        disabled_cache.clear()  # Should not raise

    def test_evict_expired_returns_zero(self, disabled_cache: EmbeddingCache) -> None:
        assert disabled_cache.evict_expired() == 0

    def test_close_no_error(self, disabled_cache: EmbeddingCache) -> None:
        disabled_cache.close()  # Should not raise


class TestCacheExpiry:
    """Test TTL-based expiry."""

    def test_expired_entry_returns_none(self, cache_dir: Path) -> None:
        """Entries past TTL should be evicted on access."""
        cache = EmbeddingCache(cache_dir=cache_dir, ttl_seconds=1)
        key = "expiring_key"
        arr = np.array([1.0, 2.0, 3.0], dtype=np.float32)

        cache.put(key, arr)
        result_before = cache.get(key)
        assert result_before is not None

        # Wait for expiry
        time.sleep(1.5)

        result_after = cache.get(key)
        assert result_after is None
        cache.close()

    def test_evict_expired(self, cache_dir: Path) -> None:
        """evict_expired() should remove expired entries."""
        cache = EmbeddingCache(cache_dir=cache_dir, ttl_seconds=1)

        cache.put("key1", np.array([1.0], dtype=np.float32))
        cache.put("key2", np.array([2.0], dtype=np.float32))

        time.sleep(1.5)

        evicted = cache.evict_expired()
        assert evicted == 2
        cache.close()


class TestCacheClear:
    """Test cache clearing."""

    def test_clear_removes_all(self, cache: EmbeddingCache) -> None:
        cache.put("k1", np.array([1.0], dtype=np.float32))
        cache.put("k2", np.array([2.0], dtype=np.float32))

        cache.clear()

        assert cache.get("k1") is None
        assert cache.get("k2") is None


class TestCacheClose:
    """Test connection lifecycle."""

    def test_close_then_reopen(self, cache_dir: Path) -> None:
        """After close, a new get should re-open the connection."""
        cache = EmbeddingCache(cache_dir=cache_dir)
        cache.put("test", np.array([1.0], dtype=np.float32))
        cache.close()

        # Should re-open the connection on next access
        result = cache.get("test")
        assert result is not None
        cache.close()


class TestCacheSerialization:
    """Test numpy array serialization round-trips."""

    def test_various_dtypes(self, cache: EmbeddingCache) -> None:
        """Different numpy dtypes should round-trip correctly."""
        for dtype in [np.float32, np.float64, np.float16]:
            key = f"dtype_{dtype.__name__}"
            original = np.array([1.0, 2.0, 3.0], dtype=dtype)
            cache.put(key, original)
            result = cache.get(key)
            assert result is not None
            assert result.dtype == dtype

    def test_large_array(self, cache: EmbeddingCache) -> None:
        """Large arrays should round-trip correctly."""
        key = "large_array"
        original = np.random.rand(1000, 384).astype(np.float32)
        cache.put(key, original)
        result = cache.get(key)
        assert result is not None
        assert result.shape == (1000, 384)
        np.testing.assert_array_almost_equal(result, original)
