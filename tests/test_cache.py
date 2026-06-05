"""Unit tests for content hashing and scan result caching."""

from pathlib import Path

from ai_artifact_risk_validator._internal.cache import ScanCache
from ai_artifact_risk_validator._internal.hashing import compute_cache_key, compute_content_hash
from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding


def _make_finding(risk_id: str = "P-S1") -> ScanFinding:
    """Create a minimal ScanFinding for testing."""
    return ScanFinding(
        id=risk_id,
        artifact_type=ArtifactType.PROMPT,
        artifact_path="/test/file.prompt.md",
        severity_score=7,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        category=RiskCategory.SECURITY,
        title="Test finding",
        description="A test finding for caching",
        location=FindingLocation(line=10),
        evidence="test evidence",
        confidence=0.95,
        scanner_module=ScannerModule.SECRET_SCAN,
        remediation="Remove the secret",
        references=["https://example.com"],
    )


# --- Tests for hashing.py ---


class TestComputeContentHash:
    def test_returns_hex_string(self):
        result = compute_content_hash("hello world")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex is 64 chars

    def test_deterministic(self):
        content = "some content to hash"
        assert compute_content_hash(content) == compute_content_hash(content)

    def test_different_content_different_hash(self):
        assert compute_content_hash("abc") != compute_content_hash("def")

    def test_empty_string(self):
        result = compute_content_hash("")
        assert isinstance(result, str)
        assert len(result) == 64


class TestComputeCacheKey:
    def test_returns_hex_string(self):
        result = compute_cache_key("content", ["scanner1"], "0.1.0")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_deterministic(self):
        key1 = compute_cache_key("content", ["s1", "s2"], "1.0.0")
        key2 = compute_cache_key("content", ["s1", "s2"], "1.0.0")
        assert key1 == key2

    def test_scanner_order_does_not_matter(self):
        key1 = compute_cache_key("content", ["s2", "s1"], "1.0.0")
        key2 = compute_cache_key("content", ["s1", "s2"], "1.0.0")
        assert key1 == key2

    def test_different_content_different_key(self):
        key1 = compute_cache_key("content_a", ["s1"], "1.0.0")
        key2 = compute_cache_key("content_b", ["s1"], "1.0.0")
        assert key1 != key2

    def test_different_scanners_different_key(self):
        key1 = compute_cache_key("content", ["s1"], "1.0.0")
        key2 = compute_cache_key("content", ["s1", "s2"], "1.0.0")
        assert key1 != key2

    def test_different_version_different_key(self):
        key1 = compute_cache_key("content", ["s1"], "1.0.0")
        key2 = compute_cache_key("content", ["s1"], "2.0.0")
        assert key1 != key2


# --- Tests for cache.py ---


class TestScanCacheDisabled:
    def test_disabled_when_cache_dir_is_none(self):
        cache = ScanCache(cache_dir=None)
        assert cache.enabled is False

    def test_get_returns_none_when_disabled(self):
        cache = ScanCache(cache_dir=None)
        assert cache.get("any_key") is None

    def test_put_is_noop_when_disabled(self):
        cache = ScanCache(cache_dir=None)
        cache.put("key", [_make_finding()])  # should not raise

    def test_invalidate_is_noop_when_disabled(self):
        cache = ScanCache(cache_dir=None)
        cache.invalidate("key")  # should not raise

    def test_clear_is_noop_when_disabled(self):
        cache = ScanCache(cache_dir=None)
        cache.clear()  # should not raise


class TestScanCacheEnabled:
    def test_enabled_when_cache_dir_provided(self, tmp_path: Path):
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))
        assert cache.enabled is True

    def test_get_returns_none_for_missing_key(self, tmp_path: Path):
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))
        assert cache.get("nonexistent") is None

    def test_put_and_get_roundtrip(self, tmp_path: Path):
        cache_dir = tmp_path / "cache"
        cache = ScanCache(cache_dir=str(cache_dir))
        finding = _make_finding()

        cache.put("test_key", [finding])
        result = cache.get("test_key")

        assert result is not None
        assert len(result) == 1
        assert result[0].id == "P-S1"
        assert result[0].severity_score == 7
        assert result[0].confidence == 0.95

    def test_put_creates_cache_dir(self, tmp_path: Path):
        cache_dir = tmp_path / "nested" / "cache" / "dir"
        cache = ScanCache(cache_dir=str(cache_dir))

        cache.put("key", [])
        assert cache_dir.exists()

    def test_put_empty_findings(self, tmp_path: Path):
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))
        cache.put("empty_key", [])
        result = cache.get("empty_key")
        assert result == []

    def test_invalidate_removes_entry(self, tmp_path: Path):
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))
        cache.put("key_to_remove", [_make_finding()])

        cache.invalidate("key_to_remove")
        assert cache.get("key_to_remove") is None

    def test_invalidate_nonexistent_key_is_noop(self, tmp_path: Path):
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))
        cache.invalidate("no_such_key")  # should not raise

    def test_clear_removes_all_entries(self, tmp_path: Path):
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))
        cache.put("key1", [_make_finding("P-S1")])
        cache.put("key2", [_make_finding("P-S2")])

        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_corrupted_cache_returns_none(self, tmp_path: Path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        # Write invalid JSON
        (cache_dir / "bad_key.json").write_text("not valid json{{{", encoding="utf-8")

        cache = ScanCache(cache_dir=str(cache_dir))
        assert cache.get("bad_key") is None

    def test_non_list_cache_returns_none(self, tmp_path: Path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        # Write valid JSON that's not a list
        (cache_dir / "obj_key.json").write_text('{"not": "a list"}', encoding="utf-8")

        cache = ScanCache(cache_dir=str(cache_dir))
        assert cache.get("obj_key") is None

    def test_cache_invalidation_on_content_change(self, tmp_path: Path):
        """Content change produces a different cache key, simulating invalidation."""
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))

        key_v1 = compute_cache_key("original content", ["s1"], "1.0.0")
        key_v2 = compute_cache_key("modified content", ["s1"], "1.0.0")

        cache.put(key_v1, [_make_finding()])

        # Original key still has data
        assert cache.get(key_v1) is not None
        # New key (content changed) has no data
        assert cache.get(key_v2) is None

    def test_multiple_findings_roundtrip(self, tmp_path: Path):
        cache = ScanCache(cache_dir=str(tmp_path / "cache"))
        findings = [_make_finding("P-S1"), _make_finding("P-S2")]

        cache.put("multi_key", findings)
        result = cache.get("multi_key")

        assert result is not None
        assert len(result) == 2
        assert result[0].id == "P-S1"
        assert result[1].id == "P-S2"
