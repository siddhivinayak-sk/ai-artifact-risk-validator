"""Unit tests for FileDiscovery."""

from pathlib import Path

from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.pipeline.discovery import FileDiscovery


class TestFileDiscoverySingleFile:
    """Tests for single file discovery."""

    def test_returns_file_if_passes_filters(self, tmp_path: Path):
        f = tmp_path / "hello.py"
        f.write_text("print('hi')")

        discovery = FileDiscovery()
        result = discovery.discover(f)
        assert result == [f]

    def test_returns_empty_for_excluded_file(self, tmp_path: Path):
        f = tmp_path / "secret.log"
        f.write_text("some log data")

        config = ValidatorConfig(file_exclude_patterns=["*.log"])
        discovery = FileDiscovery(config)
        result = discovery.discover(f)
        assert result == []

    def test_returns_empty_when_not_in_include_patterns(self, tmp_path: Path):
        f = tmp_path / "readme.txt"
        f.write_text("hello")

        config = ValidatorConfig(file_include_patterns=["*.py"])
        discovery = FileDiscovery(config)
        result = discovery.discover(f)
        assert result == []

    def test_returns_file_when_in_include_patterns(self, tmp_path: Path):
        f = tmp_path / "main.py"
        f.write_text("x = 1")

        config = ValidatorConfig(file_include_patterns=["*.py"])
        discovery = FileDiscovery(config)
        result = discovery.discover(f)
        assert result == [f]

    def test_returns_empty_for_oversized_file(self, tmp_path: Path):
        f = tmp_path / "big.py"
        f.write_bytes(b"x" * 200)

        config = ValidatorConfig(max_file_size_bytes=100)
        discovery = FileDiscovery(config)
        result = discovery.discover(f)
        assert result == []

    def test_returns_file_at_exact_size_limit(self, tmp_path: Path):
        f = tmp_path / "exact.py"
        f.write_bytes(b"x" * 100)

        config = ValidatorConfig(max_file_size_bytes=100)
        discovery = FileDiscovery(config)
        result = discovery.discover(f)
        assert result == [f]


class TestFileDiscoveryDirectory:
    """Tests for directory discovery."""

    def test_discovers_all_files_in_flat_directory(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("a")
        (tmp_path / "b.py").write_text("b")
        (tmp_path / "c.txt").write_text("c")

        discovery = FileDiscovery()
        result = discovery.discover(tmp_path)
        assert len(result) == 3

    def test_discovers_files_recursively(self, tmp_path: Path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.py").write_text("top")
        (sub / "nested.py").write_text("nested")

        discovery = FileDiscovery()
        result = discovery.discover(tmp_path)
        assert len(result) == 2
        names = {p.name for p in result}
        assert names == {"top.py", "nested.py"}

    def test_applies_exclude_patterns_in_directory(self, tmp_path: Path):
        (tmp_path / "keep.py").write_text("keep")
        (tmp_path / "skip.log").write_text("skip")
        (tmp_path / "also_skip.log").write_text("skip2")

        config = ValidatorConfig(file_exclude_patterns=["*.log"])
        discovery = FileDiscovery(config)
        result = discovery.discover(tmp_path)
        assert len(result) == 1
        assert result[0].name == "keep.py"

    def test_applies_include_patterns_in_directory(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("py")
        (tmp_path / "data.json").write_text("{}")
        (tmp_path / "readme.md").write_text("# hi")

        config = ValidatorConfig(file_include_patterns=["*.py", "*.json"])
        discovery = FileDiscovery(config)
        result = discovery.discover(tmp_path)
        names = {p.name for p in result}
        assert names == {"main.py", "data.json"}

    def test_applies_max_file_size_in_directory(self, tmp_path: Path):
        (tmp_path / "small.py").write_bytes(b"x" * 50)
        (tmp_path / "big.py").write_bytes(b"x" * 200)

        config = ValidatorConfig(max_file_size_bytes=100)
        discovery = FileDiscovery(config)
        result = discovery.discover(tmp_path)
        assert len(result) == 1
        assert result[0].name == "small.py"

    def test_skips_directories_in_results(self, tmp_path: Path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "file.py").write_text("x")

        discovery = FileDiscovery()
        result = discovery.discover(tmp_path)
        assert all(p.is_file() for p in result)
        assert len(result) == 1


class TestFileDiscoveryEdgeCases:
    """Tests for edge cases and error handling."""

    def test_nonexistent_path_returns_empty(self):
        discovery = FileDiscovery()
        result = discovery.discover(Path("/nonexistent/path/12345"))
        assert result == []

    def test_empty_directory_returns_empty(self, tmp_path: Path):
        discovery = FileDiscovery()
        result = discovery.discover(tmp_path)
        assert result == []

    def test_default_config_when_none_provided(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("hello")

        discovery = FileDiscovery(config=None)
        result = discovery.discover(f)
        assert result == [f]

    def test_empty_include_patterns_includes_all(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("a")
        (tmp_path / "b.txt").write_text("b")

        config = ValidatorConfig(file_include_patterns=[])
        discovery = FileDiscovery(config)
        result = discovery.discover(tmp_path)
        assert len(result) == 2

    def test_multiple_exclude_patterns(self, tmp_path: Path):
        (tmp_path / "keep.py").write_text("keep")
        (tmp_path / "skip.log").write_text("log")
        (tmp_path / "skip.tmp").write_text("tmp")

        config = ValidatorConfig(file_exclude_patterns=["*.log", "*.tmp"])
        discovery = FileDiscovery(config)
        result = discovery.discover(tmp_path)
        assert len(result) == 1
        assert result[0].name == "keep.py"

    def test_exclude_takes_priority_over_include(self, tmp_path: Path):
        """A file matching both include and exclude should be excluded."""
        (tmp_path / "test.py").write_text("test")

        config = ValidatorConfig(
            file_include_patterns=["*.py"],
            file_exclude_patterns=["test*"],
        )
        discovery = FileDiscovery(config)
        result = discovery.discover(tmp_path)
        assert result == []

    def test_deeply_nested_files(self, tmp_path: Path):
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        f = deep / "deep.py"
        f.write_text("deep")

        discovery = FileDiscovery()
        result = discovery.discover(tmp_path)
        assert len(result) == 1
        assert result[0] == f
