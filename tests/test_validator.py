"""Unit tests for the Validator class (main entry point).

Tests cover:
- Initialization with default and custom config
- verify() with non-existent paths returns error report
- verify() with file paths scans a single file
- verify() with directory paths scans recursively
- Graceful degradation: no exceptions propagate to callers
- Report structure correctness
"""

from __future__ import annotations

import pytest

from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import GateAction
from ai_artifact_risk_validator.models.report import ScanReport
from ai_artifact_risk_validator.validator import Validator


class TestValidatorInit:
    """Tests for Validator initialization."""

    def test_init_default_config(self):
        """Validator initializes successfully with no config."""
        v = Validator()
        assert v._config is not None
        assert v._config.log_level == "INFO"

    def test_init_custom_config(self):
        """Validator initializes with a custom ValidatorConfig."""
        config = ValidatorConfig(log_level="DEBUG", parallel_files=2)
        v = Validator(config=config)
        assert v._config.log_level == "DEBUG"
        assert v._config.parallel_files == 2

    def test_version_property(self):
        """Version property returns the package version string."""
        v = Validator()
        assert v.version == "0.4.0"


class TestVerifyNonExistentPath:
    """Tests for verify() with non-existent paths."""

    def test_nonexistent_path_returns_scan_report(self):
        """verify() with non-existent path returns a ScanReport, not an exception."""
        v = Validator()
        report = v.verify("/nonexistent/path/abc123xyz")
        assert isinstance(report, ScanReport)

    def test_nonexistent_path_has_zero_findings(self):
        """verify() with non-existent path returns zero findings."""
        v = Validator()
        report = v.verify("/nonexistent/path/abc123xyz")
        assert len(report.findings) == 0
        assert report.summary.total_findings == 0

    def test_nonexistent_path_has_error_message(self):
        """verify() with non-existent path includes an error message."""
        v = Validator()
        report = v.verify("/nonexistent/path/abc123xyz")
        assert len(report.errors) == 1
        assert (
            "does not exist" in report.errors[0].lower() or "not exist" in report.errors[0].lower()
        )

    def test_nonexistent_path_gate_decision_is_info(self):
        """verify() with non-existent path returns INFO gate decision."""
        v = Validator()
        report = v.verify("/nonexistent/path/abc123xyz")
        assert report.summary.gate_decision == GateAction.INFO

    def test_nonexistent_path_preserves_artifact_path(self):
        """verify() with non-existent path preserves the original path in report."""
        v = Validator()
        report = v.verify("/some/nonexistent/dir")
        assert report.artifact_path == "/some/nonexistent/dir"


class TestVerifyFilePath:
    """Tests for verify() with file paths."""

    def test_file_path_returns_scan_report(self, tmp_path):
        """verify() with a valid file returns a ScanReport."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")
        v = Validator()
        report = v.verify(str(test_file))
        assert isinstance(report, ScanReport)

    def test_file_path_no_errors(self, tmp_path):
        """verify() with a valid file has no errors."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")
        v = Validator()
        report = v.verify(str(test_file))
        assert report.errors == []

    def test_file_path_preserves_artifact_path(self, tmp_path):
        """verify() preserves the original path string in the report."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")
        path_str = str(test_file)
        v = Validator()
        report = v.verify(path_str)
        assert report.artifact_path == path_str


class TestVerifyDirectoryPath:
    """Tests for verify() with directory paths."""

    def test_directory_path_returns_scan_report(self, tmp_path):
        """verify() with a valid directory returns a ScanReport."""
        (tmp_path / "file.md").write_text("# Test")
        v = Validator()
        report = v.verify(str(tmp_path))
        assert isinstance(report, ScanReport)

    def test_empty_directory_returns_report(self, tmp_path):
        """verify() with an empty directory returns a valid report."""
        v = Validator()
        report = v.verify(str(tmp_path))
        assert isinstance(report, ScanReport)
        assert len(report.findings) == 0
        assert report.errors == []

    def test_directory_path_preserves_artifact_path(self, tmp_path):
        """verify() preserves the directory path in the report."""
        path_str = str(tmp_path)
        v = Validator()
        report = v.verify(path_str)
        assert report.artifact_path == path_str


class TestVerifyGracefulDegradation:
    """Tests for graceful exception handling in verify()."""

    def test_never_raises_on_broken_internal(self):
        """verify() catches internal errors and returns error report."""
        v = Validator()
        # Break the file discovery to simulate an internal error
        v._file_discovery.discover = lambda path: (_ for _ in ()).throw(
            RuntimeError("Internal failure")
        )
        # Should NOT raise
        report = v.verify("src")
        assert isinstance(report, ScanReport)
        assert len(report.errors) == 1
        assert "Internal failure" in report.errors[0]

    def test_never_raises_on_none_path(self):
        """verify() handles unusual path inputs without raising."""
        v = Validator()
        # Path(None) would raise TypeError - verify should catch it
        try:
            report = v.verify(None)  # type: ignore[arg-type]
            assert isinstance(report, ScanReport)
            assert len(report.errors) >= 1
        except TypeError:
            # This is acceptable if Path(None) raises before our try/except
            # but ideally the outer try/except catches it
            pytest.fail("verify() should not propagate TypeError")

    def test_report_has_valid_scan_id(self):
        """Error reports have a valid UUID scan_id."""
        v = Validator()
        report = v.verify("/nonexistent/xyz")
        assert len(report.scan_id) > 0
        # UUID format: 8-4-4-4-12 hex chars
        parts = report.scan_id.split("-")
        assert len(parts) == 5

    def test_report_has_scan_timestamp(self):
        """Reports include a scan timestamp."""
        v = Validator()
        report = v.verify("/nonexistent/xyz")
        assert report.scan_timestamp is not None

    def test_report_has_scanner_version(self):
        """Reports include the scanner version."""
        v = Validator()
        report = v.verify("/nonexistent/xyz")
        assert report.scanner_version == "0.4.0"


class TestVerifyReportStructure:
    """Tests for verify() report completeness."""

    def test_summary_fields_present(self, tmp_path):
        """ScanSummary has all required fields."""
        (tmp_path / "test.txt").write_text("content")
        v = Validator()
        report = v.verify(str(tmp_path))
        summary = report.summary
        assert hasattr(summary, "total_findings")
        assert hasattr(summary, "by_severity")
        assert hasattr(summary, "by_category")
        assert hasattr(summary, "gate_decision")
        assert hasattr(summary, "blocking_findings")
        assert hasattr(summary, "warning_findings")
        assert hasattr(summary, "info_findings")

    def test_gate_decision_is_valid_enum(self, tmp_path):
        """Gate decision is always a valid GateAction enum value."""
        v = Validator()
        report = v.verify(str(tmp_path))
        assert report.summary.gate_decision in (
            GateAction.INFO,
            GateAction.WARN,
            GateAction.BLOCK,
        )

    def test_artifact_type_none_for_directory(self, tmp_path):
        """artifact_type is None for directory scans with no findings."""
        v = Validator()
        report = v.verify(str(tmp_path))
        assert report.artifact_type is None
