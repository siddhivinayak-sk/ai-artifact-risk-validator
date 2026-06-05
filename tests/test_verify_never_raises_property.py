"""Property-based test for verify never raises.

**Validates: Requirements 4.2, 4.4, 7.1, 7.4**

Property 3: Verify Never Raises
Tests that for any input path (valid directory, valid file, non-existent path,
empty string), verify() returns a ScanReport and never propagates exceptions.
"""

from __future__ import annotations

import string
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.report import ScanReport
from ai_artifact_risk_validator.validator import Validator

# --- Strategies ---

# Paths that are guaranteed not to exist (absolute non-existent paths avoid
# accidentally scanning the CWD which could be huge)
nonexistent_path_strategy = st.one_of(
    st.just(""),
    st.just("/nonexistent_abc_xyz_123/path"),
    st.just("C:\\nonexistent_abc_xyz_123\\path"),
    st.just("/tmp/nonexistent_" + "x" * 50),
    st.text(
        alphabet=string.ascii_letters + string.digits + "/_-.",
        min_size=1,
        max_size=80,
    ).map(lambda s: f"/nonexistent_root_xyz/{s}"),
    st.text(
        alphabet=st.characters(
            whitelist_categories=("L", "N", "P", "S"),
            blacklist_characters="\x00\n\r",
        ),
        min_size=1,
        max_size=60,
    ).map(lambda s: f"/nonexistent_root_xyz/{s}"),
)


# --- Property Tests ---


class TestVerifyNeverRaises:
    """Property 3: Verify Never Raises.

    **Validates: Requirements 4.2, 4.4, 7.1, 7.4**
    """

    @given(path_input=nonexistent_path_strategy)
    @settings(max_examples=50, deadline=None)
    def test_verify_returns_scan_report_for_any_path_string(self, path_input: str) -> None:
        """verify() always returns a ScanReport instance and never raises
        an exception, regardless of the input path string."""
        validator = Validator()
        result = validator.verify(path_input)
        assert isinstance(result, ScanReport)

    @given(path_input=nonexistent_path_strategy)
    @settings(max_examples=50, deadline=None)
    def test_verify_report_has_valid_structure(self, path_input: str) -> None:
        """verify() always returns a ScanReport with valid summary fields,
        regardless of the input path."""
        validator = Validator()
        report = validator.verify(path_input)

        # Report must have required structural fields
        assert report.scan_id is not None
        assert len(report.scan_id) > 0
        assert report.scan_timestamp is not None
        assert report.scanner_version is not None
        assert report.findings is not None
        assert report.summary is not None
        assert report.summary.total_findings >= 0
        assert report.summary.blocking_findings >= 0
        assert report.summary.warning_findings >= 0
        assert report.summary.info_findings >= 0

    @given(
        dir_contents=st.lists(
            st.tuples(
                st.from_regex(r"[a-z]{1,10}\.(md|txt|yaml|json|py)", fullmatch=True),
                st.text(min_size=0, max_size=200),
            ),
            min_size=0,
            max_size=3,
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_verify_returns_scan_report_for_valid_directories(
        self, dir_contents: list[tuple[str, str]]
    ) -> None:
        """verify() returns a ScanReport for valid directories with arbitrary
        file contents, never raising an exception."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            for filename, content in dir_contents:
                file_path = Path(tmp_dir) / filename
                file_path.write_text(content, encoding="utf-8")

            validator = Validator()
            result = validator.verify(tmp_dir)
            assert isinstance(result, ScanReport)
            assert result.errors == [] or isinstance(result.errors, list)

    @given(file_content=st.text(min_size=0, max_size=500))
    @settings(max_examples=20, deadline=None)
    def test_verify_returns_scan_report_for_valid_files(self, file_content: str) -> None:
        """verify() returns a ScanReport for valid file paths with arbitrary
        content, never raising an exception."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as f:
            f.write(file_content)
            f.flush()
            file_path = f.name

        try:
            validator = Validator()
            result = validator.verify(file_path)
            assert isinstance(result, ScanReport)
        finally:
            # Clean up
            Path(file_path).unlink(missing_ok=True)

    @given(path_input=nonexistent_path_strategy)
    @settings(max_examples=50, deadline=None)
    def test_verify_artifact_path_preserved_in_report(self, path_input: str) -> None:
        """verify() always preserves the input path in the report's artifact_path
        field, regardless of whether the path exists."""
        validator = Validator()
        report = validator.verify(path_input)
        assert report.artifact_path == path_input

    def test_verify_with_empty_string_returns_scan_report(self) -> None:
        """verify('') returns a ScanReport and never raises, even for edge
        case of empty string input."""
        validator = Validator()
        result = validator.verify("")
        assert isinstance(result, ScanReport)

    def test_verify_with_special_characters_returns_scan_report(self) -> None:
        """verify() returns ScanReport for paths with special characters."""
        validator = Validator()
        special_paths = [
            "path with spaces/file.md",
            "path/with/ünïcödé/file.txt",
            "../../../etc/passwd",
            "C:\\Windows\\System32\\fake",
            "/dev/null",
            "file\twith\ttabs",
            "." * 255,
        ]
        for path in special_paths:
            result = validator.verify(path)
            assert isinstance(result, ScanReport)
