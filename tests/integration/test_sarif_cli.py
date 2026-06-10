"""Integration tests for CLI SARIF format output.

Tests cover:
- --format sarif writes valid SARIF to stdout
- --format sarif --output path writes SARIF to file
- non-writable output path exits with error to stderr
- case-insensitive format value (SARIF, Sarif) accepted
- exit codes remain determined by gate decision regardless of format

Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.6
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.main import cli

# Common CLI args to suppress log output in tests
_QUIET_ARGS = ["--log-level", "CRITICAL"]


def _extract_json(output: str) -> dict[str, Any]:
    """Extract and parse the JSON object from CLI output.

    The CLI may emit warnings to stdout before the JSON content.
    This function finds the first '{' and parses from there.
    """
    start = output.find("{")
    if start == -1:
        raise ValueError(f"No JSON object found in output: {output!r}")
    return json.loads(output[start:])  # type: ignore[no-any-return]


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def scan_dir(tmp_path: Path) -> Path:
    """Create a temporary scan directory with a simple prompt file."""
    d = tmp_path / "scan"
    d.mkdir()
    (d / "test.prompt.md").write_text(
        "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
        encoding="utf-8",
    )
    return d


@pytest.mark.integration
class TestSarifFormatStdout:
    """Test --format sarif writes valid SARIF to stdout."""

    def test_format_sarif_outputs_valid_json_to_stdout(
        self, runner: CliRunner, scan_dir: Path
    ) -> None:
        """--format sarif should output a valid JSON SARIF document to stdout."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "sarif", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        doc = _extract_json(result.output)
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert "runs" in doc
        assert len(doc["runs"]) == 1

    def test_format_sarif_contains_tool_driver(self, runner: CliRunner, scan_dir: Path) -> None:
        """--format sarif output should contain tool.driver with correct name."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "sarif", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        doc = _extract_json(result.output)
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "ai-artifact-risk-validator"
        assert "version" in run["tool"]["driver"]

    def test_format_sarif_contains_results_array(self, runner: CliRunner, scan_dir: Path) -> None:
        """--format sarif output should contain a results array in the run."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "sarif", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        doc = _extract_json(result.output)
        run = doc["runs"][0]
        assert "results" in run
        assert isinstance(run["results"], list)


@pytest.mark.integration
class TestSarifFormatOutputFile:
    """Test --format sarif --output path writes SARIF to file."""

    def test_format_sarif_output_writes_to_file(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ) -> None:
        """--format sarif --output <path> writes SARIF report to the specified file."""
        output_file = tmp_path / "report.sarif"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "sarif",
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        doc = json.loads(content)
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert len(doc["runs"]) == 1

    def test_format_sarif_output_creates_parent_directories(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ) -> None:
        """--format sarif --output <path> creates parent directories if needed."""
        output_file = tmp_path / "nested" / "deep" / "report.sarif"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "sarif",
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        doc = json.loads(content)
        assert doc["version"] == "2.1.0"

    def test_format_sarif_output_file_not_on_stdout(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ) -> None:
        """When --output is used, SARIF JSON should not appear on stdout."""
        output_file = tmp_path / "report.sarif"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "sarif",
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        # stdout should not contain the full SARIF document
        assert '"$schema"' not in result.output


@pytest.mark.integration
class TestSarifNonWritableOutput:
    """Test non-writable output path exits with error to stderr."""

    def test_non_writable_path_exits_with_error(self, runner: CliRunner, scan_dir: Path) -> None:
        """Non-writable output path should exit with non-zero code and show error."""
        # Use a path where the parent directory doesn't exist and cannot be created
        # On all platforms, a path starting with an invalid root should fail
        non_writable_path = str(
            Path(tempfile.gettempdir())
            / "nonexistent_parent_xyz_sarif_test_abc123"
            / "deep"
            / "nested"
            / "output.sarif"
        )
        # The CLI creates parent directories via mkdir(parents=True, exist_ok=True)
        # so we need to use a truly non-writable path. We'll use a file as a "directory"
        # to prevent directory creation.
        with tempfile.NamedTemporaryFile(suffix=".block", delete=False) as blocker:
            blocker_path = blocker.name

        # Try to write inside the file (which can't be a directory)
        bad_output_path = str(Path(blocker_path) / "subdir" / "output.sarif")

        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "sarif",
                "--output",
                bad_output_path,
                *_QUIET_ARGS,
            ],
        )
        # Should exit with non-zero exit code
        assert result.exit_code != 0
        # Clean up blocker file
        Path(blocker_path).unlink(missing_ok=True)


@pytest.mark.integration
class TestSarifCaseInsensitiveFormat:
    """Test case-insensitive format value (SARIF, Sarif) accepted."""

    def test_uppercase_sarif_format_accepted(self, runner: CliRunner, scan_dir: Path) -> None:
        """--format SARIF (uppercase) should be accepted and produce valid SARIF."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "SARIF", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        doc = _extract_json(result.output)
        assert doc["version"] == "2.1.0"

    def test_mixed_case_sarif_format_accepted(self, runner: CliRunner, scan_dir: Path) -> None:
        """--format Sarif (mixed case) should be accepted and produce valid SARIF."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "Sarif", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        doc = _extract_json(result.output)
        assert doc["version"] == "2.1.0"

    def test_all_caps_sarif_matches_lowercase(self, runner: CliRunner, scan_dir: Path) -> None:
        """--format SARIF should produce identical structure to --format sarif."""
        result_lower = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "sarif", *_QUIET_ARGS],
        )
        result_upper = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "SARIF", *_QUIET_ARGS],
        )
        assert result_lower.exit_code == result_upper.exit_code
        # Both should be valid SARIF
        doc_lower = _extract_json(result_lower.output)
        doc_upper = _extract_json(result_upper.output)
        assert doc_lower["version"] == doc_upper["version"]
        assert doc_lower["$schema"] == doc_upper["$schema"]


@pytest.mark.integration
class TestSarifExitCodes:
    """Test exit codes remain determined by gate decision regardless of format."""

    def test_exit_code_consistent_between_sarif_and_json(
        self, runner: CliRunner, scan_dir: Path
    ) -> None:
        """Exit code for same input should be identical for --format sarif and --format json."""
        result_sarif = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "sarif", *_QUIET_ARGS],
        )
        result_json = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
        )
        assert result_sarif.exit_code == result_json.exit_code

    def test_exit_code_consistent_between_sarif_and_text(
        self, runner: CliRunner, scan_dir: Path
    ) -> None:
        """Exit code for same input should be identical for --format sarif and --format text."""
        result_sarif = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "sarif", *_QUIET_ARGS],
        )
        result_text = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "text", *_QUIET_ARGS],
        )
        assert result_sarif.exit_code == result_text.exit_code

    def test_sarif_exit_code_values_are_valid_gate_decisions(
        self, runner: CliRunner, scan_dir: Path
    ) -> None:
        """SARIF format exit code should be 0, 1, or 2 (valid gate decisions)."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "sarif", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
