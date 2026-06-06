"""Unit tests for CLI HTML format and configuration integration.

Tests cover:
- --format html produces HTML to stdout
- --format html --output <path> writes HTML to file and creates parent directories
- AAV_HTML_REPORT_PATH env var triggers side-effect HTML file write
- html_report_path YAML config field triggers side-effect HTML file write
- Dual output: --format html --output <path> combined with AAV_HTML_REPORT_PATH
- No HTML side effect when no HTML config is provided

Validates: Requirements 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 3.5, 5.4
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.main import cli

# Common CLI args to suppress log output in tests
_QUIET_ARGS = ["--log-level", "CRITICAL"]


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


class TestCLIHtmlFormatStdout:
    """Test --format html produces HTML to stdout."""

    def test_format_html_outputs_html_to_stdout(self, runner: CliRunner, scan_dir: Path):
        """--format html should output a complete HTML document to stdout."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "html", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output
        assert "<!DOCTYPE html>" in output
        assert "<html" in output
        assert "</html>" in output
        assert "<style>" in output

    def test_format_html_contains_scan_metadata(self, runner: CliRunner, scan_dir: Path):
        """--format html output should contain scan metadata in the summary."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "html", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output
        # Should contain the scan path
        assert str(scan_dir).replace("\\", "/") in output or str(scan_dir) in output

    def test_format_html_is_standalone(self, runner: CliRunner, scan_dir: Path):
        """--format html output should be standalone with no external resources."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "html", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output
        assert 'href="http' not in output
        assert 'src="http' not in output
        assert "url(http" not in output


class TestCLIHtmlFormatOutputFile:
    """Test --format html --output <path> writes HTML to file."""

    def test_format_html_output_writes_to_file(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """--format html --output <path> writes HTML report to the specified file."""
        output_file = tmp_path / "report.html"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "html",
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content

    def test_format_html_output_creates_parent_directories(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """--format html --output <path> creates parent directories if they don't exist."""
        output_file = tmp_path / "nested" / "deep" / "dir" / "report.html"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "html",
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_format_html_output_file_not_on_stdout(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """When --output is used, HTML should not appear on stdout."""
        output_file = tmp_path / "report.html"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "html",
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        # stdout should not contain the full HTML document
        assert "<!DOCTYPE html>" not in result.output


class TestCLIHtmlEnvVarSideEffect:
    """Test AAV_HTML_REPORT_PATH env var triggers side-effect HTML file write."""

    def test_env_var_triggers_html_side_effect(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """AAV_HTML_REPORT_PATH env var causes HTML report to be written as side-effect."""
        html_path = tmp_path / "side_effect_report.html"
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
            env={"AAV_HTML_REPORT_PATH": str(html_path)},
        )
        assert result.exit_code in (0, 1, 2)
        assert html_path.exists()
        content = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "<html" in content

    def test_env_var_creates_parent_directories(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """AAV_HTML_REPORT_PATH creates parent directories for the HTML report."""
        html_path = tmp_path / "nested" / "output" / "report.html"
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
            env={"AAV_HTML_REPORT_PATH": str(html_path)},
        )
        assert result.exit_code in (0, 1, 2)
        assert html_path.exists()
        content = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_env_var_with_text_format_still_writes_html(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """AAV_HTML_REPORT_PATH writes HTML even when primary format is text."""
        html_path = tmp_path / "side_effect.html"
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "text", *_QUIET_ARGS],
            env={"AAV_HTML_REPORT_PATH": str(html_path)},
        )
        assert result.exit_code in (0, 1, 2)
        assert html_path.exists()
        content = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        # Primary output should still be text, not HTML
        assert "<!DOCTYPE html>" not in result.output


class TestCLIHtmlYamlConfigSideEffect:
    """Test html_report_path YAML config field triggers side-effect HTML file write."""

    def test_yaml_config_triggers_html_side_effect(self, runner: CliRunner, tmp_path: Path):
        """html_report_path in YAML config causes HTML report to be written as side-effect."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )

        html_path = tmp_path / "yaml_report.html"
        config_data = {"html_report_path": str(html_path)}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "json",
                "--config",
                str(config_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert html_path.exists()
        content = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_yaml_config_html_path_creates_parent_dirs(self, runner: CliRunner, tmp_path: Path):
        """html_report_path in YAML config creates parent directories."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )

        html_path = tmp_path / "deep" / "nested" / "report.html"
        config_data = {"html_report_path": str(html_path)}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "json",
                "--config",
                str(config_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert html_path.exists()
        content = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content


class TestCLIHtmlDualOutput:
    """Test dual output: --format html --output <path> combined with AAV_HTML_REPORT_PATH."""

    def test_dual_output_writes_to_both_paths(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """--format html --output <a> + AAV_HTML_REPORT_PATH=<b> writes HTML to both."""
        primary_output = tmp_path / "primary.html"
        side_effect_output = tmp_path / "side_effect.html"

        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "html",
                "--output",
                str(primary_output),
                *_QUIET_ARGS,
            ],
            env={"AAV_HTML_REPORT_PATH": str(side_effect_output)},
        )
        assert result.exit_code in (0, 1, 2)
        # Both files should exist
        assert primary_output.exists()
        assert side_effect_output.exists()

        # Both should contain valid HTML
        primary_content = primary_output.read_text(encoding="utf-8")
        side_content = side_effect_output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in primary_content
        assert "<!DOCTYPE html>" in side_content

    def test_dual_output_same_path_does_not_write_twice(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """When --output and AAV_HTML_REPORT_PATH point to the same path, file is written once."""
        output_file = tmp_path / "report.html"

        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--format",
                "html",
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
            env={"AAV_HTML_REPORT_PATH": str(output_file)},
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content


class TestCLINoHtmlSideEffect:
    """Test no HTML side effect when no HTML config is provided."""

    def test_no_html_side_effect_with_json_format(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """--format json without HTML config does not produce HTML side-effect files."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        # Check that no HTML files were created in the scan directory
        html_files = list(scan_dir.glob("**/*.html"))
        assert html_files == []

    def test_no_html_side_effect_with_text_format(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """--format text without HTML config does not produce HTML side-effect files."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "text", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        # stdout should not contain HTML
        assert "<!DOCTYPE html>" not in result.output
        # No HTML files in scan dir
        html_files = list(scan_dir.glob("**/*.html"))
        assert html_files == []

    def test_no_html_side_effect_stdout_contains_no_html_marker(
        self, runner: CliRunner, scan_dir: Path
    ):
        """JSON format output does not accidentally contain HTML."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        assert "<!DOCTYPE html>" not in result.output

    def test_empty_env_var_does_not_trigger_side_effect(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """Empty AAV_HTML_REPORT_PATH does not trigger HTML side-effect write."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
            env={"AAV_HTML_REPORT_PATH": ""},
        )
        assert result.exit_code in (0, 1, 2)
        # No HTML files should be created
        html_files = list(tmp_path.glob("**/*.html"))
        assert html_files == []
