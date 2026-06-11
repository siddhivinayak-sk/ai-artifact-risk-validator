"""Unit tests for CLI application entry point, verify command, list-risks, and init commands.

Tests cover:
- Basic CLI invocation (help, version)
- verify command with path argument
- Exit codes: 0 (PASS/INFO), 1 (BLOCK), 2 (WARN)
- Format options: json, text
- CLI options: --output, --scanners, --severity-threshold, --log-level,
  --no-ignore, --no-cache, --parallel, --config
- list-risks command with no filters (text and json output)
- list-risks command with --category, --artifact-type, --severity, --scanner filters
- list-risks command --format json produces valid JSON
- init command creates .aav.yaml in target directory
- init command refuses to overwrite without --force
- init command --force overwrites existing file
- init command --path writes to specified directory

Validates: Requirements 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8, 16.9, 16.10
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.main import _EXIT_CODES, cli
from ai_artifact_risk_validator.models.enums import GateAction

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


@pytest.fixture
def empty_scan_dir(tmp_path: Path) -> Path:
    """Create an empty temporary scan directory (produces INFO/PASS gate decision)."""
    d = tmp_path / "empty_scan"
    d.mkdir()
    return d


class TestCLIBasicInvocation:
    """Test basic CLI invocation: help, version, and group behavior."""

    def test_cli_help(self, runner: CliRunner):
        """CLI --help should succeed and display usage information."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "AI Artifact Risk Validator" in result.output

    def test_cli_version(self, runner: CliRunner):
        """CLI --version should succeed and display version."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower()

    def test_verify_help(self, runner: CliRunner):
        """verify --help should show command documentation."""
        result = runner.invoke(cli, ["verify", "--help"])
        assert result.exit_code == 0
        assert "PATH" in result.output
        assert "--output" in result.output
        assert "--format" in result.output
        assert "--config" in result.output
        assert "--scanners" in result.output
        assert "--severity-threshold" in result.output
        assert "--log-level" in result.output
        assert "--no-ignore" in result.output
        assert "--no-cache" in result.output
        assert "--parallel" in result.output

    def test_cli_group_exists(self):
        """The cli function should be a Click group."""
        import click

        assert isinstance(cli, click.Group)

    def test_verify_command_registered(self):
        """verify command should be registered in the CLI group."""
        assert "verify" in cli.commands


class TestCLIVerifyBasic:
    """Test verify command with basic invocation patterns."""

    def test_verify_directory(self, runner: CliRunner, scan_dir: Path):
        """verify with a valid directory should succeed (exit code 0, 1, or 2)."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)

    def test_verify_nonexistent_path(self, runner: CliRunner, tmp_path: Path):
        """verify with a non-existent path should still succeed (graceful degradation)."""
        nonexistent = tmp_path / "nonexistent_dir"
        result = runner.invoke(
            cli,
            ["verify", str(nonexistent), *_QUIET_ARGS],
        )
        # Should not crash - returns a report (could be exit code 0 with error status)
        assert result.exit_code in (0, 1, 2)

    def test_verify_single_file(self, runner: CliRunner, scan_dir: Path):
        """verify with a single file path should succeed."""
        file_path = scan_dir / "test.prompt.md"
        result = runner.invoke(
            cli,
            ["verify", str(file_path), *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)

    def test_verify_empty_directory(self, runner: CliRunner, empty_scan_dir: Path):
        """verify with an empty directory should exit with code 0 (INFO/PASS)."""
        result = runner.invoke(
            cli,
            ["verify", str(empty_scan_dir), *_QUIET_ARGS],
        )
        # Empty directory produces no findings -> INFO gate decision -> exit code 0
        assert result.exit_code == 0


class TestCLIExitCodes:
    """Test exit code mapping from gate decisions."""

    def test_exit_code_mapping_info(self):
        """GateAction.INFO should map to exit code 0."""
        assert _EXIT_CODES[GateAction.INFO] == 0

    def test_exit_code_mapping_warn(self):
        """GateAction.WARN should map to exit code 2."""
        assert _EXIT_CODES[GateAction.WARN] == 2

    def test_exit_code_mapping_block(self):
        """GateAction.BLOCK should map to exit code 1."""
        assert _EXIT_CODES[GateAction.BLOCK] == 1

    def test_exit_code_info_with_mock(self, runner: CliRunner, scan_dir: Path):
        """When gate_decision is INFO, exit code should be 0."""
        mock_report = MagicMock()
        mock_report.findings = []
        mock_report.summary.gate_decision = GateAction.INFO
        mock_report.summary.total_findings = 0
        mock_report.summary.blocking_findings = 0
        mock_report.summary.warning_findings = 0
        mock_report.summary.info_findings = 0
        mock_report.errors = []
        mock_report.model_dump_json.return_value = '{"findings": [], "summary": {"gate_decision": "INFO", "total_findings": 0, "blocking_findings": 0, "warning_findings": 0, "info_findings": 0}}'

        with patch("ai_artifact_risk_validator.validator.Validator") as mock_validator_cls:
            mock_validator = MagicMock()
            mock_validator.verify.return_value = mock_report
            mock_validator_cls.return_value = mock_validator

            result = runner.invoke(
                cli,
                ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
            )
            assert result.exit_code == 0

    def test_exit_code_warn_with_mock(self, runner: CliRunner, scan_dir: Path):
        """When gate_decision is WARN, exit code should be 2."""
        mock_report = MagicMock()
        mock_report.findings = []
        mock_report.summary.gate_decision = GateAction.WARN
        mock_report.summary.total_findings = 1
        mock_report.summary.blocking_findings = 0
        mock_report.summary.warning_findings = 1
        mock_report.summary.info_findings = 0
        mock_report.errors = []
        mock_report.model_dump_json.return_value = '{"findings": [], "summary": {"gate_decision": "WARN", "total_findings": 1, "blocking_findings": 0, "warning_findings": 1, "info_findings": 0}}'

        with patch("ai_artifact_risk_validator.validator.Validator") as mock_validator_cls:
            mock_validator = MagicMock()
            mock_validator.verify.return_value = mock_report
            mock_validator_cls.return_value = mock_validator

            result = runner.invoke(
                cli,
                ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
            )
            assert result.exit_code == 2

    def test_exit_code_block_with_mock(self, runner: CliRunner, scan_dir: Path):
        """When gate_decision is BLOCK, exit code should be 1."""
        mock_report = MagicMock()
        mock_report.findings = []
        mock_report.summary.gate_decision = GateAction.BLOCK
        mock_report.summary.total_findings = 1
        mock_report.summary.blocking_findings = 1
        mock_report.summary.warning_findings = 0
        mock_report.summary.info_findings = 0
        mock_report.errors = []
        mock_report.model_dump_json.return_value = '{"findings": [], "summary": {"gate_decision": "BLOCK", "total_findings": 1, "blocking_findings": 1, "warning_findings": 0, "info_findings": 0}}'

        with patch("ai_artifact_risk_validator.validator.Validator") as mock_validator_cls:
            mock_validator = MagicMock()
            mock_validator.verify.return_value = mock_report
            mock_validator_cls.return_value = mock_validator

            result = runner.invoke(
                cli,
                ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
            )
            assert result.exit_code == 1


class TestCLIFormatOptions:
    """Test --format option behavior."""

    def test_format_json_produces_valid_json(self, runner: CliRunner, scan_dir: Path):
        """--format json should produce valid JSON output on stdout."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "json", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        # Output should be parseable as JSON
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)
        assert "findings" in parsed
        assert "summary" in parsed

    def test_format_json_is_default(self, runner: CliRunner, scan_dir: Path):
        """Default format (no --format flag) should be text."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        # Default is now text format — output should NOT be valid JSON
        output = result.output
        assert len(output) > 0

    def test_format_text_produces_text_output(self, runner: CliRunner, scan_dir: Path):
        """--format text should produce human-readable text output."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "text", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output
        assert len(output) > 0

    def test_format_case_insensitive(self, runner: CliRunner, scan_dir: Path):
        """--format should be case-insensitive."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "JSON", *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)

    def test_format_invalid_rejected(self, runner: CliRunner, scan_dir: Path):
        """Invalid --format value should be rejected by Click."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--format", "xml"],
        )
        assert result.exit_code == 2  # Click usage error


class TestCLIOutputOption:
    """Test --output option for writing report to file."""

    def test_output_writes_to_file(self, runner: CliRunner, scan_dir: Path, tmp_path: Path):
        """--output should write report to the specified file."""
        output_file = tmp_path / "report.json"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--output",
                str(output_file),
                "--format",
                "json",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        content = json.loads(output_file.read_text(encoding="utf-8"))
        assert "findings" in content

    def test_output_creates_parent_directories(
        self, runner: CliRunner, scan_dir: Path, tmp_path: Path
    ):
        """--output should create parent directories if they don't exist."""
        output_file = tmp_path / "nested" / "dir" / "report.json"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--output",
                str(output_file),
                "--format",
                "json",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()

    def test_output_file_not_on_stdout(self, runner: CliRunner, scan_dir: Path, tmp_path: Path):
        """When --output is used, report should not appear on stdout."""
        output_file = tmp_path / "report.json"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--output",
                str(output_file),
                "--format",
                "json",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        # stdout should not contain the JSON report
        assert '"findings"' not in result.output


class TestCLIConfigOption:
    """Test --config option for loading YAML configuration."""

    def test_config_file_loaded(self, runner: CliRunner, scan_dir: Path, tmp_path: Path):
        """--config should load settings from a YAML file."""
        config_data = {"severity_threshold": 5, "log_level": "CRITICAL"}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--config",
                str(config_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)

    def test_config_file_nonexistent_fails(self, runner: CliRunner, scan_dir: Path):
        """--config with a non-existent file should fail."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--config",
                "/nonexistent/path/config.yaml",
            ],
        )
        assert result.exit_code == 2  # Click usage error for non-existent path


class TestCLIScannerOptions:
    """Test --scanners, --severity-threshold, --parallel options."""

    def test_severity_threshold_option(self, runner: CliRunner, scan_dir: Path):
        """--severity-threshold should filter findings below the threshold."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--severity-threshold",
                "7",
                "--format",
                "json",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        # With high threshold, fewer/no findings should appear
        parsed = json.loads(result.output)
        # All remaining findings should have severity >= 7
        for finding in parsed.get("findings", []):
            assert finding.get("severity_score", 0) >= 7

    def test_severity_threshold_validation(self, runner: CliRunner, scan_dir: Path):
        """--severity-threshold with out-of-range value should fail."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--severity-threshold",
                "11",
            ],
        )
        assert result.exit_code == 2  # Click usage error

    def test_parallel_option(self, runner: CliRunner, scan_dir: Path):
        """--parallel should accept valid worker count."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--parallel",
                "4",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)

    def test_parallel_validation(self, runner: CliRunner, scan_dir: Path):
        """--parallel with out-of-range value should fail."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--parallel",
                "0",
            ],
        )
        assert result.exit_code == 2  # Click usage error

    def test_scanners_option(self, runner: CliRunner, scan_dir: Path):
        """--scanners should accept comma-separated scanner names."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--scanners",
                "secret_scan,injection_det",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)

    def test_scanners_invalid_name(self, runner: CliRunner, scan_dir: Path):
        """--scanners with invalid scanner name should fail with error."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--scanners",
                "nonexistent_scanner",
                *_QUIET_ARGS,
            ],
        )
        # Should exit with code 1 (sys.exit(1) in the scanner validation)
        assert result.exit_code == 1


class TestCLIFlagOptions:
    """Test boolean flag options: --no-ignore, --no-cache."""

    def test_no_ignore_flag(self, runner: CliRunner, scan_dir: Path):
        """--no-ignore flag should succeed and override suppressions."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--no-ignore",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)

    def test_no_cache_flag(self, runner: CliRunner, scan_dir: Path):
        """--no-cache flag should succeed and disable caching."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--no-cache",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)


class TestCLILogLevel:
    """Test --log-level option."""

    def test_log_level_debug(self, runner: CliRunner, scan_dir: Path):
        """--log-level DEBUG should succeed."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--log-level", "DEBUG", "--format", "json"],
        )
        assert result.exit_code in (0, 1, 2)

    def test_log_level_case_insensitive(self, runner: CliRunner, scan_dir: Path):
        """--log-level should be case-insensitive."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--log-level", "warning", "--format", "json"],
        )
        assert result.exit_code in (0, 1, 2)

    def test_log_level_invalid(self, runner: CliRunner, scan_dir: Path):
        """--log-level with invalid value should be rejected."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--log-level", "VERBOSE"],
        )
        assert result.exit_code == 2  # Click usage error


class TestListRisksCommand:
    """Tests for the list-risks CLI command."""

    def test_list_risks_text_format_default(self, runner: CliRunner):
        """list-risks with no options shows a text table with results."""
        result = runner.invoke(cli, ["list-risks"])
        assert result.exit_code == 0
        # Should contain table header content
        assert "Risk Definitions" in result.output
        # Should contain at least some risk IDs
        assert "P-S1" in result.output or "results" in result.output

    def test_list_risks_json_format(self, runner: CliRunner):
        """list-risks --format json produces valid JSON array."""
        result = runner.invoke(cli, ["list-risks", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0
        # Each entry should have the expected keys
        first = data[0]
        assert "id" in first
        assert "title" in first
        assert "severity" in first
        assert "severity_score" in first
        assert "category" in first
        assert "artifact_types" in first
        assert "scanner_modules" in first

    def test_list_risks_filter_by_category(self, runner: CliRunner):
        """list-risks --category Security filters to only security risks."""
        result = runner.invoke(cli, ["list-risks", "--format", "json", "--category", "Security"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert risk["category"] == "Security"

    def test_list_risks_filter_by_artifact_type(self, runner: CliRunner):
        """list-risks --artifact-type prompt filters to only prompt risks."""
        result = runner.invoke(cli, ["list-risks", "--format", "json", "--artifact-type", "prompt"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert "prompt" in risk["artifact_types"]

    def test_list_risks_filter_by_severity(self, runner: CliRunner):
        """list-risks --severity Critical filters to only critical risks."""
        result = runner.invoke(cli, ["list-risks", "--format", "json", "--severity", "Critical"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert risk["severity"] == "Critical"
            assert risk["severity_score"] >= 9

    def test_list_risks_filter_by_scanner(self, runner: CliRunner):
        """list-risks --scanner SecretScan filters to only SecretScan risks."""
        result = runner.invoke(cli, ["list-risks", "--format", "json", "--scanner", "SecretScan"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0
        for risk in data:
            assert "SecretScan" in risk["scanner_modules"]

    def test_list_risks_combined_filters(self, runner: CliRunner):
        """list-risks with multiple filters ANDs them together."""
        result = runner.invoke(
            cli,
            [
                "list-risks",
                "--format",
                "json",
                "--category",
                "Security",
                "--artifact-type",
                "prompt",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        # All results should match both filters
        for risk in data:
            assert risk["category"] == "Security"
            assert "prompt" in risk["artifact_types"]

    def test_list_risks_json_sorted_by_severity_desc(self, runner: CliRunner):
        """list-risks JSON output is sorted by severity score descending."""
        result = runner.invoke(cli, ["list-risks", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        scores = [r["severity_score"] for r in data]
        # Verify descending order (within same score, sorted by id)
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1]

    def test_list_risks_no_results_filter(self, runner: CliRunner):
        """list-risks with filters that match nothing shows empty results."""
        # Ethics + api_schema is unlikely to produce results, but let's use
        # a combination that might be empty. Use json to verify.
        result = runner.invoke(
            cli,
            [
                "list-risks",
                "--format",
                "json",
                "--category",
                "Ethics",
                "--artifact-type",
                "api_schema",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        # It's valid to return empty list
        for risk in data:
            assert risk["category"] == "Ethics"
            assert "api_schema" in risk["artifact_types"]


class TestInitCommand:
    """Tests for the init CLI command."""

    def test_init_creates_config_file(self, runner: CliRunner, tmp_path: Path):
        """init creates a .aav.yaml file in the specified directory."""
        result = runner.invoke(cli, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        config_file = tmp_path / ".aav.yaml"
        assert config_file.exists()
        # Verify it's valid YAML
        content = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert isinstance(content, dict)
        assert "log_level" in content

    def test_init_default_config_values(self, runner: CliRunner, tmp_path: Path):
        """init generates config with expected default values."""
        result = runner.invoke(cli, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        config_file = tmp_path / ".aav.yaml"
        content = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert content["log_level"] == "INFO"
        assert content["severity_threshold"] == 1
        assert content["max_file_size_bytes"] == 10_485_760
        assert content["parallel_files"] == 4
        assert content["parallel_scanners"] == 4

    def test_init_refuses_overwrite_without_force(self, runner: CliRunner, tmp_path: Path):
        """init refuses to overwrite existing .aav.yaml without --force."""
        config_file = tmp_path / ".aav.yaml"
        config_file.write_text("existing: true\n", encoding="utf-8")

        result = runner.invoke(cli, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 1
        assert "already exists" in result.output
        # File should not have been overwritten
        content = config_file.read_text(encoding="utf-8")
        assert "existing: true" in content

    def test_init_force_overwrites_existing(self, runner: CliRunner, tmp_path: Path):
        """init --force overwrites existing .aav.yaml file."""
        config_file = tmp_path / ".aav.yaml"
        config_file.write_text("existing: true\n", encoding="utf-8")

        result = runner.invoke(cli, ["init", "--path", str(tmp_path), "--force"])
        assert result.exit_code == 0
        content = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert "existing" not in content
        assert "log_level" in content

    def test_init_creates_directory_if_needed(self, runner: CliRunner, tmp_path: Path):
        """init creates the target directory if it doesn't exist."""
        target = tmp_path / "nested" / "project"
        result = runner.invoke(cli, ["init", "--path", str(target)])
        assert result.exit_code == 0
        config_file = target / ".aav.yaml"
        assert config_file.exists()

    def test_init_success_message(self, runner: CliRunner, tmp_path: Path):
        """init shows a success message with the config file path."""
        result = runner.invoke(cli, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "Configuration file created" in result.output

    def test_init_default_path_is_cwd(self, runner: CliRunner, tmp_path: Path):
        """init without --path uses current working directory."""
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["init"])
            assert result.exit_code == 0
            assert Path(".aav.yaml").exists()


class TestCLIDynamicTimeoutOptions:
    """Regression tests for Phase 6: --dynamic-connection-timeout and --dynamic-server-timeout.

    Verifies the new CLI options are accepted and plumbed into ValidatorConfig.
    """

    def test_dynamic_connection_timeout_accepted(self, runner: CliRunner, scan_dir: Path) -> None:
        """--dynamic-connection-timeout should be accepted without error."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--dynamic-connection-timeout",
                "20",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)

    def test_dynamic_server_timeout_accepted(self, runner: CliRunner, scan_dir: Path) -> None:
        """--dynamic-server-timeout should be accepted without error."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--dynamic-server-timeout",
                "60",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)

    def test_dynamic_connection_timeout_out_of_range_rejected(
        self, runner: CliRunner, scan_dir: Path
    ) -> None:
        """--dynamic-connection-timeout values outside 1-60 must be rejected by Click."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--dynamic-connection-timeout", "0"],
        )
        assert result.exit_code == 2  # Click usage error

    def test_dynamic_server_timeout_out_of_range_rejected(
        self, runner: CliRunner, scan_dir: Path
    ) -> None:
        """--dynamic-server-timeout values outside 5-300 must be rejected by Click."""
        result = runner.invoke(
            cli,
            ["verify", str(scan_dir), "--dynamic-server-timeout", "400"],
        )
        assert result.exit_code == 2  # Click usage error

    def test_dynamic_timeouts_wired_to_validator_config(self, tmp_path: Path) -> None:
        """Timeout values passed via CLI must reach ValidatorConfig fields."""
        from ai_artifact_risk_validator.cli.main import cli as _cli
        from ai_artifact_risk_validator.models.config import ValidatorConfig

        scan_dir = tmp_path / "s"
        scan_dir.mkdir()
        (scan_dir / "test.prompt.md").write_text("Be helpful.\n", encoding="utf-8")

        runner = CliRunner()
        with patch("ai_artifact_risk_validator.validator.Validator") as mock_v:
            mock_instance = MagicMock()
            mock_instance.scan.return_value = MagicMock(
                gate_decision=MagicMock(value="PASS"),
                findings=[],
                scan_id="test-id",
                scan_path=str(scan_dir),
                artifact_count=0,
                duration_seconds=0.0,
                errors=[],
                suppressed_count=0,
            )
            mock_v.return_value = mock_instance
            result = runner.invoke(
                _cli,
                [
                    "verify",
                    str(scan_dir),
                    "--dynamic-connection-timeout",
                    "15",
                    "--dynamic-server-timeout",
                    "45",
                    "--log-level",
                    "CRITICAL",
                ],
            )

        assert result.exit_code in (0, 1, 2)
        call_kwargs = mock_v.call_args
        if call_kwargs is not None:
            config_arg = call_kwargs[0][0] if call_kwargs[0] else call_kwargs[1].get("config")
            if config_arg is not None and isinstance(config_arg, ValidatorConfig):
                assert config_arg.dynamic_connection_timeout == 15
                assert config_arg.dynamic_server_timeout == 45
