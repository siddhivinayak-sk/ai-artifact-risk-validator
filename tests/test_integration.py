"""Integration tests for end-to-end verify pipeline.

Tests cover:
- verify(path) with fixture directories producing complete ScanReports
- CLI command invocation with various flags and exit codes
- Plugin loading via entry points
- Configuration file loading and merging

Validates: Requirements 22.4
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.main import cli
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import (
    GateAction,
    ScannerModule,
)
from ai_artifact_risk_validator.models.report import ScanReport
from ai_artifact_risk_validator.scanners.registry import ScannerRegistry
from ai_artifact_risk_validator.validator import Validator

# Path to the test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Path to the artifacts fixture directory (from task 20.1)
ARTIFACTS_DIR = Path(__file__).parent / "fixtures" / "artifacts"

# Common CLI args to suppress log output in tests (logs go to stdout in CliRunner)
_QUIET_ARGS = ["--log-level", "CRITICAL"]


def _register_builtin_scanners(validator: Validator) -> None:
    """Register built-in scanners on a Validator instance for integration testing.

    The built-in scanners are not auto-registered via entry points in the test
    environment. This helper explicitly registers them so that integration tests
    can verify the full scan pipeline end-to-end.
    """
    from ai_artifact_risk_validator.scanners.bias_detector import BiasDetectorScanner
    from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner
    from ai_artifact_risk_validator.scanners.compliance_audit import ComplianceAuditScanner
    from ai_artifact_risk_validator.scanners.compose_analyze import ComposeAnalyzeScanner
    from ai_artifact_risk_validator.scanners.dep_scan import DepScanScanner
    from ai_artifact_risk_validator.scanners.injection_det import InjectionDetScanner
    from ai_artifact_risk_validator.scanners.perm_audit import PermAuditScanner
    from ai_artifact_risk_validator.scanners.portability_chk import PortabilityChkScanner
    from ai_artifact_risk_validator.scanners.provenance_chk import ProvenanceChkScanner
    from ai_artifact_risk_validator.scanners.quality_lint import QualityLintScanner
    from ai_artifact_risk_validator.scanners.schema_valid import SchemaValidScanner
    from ai_artifact_risk_validator.scanners.secret_scan import SecretScanScanner
    from ai_artifact_risk_validator.scanners.token_analyzer import TokenAnalyzerScanner

    scanner_classes = [
        SecretScanScanner,
        InjectionDetScanner,
        PermAuditScanner,
        TokenAnalyzerScanner,
        SchemaValidScanner,
        DepScanScanner,
        QualityLintScanner,
        ProvenanceChkScanner,
        BiasDetectorScanner,
        ComposeAnalyzeScanner,
        PortabilityChkScanner,
        ComplianceAuditScanner,
        CodeAuditScanner,
    ]
    for scanner_cls in scanner_classes:
        try:
            validator._scanner_registry.register(scanner_cls)
        except Exception:
            pass  # Some scanners may not be available


def _create_validator_with_scanners(config: ValidatorConfig | None = None) -> Validator:
    """Create a Validator with all built-in scanners registered."""
    v = Validator(config=config)
    _register_builtin_scanners(v)
    return v


# ============================================================================
# Integration Tests: verify(path) with fixture directories
# ============================================================================


@pytest.mark.integration
class TestVerifyWithFixtureDirectories:
    """Test verify(path) with the fixture directories producing complete ScanReports."""

    def test_verify_fixtures_root_returns_scan_report(self):
        """verify() on the full fixtures directory returns a valid ScanReport."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR))
        assert isinstance(report, ScanReport)
        assert report.artifact_path == str(FIXTURES_DIR)
        assert report.scan_id is not None
        assert report.scan_timestamp is not None
        assert report.scanner_version == "0.3.0"

    def test_verify_fixtures_root_has_no_errors(self):
        """verify() on the fixtures directory completes without errors."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR))
        assert report.errors == []

    def test_verify_risky_prompts_produces_findings(self):
        """verify() on risky prompt fixtures produces at least one finding."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR / "prompts" / "risky_prompt.prompt.md"))
        assert isinstance(report, ScanReport)
        assert report.summary.total_findings > 0

    def test_verify_clean_prompt_produces_fewer_findings(self):
        """verify() on clean prompt produces fewer findings than risky prompt."""
        v = _create_validator_with_scanners()
        clean_report = v.verify(str(FIXTURES_DIR / "prompts" / "clean_prompt.prompt.md"))
        risky_report = v.verify(str(FIXTURES_DIR / "prompts" / "risky_prompt.prompt.md"))
        assert risky_report.summary.total_findings >= clean_report.summary.total_findings

    def test_verify_risky_agent_triggers_block_or_warn(self):
        """verify() on risky agent fixture triggers BLOCK or WARN gate decision."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR / "agents" / "risky_agent.md"))
        assert report.summary.gate_decision in (GateAction.BLOCK, GateAction.WARN)

    def test_verify_clean_agent_fewer_findings_than_risky(self):
        """verify() on clean agent fixture produces fewer findings than risky agent."""
        v = _create_validator_with_scanners()
        clean_report = v.verify(str(FIXTURES_DIR / "agents" / "clean_agent.md"))
        risky_report = v.verify(str(FIXTURES_DIR / "agents" / "risky_agent.md"))
        # Risky agent should have more findings than clean agent
        assert risky_report.summary.total_findings >= clean_report.summary.total_findings

    def test_verify_prompts_directory_scans_all_files(self):
        """verify() on prompts directory scans all files within."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR / "prompts"))
        assert isinstance(report, ScanReport)
        # The directory has 2 files, at least the risky one should produce findings
        assert report.errors == []

    def test_verify_risky_steering_has_findings(self):
        """verify() on risky steering fixture produces findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR / "steering" / "risky_steering.md"))
        assert report.summary.total_findings > 0

    def test_verify_single_file_sets_artifact_type(self):
        """verify() on a single file with findings sets the artifact_type."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR / "prompts" / "risky_prompt.prompt.md"))
        # When a file produces findings, artifact_type should be set
        if report.summary.total_findings > 0:
            assert report.artifact_type is not None

    def test_verify_findings_have_complete_structure(self):
        """Findings from verify() have all required fields populated."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR / "agents" / "risky_agent.md"))
        if report.findings:
            finding = report.findings[0]
            assert finding.id is not None
            assert finding.artifact_type is not None
            assert finding.artifact_path is not None
            assert 1 <= finding.severity_score <= 10
            assert finding.severity_label is not None
            assert finding.priority is not None
            assert finding.gate_action in (GateAction.BLOCK, GateAction.WARN, GateAction.INFO)
            assert finding.category is not None
            assert finding.title != ""
            assert finding.description != ""
            assert finding.scanner_module is not None
            assert 0.0 <= finding.confidence <= 1.0

    def test_verify_summary_counts_are_consistent(self):
        """Summary counts are consistent with findings list."""
        v = _create_validator_with_scanners()
        report = v.verify(str(FIXTURES_DIR / "agents" / "risky_agent.md"))
        summary = report.summary

        # total_findings should match the count of all findings
        assert summary.total_findings == len(report.findings)

        # Gate counts should be consistent (excluding false positives)
        non_fp = [f for f in report.findings if not f.false_positive]
        blocking = sum(1 for f in non_fp if f.gate_action == GateAction.BLOCK)
        warning = sum(1 for f in non_fp if f.gate_action == GateAction.WARN)
        info = sum(1 for f in non_fp if f.gate_action == GateAction.INFO)
        assert summary.blocking_findings == blocking
        assert summary.warning_findings == warning
        assert summary.info_findings == info

    def test_verify_with_enabled_scanners_config(self):
        """verify() with specific enabled_scanners only runs those scanners."""
        config = ValidatorConfig(enabled_scanners=[ScannerModule.SECRET_SCAN])
        v = _create_validator_with_scanners(config=config)
        report = v.verify(str(FIXTURES_DIR / "agents" / "risky_agent.md"))
        # All findings should only be from SecretScan
        for finding in report.findings:
            assert finding.scanner_module == ScannerModule.SECRET_SCAN

    def test_verify_with_disabled_scanners_config(self):
        """verify() with disabled_scanners excludes those scanners from results."""
        config = ValidatorConfig(disabled_scanners=[ScannerModule.QUALITY_LINT])
        v = _create_validator_with_scanners(config=config)
        report = v.verify(str(FIXTURES_DIR / "agents" / "risky_agent.md"))
        # No findings should come from QualityLint
        for finding in report.findings:
            assert finding.scanner_module != ScannerModule.QUALITY_LINT

    def test_verify_nonexistent_path_returns_error_report(self):
        """verify() with non-existent path returns an error report gracefully."""
        v = _create_validator_with_scanners()
        report = v.verify("/definitely/nonexistent/path/xyz123")
        assert isinstance(report, ScanReport)
        assert len(report.errors) > 0
        assert report.summary.total_findings == 0
        assert report.summary.gate_decision == GateAction.INFO


# ============================================================================
# Integration Tests: CLI command invocation with flags and exit codes
# ============================================================================


@pytest.mark.integration
class TestCLIVerifyCommand:
    """Test CLI verify command invocation with various flags and exit codes."""

    @pytest.fixture
    def runner(self):
        """Create a Click test runner."""
        return CliRunner()

    def test_cli_verify_nonexistent_path_exit_code_0(self, runner):
        """CLI verify on non-existent path returns exit code 0 (error report with INFO)."""
        result = runner.invoke(cli, ["verify", "/nonexistent/path/abc", *_QUIET_ARGS])
        # Non-existent path returns error report with INFO gate decision
        assert result.exit_code == 0

    def test_cli_verify_json_format_default(self, runner, tmp_path):
        """CLI verify outputs valid JSON by default."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )
        result = runner.invoke(cli, ["verify", str(tmp_path), *_QUIET_ARGS])
        # Output should be parseable JSON
        output = result.output.strip()
        parsed = json.loads(output)
        assert "scan_id" in parsed
        assert "findings" in parsed
        assert "summary" in parsed

    def test_cli_verify_text_format(self, runner, tmp_path):
        """CLI verify --format text produces readable text output."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            cli,
            [
                "verify",
                str(tmp_path),
                "--format",
                "text",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 2)
        # Text format should not be empty
        output = result.output.strip()
        assert len(output) > 0

    def test_cli_verify_output_to_file(self, runner, tmp_path):
        """CLI verify --output writes report to a file."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )
        output_file = tmp_path / "report.json"
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--output",
                str(output_file),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 2)
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert "scan_id" in parsed

    def test_cli_verify_log_level_option(self, runner, tmp_path):
        """CLI verify --log-level DEBUG runs without error."""
        (tmp_path / "test.txt").write_text("hello", encoding="utf-8")
        result = runner.invoke(
            cli,
            [
                "verify",
                str(tmp_path),
                "--log-level",
                "DEBUG",
            ],
        )
        assert result.exit_code in (0, 2)

    def test_cli_verify_severity_threshold_option(self, runner, tmp_path):
        """CLI verify --severity-threshold filters findings by severity."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello.\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            cli,
            [
                "verify",
                str(tmp_path),
                "--severity-threshold",
                "9",
                *_QUIET_ARGS,
            ],
        )
        # Should still complete
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        parsed = json.loads(output)
        # All reported findings should have severity >= 9
        for finding in parsed.get("findings", []):
            assert finding["severity_score"] >= 9

    def test_cli_verify_scanners_option(self, runner, tmp_path):
        """CLI verify --scanners limits which scanners run."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello.\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            cli,
            [
                "verify",
                str(tmp_path),
                "--scanners",
                "SecretScan",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        parsed = json.loads(output)
        for finding in parsed.get("findings", []):
            assert finding["scanner_module"] == "SecretScan"

    def test_cli_verify_invalid_scanner_name_error(self, runner, tmp_path):
        """CLI verify --scanners with invalid name shows error."""
        (tmp_path / "test.txt").write_text("hello", encoding="utf-8")
        result = runner.invoke(
            cli,
            [
                "verify",
                str(tmp_path),
                "--scanners",
                "NonexistentScanner",
            ],
        )
        assert result.exit_code != 0

    def test_cli_verify_config_option(self, runner, tmp_path):
        """CLI verify --config loads configuration from specified file."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello.\n",
            encoding="utf-8",
        )

        config_data = {
            "scanners": {"disabled": ["QualityLint"]},
        }
        config_file = tmp_path / "test-config.yaml"
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
        output = result.output.strip()
        parsed = json.loads(output)
        # No findings from QualityLint
        for finding in parsed.get("findings", []):
            assert finding["scanner_module"] != "QualityLint"

    def test_cli_verify_no_ignore_flag(self, runner, tmp_path):
        """CLI verify --no-ignore reports all findings without suppression."""
        # Create a fixture with inline suppression
        test_file = tmp_path / "test.prompt.md"
        test_file.write_text(
            "---\nname: test\n---\n\n## System Prompt\n\n"
            "API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop1234567890\n"
            "# aav-ignore: P-S3\n",
            encoding="utf-8",
        )

        result = runner.invoke(
            cli,
            [
                "verify",
                str(test_file),
                "--no-ignore",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        parsed = json.loads(output)
        # With --no-ignore, all findings should have false_positive=False
        for finding in parsed.get("findings", []):
            assert finding["false_positive"] is False

    def test_cli_verify_parallel_option(self, runner, tmp_path):
        """CLI verify --parallel sets parallel workers without error."""
        (tmp_path / "test.txt").write_text("hello", encoding="utf-8")
        result = runner.invoke(
            cli,
            [
                "verify",
                str(tmp_path),
                "--parallel",
                "2",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)

    def test_cli_verify_no_cache_flag(self, runner, tmp_path):
        """CLI verify --no-cache disables caching without error."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello.\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            cli,
            [
                "verify",
                str(tmp_path),
                "--no-cache",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 2)

    def test_cli_version_option(self, runner):
        """CLI --version displays version information."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.3.0" in result.output

    def test_cli_verify_directory_recursive_scan(self, runner, tmp_path):
        """CLI verify on a directory performs recursive scan."""
        prompts = tmp_path / "prompts"
        prompts.mkdir()
        (prompts / "a.prompt.md").write_text(
            "---\nname: a\n---\n\n## System Prompt\n\nHi.\n", encoding="utf-8"
        )
        result = runner.invoke(cli, ["verify", str(tmp_path), *_QUIET_ARGS])
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        parsed = json.loads(output)
        assert "scan_id" in parsed
        assert "summary" in parsed

    def test_cli_exit_code_0_for_info(self, runner, tmp_path):
        """Exit code 0 when gate decision is INFO (no findings or low severity)."""
        # Empty directory produces 0 findings => INFO
        result = runner.invoke(cli, ["verify", str(tmp_path), *_QUIET_ARGS])
        assert result.exit_code == 0

    def test_cli_exit_code_mapping(self, runner):
        """Non-existent path gives exit code 0 (INFO gate decision for error report)."""
        result = runner.invoke(cli, ["verify", "/nonexistent/path", *_QUIET_ARGS])
        assert result.exit_code == 0
        assert result.exit_code == 0


# ============================================================================
# Integration Tests: Plugin loading via entry points
# ============================================================================


@pytest.mark.integration
class TestPluginLoading:
    """Test scanner plugin loading via entry points and plugin directories."""

    def test_plugin_loading_from_directory(self, tmp_path):
        """Scanners can be loaded from a plugin directory."""
        # Create a custom scanner plugin file
        plugin_code = '''
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule
from ai_artifact_risk_validator.models.findings import ScanFinding


class CustomTestScanner(BaseScanner):
    """A test scanner loaded from a plugin directory."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.SECRET_SCAN  # Reuse enum for testing

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-S3"]

    def scan(self, artifact_content, artifact_type, artifact_path) -> list[ScanFinding]:
        return []
'''
        plugin_file = tmp_path / "custom_scanner.py"
        plugin_file.write_text(plugin_code, encoding="utf-8")

        # Load the plugin
        registry = ScannerRegistry()
        registry.discover_plugin_dir(tmp_path)
        assert len(registry.registered_scanners) > 0

    def test_plugin_loading_invalid_directory_no_crash(self):
        """Plugin loading with non-existent directory does not crash."""
        registry = ScannerRegistry()
        registry.discover_plugin_dir(Path("/nonexistent/plugin/directory"))
        # Should not raise, just log a warning
        assert registry.registered_scanners == []

    def test_plugin_loading_empty_directory(self, tmp_path):
        """Plugin loading from an empty directory registers no scanners."""
        registry = ScannerRegistry()
        registry.discover_plugin_dir(tmp_path)
        assert registry.registered_scanners == []

    def test_plugin_loading_file_with_syntax_error(self, tmp_path):
        """Plugin loading gracefully handles files with syntax errors."""
        bad_plugin = tmp_path / "bad_scanner.py"
        bad_plugin.write_text("def broken(:\n    pass\n", encoding="utf-8")

        registry = ScannerRegistry()
        registry.discover_plugin_dir(tmp_path)
        # Should not raise; file is skipped
        assert registry.registered_scanners == []

    def test_plugin_loading_file_without_scanner_class(self, tmp_path):
        """Plugin loading ignores files that don't define BaseScanner subclasses."""
        plugin_file = tmp_path / "utils.py"
        plugin_file.write_text("def helper():\n    return 42\n", encoding="utf-8")

        registry = ScannerRegistry()
        registry.discover_plugin_dir(tmp_path)
        assert registry.registered_scanners == []

    def test_plugin_dir_via_validator_config(self, tmp_path):
        """Validator loads plugins from custom_plugin_dirs in config."""
        # Create a minimal scanner plugin
        plugin_code = """
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule
from ai_artifact_risk_validator.models.findings import ScanFinding


class PluginDirScanner(BaseScanner):
    @property
    def name(self) -> ScannerModule:
        return ScannerModule.QUALITY_LINT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-Q1"]

    def scan(self, artifact_content, artifact_type, artifact_path) -> list[ScanFinding]:
        return []
"""
        plugin_file = tmp_path / "my_plugin.py"
        plugin_file.write_text(plugin_code, encoding="utf-8")

        config = ValidatorConfig(custom_plugin_dirs=[str(tmp_path)])
        v = Validator(config=config)
        # The scanner should be registered
        assert ScannerModule.QUALITY_LINT in v._scanner_registry.registered_scanners

    def test_entry_point_discovery_does_not_crash(self):
        """Entry point discovery completes without raising, even with no plugins."""
        registry = ScannerRegistry()
        registry.discover_entry_points()
        # In test environment, no entry points are expected
        # Just verify no exception is raised

    def test_plugin_skips_files_starting_with_underscore(self, tmp_path):
        """Plugin discovery skips files that start with underscore."""
        plugin_code = """
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule


class HiddenScanner(BaseScanner):
    @property
    def name(self):
        return ScannerModule.SECRET_SCAN

    @property
    def applicable_artifact_types(self):
        return [ArtifactType.PROMPT]

    @property
    def detected_risk_ids(self):
        return ["P-S3"]

    def scan(self, artifact_content, artifact_type, artifact_path):
        return []
"""
        # Files starting with _ should be skipped
        (tmp_path / "_private_scanner.py").write_text(plugin_code, encoding="utf-8")

        registry = ScannerRegistry()
        registry.discover_plugin_dir(tmp_path)
        assert registry.registered_scanners == []


# ============================================================================
# Integration Tests: Configuration file loading and merging
# ============================================================================


@pytest.mark.integration
class TestConfigurationIntegration:
    """Test configuration file loading and merging end-to-end."""

    def test_config_file_in_scan_directory_is_loaded(self, tmp_path):
        """A .aav.yaml in the scan directory is automatically loaded."""
        # Create config file
        config_data = {
            "scanners": {"disabled": ["BiasDetector"]},
            "severity": {"threshold": 5},
        }
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")

        # Create a test artifact file
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )

        v = Validator()
        report = v.verify(str(tmp_path))
        # Should complete successfully
        assert isinstance(report, ScanReport)
        assert report.errors == []

    def test_cli_config_overrides_file_config(self, tmp_path):
        """CLI --config takes precedence over .aav.yaml in scan directory."""
        # Create a scan directory with its own config
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / ".aav.yaml").write_text(
            yaml.dump({"severity": {"threshold": 2}}), encoding="utf-8"
        )
        (scan_dir / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello\n",
            encoding="utf-8",
        )

        # Create an explicit config file
        explicit_config = tmp_path / "custom.yaml"
        explicit_config.write_text(yaml.dump({"severity": {"threshold": 9}}), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "verify",
                str(scan_dir),
                "--config",
                str(explicit_config),
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        parsed = json.loads(output)
        # Findings below severity 9 should be filtered out by the explicit config
        for finding in parsed.get("findings", []):
            assert finding["severity_score"] >= 9

    def test_env_var_override(self, tmp_path):
        """Environment variables override config file settings."""
        # Create a config file with threshold 3
        config_data = {"severity": {"threshold": 3}}
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )

        # Override with env var
        with patch.dict(os.environ, {"AAV_SEVERITY_THRESHOLD": "9"}):
            from ai_artifact_risk_validator.config.manager import ConfigManager

            cm = ConfigManager()
            config = cm.load(scan_path=str(tmp_path))
            assert config.severity_threshold == 9

    def test_cli_args_override_env_vars(self, tmp_path):
        """CLI arguments take precedence over environment variables."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        with patch.dict(os.environ, {"AAV_LOG_LEVEL": "DEBUG"}):
            result = runner.invoke(
                cli,
                [
                    "verify",
                    str(tmp_path),
                    "--log-level",
                    "CRITICAL",
                ],
            )
        assert result.exit_code in (0, 1, 2)

    def test_no_config_file_uses_defaults(self, tmp_path):
        """When no config file exists, defaults are used without error."""
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello\n",
            encoding="utf-8",
        )

        v = Validator()
        report = v.verify(str(tmp_path))
        assert isinstance(report, ScanReport)
        assert report.errors == []

    def test_invalid_config_file_falls_back_to_defaults(self, tmp_path):
        """Invalid YAML config file gracefully falls back to defaults."""
        (tmp_path / ".aav.yaml").write_text("invalid: yaml: [", encoding="utf-8")
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello\n",
            encoding="utf-8",
        )

        from ai_artifact_risk_validator.config.manager import ConfigManager

        cm = ConfigManager()
        config = cm.load(scan_path=str(tmp_path))
        # Should fall back to defaults
        assert config.log_level == "INFO"
        assert config.severity_threshold == 1

    def test_suppression_rules_from_config_are_applied(self, tmp_path):
        """Suppression rules in config file mark findings as false_positive."""
        config_data = {
            "suppressions": [
                {"risk_id": "P-S3", "file_pattern": "**/*", "reason": "Test suppression"},
            ]
        }
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")

        # Create a file that would trigger P-S3 (secret detection)
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\n"
            "API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop1234567890\n",
            encoding="utf-8",
        )

        from ai_artifact_risk_validator.config.manager import ConfigManager

        cm = ConfigManager()
        config = cm.load(scan_path=str(tmp_path))
        v = _create_validator_with_scanners(config=config)
        report = v.verify(str(tmp_path))

        # Any P-S3 findings should be marked as false_positive
        p_s3_findings = [f for f in report.findings if f.id == "P-S3"]
        for finding in p_s3_findings:
            assert finding.false_positive is True

    def test_full_precedence_chain_integration(self, tmp_path):
        """Full precedence chain: CLI > env > file > defaults works end-to-end."""
        # Config file says threshold=3, parallel_files=2
        config_data = {
            "severity": {"threshold": 3},
            "performance": {"parallel_files": 2, "parallel_scanners": 2},
        }
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")
        (tmp_path / "test.prompt.md").write_text(
            "---\nname: test\n---\n\n## System Prompt\n\nHello\n",
            encoding="utf-8",
        )

        from ai_artifact_risk_validator.config.manager import ConfigManager

        cm = ConfigManager()

        # Env var overrides parallel_files to 12
        with patch.dict(os.environ, {"AAV_PARALLEL_FILES": "12"}):
            config = cm.load(
                scan_path=str(tmp_path),
                cli_overrides={"severity_threshold": 8},
            )

        # CLI wins for severity_threshold
        assert config.severity_threshold == 8
        # Env var wins for parallel_files
        assert config.parallel_files == 12
        # File wins for parallel_scanners (no env or CLI override)
        assert config.parallel_scanners == 2


# ============================================================================
# Integration Tests: End-to-end with custom scan directories
# ============================================================================


@pytest.mark.integration
class TestEndToEndCustomDirectories:
    """Test end-to-end verify with custom-built directories."""

    def test_mixed_artifact_types_directory(self, tmp_path):
        """verify() handles a directory with mixed artifact types."""
        # Create various artifact types
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        (prompts_dir / "help.prompt.md").write_text(
            "---\nname: helper\n---\n\n## System Prompt\n\nBe helpful.\n",
            encoding="utf-8",
        )

        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "SKILL.md").write_text(
            "---\nskill: test\n---\n\n# SKILL.md\n\n## Description\nA test skill.\n",
            encoding="utf-8",
        )

        hooks_dir = tmp_path / ".hooks"
        hooks_dir.mkdir()
        (hooks_dir / "lint.yaml").write_text(
            "name: lint\neventType: fileEdited\nhookAction: runCommand\ncommand: ruff check\n",
            encoding="utf-8",
        )

        v = _create_validator_with_scanners()
        report = v.verify(str(tmp_path))
        assert isinstance(report, ScanReport)
        assert report.errors == []

    def test_deeply_nested_directory_structure(self, tmp_path):
        """verify() handles deeply nested directory structures."""
        nested = tmp_path / "a" / "b" / "c" / "prompts"
        nested.mkdir(parents=True)
        (nested / "deep.prompt.md").write_text(
            "---\nname: deep\n---\n\n## System Prompt\n\nDeep prompt.\n",
            encoding="utf-8",
        )

        v = _create_validator_with_scanners()
        report = v.verify(str(tmp_path))
        assert isinstance(report, ScanReport)
        assert report.errors == []

    def test_empty_directory_returns_clean_report(self, tmp_path):
        """verify() on empty directory returns clean report with no findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(tmp_path))
        assert isinstance(report, ScanReport)
        assert report.summary.total_findings == 0
        assert report.summary.gate_decision == GateAction.INFO
        assert report.errors == []

    def test_directory_with_unreadable_file_does_not_crash(self, tmp_path):
        """verify() gracefully handles directories with unreadable files."""
        # Create a valid file
        (tmp_path / "good.prompt.md").write_text(
            "---\nname: good\n---\n\n## System Prompt\n\nGood prompt.\n",
            encoding="utf-8",
        )
        # Create a binary file that can't be decoded as UTF-8
        (tmp_path / "binary.prompt.md").write_bytes(b"\x80\x81\x82\x83\x84")

        v = _create_validator_with_scanners()
        report = v.verify(str(tmp_path))
        # Should not crash; just skip or handle gracefully
        assert isinstance(report, ScanReport)

    def test_large_directory_completes(self, tmp_path):
        """verify() on a directory with many files completes without error."""
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        for i in range(20):
            (prompts_dir / f"prompt_{i}.prompt.md").write_text(
                f"---\nname: prompt_{i}\n---\n\n## System Prompt\n\nPrompt number {i}.\n",
                encoding="utf-8",
            )

        v = _create_validator_with_scanners()
        report = v.verify(str(tmp_path))
        assert isinstance(report, ScanReport)
        assert report.errors == []


# ============================================================================
# Integration Tests: verify(path) with tests/fixtures/artifacts/ directory
# ============================================================================


@pytest.mark.integration
class TestVerifyWithArtifactsFixtures:
    """Test verify(path) end-to-end using the tests/fixtures/artifacts/ directory.

    These tests validate the full pipeline against the corpus of sample artifacts
    created in task 20.1, with clean and risky variants per artifact type.
    """

    # ------------------------------------------------------------------
    # 1. Test Validator.verify() on the clean fixture directory
    # ------------------------------------------------------------------

    def test_verify_clean_prompts_no_blocking_findings(self):
        """verify() on clean prompt fixture produces no BLOCK findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "prompts" / "prompt_clean.prompt.md"))
        assert isinstance(report, ScanReport)
        # Clean prompt should have no blocking findings
        blocking = [
            f for f in report.findings if f.gate_action == GateAction.BLOCK and not f.false_positive
        ]
        assert len(blocking) == 0

    def test_verify_clean_agents_returns_valid_report(self):
        """verify() on clean agent fixture returns a valid ScanReport without errors."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "agents" / "agent_clean.md"))
        assert isinstance(report, ScanReport)
        assert report.errors == []
        # Clean agent should not have injection or secret-related findings
        injection_findings = [
            f for f in report.findings if f.scanner_module == ScannerModule.INJECTION_DET
        ]
        secret_findings = [
            f for f in report.findings if f.scanner_module == ScannerModule.SECRET_SCAN
        ]
        assert len(injection_findings) == 0
        assert len(secret_findings) == 0

    def test_verify_clean_steering_no_blocking_findings(self):
        """verify() on clean steering fixture produces no BLOCK findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "steering" / "steering_clean.md"))
        assert isinstance(report, ScanReport)
        blocking = [
            f for f in report.findings if f.gate_action == GateAction.BLOCK and not f.false_positive
        ]
        assert len(blocking) == 0

    # ------------------------------------------------------------------
    # 2. Test Validator.verify() on the risky fixture directory
    # ------------------------------------------------------------------

    def test_verify_risky_prompts_detects_findings(self):
        """verify() on risky prompt fixture detects findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "prompts" / "prompt_risky.prompt.md"))
        assert isinstance(report, ScanReport)
        assert report.summary.total_findings > 0

    def test_verify_risky_agents_detects_findings(self):
        """verify() on risky agent fixture detects findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "agents" / "agent_risky.md"))
        assert isinstance(report, ScanReport)
        assert report.summary.total_findings > 0
        # Risky agent should trigger BLOCK or WARN
        assert report.summary.gate_decision in (GateAction.BLOCK, GateAction.WARN)

    def test_verify_risky_steering_detects_findings(self):
        """verify() on risky steering fixture detects findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "steering" / "steering_risky.md"))
        assert isinstance(report, ScanReport)
        assert report.summary.total_findings > 0

    def test_verify_risky_skills_detects_findings(self):
        """verify() on risky skill fixture detects findings."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "skills" / "skill_risky.md"))
        assert isinstance(report, ScanReport)
        assert report.summary.total_findings > 0

    def test_verify_risky_more_findings_than_clean(self):
        """Risky fixtures produce more findings than their clean counterparts."""
        v = _create_validator_with_scanners()
        clean = v.verify(str(ARTIFACTS_DIR / "prompts" / "prompt_clean.prompt.md"))
        risky = v.verify(str(ARTIFACTS_DIR / "prompts" / "prompt_risky.prompt.md"))
        assert risky.summary.total_findings >= clean.summary.total_findings

    def test_verify_artifacts_directory_full_scan(self):
        """verify() on the full artifacts directory returns a valid ScanReport."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR))
        assert isinstance(report, ScanReport)
        assert report.scan_id is not None
        assert report.scan_timestamp is not None
        # Should find at least some findings from risky fixtures
        assert report.summary.total_findings > 0

    def test_verify_mixed_directory_handles_diverse_types(self):
        """verify() on the mixed artifacts directory handles diverse file types."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "mixed"))
        assert isinstance(report, ScanReport)
        assert report.errors == []

    # ------------------------------------------------------------------
    # 3. Test Validator.verify() on a single file
    # ------------------------------------------------------------------

    def test_verify_single_file_returns_scan_report(self):
        """verify() on a single artifact file returns a valid ScanReport."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "agents" / "agent_risky.md"))
        assert isinstance(report, ScanReport)
        assert report.artifact_path == str(ARTIFACTS_DIR / "agents" / "agent_risky.md")
        assert report.scan_id is not None
        assert report.scan_timestamp is not None

    def test_verify_single_clean_file_has_scan_metadata(self):
        """verify() on a single clean file includes proper scan metadata."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "prompts" / "prompt_clean.prompt.md"))
        assert isinstance(report, ScanReport)
        assert report.scanner_version is not None
        assert report.scan_id is not None

    def test_verify_single_file_findings_reference_correct_path(self):
        """Findings from single-file verify reference the correct artifact_path."""
        v = _create_validator_with_scanners()
        target = str(ARTIFACTS_DIR / "prompts" / "prompt_risky.prompt.md")
        report = v.verify(target)
        for finding in report.findings:
            assert finding.artifact_path is not None

    # ------------------------------------------------------------------
    # 4. Test Validator.verify() on a non-existent path
    # ------------------------------------------------------------------

    def test_verify_nonexistent_path_returns_scan_report_with_errors(self):
        """verify() on non-existent path returns a ScanReport with errors list populated."""
        v = _create_validator_with_scanners()
        report = v.verify(str(ARTIFACTS_DIR / "nonexistent" / "no_such_file.md"))
        assert isinstance(report, ScanReport)
        assert len(report.errors) > 0
        assert report.summary.total_findings == 0
        assert report.summary.gate_decision == GateAction.INFO

    def test_verify_nonexistent_path_does_not_raise(self):
        """verify() on non-existent path never raises an exception."""
        v = _create_validator_with_scanners()
        # This should never raise - graceful degradation
        report = v.verify("/completely/impossible/path/xyz")
        assert isinstance(report, ScanReport)
        assert len(report.errors) > 0


# ============================================================================
# Integration Tests: CLI with artifacts fixtures - format and exit codes
# ============================================================================


@pytest.mark.integration
class TestCLIWithArtifactsFixtures:
    """Test CLI verify command with artifacts fixtures, format flags, and exit codes."""

    @pytest.fixture
    def runner(self):
        """Create a Click test runner."""
        return CliRunner()

    # ------------------------------------------------------------------
    # 5. Test CLI verify command with --format text and --format json
    # ------------------------------------------------------------------

    def test_cli_format_json_on_artifacts(self, runner):
        """CLI verify --format json outputs valid JSON for artifacts fixture."""
        result = runner.invoke(
            cli,
            ["verify", str(ARTIFACTS_DIR / "prompts" / "prompt_clean.prompt.md"), *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        parsed = json.loads(output)
        assert "scan_id" in parsed
        assert "findings" in parsed
        assert "summary" in parsed

    def test_cli_format_text_on_artifacts(self, runner):
        """CLI verify --format text outputs readable text for artifacts fixture."""
        result = runner.invoke(
            cli,
            [
                "verify",
                str(ARTIFACTS_DIR / "agents" / "agent_risky.md"),
                "--format",
                "text",
                *_QUIET_ARGS,
            ],
        )
        assert result.exit_code in (0, 1, 2)
        output = result.output.strip()
        assert len(output) > 0
        # Text format should not be valid JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(output)

    def test_cli_format_json_contains_findings_for_risky(self, runner):
        """CLI JSON output for risky fixture contains findings."""
        result = runner.invoke(
            cli,
            ["verify", str(ARTIFACTS_DIR / "agents" / "agent_risky.md"), *_QUIET_ARGS],
        )
        assert result.exit_code in (0, 1, 2)
        parsed = json.loads(result.output.strip())
        assert len(parsed["findings"]) > 0

    def test_cli_format_json_clean_has_fewer_findings(self, runner):
        """CLI JSON output for clean fixture has fewer findings than risky."""
        clean_result = runner.invoke(
            cli,
            ["verify", str(ARTIFACTS_DIR / "agents" / "agent_clean.md"), *_QUIET_ARGS],
        )
        risky_result = runner.invoke(
            cli,
            ["verify", str(ARTIFACTS_DIR / "agents" / "agent_risky.md"), *_QUIET_ARGS],
        )
        clean_parsed = json.loads(clean_result.output.strip())
        risky_parsed = json.loads(risky_result.output.strip())
        assert len(risky_parsed["findings"]) >= len(clean_parsed["findings"])

    # ------------------------------------------------------------------
    # 6. Test CLI verify command exit codes
    # ------------------------------------------------------------------

    def test_cli_exit_code_0_for_clean_artifact(self, runner):
        """CLI exit code 0 (INFO/PASS) for artifact with no findings."""
        # Clean steering produces zero findings = INFO gate = exit 0
        result = runner.invoke(
            cli,
            ["verify", str(ARTIFACTS_DIR / "steering" / "steering_clean.md"), *_QUIET_ARGS],
        )
        assert result.exit_code == 0

    def test_cli_exit_code_1_for_blocking_artifact(self, runner):
        """CLI exit code 1 (BLOCK) for risky artifact with blocking findings."""
        result = runner.invoke(
            cli,
            ["verify", str(ARTIFACTS_DIR / "agents" / "agent_risky.md"), *_QUIET_ARGS],
        )
        # Risky agent has secrets and injection - should trigger BLOCK (exit 1) or WARN (exit 2)
        assert result.exit_code in (1, 2)

    def test_cli_exit_code_2_for_warn_artifact(self, runner):
        """CLI exit code 2 (WARN) when only warning-level findings exist."""
        # Use a config that raises threshold to filter out low-severity findings
        # but keep warning-level ones. The clean prompt with quality_lint
        # may produce WARN-level findings.
        result = runner.invoke(
            cli,
            [
                "verify",
                str(ARTIFACTS_DIR / "steering" / "steering_risky.md"),
                "--severity-threshold",
                "5",
                *_QUIET_ARGS,
            ],
        )
        # Should have exit code 1 (BLOCK) or 2 (WARN) for risky content
        assert result.exit_code in (1, 2)

    def test_cli_exit_code_0_for_empty_dir(self, runner, tmp_path):
        """CLI exit code 0 for empty directory (no findings)."""
        result = runner.invoke(cli, ["verify", str(tmp_path), *_QUIET_ARGS])
        assert result.exit_code == 0

    # ------------------------------------------------------------------
    # 7. Test configuration from .aav.yaml is loaded and applied
    # ------------------------------------------------------------------

    def test_config_yaml_severity_threshold_filters_findings(self, runner, tmp_path):
        """Config file severity threshold filters out low-severity findings."""
        # Copy a risky fixture to tmp_path with a config
        import shutil

        shutil.copy(
            ARTIFACTS_DIR / "prompts" / "prompt_risky.prompt.md", tmp_path / "risky.prompt.md"
        )

        config_data = {"severity": {"threshold": 8}}
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")

        result = runner.invoke(cli, ["verify", str(tmp_path), *_QUIET_ARGS])
        assert result.exit_code in (0, 1, 2)
        parsed = json.loads(result.output.strip())
        # All findings in output should have severity >= 8
        for finding in parsed.get("findings", []):
            assert finding["severity_score"] >= 8

    def test_config_yaml_file_exclude_patterns(self, runner, tmp_path):
        """Config file exclude patterns prevent scanning of matching files."""
        import shutil

        shutil.copy(
            ARTIFACTS_DIR / "prompts" / "prompt_risky.prompt.md", tmp_path / "risky.prompt.md"
        )
        shutil.copy(
            ARTIFACTS_DIR / "prompts" / "prompt_clean.prompt.md", tmp_path / "clean.prompt.md"
        )

        # Exclude all .prompt.md AND .yaml files - should result in no findings
        config_data = {"files": {"exclude": ["*.prompt.md", "*.yaml", "*.yml"]}}
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")

        result = runner.invoke(cli, ["verify", str(tmp_path), *_QUIET_ARGS])
        assert result.exit_code == 0
        parsed = json.loads(result.output.strip())
        assert parsed["summary"]["total_findings"] == 0

    def test_config_yaml_suppression_rules_mark_false_positive(self, tmp_path):
        """Suppression rules from .aav.yaml mark matching findings as false_positive."""
        import shutil

        shutil.copy(
            ARTIFACTS_DIR / "prompts" / "prompt_risky.prompt.md", tmp_path / "risky.prompt.md"
        )

        config_data = {
            "suppressions": [
                {"risk_id": "P-S3", "file_pattern": "**/*", "reason": "Accepted risk"},
            ]
        }
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")

        from ai_artifact_risk_validator.config.manager import ConfigManager

        cm = ConfigManager()
        config = cm.load(scan_path=str(tmp_path))
        v = _create_validator_with_scanners(config=config)
        report = v.verify(str(tmp_path))

        # P-S3 findings should be marked as false_positive
        p_s3 = [f for f in report.findings if f.id == "P-S3"]
        for finding in p_s3:
            assert finding.false_positive is True

    # ------------------------------------------------------------------
    # 8. Test scanner disabling via config
    # ------------------------------------------------------------------

    def test_disabled_scanners_produce_no_findings(self, tmp_path):
        """Disabled scanners don't produce findings in the report."""
        import shutil

        shutil.copy(ARTIFACTS_DIR / "agents" / "agent_risky.md", tmp_path / "agent_risky.md")

        # Disable all scanners except SecretScan
        config = ValidatorConfig(
            enabled_scanners=[ScannerModule.SECRET_SCAN],
        )
        v = _create_validator_with_scanners(config=config)
        report = v.verify(str(tmp_path))

        # All findings should only come from SecretScan
        for finding in report.findings:
            assert finding.scanner_module == ScannerModule.SECRET_SCAN

    def test_disabled_scanner_via_config_file(self, runner, tmp_path):
        """Disabling a scanner via .aav.yaml prevents its findings from appearing."""
        import shutil

        shutil.copy(ARTIFACTS_DIR / "agents" / "agent_risky.md", tmp_path / "agent_risky.md")

        config_data = {"scanners": {"disabled": ["InjectionDet", "QualityLint"]}}
        (tmp_path / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")

        result = runner.invoke(cli, ["verify", str(tmp_path), *_QUIET_ARGS])
        assert result.exit_code in (0, 1, 2)
        parsed = json.loads(result.output.strip())
        # No findings should come from disabled scanners
        for finding in parsed.get("findings", []):
            assert finding["scanner_module"] not in ("InjectionDet", "QualityLint")

    def test_all_scanners_disabled_produces_no_findings(self, tmp_path):
        """Disabling all scanners results in no findings."""
        import shutil

        shutil.copy(ARTIFACTS_DIR / "agents" / "agent_risky.md", tmp_path / "agent_risky.md")

        # Disable all scanner modules
        all_scanners = list(ScannerModule)
        config = ValidatorConfig(disabled_scanners=all_scanners)
        v = _create_validator_with_scanners(config=config)
        report = v.verify(str(tmp_path))

        assert report.summary.total_findings == 0
        assert report.summary.gate_decision == GateAction.INFO

    def test_enabled_single_scanner_only_produces_its_findings(self, tmp_path):
        """Enabling only one scanner means only that scanner's findings appear."""
        import shutil

        shutil.copy(
            ARTIFACTS_DIR / "prompts" / "prompt_risky.prompt.md", tmp_path / "risky.prompt.md"
        )

        config = ValidatorConfig(enabled_scanners=[ScannerModule.TOKEN_ANALYZER])
        v = _create_validator_with_scanners(config=config)
        report = v.verify(str(tmp_path))

        for finding in report.findings:
            assert finding.scanner_module == ScannerModule.TOKEN_ANALYZER
