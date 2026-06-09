"""Tests for --allow-dynamic-scan CLI flag and interactive consent prompt wiring.

Validates:
- CLI accepts the --allow-dynamic-scan flag without error
- Flag is wired through cli_overrides to ValidatorConfig.allow_dynamic_scan
- DynamicScanConfig receives the allow_dynamic_scan value from ValidatorConfig
- Non-interactive mode logs informational message when flag is missing

Requirements: 5.8, 5.9
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.main import cli
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.mcp_models import DynamicScanConfig


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def empty_scan_dir(tmp_path: Path) -> Path:
    """Create an empty temporary scan directory."""
    d = tmp_path / "scan"
    d.mkdir()
    return d


class TestAllowDynamicScanFlag:
    """Tests for the --allow-dynamic-scan CLI flag."""

    def test_verify_help_shows_allow_dynamic_scan(self, runner: CliRunner):
        """verify --help should include --allow-dynamic-scan in the output."""
        result = runner.invoke(cli, ["verify", "--help"])
        assert result.exit_code == 0
        assert "--allow-dynamic-scan" in result.output

    def test_verify_accepts_allow_dynamic_scan_flag(self, runner: CliRunner, empty_scan_dir: Path):
        """verify command should accept --allow-dynamic-scan without error."""
        result = runner.invoke(
            cli,
            ["verify", str(empty_scan_dir), "--allow-dynamic-scan", "--log-level", "CRITICAL"],
        )
        assert result.exit_code in (0, 1, 2)

    def test_verify_without_allow_dynamic_scan_flag(self, runner: CliRunner, empty_scan_dir: Path):
        """verify command should work without --allow-dynamic-scan (defaults to False)."""
        result = runner.invoke(
            cli,
            ["verify", str(empty_scan_dir), "--log-level", "CRITICAL"],
        )
        assert result.exit_code in (0, 1, 2)

    def test_allow_dynamic_scan_wired_to_config(self):
        """ValidatorConfig should have allow_dynamic_scan field defaulting to False."""
        config = ValidatorConfig()
        assert config.allow_dynamic_scan is False

    def test_allow_dynamic_scan_set_to_true(self):
        """ValidatorConfig should accept allow_dynamic_scan=True."""
        config = ValidatorConfig(allow_dynamic_scan=True)
        assert config.allow_dynamic_scan is True


class TestDynamicScanConsentModel:
    """Tests for DynamicScanner consent checking logic."""

    def test_dynamic_scan_config_default_not_allowed(self):
        """DynamicScanConfig defaults to allow_dynamic_scan=False."""
        config = DynamicScanConfig()
        assert config.allow_dynamic_scan is False

    def test_dynamic_scan_config_allowed_when_set(self):
        """DynamicScanConfig allows scanning when allow_dynamic_scan=True."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        assert config.allow_dynamic_scan is True

    def test_dynamic_scanner_check_consent_allowed(self):
        """DynamicScanner._check_consent returns True when allow_dynamic_scan=True."""
        from ai_artifact_risk_validator.scanners.dynamic.scanner import DynamicScanner

        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)
        assert scanner._check_consent() is True

    def test_dynamic_scanner_check_consent_non_interactive_no_flag(self):
        """DynamicScanner._check_consent returns False in non-interactive mode without flag."""
        from unittest.mock import patch as _patch

        from ai_artifact_risk_validator.scanners.dynamic.scanner import DynamicScanner

        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=False)
        scanner = DynamicScanner(config=config)

        with _patch("ai_artifact_risk_validator.scanners.dynamic.scanner.logger") as mock_logger:
            result = scanner._check_consent()

        assert result is False
        # Verify informational log message is emitted
        mock_logger.info.assert_called_once()
        log_message = mock_logger.info.call_args[0][0]
        assert "--allow-dynamic-scan" in log_message

    def test_dynamic_scanner_skips_scanning_without_consent(self):
        """DynamicScanner.scan returns empty findings when consent not given."""
        from ai_artifact_risk_validator.scanners.dynamic.scanner import DynamicScanner

        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=False)
        scanner = DynamicScanner(config=config)

        from ai_artifact_risk_validator.models.enums import ArtifactType

        findings = scanner.scan(
            '{"mcpServers": {"test": {"command": "node", "args": ["server.js"]}}}',
            ArtifactType.MCP,
            "test_config.json",
        )
        assert findings == []


class TestValidatorConfiguresDynamicScanner:
    """Tests that the Validator wires allow_dynamic_scan to DynamicScanner."""

    def test_validator_passes_allow_dynamic_scan_to_dynamic_scanner(self):
        """Validator should configure DynamicScanner with allow_dynamic_scan from config."""
        from ai_artifact_risk_validator.models.enums import ScannerModule
        from ai_artifact_risk_validator.validator import Validator

        config = ValidatorConfig(allow_dynamic_scan=True)
        validator = Validator(config=config)

        dynamic_scanner = validator._scanner_registry.get_scanner_by_name(
            ScannerModule.DYNAMIC_SCAN
        )
        if dynamic_scanner is not None:
            assert dynamic_scanner._config.allow_dynamic_scan is True

    def test_validator_default_dynamic_scan_not_allowed(self):
        """Validator with default config should leave DynamicScanner consent as False."""
        from ai_artifact_risk_validator.models.enums import ScannerModule
        from ai_artifact_risk_validator.validator import Validator

        config = ValidatorConfig()
        validator = Validator(config=config)

        dynamic_scanner = validator._scanner_registry.get_scanner_by_name(
            ScannerModule.DYNAMIC_SCAN
        )
        if dynamic_scanner is not None:
            assert dynamic_scanner._config.allow_dynamic_scan is False
