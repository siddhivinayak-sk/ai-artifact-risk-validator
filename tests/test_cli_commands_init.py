"""Unit tests for the standalone cli/commands/init.py module.

This module has 0% coverage because it's a separate implementation from
cli/main.py's init command. Tests exercise the Click command directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_artifact_risk_validator.cli.commands.init import init


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


class TestInitCommandStandalone:
    """Tests for the standalone init command in cli/commands/init.py."""

    def test_creates_config_file_in_default_directory(self, runner: CliRunner, tmp_path: Path):
        """init creates .aav.yaml in the target directory."""
        result = runner.invoke(init, ["--path", str(tmp_path)])
        assert result.exit_code == 0
        config_file = tmp_path / ".aav.yaml"
        assert config_file.exists()
        content = config_file.read_text(encoding="utf-8")
        assert "version:" in content
        assert "scanners:" in content

    def test_config_file_contains_expected_sections(self, runner: CliRunner, tmp_path: Path):
        """Generated config contains all expected sections."""
        runner.invoke(init, ["--path", str(tmp_path)])
        config_file = tmp_path / ".aav.yaml"
        content = config_file.read_text(encoding="utf-8")
        assert "severity:" in content
        assert "files:" in content
        assert "performance:" in content
        assert "suppressions:" in content
        assert "custom_patterns:" in content
        assert "plugins:" in content

    def test_refuses_overwrite_without_force(self, runner: CliRunner, tmp_path: Path):
        """init refuses to overwrite existing .aav.yaml without --force."""
        config_file = tmp_path / ".aav.yaml"
        config_file.write_text("existing: true\n", encoding="utf-8")

        result = runner.invoke(init, ["--path", str(tmp_path)])
        assert result.exit_code == 1
        assert "already exists" in result.output
        # Original content preserved
        assert config_file.read_text(encoding="utf-8") == "existing: true\n"

    def test_force_overwrites_existing(self, runner: CliRunner, tmp_path: Path):
        """init --force overwrites an existing .aav.yaml file."""
        config_file = tmp_path / ".aav.yaml"
        config_file.write_text("existing: true\n", encoding="utf-8")

        result = runner.invoke(init, ["--path", str(tmp_path), "--force"])
        assert result.exit_code == 0
        content = config_file.read_text(encoding="utf-8")
        assert "existing: true" not in content
        assert "version:" in content

    def test_success_message_printed(self, runner: CliRunner, tmp_path: Path):
        """init shows a success message with the config file path."""
        result = runner.invoke(init, ["--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "Created configuration file" in result.output

    def test_default_path_is_current_directory(self, runner: CliRunner, tmp_path: Path):
        """init without --path uses current working directory."""
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(init)
            assert result.exit_code == 0
            assert Path(".aav.yaml").exists()
