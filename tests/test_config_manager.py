"""Unit tests for ConfigManager."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from ai_artifact_risk_validator.config.manager import ConfigManager
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import GateAction, ScannerModule


@pytest.fixture
def config_manager():
    """Create a ConfigManager instance for testing."""
    return ConfigManager()


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Create a temporary directory with a config file."""
    return tmp_path


class TestConfigManagerDefaults:
    """Tests that defaults are correctly applied."""

    def test_load_with_no_args_returns_default_config(self, config_manager):
        config = config_manager.load()
        assert isinstance(config, ValidatorConfig)
        assert config.log_level == "INFO"
        assert config.severity_threshold == 1
        assert config.parallel_files == 4
        assert config.parallel_scanners == 4
        assert config.max_file_size_bytes == 10_485_760
        assert config.cache_dir is None
        assert config.enabled_scanners is None
        assert config.disabled_scanners == []

    def test_load_with_nonexistent_config_path_returns_defaults(self, config_manager):
        config = config_manager.load(config_path="/nonexistent/path/.aav.yaml")
        assert config.log_level == "INFO"
        assert config.severity_threshold == 1

    def test_load_with_nonexistent_scan_path_returns_defaults(self, config_manager):
        config = config_manager.load(scan_path="/nonexistent/dir")
        assert config.log_level == "INFO"


class TestConfigFileLoading:
    """Tests for YAML config file loading."""

    def test_load_aav_yaml_file(self, config_manager, tmp_config_dir):
        config_data = {
            "scanners": {
                "disabled": ["BiasDetector"],
            },
            "severity": {
                "threshold": 5,
            },
            "performance": {
                "parallel_files": 8,
                "cache_dir": ".cache",
            },
        }
        config_file = tmp_config_dir / ".aav.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        config = config_manager.load(scan_path=str(tmp_config_dir))
        assert config.severity_threshold == 5
        assert config.parallel_files == 8
        assert config.cache_dir == ".cache"
        assert ScannerModule.BIAS_DETECTOR in config.disabled_scanners

    def test_load_aav_yml_file(self, config_manager, tmp_config_dir):
        config_data = {
            "severity": {"threshold": 3},
        }
        config_file = tmp_config_dir / ".aav.yml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        config = config_manager.load(scan_path=str(tmp_config_dir))
        assert config.severity_threshold == 3

    def test_yaml_prefers_aav_yaml_over_aav_yml(self, config_manager, tmp_config_dir):
        # .aav.yaml takes precedence
        yaml_data = {"severity": {"threshold": 7}}
        yml_data = {"severity": {"threshold": 3}}

        (tmp_config_dir / ".aav.yaml").write_text(yaml.dump(yaml_data), encoding="utf-8")
        (tmp_config_dir / ".aav.yml").write_text(yaml.dump(yml_data), encoding="utf-8")

        config = config_manager.load(scan_path=str(tmp_config_dir))
        assert config.severity_threshold == 7

    def test_explicit_config_path_overrides_scan_path(self, config_manager, tmp_config_dir):
        # Config in scan_path
        scan_config = {"severity": {"threshold": 3}}
        (tmp_config_dir / ".aav.yaml").write_text(yaml.dump(scan_config), encoding="utf-8")

        # Explicit config in different location
        explicit_dir = tmp_config_dir / "custom"
        explicit_dir.mkdir()
        explicit_config = {"severity": {"threshold": 9}}
        explicit_file = explicit_dir / "custom.yaml"
        explicit_file.write_text(yaml.dump(explicit_config), encoding="utf-8")

        config = config_manager.load(
            config_path=str(explicit_file), scan_path=str(tmp_config_dir)
        )
        assert config.severity_threshold == 9

    def test_invalid_yaml_returns_defaults(self, config_manager, tmp_config_dir):
        config_file = tmp_config_dir / ".aav.yaml"
        config_file.write_text("invalid: yaml: [missing bracket", encoding="utf-8")

        config = config_manager.load(scan_path=str(tmp_config_dir))
        # Should fall back to defaults
        assert config.log_level == "INFO"

    def test_non_dict_yaml_returns_defaults(self, config_manager, tmp_config_dir):
        config_file = tmp_config_dir / ".aav.yaml"
        config_file.write_text("- item1\n- item2\n", encoding="utf-8")

        config = config_manager.load(scan_path=str(tmp_config_dir))
        assert config.log_level == "INFO"

    def test_full_config_file_parsing(self, config_manager, tmp_config_dir):
        config_data = {
            "scanners": {
                "enabled": ["SecretScan", "InjectionDet"],
                "disabled": ["BiasDetector"],
            },
            "severity": {
                "threshold": 5,
                "gate_overrides": {"P-P5": "INFO"},
            },
            "files": {
                "include": ["**/*.md", "**/*.yaml"],
                "exclude": ["node_modules/**"],
                "max_size_bytes": 5_000_000,
            },
            "performance": {
                "parallel_files": 8,
                "parallel_scanners": 2,
                "cache_dir": ".aav_cache",
            },
            "token_budgets": {
                "total_artifact": 8000,
            },
            "suppressions": [
                {
                    "risk_id": "P-S3",
                    "file_pattern": "tests/**",
                    "reason": "Test fixtures",
                },
            ],
            "custom_patterns": {
                "prompt": ["*.prompt.txt"],
            },
            "plugins": {
                "directories": ["./custom-scanners/"],
            },
        }
        config_file = tmp_config_dir / ".aav.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        config = config_manager.load(scan_path=str(tmp_config_dir))
        assert config.enabled_scanners == [
            ScannerModule.SECRET_SCAN,
            ScannerModule.INJECTION_DET,
        ]
        assert ScannerModule.BIAS_DETECTOR in config.disabled_scanners
        assert config.severity_threshold == 5
        assert config.gate_overrides == {"P-P5": GateAction.INFO}
        assert config.file_include_patterns == ["**/*.md", "**/*.yaml"]
        assert config.file_exclude_patterns == ["node_modules/**"]
        assert config.max_file_size_bytes == 5_000_000
        assert config.parallel_files == 8
        assert config.parallel_scanners == 2
        assert config.cache_dir == ".aav_cache"
        assert config.token_budget_limit == 8000
        assert len(config.suppression_rules) == 1
        assert config.suppression_rules[0].risk_id == "P-S3"
        assert config.suppression_rules[0].file_pattern == "tests/**"
        assert config.custom_artifact_patterns == {"prompt": ["*.prompt.txt"]}
        assert config.custom_plugin_dirs == ["./custom-scanners/"]


class TestEnvironmentVariables:
    """Tests for environment variable parsing."""

    def test_aav_log_level(self, config_manager):
        with patch.dict(os.environ, {"AAV_LOG_LEVEL": "DEBUG"}):
            config = config_manager.load()
        assert config.log_level == "DEBUG"

    def test_aav_severity_threshold(self, config_manager):
        with patch.dict(os.environ, {"AAV_SEVERITY_THRESHOLD": "7"}):
            config = config_manager.load()
        assert config.severity_threshold == 7

    def test_aav_parallel_files(self, config_manager):
        with patch.dict(os.environ, {"AAV_PARALLEL_FILES": "16"}):
            config = config_manager.load()
        assert config.parallel_files == 16

    def test_aav_parallel_scanners(self, config_manager):
        with patch.dict(os.environ, {"AAV_PARALLEL_SCANNERS": "8"}):
            config = config_manager.load()
        assert config.parallel_scanners == 8

    def test_aav_cache_dir(self, config_manager):
        with patch.dict(os.environ, {"AAV_CACHE_DIR": "/tmp/aav_cache"}):
            config = config_manager.load()
        assert config.cache_dir == "/tmp/aav_cache"

    def test_aav_max_file_size(self, config_manager):
        with patch.dict(os.environ, {"AAV_MAX_FILE_SIZE": "20000000"}):
            config = config_manager.load()
        assert config.max_file_size_bytes == 20_000_000

    def test_aav_disabled_scanners(self, config_manager):
        with patch.dict(os.environ, {"AAV_DISABLED_SCANNERS": "BiasDetector,ComposeAnalyze"}):
            config = config_manager.load()
        assert ScannerModule.BIAS_DETECTOR in config.disabled_scanners
        assert ScannerModule.COMPOSE_ANALYZE in config.disabled_scanners

    def test_invalid_int_env_var_is_ignored(self, config_manager):
        with patch.dict(os.environ, {"AAV_PARALLEL_FILES": "not_a_number"}):
            config = config_manager.load()
        # Should use default
        assert config.parallel_files == 4

    def test_env_vars_override_config_file(self, config_manager, tmp_config_dir):
        config_data = {
            "severity": {"threshold": 3},
            "performance": {"parallel_files": 2},
        }
        config_file = tmp_config_dir / ".aav.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        with patch.dict(os.environ, {"AAV_SEVERITY_THRESHOLD": "8"}):
            config = config_manager.load(scan_path=str(tmp_config_dir))

        # Env var overrides config file
        assert config.severity_threshold == 8
        # Config file value is kept if no env var override
        assert config.parallel_files == 2


class TestCLIOverrides:
    """Tests for CLI argument overrides."""

    def test_cli_overrides_applied(self, config_manager):
        config = config_manager.load(cli_overrides={"log_level": "ERROR", "severity_threshold": 9})
        assert config.log_level == "ERROR"
        assert config.severity_threshold == 9

    def test_cli_overrides_take_precedence_over_env_vars(self, config_manager):
        with patch.dict(os.environ, {"AAV_LOG_LEVEL": "DEBUG"}):
            config = config_manager.load(cli_overrides={"log_level": "CRITICAL"})
        assert config.log_level == "CRITICAL"

    def test_cli_overrides_take_precedence_over_config_file(
        self, config_manager, tmp_config_dir
    ):
        config_data = {"severity": {"threshold": 3}}
        config_file = tmp_config_dir / ".aav.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        config = config_manager.load(
            scan_path=str(tmp_config_dir), cli_overrides={"severity_threshold": 10}
        )
        assert config.severity_threshold == 10

    def test_none_cli_overrides_are_filtered(self, config_manager):
        config = config_manager.load(
            cli_overrides={"log_level": "ERROR", "cache_dir": None}
        )
        assert config.log_level == "ERROR"
        assert config.cache_dir is None  # Default, not overridden

    def test_full_precedence_chain(self, config_manager, tmp_config_dir):
        """Test the complete precedence chain: CLI > env > file > defaults."""
        config_data = {
            "severity": {"threshold": 3},
            "performance": {"parallel_files": 2, "parallel_scanners": 2},
        }
        config_file = tmp_config_dir / ".aav.yaml"
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        with patch.dict(
            os.environ,
            {"AAV_SEVERITY_THRESHOLD": "5", "AAV_PARALLEL_FILES": "12"},
        ):
            config = config_manager.load(
                scan_path=str(tmp_config_dir),
                cli_overrides={"severity_threshold": 8},
            )

        # CLI wins over env var and file
        assert config.severity_threshold == 8
        # Env var wins over file
        assert config.parallel_files == 12
        # File value used (no env var or CLI override)
        assert config.parallel_scanners == 2
        # Default used (not in file, env, or CLI)
        assert config.log_level == "INFO"


class TestConfigPathHandling:
    """Tests for config path resolution."""

    def test_config_path_stored_when_explicit(self, config_manager, tmp_config_dir):
        config_file = tmp_config_dir / "my-config.yaml"
        config_file.write_text(yaml.dump({"severity": {"threshold": 2}}), encoding="utf-8")

        config = config_manager.load(config_path=str(config_file))
        assert config.config_path == str(config_file)

    def test_scan_path_as_file_uses_parent_dir(self, config_manager, tmp_config_dir):
        """When scan_path is a file, search its parent directory for config."""
        config_data = {"severity": {"threshold": 6}}
        (tmp_config_dir / ".aav.yaml").write_text(yaml.dump(config_data), encoding="utf-8")

        # Create a file in the directory to use as scan_path
        target_file = tmp_config_dir / "some_file.md"
        target_file.write_text("content", encoding="utf-8")

        config = config_manager.load(scan_path=str(target_file))
        assert config.severity_threshold == 6
