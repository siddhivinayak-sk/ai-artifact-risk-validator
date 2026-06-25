"""Unit tests for ValidatorConfig script scanning extensions.

Tests default values, empty extensions behavior, disabled flag behavior,
extension validation (dot prefix, alphanumeric), backward compatibility,
and serialization/deserialization of the new script scanning fields.
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.config import ValidatorConfig


class TestScriptScanningDefaults:
    """Tests that new script scanning fields have correct defaults."""

    def test_script_scanning_enabled_defaults_to_true(self):
        config = ValidatorConfig()
        assert config.script_scanning_enabled is True

    def test_script_extensions_defaults_to_12_entries(self):
        config = ValidatorConfig()
        assert len(config.script_extensions) == 12

    def test_script_extensions_default_contains_all_expected(self):
        config = ValidatorConfig()
        expected = [
            ".py",
            ".ts",
            ".js",
            ".ps1",
            ".sh",
            ".bash",
            ".bat",
            ".cmd",
            ".rb",
            ".java",
            ".kt",
            ".rs",
        ]
        assert config.script_extensions == expected

    def test_each_default_extension_starts_with_dot(self):
        config = ValidatorConfig()
        for ext in config.script_extensions:
            assert ext.startswith("."), f"Extension {ext!r} does not start with a dot"

    def test_each_default_extension_has_alphanumeric_after_dot(self):
        config = ValidatorConfig()
        for ext in config.script_extensions:
            suffix = ext[1:]  # Remove the dot prefix
            assert suffix.isalnum(), f"Extension {ext!r} has non-alphanumeric chars after dot"


class TestScriptScanningDisabled:
    """Tests for script_scanning_enabled=False behavior."""

    def test_setting_script_scanning_disabled(self):
        config = ValidatorConfig(script_scanning_enabled=False)
        assert config.script_scanning_enabled is False

    def test_disabled_scanning_preserves_extensions_list(self):
        config = ValidatorConfig(script_scanning_enabled=False)
        assert len(config.script_extensions) == 12

    def test_disabled_scanning_with_custom_extensions(self):
        config = ValidatorConfig(
            script_scanning_enabled=False,
            script_extensions=[".py", ".go"],
        )
        assert config.script_scanning_enabled is False
        assert config.script_extensions == [".py", ".go"]


class TestEmptyScriptExtensions:
    """Tests for empty script_extensions list behavior."""

    def test_empty_extensions_list_is_valid(self):
        config = ValidatorConfig(script_extensions=[])
        assert config.script_extensions == []

    def test_empty_extensions_with_scanning_enabled(self):
        config = ValidatorConfig(script_scanning_enabled=True, script_extensions=[])
        assert config.script_scanning_enabled is True
        assert config.script_extensions == []


class TestCustomScriptExtensions:
    """Tests for custom script_extensions values."""

    def test_custom_extensions_override_defaults(self):
        config = ValidatorConfig(script_extensions=[".py", ".go"])
        assert config.script_extensions == [".py", ".go"]

    def test_single_extension(self):
        config = ValidatorConfig(script_extensions=[".py"])
        assert config.script_extensions == [".py"]

    def test_extensions_with_longer_suffixes(self):
        config = ValidatorConfig(script_extensions=[".bash", ".ps1"])
        assert config.script_extensions == [".bash", ".ps1"]


class TestBackwardCompatibility:
    """Tests that existing ValidatorConfig fields remain unchanged."""

    def test_existing_fields_unchanged_when_script_fields_set(self):
        config = ValidatorConfig(
            script_scanning_enabled=False,
            script_extensions=[".py"],
        )
        # All pre-existing defaults must remain intact
        assert config.log_level == "INFO"
        assert config.enabled_scanners is None
        assert config.disabled_scanners == []
        assert config.severity_threshold == 1
        assert config.file_include_patterns == []
        assert config.file_exclude_patterns == []
        assert config.max_file_size_bytes == 10_485_760
        assert config.parallel_files == 4
        assert config.parallel_scanners == 4
        assert config.cache_dir is None
        assert config.config_path is None
        assert config.custom_plugin_dirs == []
        assert config.suppression_rules == []
        assert config.token_budget_limit is None
        assert config.gate_overrides == {}
        assert config.custom_artifact_patterns == {}
        assert config.html_report_path is None
        assert config.allow_dynamic_scan is False

    def test_default_config_has_no_side_effects_from_new_fields(self):
        config = ValidatorConfig()
        # Script fields exist with correct defaults
        assert config.script_scanning_enabled is True
        assert len(config.script_extensions) == 12
        # Existing fields are unaffected
        assert config.log_level == "INFO"
        assert config.severity_threshold == 1


class TestConfigSerialization:
    """Tests for model_dump and model_validate round-trip."""

    def test_model_dump_includes_script_fields(self):
        config = ValidatorConfig()
        data = config.model_dump()
        assert "script_scanning_enabled" in data
        assert "script_extensions" in data
        assert data["script_scanning_enabled"] is True
        assert len(data["script_extensions"]) == 12

    def test_model_dump_with_custom_script_values(self):
        config = ValidatorConfig(
            script_scanning_enabled=False,
            script_extensions=[".py", ".go"],
        )
        data = config.model_dump()
        assert data["script_scanning_enabled"] is False
        assert data["script_extensions"] == [".py", ".go"]

    def test_model_validate_round_trip(self):
        original = ValidatorConfig(
            script_scanning_enabled=False,
            script_extensions=[".rs", ".kt"],
        )
        data = original.model_dump()
        restored = ValidatorConfig.model_validate(data)
        assert restored.script_scanning_enabled == original.script_scanning_enabled
        assert restored.script_extensions == original.script_extensions

    def test_model_validate_from_dict_with_script_fields(self):
        data = {
            "script_scanning_enabled": False,
            "script_extensions": [".py"],
        }
        config = ValidatorConfig.model_validate(data)
        assert config.script_scanning_enabled is False
        assert config.script_extensions == [".py"]

    def test_model_validate_without_script_fields_uses_defaults(self):
        data = {"log_level": "DEBUG"}
        config = ValidatorConfig.model_validate(data)
        assert config.script_scanning_enabled is True
        assert len(config.script_extensions) == 12

    def test_full_round_trip_preserves_all_fields(self):
        original = ValidatorConfig(
            log_level="DEBUG",
            severity_threshold=5,
            script_scanning_enabled=False,
            script_extensions=[".py", ".ts"],
        )
        data = original.model_dump()
        restored = ValidatorConfig.model_validate(data)
        assert restored.log_level == original.log_level
        assert restored.severity_threshold == original.severity_threshold
        assert restored.script_scanning_enabled == original.script_scanning_enabled
        assert restored.script_extensions == original.script_extensions
