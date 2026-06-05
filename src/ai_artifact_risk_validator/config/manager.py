"""Configuration manager for the AI Artifact Risk Validator.

Implements configuration loading with precedence:
CLI args > environment variables > config file > built-in defaults.

Supports YAML config files (.aav.yaml / .aav.yml) with JSON Schema validation
and environment variable overrides with the AAV_ prefix.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.models.config import SuppressionRule, ValidatorConfig
from ai_artifact_risk_validator.models.enums import GateAction, ScannerModule

logger = get_logger(__name__)

# Environment variable prefix
_ENV_PREFIX = "AAV_"

# Mapping of environment variable names (without prefix) to config fields and types
_ENV_VAR_MAP: dict[str, tuple[str, type]] = {
    "LOG_LEVEL": ("log_level", str),
    "SEVERITY_THRESHOLD": ("severity_threshold", int),
    "PARALLEL_FILES": ("parallel_files", int),
    "PARALLEL_SCANNERS": ("parallel_scanners", int),
    "CACHE_DIR": ("cache_dir", str),
    "MAX_FILE_SIZE": ("max_file_size_bytes", int),
}

# Keys that belong to the flat config schema format
_FLAT_SCHEMA_KEYS = {
    "log_level",
    "severity_threshold",
    "max_file_size_bytes",
    "parallel_files",
    "parallel_scanners",
    "file_include_patterns",
    "file_exclude_patterns",
    "enabled_scanners",
    "disabled_scanners",
    "custom_plugin_dirs",
    "suppression_rules",
    "gate_overrides",
    "custom_artifact_patterns",
    "cache_dir",
    "token_budget_limit",
}

# Keys that indicate nested (design doc) YAML format
_NESTED_FORMAT_KEYS = {"scanners", "severity", "files", "performance", "suppressions", "plugins"}


def _get_config_schema() -> dict[str, Any]:
    """Get the JSON Schema for config file validation.

    Attempts to import from config/schema.py if available,
    otherwise returns a permissive schema.
    """
    try:
        from ai_artifact_risk_validator.config.schema import CONFIG_SCHEMA

        return CONFIG_SCHEMA  # type: ignore[no-any-return]
    except (ImportError, AttributeError):
        # If schema module not yet available, allow any valid YAML
        return {"type": "object"}


def _validate_against_schema(data: dict[str, Any]) -> list[str]:
    """Validate config data against JSON Schema.

    Returns a list of validation error messages (empty if valid).
    """
    try:
        import jsonschema
    except ImportError:
        logger.warning("jsonschema not available; skipping config validation")
        return []

    schema = _get_config_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors: list[str] = []
    for error in validator.iter_errors(data):
        path = ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "root"
        errors.append(f"{path}: {error.message}")
    return errors


def _is_nested_format(data: dict[str, Any]) -> bool:
    """Detect whether the YAML config uses the nested format from the design doc."""
    return bool(_NESTED_FORMAT_KEYS & set(data.keys()))


def _flatten_nested_config(data: dict[str, Any]) -> dict[str, Any]:
    """Transform nested YAML config format into the flat schema format.

    Maps nested sections like:
      scanners.enabled -> enabled_scanners
      severity.threshold -> severity_threshold
      performance.parallel_files -> parallel_files
    """
    flat: dict[str, Any] = {}

    # Copy any top-level flat keys directly
    for key in list(data.keys()):
        if key in _FLAT_SCHEMA_KEYS:
            flat[key] = data[key]

    # Top-level log_level
    if "log_level" in data and "log_level" not in flat:
        flat["log_level"] = str(data["log_level"]).upper()

    # Scanner control: scanners.enabled -> enabled_scanners, scanners.disabled -> disabled_scanners
    scanners = data.get("scanners", {})
    if isinstance(scanners, dict):
        if "enabled" in scanners:
            flat["enabled_scanners"] = scanners["enabled"]
        if "disabled" in scanners:
            flat["disabled_scanners"] = scanners["disabled"]

    # Severity: severity.threshold -> severity_threshold, severity.gate_overrides -> gate_overrides
    severity = data.get("severity", {})
    if isinstance(severity, dict):
        if "threshold" in severity:
            flat["severity_threshold"] = int(severity["threshold"])
        if "gate_overrides" in severity:
            flat["gate_overrides"] = severity["gate_overrides"]

    # File filtering: files.include -> file_include_patterns, etc.
    files = data.get("files", {})
    if isinstance(files, dict):
        if "include" in files and isinstance(files["include"], list):
            flat["file_include_patterns"] = files["include"]
        if "exclude" in files and isinstance(files["exclude"], list):
            flat["file_exclude_patterns"] = files["exclude"]
        if "max_size_bytes" in files:
            flat["max_file_size_bytes"] = int(files["max_size_bytes"])

    # Performance: performance.parallel_files, performance.parallel_scanners, performance.cache_dir
    performance = data.get("performance", {})
    if isinstance(performance, dict):
        if "parallel_files" in performance:
            flat["parallel_files"] = int(performance["parallel_files"])
        if "parallel_scanners" in performance:
            flat["parallel_scanners"] = int(performance["parallel_scanners"])
        if "cache_dir" in performance:
            flat["cache_dir"] = str(performance["cache_dir"])

    # Token budgets: token_budgets.total_artifact -> token_budget_limit
    token_budgets = data.get("token_budgets", {})
    if isinstance(token_budgets, dict) and "total_artifact" in token_budgets:
        flat["token_budget_limit"] = int(token_budgets["total_artifact"])

    # Suppressions: list format -> suppression_rules
    suppressions = data.get("suppressions", [])
    if isinstance(suppressions, list) and suppressions:
        flat["suppression_rules"] = suppressions

    # Custom patterns: custom_patterns -> custom_artifact_patterns
    custom_patterns = data.get("custom_patterns", {})
    if isinstance(custom_patterns, dict) and custom_patterns:
        flat["custom_artifact_patterns"] = {
            k: v for k, v in custom_patterns.items() if isinstance(v, list)
        }

    # Plugin directories: plugins.directories -> custom_plugin_dirs
    plugins = data.get("plugins", {})
    if isinstance(plugins, dict):
        directories = plugins.get("directories", [])
        if isinstance(directories, list):
            flat["custom_plugin_dirs"] = [str(d) for d in directories]

    return flat


def _config_dict_to_validator_config(data: dict[str, Any]) -> dict[str, Any]:
    """Convert a flat config dict (matching schema) into ValidatorConfig kwargs.

    Handles type conversions for enum fields.
    """
    kwargs: dict[str, Any] = {}

    # Direct scalar fields
    if "log_level" in data:
        kwargs["log_level"] = str(data["log_level"]).upper()
    if "severity_threshold" in data:
        kwargs["severity_threshold"] = int(data["severity_threshold"])
    if "max_file_size_bytes" in data:
        kwargs["max_file_size_bytes"] = int(data["max_file_size_bytes"])
    if "parallel_files" in data:
        kwargs["parallel_files"] = int(data["parallel_files"])
    if "parallel_scanners" in data:
        kwargs["parallel_scanners"] = int(data["parallel_scanners"])
    if "cache_dir" in data:
        kwargs["cache_dir"] = data["cache_dir"]
    if "token_budget_limit" in data:
        kwargs["token_budget_limit"] = data["token_budget_limit"]

    # List fields
    if "file_include_patterns" in data:
        kwargs["file_include_patterns"] = data["file_include_patterns"]
    if "file_exclude_patterns" in data:
        kwargs["file_exclude_patterns"] = data["file_exclude_patterns"]
    if "custom_plugin_dirs" in data:
        kwargs["custom_plugin_dirs"] = data["custom_plugin_dirs"]

    # Scanner enum lists
    if "enabled_scanners" in data:
        enabled = data["enabled_scanners"]
        if enabled is None:
            kwargs["enabled_scanners"] = None
        elif isinstance(enabled, list):
            kwargs["enabled_scanners"] = [
                ScannerModule(s) if isinstance(s, str) else s for s in enabled
            ]
    if "disabled_scanners" in data:
        disabled = data["disabled_scanners"]
        if isinstance(disabled, list):
            kwargs["disabled_scanners"] = [
                ScannerModule(s) if isinstance(s, str) else s for s in disabled
            ]

    # Gate overrides dict
    if "gate_overrides" in data:
        overrides = data["gate_overrides"]
        if isinstance(overrides, dict):
            kwargs["gate_overrides"] = {
                k: GateAction(v) if isinstance(v, str) else v for k, v in overrides.items()
            }

    # Suppression rules
    if "suppression_rules" in data:
        rules_data = data["suppression_rules"]
        if isinstance(rules_data, list):
            rules: list[SuppressionRule] = []
            for item in rules_data:
                if isinstance(item, dict) and "risk_id" in item:
                    rules.append(
                        SuppressionRule(
                            risk_id=item["risk_id"],
                            file_pattern=item.get("file_pattern"),
                            reason=item.get("reason"),
                        )
                    )
                elif isinstance(item, SuppressionRule):
                    rules.append(item)
            kwargs["suppression_rules"] = rules

    # Custom artifact patterns
    if "custom_artifact_patterns" in data:
        patterns = data["custom_artifact_patterns"]
        if isinstance(patterns, dict):
            kwargs["custom_artifact_patterns"] = {
                k: v for k, v in patterns.items() if isinstance(v, list)
            }

    return kwargs


def _parse_env_vars() -> dict[str, Any]:
    """Parse environment variables with AAV_ prefix into config kwargs."""
    config_kwargs: dict[str, Any] = {}

    for env_suffix, (field_name, field_type) in _ENV_VAR_MAP.items():
        env_key = f"{_ENV_PREFIX}{env_suffix}"
        value = os.environ.get(env_key)
        if value is not None:
            try:
                if field_type is int:
                    config_kwargs[field_name] = int(value)
                else:
                    config_kwargs[field_name] = value
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid environment variable value",
                    env_var=env_key,
                    value=value,
                )

    # Handle AAV_DISABLED_SCANNERS (comma-separated list)
    disabled_scanners_env = os.environ.get(f"{_ENV_PREFIX}DISABLED_SCANNERS")
    if disabled_scanners_env:
        scanner_names = [s.strip() for s in disabled_scanners_env.split(",") if s.strip()]
        try:
            config_kwargs["disabled_scanners"] = [ScannerModule(s) for s in scanner_names]
        except ValueError:
            logger.warning(
                "Invalid scanner names in AAV_DISABLED_SCANNERS",
                value=disabled_scanners_env,
            )

    return config_kwargs


def _find_config_file(scan_path: str | None = None) -> Path | None:
    """Find .aav.yaml or .aav.yml in the scan path root.

    Returns the path to the config file if found, or None.
    """
    if scan_path is None:
        scan_path = "."

    base = Path(scan_path)
    if base.is_file():
        base = base.parent

    for name in (".aav.yaml", ".aav.yml"):
        config_file = base / name
        if config_file.is_file():
            return config_file

    return None


class ConfigManager:
    """Manages configuration loading and merging for the validator.

    Implements configuration precedence:
    1. CLI arguments (highest priority)
    2. Environment variables (AAV_ prefix)
    3. Config file (.aav.yaml / .aav.yml)
    4. Built-in defaults (lowest priority)
    """

    def load(
        self,
        config_path: str | None = None,
        scan_path: str | None = None,
        cli_overrides: dict[str, Any] | None = None,
    ) -> ValidatorConfig:
        """Load and merge configuration from all sources.

        Args:
            config_path: Explicit path to a config file. If provided, this is
                used instead of searching scan_path for .aav.yaml/.aav.yml.
            scan_path: Directory being scanned. Used to locate a config file
                if config_path is not specified.
            cli_overrides: Dictionary of CLI argument overrides to apply on top.

        Returns:
            A merged ValidatorConfig with precedence applied.
        """
        # Step 1: Start with defaults (ValidatorConfig with no args gives defaults)
        config_kwargs: dict[str, Any] = {}

        # Step 2: Load config file
        file_kwargs = self._load_config_file(config_path, scan_path)
        config_kwargs.update(file_kwargs)

        # Step 3: Apply environment variables
        env_kwargs = _parse_env_vars()
        config_kwargs.update(env_kwargs)

        # Step 4: Apply CLI overrides
        if cli_overrides:
            # Filter out None values from CLI overrides
            filtered_overrides = {k: v for k, v in cli_overrides.items() if v is not None}
            config_kwargs.update(filtered_overrides)

        # Store config_path if explicitly provided
        if config_path:
            config_kwargs["config_path"] = config_path

        # Build and return the ValidatorConfig
        return ValidatorConfig(**config_kwargs)

    def _load_config_file(
        self,
        config_path: str | None = None,
        scan_path: str | None = None,
    ) -> dict[str, Any]:
        """Load configuration from a YAML file.

        Supports both the flat schema format and the nested design-doc format.

        Args:
            config_path: Explicit config file path.
            scan_path: Directory to search for config files.

        Returns:
            Dict of config kwargs parsed from the file, or empty dict.
        """
        # Determine which config file to use
        if config_path:
            file_path = Path(config_path)
            if not file_path.is_file():
                logger.warning(
                    "Specified config file not found",
                    config_path=config_path,
                )
                return {}
        else:
            found = _find_config_file(scan_path)
            if found is None:
                return {}
            file_path = found

        # Read and parse the YAML file
        try:
            with open(file_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(
                "Failed to parse config file",
                config_path=str(file_path),
                error=str(e),
            )
            return {}
        except OSError as e:
            logger.error(
                "Failed to read config file",
                config_path=str(file_path),
                error=str(e),
            )
            return {}

        if not isinstance(data, dict):
            logger.error(
                "Config file must contain a YAML mapping",
                config_path=str(file_path),
            )
            return {}

        # Detect format and normalize to flat
        if _is_nested_format(data):
            # Transform nested format to flat format
            flat_data = _flatten_nested_config(data)
        else:
            flat_data = data

        # Remove 'version' key if present (not part of config schema)
        flat_data.pop("version", None)

        # Validate against JSON Schema
        validation_errors = _validate_against_schema(flat_data)
        if validation_errors:
            for error in validation_errors:
                logger.error(
                    "Config file validation error",
                    config_path=str(file_path),
                    error=error,
                )
            return {}

        # Convert to ValidatorConfig kwargs with proper type handling
        return _config_dict_to_validator_config(flat_data)
