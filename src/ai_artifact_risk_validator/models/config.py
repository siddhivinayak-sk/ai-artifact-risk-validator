"""Configuration models for the AI Artifact Risk Validator.

Defines the ValidatorConfig and SuppressionRule Pydantic models used to
configure the validator engine's behavior, scanner selection, file filtering,
and suppression rules.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ai_artifact_risk_validator.models.enums import GateAction, ScannerModule


class SuppressionRule(BaseModel):
    """Rule for suppressing specific findings.

    A suppression rule identifies a risk ID (and optionally a file pattern)
    that should be marked as a false positive in the scan report.
    """

    risk_id: str
    file_pattern: str | None = None
    reason: str | None = None


class ValidatorConfig(BaseModel):
    """Configuration for the Validator engine.

    Controls logging level, scanner selection, severity thresholds,
    file filtering, parallelism, caching, suppression rules, and
    custom extension points.
    """

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    enabled_scanners: list[ScannerModule] | None = None  # None = all
    disabled_scanners: list[ScannerModule] = Field(default_factory=list)
    severity_threshold: int = Field(default=1, ge=1, le=10)  # Min severity to report
    file_include_patterns: list[str] = Field(default_factory=list)
    file_exclude_patterns: list[str] = Field(default_factory=list)
    max_file_size_bytes: int = Field(default=10_485_760)  # 10 MB
    parallel_files: int = Field(default=4, ge=1, le=32)
    parallel_scanners: int = Field(default=4, ge=1, le=16)
    cache_dir: str | None = None
    config_path: str | None = None
    custom_plugin_dirs: list[str] = Field(default_factory=list)
    suppression_rules: list[SuppressionRule] = Field(default_factory=list)
    token_budget_limit: int | None = None
    gate_overrides: dict[str, GateAction] = Field(default_factory=dict)
    custom_artifact_patterns: dict[str, list[str]] = Field(default_factory=dict)
