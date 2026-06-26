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

    Fields:
        risk_id: The risk ID to suppress (required, e.g. "SK-S7").
        reason: Explanation for why this suppression exists (required).
        file_pattern: Optional glob pattern to limit suppression to specific files.
            If not provided, the rule applies to ALL files matching the risk_id.
    """

    risk_id: str
    file_pattern: str | None = None
    reason: str


class SemanticConfig(BaseModel):
    """Configuration for the semantic analysis engine.

    Controls whether embedding-based analysis is enabled, which model to
    use, and the similarity threshold for semantic matches.
    """

    enabled: bool = True
    model_name: str = "all-MiniLM-L6-v2"
    threshold: float = Field(default=0.55, ge=0.0, le=1.0)


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
    html_report_path: str | None = None
    allow_dynamic_scan: bool = False
    dynamic_connection_timeout: int = Field(default=10, ge=1, le=60)
    dynamic_server_timeout: int = Field(default=30, ge=5, le=300)
    semantic: SemanticConfig = Field(default_factory=SemanticConfig)
    # --- Network & remote scan options (opt-in, default offline-safe) ---
    # Enable network requests: OSV.dev CVE lookup, abandoned-dep check, HTTP URL fetch
    allow_network_requests: bool = False
    # Enable remote artifact scanning: git URL cloning, HTTP URL download (requires git on PATH)
    allow_remote_scan: bool = False
    # --- LLM analysis options (opt-in, requires API subscription) ---
    allow_llm_analysis: bool = False
    llm_provider: str = "openai"  # openai | anthropic | nvidia
    llm_model: str | None = None  # None = provider default
    # --- Script scanning options ---
    script_scanning_enabled: bool = True
    script_extensions: list[str] = Field(
        default_factory=lambda: [
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
    )
    # --- Phase 2: Scanner false-positive reduction options ---
    first_party_path_patterns: list[str] = Field(
        default_factory=lambda: [
            "tests/**",
            "test/**",
            "__tests__/**",
            "spec/**",
            ".kiro/specs/**",
            "docs/**",
            "doc/**",
            "src/**",
            "lib/**",
        ],
        description="Glob patterns for first-party files (provenance checks relaxed)",
    )
    additional_shell_executables: list[str] = Field(
        default_factory=list,
        description="Additional shell executable names for Command_Pattern detection",
    )
