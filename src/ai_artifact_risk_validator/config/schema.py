"""JSON Schema for .aav.yaml configuration file validation.

Defines CONFIG_SCHEMA as a valid JSON Schema dict that can be used with
jsonschema.validate() to validate user-provided .aav.yaml configuration files.

Requirements: 6.5, 6.6
"""

from __future__ import annotations

# All valid scanner module names
_SCANNER_NAMES = [
    "SecretScan",
    "InjectionDet",
    "PermAudit",
    "TokenAnalyzer",
    "SchemaValid",
    "DepScan",
    "QualityLint",
    "ProvenanceChk",
    "BiasDetector",
    "ComposeAnalyze",
    "PortabilityChk",
    "ComplianceAudit",
    "CodeAudit",
]

# All valid gate action values
_GATE_ACTIONS = ["BLOCK", "WARN", "INFO"]

# All valid log levels
_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

CONFIG_SCHEMA: dict[str, object] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "AI Artifact Risk Validator Configuration",
    "description": "Schema for .aav.yaml configuration files.",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "log_level": {
            "type": "string",
            "enum": _LOG_LEVELS,
            "description": "Logging level for the validator.",
        },
        "severity_threshold": {
            "type": "integer",
            "minimum": 1,
            "maximum": 10,
            "description": "Minimum severity score (1-10) for findings to be reported.",
        },
        "max_file_size_bytes": {
            "type": "integer",
            "minimum": 1,
            "description": "Maximum file size in bytes to scan.",
        },
        "parallel_files": {
            "type": "integer",
            "minimum": 1,
            "maximum": 32,
            "description": "Number of files to process in parallel.",
        },
        "parallel_scanners": {
            "type": "integer",
            "minimum": 1,
            "maximum": 16,
            "description": "Number of scanners to run in parallel per file.",
        },
        "file_include_patterns": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Glob patterns for files to include in scanning.",
        },
        "file_exclude_patterns": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Glob patterns for files to exclude from scanning.",
        },
        "enabled_scanners": {
            "oneOf": [
                {
                    "type": "array",
                    "items": {"type": "string", "enum": _SCANNER_NAMES},
                },
                {"type": "null"},
            ],
            "description": "List of scanner module names to enable. Null means all scanners.",
        },
        "disabled_scanners": {
            "type": "array",
            "items": {"type": "string", "enum": _SCANNER_NAMES},
            "description": "List of scanner module names to disable.",
        },
        "custom_plugin_dirs": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Directories to search for custom scanner plugins.",
        },
        "suppression_rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["risk_id"],
                "additionalProperties": False,
                "properties": {
                    "risk_id": {
                        "type": "string",
                        "description": "Risk ID to suppress (e.g. P-S1, MCP-S3).",
                    },
                    "file_pattern": {
                        "type": ["string", "null"],
                        "description": "Glob pattern for files where this suppression applies.",
                    },
                    "reason": {
                        "type": ["string", "null"],
                        "description": "Reason for the suppression.",
                    },
                },
            },
            "description": "Rules for suppressing specific risk findings.",
        },
        "gate_overrides": {
            "type": "object",
            "additionalProperties": {
                "type": "string",
                "enum": _GATE_ACTIONS,
            },
            "description": "Override gate actions for specific risk IDs (risk_id -> gate_action).",
        },
        "custom_artifact_patterns": {
            "type": "object",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string"},
            },
            "description": "Custom artifact classification patterns (artifact_type -> list of glob patterns).",
        },
        "cache_dir": {
            "type": ["string", "null"],
            "description": "Directory for scan result caching.",
        },
        "token_budget_limit": {
            "type": ["integer", "null"],
            "minimum": 1,
            "description": "Maximum token budget for scanned artifacts.",
        },
        "html_report_path": {
            "type": ["string", "null"],
            "description": "File path to write the HTML report to as a side effect.",
        },
        "semantic": {
            "type": "object",
            "description": "Semantic analysis engine configuration.",
            "additionalProperties": False,
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "description": "Enable or disable semantic (embedding-based) analysis.",
                },
                "model_name": {
                    "type": "string",
                    "description": "Sentence-transformer model name.",
                },
                "threshold": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "description": "Minimum similarity score to flag a semantic match.",
                },
            },
        },
    },
}
