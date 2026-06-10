"""Built-in default configuration values for the AI Artifact Risk Validator.

Defines DEFAULT_CONFIG as a dict containing the default values used when no
configuration file or overrides are provided.

Requirements: 6.5, 6.6
"""

from __future__ import annotations

DEFAULT_CONFIG: dict[str, object] = {
    "log_level": "INFO",
    "severity_threshold": 1,
    "max_file_size_bytes": 10_485_760,  # 10 MB
    "parallel_files": 4,
    "parallel_scanners": 4,
    "file_include_patterns": [],
    "file_exclude_patterns": [],
    "enabled_scanners": None,  # None means all scanners enabled
    "disabled_scanners": [],
    "custom_plugin_dirs": [],
    "suppression_rules": [],
    "gate_overrides": {},
    "custom_artifact_patterns": {},
    "semantic": {
        "enabled": True,
        "model_name": "all-MiniLM-L6-v2",
        "threshold": 0.55,
    },
}
