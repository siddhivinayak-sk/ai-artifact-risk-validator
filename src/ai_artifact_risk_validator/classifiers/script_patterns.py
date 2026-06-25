"""Script file classification patterns for AI tool directory detection.

Defines pattern mappings used by the script classification layer to identify
AI-related script files based on their directory location, parent directory
naming conventions, and file extensions.

Mappings:
    - KNOWN_AI_DIRECTORIES: AI tool ecosystems and their artifact type mappings
    - TYPE_INDICATING_DIRS: Directory names that imply a specific artifact type
    - TYPE_INDICATING_PATTERNS: Regex patterns for partial directory segment matching
    - DEFAULT_SCRIPT_EXTENSIONS: File extensions considered script/code files
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.enums import ArtifactType

# ---------------------------------------------------------------------------
# KNOWN_AI_DIRECTORIES
# Maps known AI tool directory prefixes to their artifact type classification.
# For directories with subdirectory-specific types (e.g., .kiro), the value is
# a dict mapping subdirectory names to artifact types, with "_default" as the
# fallback when no subdirectory matches.
# ---------------------------------------------------------------------------

KNOWN_AI_DIRECTORIES: dict[str, ArtifactType | dict[str, ArtifactType]] = {
    ".kiro": {
        "hooks": ArtifactType.HOOK,
        "skills": ArtifactType.SKILL,
        "steering": ArtifactType.STEERING,
        "specs": ArtifactType.INSTRUCTION,
        "_default": ArtifactType.INSTRUCTION,
    },
    ".github/copilot": ArtifactType.INSTRUCTION,
    ".claude": ArtifactType.INSTRUCTION,
    ".cursor": ArtifactType.INSTRUCTION,
    ".continue": ArtifactType.PLUGIN,
    ".codeium": ArtifactType.PLUGIN,
    ".tabnine": ArtifactType.PLUGIN,
}

# ---------------------------------------------------------------------------
# TYPE_INDICATING_DIRS
# Maps directory names to artifact types. When a script file resides in a
# directory whose name matches one of these keys (case-insensitive), the file
# is classified with the corresponding artifact type.
# ---------------------------------------------------------------------------

TYPE_INDICATING_DIRS: dict[str, ArtifactType] = {
    "skills": ArtifactType.SKILL,
    "hooks": ArtifactType.HOOK,
    ".hooks": ArtifactType.HOOK,
    "mcp-servers": ArtifactType.MCP,
    "mcp": ArtifactType.MCP,
    "plugins": ArtifactType.PLUGIN,
    "extensions": ArtifactType.PLUGIN,
    "agents": ArtifactType.AGENT,
}

# ---------------------------------------------------------------------------
# TYPE_INDICATING_PATTERNS
# Regex patterns for partial directory segment matching. These are matched
# against individual path segments (directory names) using case-insensitive
# substring search. For example, "skill" matches "my-skills", "skill-lib".
# ---------------------------------------------------------------------------

TYPE_INDICATING_PATTERNS: dict[str, ArtifactType] = {
    r"skill": ArtifactType.SKILL,
    r"mcp-server": ArtifactType.MCP,
}

# ---------------------------------------------------------------------------
# DEFAULT_SCRIPT_EXTENSIONS
# File extensions considered to be script or code files. Used as the default
# value for ValidatorConfig.script_extensions.
# ---------------------------------------------------------------------------

DEFAULT_SCRIPT_EXTENSIONS: list[str] = [
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
