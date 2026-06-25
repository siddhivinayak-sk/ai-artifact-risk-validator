"""Context data for script file classification.

Provides the ScriptClassificationContext dataclass that holds information
gathered during pass 1 (non-script classification) needed for script
classification in pass 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ai_artifact_risk_validator.models.enums import ArtifactType


@dataclass
class ScriptClassificationContext:
    """Context gathered from pass 1 for script classification."""

    # Map of directory → list of (artifact_type, confidence) from classified
    # non-script files
    directory_artifacts: dict[Path, list[tuple[ArtifactType, float]]] = field(default_factory=dict)

    # Set of script file paths referenced by classified artifacts
    # (with their inferred type)
    referenced_scripts: dict[Path, ArtifactType] = field(default_factory=dict)

    # Set of directories detected as MCP server projects
    mcp_project_dirs: set[Path] = field(default_factory=set)
