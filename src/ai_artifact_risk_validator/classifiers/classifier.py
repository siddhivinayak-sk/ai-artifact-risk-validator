"""Artifact type classification using weighted signal scoring.

Implements the ArtifactClassifier which determines the type of an AI artifact
based on multiple signals: file extension, path patterns, content markers,
and directory context. Each signal contributes a weighted score, and the
artifact type with the highest aggregate score (above the minimum threshold)
is selected.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from ai_artifact_risk_validator.models.enums import ArtifactType

from .patterns import (
    CONTENT_MARKERS,
    DIR_CONTEXT_PATTERNS,
    EXTENSION_PATTERNS,
    PATH_PATTERNS,
    SIGNAL_WEIGHTS,
)

# Minimum score threshold for a valid classification
_CLASSIFICATION_THRESHOLD: float = 0.3


class ClassificationResult(BaseModel):
    """Result of artifact type classification."""

    artifact_type: ArtifactType
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[str]  # Which detection signals matched


class ArtifactClassifier:
    """Classifies files into artifact types based on multiple signals.

    Uses a weighted scoring algorithm combining:
      - Extension match (weight 0.30)
      - Path match (weight 0.35)
      - Content match (weight 0.25)
      - Directory context match (weight 0.10)

    The highest-scoring artifact type above the 0.3 threshold is returned.
    """

    def __init__(self, custom_patterns: dict[str, list[str]] | None = None) -> None:
        """Initialize the classifier with optional custom patterns.

        Args:
            custom_patterns: Optional mapping of artifact type name to list of
                regex patterns that augment the built-in path patterns for
                classification. Keys should match ArtifactType values
                (e.g. "prompt", "skill", "mcp").
        """
        self._custom_patterns: dict[ArtifactType, list[str]] = {}
        if custom_patterns:
            for type_name, patterns in custom_patterns.items():
                try:
                    artifact_type = ArtifactType(type_name)
                    self._custom_patterns[artifact_type] = patterns
                except ValueError:
                    # Skip unknown artifact type names gracefully
                    pass

    def classify(self, file_path: Path, content: str | None = None) -> ClassificationResult | None:
        """Classify a file into an artifact type.

        Args:
            file_path: Path to the file being classified.
            content: Optional file content. If not provided, the file is read
                from disk. If reading fails, content-based signals are skipped.

        Returns:
            ClassificationResult with artifact_type and confidence, or None
            if no type reaches the minimum confidence threshold.
        """
        # Read content if not provided
        if content is None:
            content = self._read_file_content(file_path)

        # Normalize the file path for matching (use forward slashes)
        normalized_path = file_path.as_posix()

        # Score each artifact type
        best_score: float = 0.0
        best_type: ArtifactType | None = None
        best_signals: list[str] = []

        for artifact_type in ArtifactType:
            score, signals = self._compute_score(artifact_type, file_path, normalized_path, content)
            if score > best_score:
                best_score = score
                best_type = artifact_type
                best_signals = signals

        # Apply threshold
        if best_score < _CLASSIFICATION_THRESHOLD or best_type is None:
            return None

        return ClassificationResult(
            artifact_type=best_type,
            confidence=best_score,
            signals=best_signals,
        )

    def _compute_score(
        self,
        artifact_type: ArtifactType,
        file_path: Path,
        normalized_path: str,
        content: str | None,
    ) -> tuple[float, list[str]]:
        """Compute the weighted score for a given artifact type.

        Returns:
            Tuple of (score, list of matched signal names).
        """
        score = 0.0
        signals: list[str] = []

        # Signal 1: Extension match (weight 0.30)
        if self._check_extension(artifact_type, file_path):
            score += SIGNAL_WEIGHTS["extension"]
            signals.append("extension")

        # Signal 2: Path match (weight 0.35)
        if self._check_path(artifact_type, normalized_path):
            score += SIGNAL_WEIGHTS["path"]
            signals.append("path")

        # Signal 3: Content match (weight 0.25)
        if content is not None and self._check_content(artifact_type, content):
            score += SIGNAL_WEIGHTS["content"]
            signals.append("content")

        # Signal 4: Directory context match (weight 0.10)
        if self._check_directory_context(artifact_type, file_path):
            score += SIGNAL_WEIGHTS["directory_context"]
            signals.append("directory_context")

        return score, signals

    def _check_extension(self, artifact_type: ArtifactType, file_path: Path) -> bool:
        """Check if the file extension matches patterns for the artifact type."""
        patterns = EXTENSION_PATTERNS.get(artifact_type, [])
        if not patterns:
            return False

        # Get the file name in lowercase for case-insensitive matching
        file_name_lower = file_path.name.lower()

        for pattern in patterns:
            pattern_lower = pattern.lower()
            # Support compound extensions like ".prompt.md"
            if file_name_lower.endswith(pattern_lower):
                return True

        return False

    def _check_path(self, artifact_type: ArtifactType, normalized_path: str) -> bool:
        """Check if the file path matches any path pattern for the artifact type."""
        patterns = PATH_PATTERNS.get(artifact_type, [])

        # Also include custom patterns
        custom = self._custom_patterns.get(artifact_type, [])

        all_patterns = patterns + custom

        for pattern in all_patterns:
            try:
                if re.search(pattern, normalized_path, re.IGNORECASE):
                    return True
            except re.error:
                # Skip invalid regex patterns gracefully
                continue

        return False

    def _check_content(self, artifact_type: ArtifactType, content: str) -> bool:
        """Check if the file content matches any content markers for the artifact type."""
        patterns = CONTENT_MARKERS.get(artifact_type, [])
        if not patterns:
            return False

        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    return True
            except re.error:
                # Skip invalid regex patterns gracefully
                continue

        return False

    def _check_directory_context(self, artifact_type: ArtifactType, file_path: Path) -> bool:
        """Check directory context signals for the artifact type.

        Checks both the parent directory name and sibling filenames against
        the DIR_CONTEXT_PATTERNS.
        """
        patterns = DIR_CONTEXT_PATTERNS.get(artifact_type, [])
        if not patterns:
            return False

        # Check parent directory name
        parent_name = file_path.parent.name

        for pattern in patterns:
            try:
                if re.search(pattern, parent_name, re.IGNORECASE):
                    return True
            except re.error:
                continue

        # Check sibling files (if parent directory exists and is readable)
        try:
            parent_dir = file_path.parent
            if parent_dir.exists() and parent_dir.is_dir():
                for sibling in parent_dir.iterdir():
                    if sibling == file_path:
                        continue
                    sibling_name = sibling.name
                    for pattern in patterns:
                        try:
                            if re.search(pattern, sibling_name, re.IGNORECASE):
                                return True
                        except re.error:
                            continue
        except (PermissionError, OSError):
            # Cannot read directory - skip this signal
            pass

        # Also check the full parent path for patterns that need it
        # (e.g., ".kiro/steering" in the path)
        parent_path = file_path.parent.as_posix()
        for pattern in patterns:
            try:
                if re.search(pattern, parent_path, re.IGNORECASE):
                    return True
            except re.error:
                continue

        return False

    @staticmethod
    def _read_file_content(file_path: Path) -> str | None:
        """Read file content, returning None on failure.

        Tries UTF-8 encoding first, then falls back to latin-1.
        Returns None if the file cannot be read at all.
        """
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                return file_path.read_text(encoding="latin-1")
            except (OSError, PermissionError):
                return None
        except (OSError, PermissionError):
            return None
