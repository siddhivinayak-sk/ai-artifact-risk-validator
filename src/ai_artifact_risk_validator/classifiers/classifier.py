"""Artifact type classification using weighted signal scoring.

Implements the ArtifactClassifier which determines the type of an AI artifact
based on multiple signals: file extension, path patterns, content markers,
directory context, and (optionally) semantic similarity.

Each signal contributes a weighted score, and the artifact type with the
highest aggregate score (above the minimum threshold) is selected.

When ``sentence-transformers`` is installed, a fifth *semantic* signal is
added by comparing file content against per-type reference hints.  The
semantic weight is redistributed from the existing content signal so that
classification behaviour is backward-compatible when ML deps are absent.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.models.enums import ArtifactType

from .patterns import (
    CONTENT_MARKERS,
    DIR_CONTEXT_PATTERNS,
    EXTENSION_PATTERNS,
    PATH_PATTERNS,
    SIGNAL_WEIGHTS,
)

if TYPE_CHECKING:
    from .script_context import ScriptClassificationContext

logger = get_logger(__name__)

# Minimum score threshold for a valid classification
_CLASSIFICATION_THRESHOLD: float = 0.3

# Pre-compiled regex patterns for detecting test file paths
_TEST_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(^|[\\/])tests?[\\/]"),
    re.compile(r"(^|[\\/])__tests__[\\/]"),
    re.compile(r"(^|[\\/])spec[\\/]"),
    re.compile(r"test_[^/\\]+\.py$"),
    re.compile(r"[^/\\]+_test\.py$"),
]

# Pre-compiled regex for YAML frontmatter with type or artifact_type field
_FRONTMATTER_TYPE_RE: re.Pattern[str] = re.compile(
    r"^---\s*\n(?:.*\n)*?\s*(?:type|artifact_type)\s*:.*\n(?:.*\n)*?---",
    re.MULTILINE,
)

# Pre-compiled regex for artifact_type comment line
_ARTIFACT_TYPE_COMMENT_RE: re.Pattern[str] = re.compile(r"^\s*#\s*artifact_type\s*:", re.MULTILINE)

# Weight allocated to the semantic signal (taken from content weight)
_SEMANTIC_WEIGHT: float = 0.10

# Path to the built-in artifact classifier hints corpus
_HINTS_PATH: Path = (
    Path(__file__).resolve().parent.parent
    / "semantic"
    / "corpora"
    / "artifact_classifier_hints.json"
)


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

    def __init__(
        self,
        custom_patterns: dict[str, list[str]] | None = None,
        semantic_enabled: bool = True,
    ) -> None:
        """Initialize the classifier with optional custom patterns.

        Args:
            custom_patterns: Optional mapping of artifact type name to list of
                regex patterns that augment the built-in path patterns for
                classification. Keys should match ArtifactType values
                (e.g. "prompt", "skill", "mcp").
            semantic_enabled: Whether semantic classification is allowed.
                When ``False``, the semantic signal is skipped regardless of
                library availability. Defaults to ``True`` for backward
                compatibility.
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

        self._semantic_enabled: bool = semantic_enabled

        # Semantic support (lazy-loaded)
        self._semantic_available: bool | None = None
        self._scorer: Any | None = None
        self._hints: dict[str, list[str]] | None = None
        self._hint_embeddings: dict[str, Any] | None = None

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

        # Signals 3 & 5: Content match + Semantic similarity
        # When semantic is available, content weight is reduced by _SEMANTIC_WEIGHT
        # and a new semantic signal is added with _SEMANTIC_WEIGHT.
        semantic_available = self._is_semantic_available()
        content_weight = SIGNAL_WEIGHTS["content"]
        if semantic_available:
            content_weight -= _SEMANTIC_WEIGHT

        if content is not None and self._check_content(artifact_type, content):
            score += content_weight
            signals.append("content")

        # Signal 5: Semantic similarity (only when ML deps present)
        if semantic_available and content is not None:
            sem_score = self._check_semantic(artifact_type, content)
            if sem_score > 0.0:
                score += _SEMANTIC_WEIGHT * sem_score
                signals.append("semantic")

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

    # ------------------------------------------------------------------
    # Semantic signal helpers
    # ------------------------------------------------------------------

    def _is_semantic_available(self) -> bool:
        """Check if semantic scoring is available (lazy, cached)."""
        if not self._semantic_enabled:
            return False
        if self._semantic_available is None:
            try:
                from ai_artifact_risk_validator.semantic.embeddings import get_shared_engine

                self._semantic_available = get_shared_engine().is_available
            except Exception:
                self._semantic_available = False
        return self._semantic_available

    def _load_hints(self) -> dict[str, list[str]]:
        """Load the artifact classifier hints corpus.

        Returns:
            Mapping of artifact type value → list of hint sentences.
        """
        if self._hints is not None:
            return self._hints

        try:
            with _HINTS_PATH.open(encoding="utf-8") as f:
                self._hints = json.load(f)
        except Exception:
            logger.debug("Failed to load classifier hints", path=str(_HINTS_PATH))
            self._hints = {}
        return self._hints

    def _get_scorer(self) -> Any:
        """Lazily create and return the SimilarityScorer."""
        if self._scorer is None:
            from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer

            self._scorer = SimilarityScorer()
        return self._scorer

    def _get_hint_embeddings(self, artifact_type: ArtifactType) -> Any:
        """Get cached hint embeddings for an artifact type.

        Returns:
            Numpy array of hint embeddings, or ``None`` if hints are empty.
        """
        if self._hint_embeddings is None:
            self._hint_embeddings = {}

        type_key = artifact_type.value
        if type_key not in self._hint_embeddings:
            hints = self._load_hints().get(type_key, [])
            if not hints:
                self._hint_embeddings[type_key] = None
            else:
                scorer = self._get_scorer()
                self._hint_embeddings[type_key] = scorer.encode(hints)
        return self._hint_embeddings[type_key]

    def _check_semantic(self, artifact_type: ArtifactType, content: str) -> float:
        """Compute semantic similarity of content to artifact type hints.

        Returns a score between 0.0 and 1.0 indicating how well the content
        matches the reference hints for the given artifact type. Returns 0.0
        if hints are missing or on any error.

        Args:
            artifact_type: The artifact type to check against.
            content: File content to score.

        Returns:
            Similarity score (0.0 – 1.0).
        """
        try:
            embeddings = self._get_hint_embeddings(artifact_type)
            if embeddings is None:
                return 0.0

            # Use first 500 chars of content for efficiency
            snippet = content[:500]
            scorer = self._get_scorer()
            result: float = scorer.score_against_corpus(snippet, embeddings)
            return result
        except Exception:
            logger.debug("Semantic classification failed", artifact_type=artifact_type.value)
            return 0.0

    def _is_test_file(self, path: str) -> bool:
        """Check if a file path matches test directory or test file patterns.

        Args:
            path: File path string to check against test patterns.

        Returns:
            True if the path matches any test file pattern.
        """
        for pattern in _TEST_PATH_PATTERNS:
            if pattern.search(path):
                return True
        return False

    def _has_explicit_artifact_metadata(self, content: str) -> bool:
        """Check if file content contains explicit artifact metadata markers.

        Looks for:
        - YAML frontmatter (between ``---`` markers) containing a ``type:``
          or ``artifact_type:`` field
        - A comment line matching ``# artifact_type:`` pattern

        Args:
            content: File content to inspect.

        Returns:
            True if any artifact metadata marker is found.
        """
        if not content:
            return False

        # Check for YAML frontmatter with type/artifact_type field
        if _FRONTMATTER_TYPE_RE.search(content):
            return True

        # Check for # artifact_type: comment line
        if _ARTIFACT_TYPE_COMMENT_RE.search(content):
            return True

        return False

    def classify_script(
        self,
        file_path: Path,
        context: ScriptClassificationContext,
        content: str | None = None,
    ) -> ClassificationResult | None:
        """Classify a script file using multi-layered signals.

        Classification precedence (highest to lowest):
        0. Test file exclusion (early exit if test path without metadata)
        1. Known AI Directory detection (path signal, weight 0.35)
        2. Type-Indicating Directory (path signal, weight 0.35)
        3. Reference resolution (referenced_scripts context)
        4. MCP Server Project detection (path signal, weight 0.35)
        5. Sibling artifact classification (directory_context signal, weight 0.30)

        Returns a ClassificationResult if at least one signal produces a score
        exceeding the classification threshold (0.30), or None otherwise.

        Args:
            file_path: Path to the script file being classified.
            context: ScriptClassificationContext with pass-1 classification data.
            content: Optional file content (unused for signal injection but
                preserved for forward compatibility).

        Returns:
            ClassificationResult with artifact_type and confidence, or None
            if no signal produces a score above the classification threshold.
        """
        # Phase 2: Test file exclusion — check BEFORE all other classification signals
        normalized_path = file_path.as_posix()
        if self._is_test_file(normalized_path):
            file_content = content if content is not None else self._read_file_content(file_path)
            if file_content is None or not self._has_explicit_artifact_metadata(file_content):
                logger.debug("test_file_classification_exclusion", path=normalized_path)
                return None
            # Has explicit metadata → proceed with normal classification
            # (the metadata will be picked up by existing classification logic)

        from .script_patterns import (
            KNOWN_AI_DIRECTORIES,
            TYPE_INDICATING_DIRS,
            TYPE_INDICATING_PATTERNS,
        )

        # 1. Known AI Directory detection (weight 0.35)
        known_result = self._check_known_ai_directory(file_path, KNOWN_AI_DIRECTORIES)
        if known_result is not None:
            return known_result

        # 2. Type-Indicating Directory (weight 0.35)
        type_dir_result = self._check_type_indicating_directory(
            file_path, TYPE_INDICATING_DIRS, TYPE_INDICATING_PATTERNS
        )
        if type_dir_result is not None:
            return type_dir_result

        # 3. Reference Resolution
        resolved_path = file_path.resolve()
        if resolved_path in context.referenced_scripts:
            ref_type = context.referenced_scripts[resolved_path]
            return ClassificationResult(
                artifact_type=ref_type,
                confidence=0.35,
                signals=["path"],
            )

        # 4. MCP Server Project detection (weight 0.35)
        file_dir = file_path.resolve().parent
        for mcp_dir in context.mcp_project_dirs:
            try:
                file_dir.relative_to(mcp_dir)
                return ClassificationResult(
                    artifact_type=ArtifactType.MCP,
                    confidence=0.35,
                    signals=["path"],
                )
            except ValueError:
                continue

        # 5. Sibling Artifact Classification (weight 0.30)
        sibling_result = self._check_sibling_classification(file_path, context)
        if sibling_result is not None:
            return sibling_result

        return None

    def _check_known_ai_directory(
        self,
        file_path: Path,
        known_dirs: dict[str, ArtifactType | dict[str, ArtifactType]],
    ) -> ClassificationResult | None:
        """Check if a file resides in a Known AI Directory.

        For directories with subdirectory-specific mappings (like .kiro),
        checks path segments after the known dir prefix for a subdirectory match.

        Args:
            file_path: Path to the script file.
            known_dirs: Mapping from KNOWN_AI_DIRECTORIES.

        Returns:
            ClassificationResult with confidence 0.35 if matched, else None.
        """
        normalized = file_path.as_posix()
        parts_lower = [p.lower() for p in Path(normalized).parts]

        for dir_key, type_or_map in known_dirs.items():
            # The dir_key can contain slashes (e.g., ".github/copilot")
            dir_segments = dir_key.lower().split("/")
            dir_len = len(dir_segments)

            # Search for the dir_key segments in the path
            for i in range(len(parts_lower) - dir_len + 1):
                if parts_lower[i : i + dir_len] == dir_segments:
                    # Matched the known directory prefix
                    if isinstance(type_or_map, dict):
                        # Check subdirectory segments after the known dir
                        remaining = parts_lower[i + dir_len :]
                        artifact_type: ArtifactType | None = None
                        for seg in remaining:
                            if seg in type_or_map:
                                artifact_type = type_or_map[seg]
                                break
                        if artifact_type is None:
                            artifact_type = type_or_map.get("_default", ArtifactType.INSTRUCTION)
                        return ClassificationResult(
                            artifact_type=artifact_type,
                            confidence=0.35,
                            signals=["path"],
                        )
                    else:
                        return ClassificationResult(
                            artifact_type=type_or_map,
                            confidence=0.35,
                            signals=["path"],
                        )

        return None

    def _check_type_indicating_directory(
        self,
        file_path: Path,
        type_dirs: dict[str, ArtifactType],
        type_patterns: dict[str, ArtifactType],
    ) -> ClassificationResult | None:
        """Check if any parent directory segment matches Type-Indicating patterns.

        Uses case-insensitive exact match against TYPE_INDICATING_DIRS and
        case-insensitive substring/regex match against TYPE_INDICATING_PATTERNS.
        Applies nearest-ancestor logic: the matching segment closest to the file
        wins. For ties at the same depth, uses alphabetical ordering of the
        directory name as a deterministic fallback.

        Args:
            file_path: Path to the script file.
            type_dirs: Mapping from TYPE_INDICATING_DIRS.
            type_patterns: Mapping from TYPE_INDICATING_PATTERNS.

        Returns:
            ClassificationResult with confidence 0.35 if matched, else None.
        """
        parts = list(file_path.parts)
        # Exclude the filename itself — only check directory segments
        dir_parts = parts[:-1] if parts else []

        # Search from nearest ancestor to farthest (reverse order)
        # Track the best match: closest to file wins
        best_type: ArtifactType | None = None
        best_depth: int = -1  # Higher index = closer to file
        best_dir_name: str = ""

        for idx, segment in enumerate(dir_parts):
            segment_lower = segment.lower()

            # Check exact match against TYPE_INDICATING_DIRS (case-insensitive)
            if segment_lower in type_dirs:
                if idx > best_depth or (idx == best_depth and segment_lower < best_dir_name):
                    best_type = type_dirs[segment_lower]
                    best_depth = idx
                    best_dir_name = segment_lower

            # Check regex/substring match against TYPE_INDICATING_PATTERNS
            for pattern, artifact_type in type_patterns.items():
                if re.search(pattern, segment_lower, re.IGNORECASE):
                    if idx > best_depth or (idx == best_depth and segment_lower < best_dir_name):
                        best_type = artifact_type
                        best_depth = idx
                        best_dir_name = segment_lower

        if best_type is not None:
            return ClassificationResult(
                artifact_type=best_type,
                confidence=0.35,
                signals=["path"],
            )

        return None

    def _check_sibling_classification(
        self,
        file_path: Path,
        context: ScriptClassificationContext,
    ) -> ClassificationResult | None:
        """Check sibling artifact classification for the file's directory.

        Only uses siblings from directory_artifacts (non-script files classified
        through non-sibling signals) to prevent transitivity.

        If mcp.json is present in the directory, always returns MCP regardless
        of other siblings.

        Args:
            file_path: Path to the script file.
            context: ScriptClassificationContext with directory_artifacts data.

        Returns:
            ClassificationResult with confidence 0.30 if matched, else None.
        """
        file_dir = file_path.resolve().parent

        # Check for mcp.json sibling override
        mcp_json_path = file_dir / "mcp.json"
        if mcp_json_path.exists():
            return ClassificationResult(
                artifact_type=ArtifactType.MCP,
                confidence=0.30,
                signals=["directory_context"],
            )

        # Look up directory_artifacts for this directory
        siblings = context.directory_artifacts.get(file_dir, [])
        if not siblings:
            return None

        # Find the sibling with the highest confidence score
        # For ties, use ArtifactType enum ordering (first in enum wins)
        best_type: ArtifactType | None = None
        best_confidence: float = -1.0

        # Build enum order mapping for tie-breaking
        enum_order = {t: i for i, t in enumerate(ArtifactType)}

        for artifact_type, confidence in siblings:
            if confidence > best_confidence or (
                confidence == best_confidence
                and best_type is not None
                and enum_order.get(artifact_type, 999) < enum_order.get(best_type, 999)
            ):
                best_type = artifact_type
                best_confidence = confidence

        if best_type is not None and best_confidence >= _CLASSIFICATION_THRESHOLD:
            return ClassificationResult(
                artifact_type=best_type,
                confidence=0.30,
                signals=["directory_context"],
            )

        return None

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
