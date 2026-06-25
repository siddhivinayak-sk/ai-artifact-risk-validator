"""Reference resolution for script files referenced by AI artifacts.

Parses classified AI artifacts to extract script file references (paths or
filenames) and resolves them against the discovered file tree.  Each resolved
reference is mapped to the artifact type of the referencing artifact, enabling
script files to inherit their classification from their referencing context.

Key behaviors:
- Tokenizes artifact content and matches tokens ending with configured
  script extensions.
- Resolves relative paths from the artifact's directory.
- Resolves bare filenames via case-insensitive exact basename match across
  all discovered files.
- Caps at 50 references per artifact (WARNING logged if exceeded).
- 30-second timeout per artifact processing.
- Rejects substring matches — only case-insensitive exact basename equality.
"""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.models.enums import ArtifactType

if TYPE_CHECKING:
    from ai_artifact_risk_validator.classifiers.classifier import ClassificationResult
    from ai_artifact_risk_validator.models.config import ValidatorConfig

logger = get_logger(__name__)

# Maximum number of references to process per artifact
_MAX_REFERENCES_PER_ARTIFACT: int = 50

# Timeout in seconds for processing a single artifact
_ARTIFACT_TIMEOUT_SECONDS: float = 30.0

# Regex pattern for tokenizing content — splits on whitespace, commas,
# quotes (single/double), brackets, colons, semicolons
_TOKEN_SPLIT_PATTERN: re.Pattern[str] = re.compile(r'[\s,\'"()\[\]{}<>:;]+')


class ReferenceResolver:
    """Resolves script file references from classified AI artifacts."""

    def __init__(
        self,
        config: ValidatorConfig,
        scan_root: Path,
        discovered_files: list[Path],
    ) -> None:
        """Initialize the reference resolver.

        Args:
            config: Validator configuration with script_extensions.
            scan_root: Root directory of the scan.
            discovered_files: All files discovered during file discovery.
        """
        self._config = config
        self._scan_root = scan_root.resolve()
        self._discovered_files = discovered_files
        self._extensions: set[str] = {ext.lower() for ext in config.script_extensions}
        # Pre-build a lookup of normalized paths for membership checks
        self._discovered_set: set[Path] = {f.resolve() for f in discovered_files}
        # Pre-build a basename → list[Path] index for bare filename resolution
        self._basename_index: dict[str, list[Path]] = {}
        for f in discovered_files:
            resolved = f.resolve()
            key = resolved.name.lower()
            if key not in self._basename_index:
                self._basename_index[key] = []
            self._basename_index[key].append(resolved)
        # Counters for summary logging (Req 9.3)
        self._unresolved_count: int = 0

    def resolve(
        self,
        classified_artifacts: dict[Path, ClassificationResult],
    ) -> dict[Path, ArtifactType]:
        """Extract and resolve script references from all classified artifacts.

        For each classified artifact, reads the file content, extracts script
        file references, and resolves them against the discovered file tree.

        Logs a summary at INFO level when at least one reference was processed,
        including resolved count, unresolved count, and wall-clock duration in
        milliseconds (Req 9.3).

        Args:
            classified_artifacts: Mapping of artifact path to its
                classification result from pass 1.

        Returns:
            Mapping of resolved script file Path → inferred ArtifactType.
        """
        import time

        resolved_scripts: dict[Path, ArtifactType] = {}
        self._unresolved_count = 0
        total_references_attempted = 0

        start_time = time.perf_counter()

        for artifact_path, classification in classified_artifacts.items():
            artifact_type = classification.artifact_type
            refs = self._process_artifact_with_timeout(artifact_path, artifact_type)
            if refs is None:
                continue

            for ref_path in refs:
                total_references_attempted += 1
                if ref_path not in resolved_scripts:
                    resolved_scripts[ref_path] = artifact_type

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Req 9.3: Log summary at INFO level when at least one reference was
        # processed. When zero references were found, do NOT log.
        total_processed = total_references_attempted + self._unresolved_count
        if total_processed > 0:
            logger.info(
                "Reference resolution complete",
                resolved_count=len(resolved_scripts),
                unresolved_count=self._unresolved_count,
                duration_ms=round(elapsed_ms, 1),
            )

        return resolved_scripts

    def _process_artifact_with_timeout(
        self,
        artifact_path: Path,
        artifact_type: ArtifactType,
    ) -> list[Path] | None:
        """Process a single artifact with a 30-second timeout.

        Returns a list of resolved script paths, or None if the artifact
        could not be processed (timeout, read error, etc.).
        """
        result: list[Path] | None = None
        exception_holder: list[BaseException] = []

        def _worker() -> None:
            nonlocal result
            try:
                result = self._process_artifact(artifact_path, artifact_type)
            except Exception as exc:
                exception_holder.append(exc)

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=_ARTIFACT_TIMEOUT_SECONDS)

        if thread.is_alive():
            logger.warning(
                "Reference resolution timed out for artifact",
                artifact_path=str(artifact_path),
                timeout_seconds=_ARTIFACT_TIMEOUT_SECONDS,
            )
            return None

        if exception_holder:
            exc = exception_holder[0]
            # Req 9.5: Log parsing/processing errors at WARNING level
            logger.warning(
                "Reference resolver parsing error",
                artifact_path=str(artifact_path),
                description=str(exc),
            )
            return None

        return result

    def _process_artifact(
        self,
        artifact_path: Path,
        artifact_type: ArtifactType,
    ) -> list[Path]:
        """Read artifact content, extract references, and resolve paths."""
        content = self._read_file_content(artifact_path)
        if content is None:
            return []

        references = self._extract_references(artifact_path, content, artifact_type)

        # Cap at 50 references per artifact
        if len(references) > _MAX_REFERENCES_PER_ARTIFACT:
            logger.warning(
                "Reference count exceeds limit, truncating",
                artifact_path=str(artifact_path),
                total_references=len(references),
                limit=_MAX_REFERENCES_PER_ARTIFACT,
            )
            references = references[:_MAX_REFERENCES_PER_ARTIFACT]

        resolved: list[Path] = []
        artifact_dir = artifact_path.resolve().parent

        for ref in references:
            path = self._resolve_path(ref, artifact_dir)
            if path is not None:
                if path in self._discovered_set:
                    resolved.append(path)
                else:
                    self._unresolved_count += 1
                    logger.info(
                        "Resolved reference not in discovered files",
                        artifact_path=str(artifact_path),
                        reference=ref,
                        resolved_path=str(path),
                    )
            else:
                self._unresolved_count += 1
                logger.info(
                    "Unresolved script reference",
                    artifact_path=str(artifact_path),
                    reference=ref,
                )

        return resolved

    def _read_file_content(self, file_path: Path) -> str | None:
        """Read file content with UTF-8 fallback to latin-1.

        Returns None if the file cannot be read.
        """
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                return file_path.read_text(encoding="latin-1")
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning(
                    "Cannot read artifact file",
                    artifact_path=str(file_path),
                    error=str(exc),
                )
                return None
        except OSError as exc:
            logger.warning(
                "Cannot read artifact file",
                artifact_path=str(file_path),
                error=str(exc),
            )
            return None

    def _extract_references(
        self,
        artifact_path: Path,
        content: str,
        artifact_type: ArtifactType,
    ) -> list[str]:
        """Extract script file references from a single artifact's content.

        Tokenizes the content by whitespace, commas, quotes, brackets, and
        colons, then matches tokens that end with one of the configured
        script extensions.

        Args:
            artifact_path: Path to the artifact (for logging context).
            content: The textual content of the artifact.
            artifact_type: Classified type of the artifact.

        Returns:
            List of reference strings (filenames or paths).
        """
        tokens = _TOKEN_SPLIT_PATTERN.split(content)
        references: list[str] = []

        for token in tokens:
            if not token:
                continue
            # Check if the token ends with a script extension
            token_lower = token.lower()
            for ext in self._extensions:
                if token_lower.endswith(ext):
                    references.append(token)
                    break

        return references

    def _resolve_path(
        self,
        reference: str,
        artifact_dir: Path,
    ) -> Path | None:
        """Resolve a reference string to an absolute Path, or None if not found.

        Resolution strategy:
        1. If the reference contains path separators (/ or \\), treat as a
           relative path and resolve from artifact_dir.
        2. If the reference is a bare filename, search discovered_files for
           a case-insensitive exact basename match.

        Rejects substring matches — only exact basename equality
        (case-insensitive) is accepted.

        Args:
            reference: The reference string extracted from the artifact.
            artifact_dir: The directory containing the referencing artifact.

        Returns:
            The resolved absolute Path, or None if not found.
        """
        if "/" in reference or "\\" in reference:
            # Relative path resolution
            try:
                resolved = (artifact_dir / reference).resolve()
            except (OSError, ValueError):
                return None
            if resolved in self._discovered_set:
                return resolved
            return None

        # Bare filename — case-insensitive exact basename match
        ref_lower = reference.lower()
        candidates = self._basename_index.get(ref_lower)
        if candidates:
            # Return the first match (deterministic since discovered_files
            # order is preserved during index construction)
            return candidates[0]

        return None
