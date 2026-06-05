"""File discovery and filtering for the validation pipeline.

Implements recursive file discovery with configurable include/exclude pattern
matching and max file size filtering. Handles permission errors and encoding
issues gracefully by logging warnings and skipping problematic files.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.models.config import ValidatorConfig

logger = get_logger(__name__)


class FileDiscovery:
    """Discovers and filters files for validation scanning.

    Recursively walks directories to find files that match inclusion patterns,
    do not match exclusion patterns, and are within the configured file size limit.

    Args:
        config: Optional ValidatorConfig providing file_include_patterns,
            file_exclude_patterns, and max_file_size_bytes. Defaults are used
            if None.
    """

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        self._config = config or ValidatorConfig()
        self._include_patterns: list[str] = self._config.file_include_patterns
        self._exclude_patterns: list[str] = self._config.file_exclude_patterns
        self._max_file_size_bytes: int = self._config.max_file_size_bytes

    def discover(self, path: Path) -> list[Path]:
        """Discover files at the given path, applying filters.

        If path is a file, returns [path] if it passes all filters.
        If path is a directory, recursively walks and returns all files
        passing filters.

        Args:
            path: A file or directory path to scan.

        Returns:
            List of Path objects for files that pass all filters.
        """
        if not path.exists():
            logger.warning("Path does not exist", path=str(path))
            return []

        if path.is_file():
            if self._passes_filters(path):
                return [path]
            return []

        if path.is_dir():
            return self._walk_directory(path)

        logger.debug("Path is neither file nor directory", path=str(path))
        return []

    def _walk_directory(self, directory: Path) -> list[Path]:
        """Recursively walk a directory and collect files passing filters.

        Args:
            directory: The directory to walk.

        Returns:
            List of Path objects for discovered files.
        """
        discovered: list[Path] = []

        try:
            entries = list(directory.rglob("*"))
        except PermissionError:
            logger.warning(
                "Permission denied accessing directory",
                artifact_path=str(directory),
            )
            return []
        except OSError as e:
            logger.warning(
                "OS error accessing directory",
                artifact_path=str(directory),
                error=str(e),
            )
            return []

        for entry in entries:
            if not entry.is_file():
                continue

            try:
                if self._passes_filters(entry):
                    discovered.append(entry)
            except PermissionError:
                logger.warning(
                    "Permission denied accessing file",
                    artifact_path=str(entry),
                )
            except OSError as e:
                logger.warning(
                    "OS error accessing file",
                    artifact_path=str(entry),
                    error=str(e),
                )

        return discovered

    def _passes_filters(self, file_path: Path) -> bool:
        """Check whether a file passes all configured filters.

        Checks in order:
        1. Exclude patterns (skip if matches any)
        2. Include patterns (skip if non-empty and matches none)
        3. Max file size (skip if exceeds limit)

        Args:
            file_path: Path to the file to check.

        Returns:
            True if the file passes all filters.
        """
        name = file_path.name
        relative_str = str(file_path)

        # Check exclude patterns
        if self._matches_any_pattern(name, relative_str, self._exclude_patterns):
            logger.debug("File excluded by pattern", artifact_path=str(file_path))
            return False

        # Check include patterns (empty means include all)
        if self._include_patterns:
            if not self._matches_any_pattern(
                name, relative_str, self._include_patterns
            ):
                logger.debug("File not matched by include patterns", artifact_path=str(file_path))
                return False

        # Check file size
        try:
            file_size = file_path.stat().st_size
        except PermissionError:
            logger.warning("Permission denied checking file size", artifact_path=str(file_path))
            return False
        except OSError as e:
            logger.warning(
                "OS error checking file size",
                artifact_path=str(file_path),
                error=str(e),
            )
            return False

        if file_size > self._max_file_size_bytes:
            logger.debug(
                "File exceeds max size",
                artifact_path=str(file_path),
                file_size=file_size,
                max_size=self._max_file_size_bytes,
            )
            return False

        return True

    def _matches_any_pattern(
        self, filename: str, full_path: str, patterns: list[str]
    ) -> bool:
        """Check if a file matches any of the given glob patterns.

        Matches against both the filename alone and the full path string
        to support patterns like '*.py' and 'tests/**/*.py'.

        Args:
            filename: The file's name (basename).
            full_path: The full string path of the file.
            patterns: List of glob patterns to match against.

        Returns:
            True if the file matches at least one pattern.
        """
        for pattern in patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
            if fnmatch.fnmatch(full_path, pattern):
                return True
        return False
