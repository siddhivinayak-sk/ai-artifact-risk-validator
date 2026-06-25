"""File discovery and filtering for the validation pipeline.

Implements recursive file discovery with configurable include/exclude pattern
matching and max file size filtering. Handles permission errors and encoding
issues gracefully by logging warnings and skipping problematic files.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.models.config import ValidatorConfig

logger = get_logger(__name__)

# Directories that are always skipped during traversal.
# These contain build artifacts, VCS internals, caches, or dependency
# trees that are never useful AI artifacts.
_ALWAYS_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        ".env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
        ".nox",
        ".eggs",
        "*.egg-info",
        "dist",
        "build",
        ".idea",
        ".vscode",
        ".kiro",
        "htmlcov",
        ".coverage",
        ".terraform",
    }
)


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
        # Build the effective skip dirs set, conditionally including .kiro
        self._skip_dirs: frozenset[str] = self._build_skip_dirs()

    def _build_skip_dirs(self) -> frozenset[str]:
        """Build the effective set of directories to skip during traversal.

        When script_scanning_enabled is True, `.kiro` is removed from the
        skip set so that script files within `.kiro/` are discovered.

        Returns:
            Frozenset of directory names to skip.
        """
        if self._config.script_scanning_enabled:
            return _ALWAYS_SKIP_DIRS - {".kiro"}
        return _ALWAYS_SKIP_DIRS

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

        Uses ``os.walk`` with ``topdown=True`` to prune well-known
        non-artifact directories (e.g. ``.git``, ``.venv``,
        ``node_modules``) *before* descending into them, avoiding
        unnecessary I/O on potentially thousands of irrelevant files.

        Args:
            directory: The directory to walk.

        Returns:
            List of Path objects for discovered files.
        """
        discovered: list[Path] = []

        try:
            for dirpath, dirnames, filenames in os.walk(directory, topdown=True):
                # Prune directories in-place so os.walk skips them
                dirnames[:] = [d for d in dirnames if not self._should_skip_dir_instance(d)]

                for fname in filenames:
                    file_path = Path(dirpath) / fname
                    try:
                        if self._passes_filters(file_path):
                            discovered.append(file_path)
                    except PermissionError:
                        logger.warning(
                            "Permission denied accessing file",
                            artifact_path=str(file_path),
                        )
                    except OSError as e:
                        logger.warning(
                            "OS error accessing file",
                            artifact_path=str(file_path),
                            error=str(e),
                        )
        except PermissionError:
            logger.warning(
                "Permission denied accessing directory",
                artifact_path=str(directory),
            )
        except OSError as e:
            logger.warning(
                "OS error accessing directory",
                artifact_path=str(directory),
                error=str(e),
            )

        return discovered

    @staticmethod
    def _should_skip_dir(dirname: str) -> bool:
        """Check whether a directory name should be pruned from traversal.

        Matches against the ``_ALWAYS_SKIP_DIRS`` set. Supports both exact
        matches and fnmatch-style patterns (e.g. ``*.egg-info``).

        Args:
            dirname: The directory's base name.

        Returns:
            True if the directory should be skipped.
        """
        if dirname in _ALWAYS_SKIP_DIRS:
            return True
        # Support glob patterns like *.egg-info
        return any(
            fnmatch.fnmatch(dirname, pat) for pat in _ALWAYS_SKIP_DIRS if "*" in pat or "?" in pat
        )

    def _should_skip_dir_instance(self, dirname: str) -> bool:
        """Check whether a directory name should be pruned from traversal.

        Uses the instance's effective skip dirs set (which may exclude
        `.kiro` when script scanning is enabled).

        Args:
            dirname: The directory's base name.

        Returns:
            True if the directory should be skipped.
        """
        if dirname in self._skip_dirs:
            return True
        # Support glob patterns like *.egg-info
        return any(
            fnmatch.fnmatch(dirname, pat) for pat in self._skip_dirs if "*" in pat or "?" in pat
        )

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
            if not self._matches_any_pattern(name, relative_str, self._include_patterns):
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

    def _matches_any_pattern(self, filename: str, full_path: str, patterns: list[str]) -> bool:
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
