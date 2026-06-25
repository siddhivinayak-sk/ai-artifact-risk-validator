"""MCP server project detection via build marker analysis.

Identifies directories containing MCP server implementations by inspecting
build marker files (package.json, pyproject.toml, setup.py, Cargo.toml,
build.gradle, build.gradle.kts, pom.xml) for MCP-specific dependency strings.

The detector maps each build marker filename to its language ecosystem and
checks for the presence of known MCP SDK references as substrings in the
file content. Unreadable or malformed markers are logged and skipped.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from ai_artifact_risk_validator._internal.logging import get_logger

logger = get_logger(__name__)

# Mapping from build marker filename to the language ecosystem key used
# in MCP_INDICATORS.
_MARKER_ECOSYSTEM_MAP: dict[str, str] = {
    "package.json": "javascript",
    "pyproject.toml": "python",
    "setup.py": "python",
    "Cargo.toml": "rust",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "pom.xml": "java",
}


class MCPProjectDetector:
    """Detects directories containing MCP server implementations."""

    # Build marker filenames to check
    BUILD_MARKERS: ClassVar[tuple[str, ...]] = (
        "package.json",
        "pyproject.toml",
        "setup.py",
        "Cargo.toml",
        "build.gradle",
        "build.gradle.kts",
        "pom.xml",
    )

    # MCP dependency indicators per language ecosystem
    MCP_INDICATORS: ClassVar[dict[str, list[str]]] = {
        "python": ["mcp", "fastmcp", "modelcontextprotocol"],
        "javascript": ["@modelcontextprotocol/sdk", "mcp-server"],
        "java": [
            "io.modelcontextprotocol",
            "mcp-sdk",
            "modelcontextprotocol",
        ],
        "rust": ["mcp-sdk", "mcp-server", "modelcontextprotocol"],
    }

    def detect(self, discovered_files: list[Path]) -> set[Path]:
        """Return set of directory paths that are MCP server projects.

        Filters *discovered_files* to locate build markers whose names match
        BUILD_MARKERS, then checks each marker for MCP dependency strings.

        Args:
            discovered_files: All files discovered during file traversal.

        Returns:
            A set of directory paths containing confirmed MCP server projects.
        """
        mcp_dirs: set[Path] = set()

        for file_path in discovered_files:
            if file_path.name not in self.BUILD_MARKERS:
                continue

            if self._check_build_marker(file_path):
                mcp_dirs.add(file_path.parent)

        return mcp_dirs

    def _check_build_marker(self, marker_path: Path) -> bool:
        """Check if a build marker contains MCP references.

        Reads the file content and checks whether any of the MCP_INDICATORS
        for the marker's ecosystem appear as substrings.

        Args:
            marker_path: Path to a build marker file.

        Returns:
            True if the marker contains at least one MCP dependency string.
        """
        ecosystem = _MARKER_ECOSYSTEM_MAP.get(marker_path.name)
        if ecosystem is None:
            return False

        indicators = self.MCP_INDICATORS.get(ecosystem, [])
        if not indicators:
            return False

        try:
            content = marker_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = marker_path.read_text(encoding="latin-1")
            except Exception:
                logger.warning(
                    "build_marker_unreadable",
                    path=str(marker_path),
                    reason="encoding_error",
                )
                return False
        except (OSError, PermissionError) as exc:
            logger.warning(
                "build_marker_unreadable",
                path=str(marker_path),
                reason=str(exc),
            )
            return False

        for indicator in indicators:
            if indicator in content:
                return True

        return False
