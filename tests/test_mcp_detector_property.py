"""Property-based tests for MCP project detection.

# Feature: script-file-scanning, Property 6: MCP project detection requires MCP dependency

**Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 8.5**

Property 6: For any build marker file, the MCPProjectDetector SHALL classify the
directory as an MCP server project if and only if the file content contains at least
one MCP-specific dependency string. The presence of a build marker file without MCP
references SHALL NOT trigger MCP classification.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.classifiers.mcp_detector import MCPProjectDetector

# --- Constants ---

# Build marker filenames mapped to their ecosystem
_MARKER_ECOSYSTEM = {
    "package.json": "javascript",
    "pyproject.toml": "python",
    "setup.py": "python",
    "Cargo.toml": "rust",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "pom.xml": "java",
}

# MCP indicators per ecosystem (must match MCPProjectDetector.MCP_INDICATORS)
_MCP_INDICATORS = {
    "python": ["mcp", "fastmcp", "modelcontextprotocol"],
    "javascript": ["@modelcontextprotocol/sdk", "mcp-server"],
    "java": ["io.modelcontextprotocol", "mcp-sdk", "modelcontextprotocol"],
    "rust": ["mcp-sdk", "mcp-server", "modelcontextprotocol"],
}

# All MCP indicator strings flattened (for exclusion in negative cases)
_ALL_MCP_STRINGS = list(
    set(indicator for indicators in _MCP_INDICATORS.values() for indicator in indicators)
)


# --- Strategies ---


@st.composite
def build_marker_choice(draw):
    """Draw a build marker filename and its ecosystem."""
    marker = draw(st.sampled_from(list(_MARKER_ECOSYSTEM.keys())))
    ecosystem = _MARKER_ECOSYSTEM[marker]
    return marker, ecosystem


@st.composite
def filler_text(draw):
    """Generate filler text that does NOT contain any MCP indicator strings."""
    safe_words = [
        "express",
        "react",
        "flask",
        "django",
        "actix-web",
        "tokio",
        "spring-boot",
        "junit",
        "numpy",
        "pandas",
        "lodash",
        "axios",
        "serde",
        "reqwest",
    ]
    lines = draw(st.lists(st.sampled_from(safe_words), min_size=1, max_size=10))
    return "\n".join(f'  "{word}": "^1.0.0"' for word in lines)


@st.composite
def build_marker_content(draw, has_mcp):
    """Generate build marker file content with or without MCP dependencies.

    When has_mcp=True, includes at least one MCP indicator string for the ecosystem.
    When has_mcp=False, ensures NO MCP indicator strings appear in the content.
    """
    marker, ecosystem = draw(build_marker_choice())
    indicators = _MCP_INDICATORS[ecosystem]

    filler = draw(filler_text())

    if has_mcp:
        indicator = draw(st.sampled_from(indicators))

        if marker == "package.json":
            content = (
                '{\n  "name": "my-project",\n  "dependencies": {\n'
                f'    "{indicator}": "^1.0.0",\n{filler}\n'
                "  }\n}"
            )
        elif marker in ("pyproject.toml", "setup.py"):
            content = (
                f'[project]\nname = "my-project"\ndependencies = [\n'
                f'  "{indicator}",\n]\n\n{filler}\n'
            )
        elif marker == "Cargo.toml":
            content = (
                f'[package]\nname = "my-project"\n\n[dependencies]\n'
                f'{indicator} = "0.1"\n\n{filler}\n'
            )
        elif marker in ("build.gradle", "build.gradle.kts"):
            content = (
                f"plugins {{\n  id 'java'\n}}\n\ndependencies {{\n"
                f"  implementation '{indicator}:1.0'\n{filler}\n}}\n"
            )
        elif marker == "pom.xml":
            content = (
                f"<project>\n  <dependencies>\n    <dependency>\n"
                f"      <groupId>{indicator}</groupId>\n"
                f"    </dependency>\n  </dependencies>\n</project>\n{filler}\n"
            )
        else:
            content = f"{indicator}\n{filler}\n"
    else:
        if marker == "package.json":
            content = f'{{\n  "name": "my-project",\n  "dependencies": {{\n{filler}\n  }}\n}}'
        elif marker in ("pyproject.toml", "setup.py"):
            content = f'[project]\nname = "my-project"\n\n{filler}\n'
        elif marker == "Cargo.toml":
            content = f'[package]\nname = "my-project"\n\n[dependencies]\n{filler}\n'
        elif marker in ("build.gradle", "build.gradle.kts"):
            content = f"plugins {{\n  id 'java'\n}}\n\ndependencies {{\n{filler}\n}}\n"
        elif marker == "pom.xml":
            content = f"<project>\n  <dependencies>\n  </dependencies>\n</project>\n{filler}\n"
        else:
            content = f"{filler}\n"

        # Ensure no MCP string accidentally snuck in
        for mcp_str in _ALL_MCP_STRINGS:
            if mcp_str in content:
                content = content.replace(mcp_str, "safe-replacement")

    return marker, content


# --- Property Tests ---


class TestMCPProjectDetectionRequiresDependency:
    """Property 6: MCP project detection requires MCP dependency.

    **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 8.5**
    """

    @given(data=build_marker_content(has_mcp=True))
    @settings(max_examples=100, deadline=None)
    def test_mcp_dependency_present_triggers_detection(self, data):
        """When a build marker contains an MCP indicator, the directory is detected."""
        marker_filename, content = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            marker_path = tmp_path / marker_filename
            marker_path.write_text(content, encoding="utf-8")

            detector = MCPProjectDetector()
            result = detector.detect([marker_path])

            assert tmp_path in result, (
                f"Expected {tmp_path} in MCP project dirs for marker '{marker_filename}' "
                f"with content containing MCP indicator"
            )

    @given(data=build_marker_content(has_mcp=False))
    @settings(max_examples=100, deadline=None)
    def test_no_mcp_dependency_does_not_trigger_detection(self, data):
        """When a build marker has no MCP indicators, the directory is NOT detected."""
        marker_filename, content = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            marker_path = tmp_path / marker_filename
            marker_path.write_text(content, encoding="utf-8")

            detector = MCPProjectDetector()
            result = detector.detect([marker_path])

            assert tmp_path not in result, (
                f"Expected {tmp_path} NOT in MCP project dirs for marker '{marker_filename}' "
                f"without MCP indicators, but it was detected. Content:\n{content}"
            )

    @given(data=build_marker_content(has_mcp=True))
    @settings(max_examples=100, deadline=None)
    def test_detection_returns_parent_directory_of_marker(self, data):
        """The detected MCP project directory is the parent of the build marker file."""
        marker_filename, content = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            project_dir = tmp_path / "my-mcp-project"
            project_dir.mkdir()
            marker_path = project_dir / marker_filename
            marker_path.write_text(content, encoding="utf-8")

            detector = MCPProjectDetector()
            result = detector.detect([marker_path])

            assert project_dir in result
            assert tmp_path not in result

    @given(
        mcp_data=build_marker_content(has_mcp=True),
        non_mcp_data=build_marker_content(has_mcp=False),
    )
    @settings(max_examples=100, deadline=None)
    def test_mixed_markers_only_mcp_directories_detected(self, mcp_data, non_mcp_data):
        """Given markers in separate directories, only the one with MCP deps is detected."""
        mcp_marker, mcp_content = mcp_data
        non_mcp_marker, non_mcp_content = non_mcp_data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            mcp_dir = tmp_path / "mcp-project"
            mcp_dir.mkdir()
            non_mcp_dir = tmp_path / "regular-project"
            non_mcp_dir.mkdir()

            mcp_path = mcp_dir / mcp_marker
            mcp_path.write_text(mcp_content, encoding="utf-8")

            non_mcp_path = non_mcp_dir / non_mcp_marker
            non_mcp_path.write_text(non_mcp_content, encoding="utf-8")

            detector = MCPProjectDetector()
            result = detector.detect([mcp_path, non_mcp_path])

            assert mcp_dir in result
            assert non_mcp_dir not in result
