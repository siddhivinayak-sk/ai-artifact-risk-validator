"""Unit tests for MCPProjectDetector edge cases.

Tests cover:
- Unreadable markers (permissions error → skip with WARNING)
- Empty content markers
- Nested project directories
- All language ecosystems (Python, JS/TS, Java/Kotlin, Rust)
- Marker without MCP refs → no MCP classification
- Multiple markers in same directory

_Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.7, 4.8_
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from ai_artifact_risk_validator.classifiers.mcp_detector import MCPProjectDetector


class TestUnreadableMarkers:
    """Test that unreadable build markers are skipped gracefully (Req 4.8)."""

    def test_permission_error_skips_marker(self, tmp_path: Path) -> None:
        """A marker file that raises PermissionError is skipped with no detection."""
        marker = tmp_path / "package.json"
        marker.write_text('{"dependencies": {"@modelcontextprotocol/sdk": "^1.0"}}')

        detector = MCPProjectDetector()

        with patch.object(Path, "read_text", side_effect=PermissionError("Access denied")):
            result = detector.detect([marker])

        assert tmp_path not in result

    def test_oserror_skips_marker(self, tmp_path: Path) -> None:
        """A marker file that raises OSError is skipped with no detection."""
        marker = tmp_path / "pyproject.toml"
        marker.write_text('[project]\ndependencies = ["fastmcp"]')

        detector = MCPProjectDetector()

        with patch.object(Path, "read_text", side_effect=OSError("I/O error")):
            result = detector.detect([marker])

        assert tmp_path not in result

    def test_unicode_decode_error_with_latin1_fallback_failure(self, tmp_path: Path) -> None:
        """When both UTF-8 and latin-1 fail, marker is skipped."""
        marker = tmp_path / "Cargo.toml"
        marker.write_text('[dependencies]\nmcp-sdk = "0.1"')

        detector = MCPProjectDetector()

        # First call (utf-8) raises UnicodeDecodeError, second (latin-1) raises Exception
        with patch.object(
            Path,
            "read_text",
            side_effect=[
                UnicodeDecodeError("utf-8", b"", 0, 1, "invalid"),
                Exception("latin-1 also failed"),
            ],
        ):
            result = detector.detect([marker])

        assert tmp_path not in result

    def test_unicode_decode_error_with_latin1_fallback_success(self, tmp_path: Path) -> None:
        """When UTF-8 fails but latin-1 succeeds, content is checked for MCP refs."""
        marker = tmp_path / "Cargo.toml"
        marker.write_text('[dependencies]\nmcp-sdk = "0.1"')

        detector = MCPProjectDetector()

        # First call (utf-8) raises UnicodeDecodeError, second (latin-1) returns content
        with patch.object(
            Path,
            "read_text",
            side_effect=[
                UnicodeDecodeError("utf-8", b"", 0, 1, "invalid"),
                '[dependencies]\nmcp-sdk = "0.1"',
            ],
        ):
            result = detector.detect([marker])

        assert tmp_path in result


class TestEmptyContentMarkers:
    """Test that empty or content-free markers do not trigger detection (Req 4.7)."""

    def test_empty_package_json(self, tmp_path: Path) -> None:
        """An empty package.json does not trigger MCP detection."""
        marker = tmp_path / "package.json"
        marker.write_text("")

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result

    def test_package_json_with_no_deps(self, tmp_path: Path) -> None:
        """A package.json with name but no MCP dependencies is not detected."""
        marker = tmp_path / "package.json"
        marker.write_text('{"name": "my-app", "version": "1.0.0", "dependencies": {}}')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result

    def test_empty_pyproject_toml(self, tmp_path: Path) -> None:
        """An empty pyproject.toml does not trigger MCP detection."""
        marker = tmp_path / "pyproject.toml"
        marker.write_text("")

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result

    def test_empty_cargo_toml(self, tmp_path: Path) -> None:
        """An empty Cargo.toml does not trigger MCP detection."""
        marker = tmp_path / "Cargo.toml"
        marker.write_text("")

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result


class TestNestedProjectDirectories:
    """Test detection in nested directory structures (Req 4.1, 4.6)."""

    def test_parent_has_mcp_marker_child_does_not(self, tmp_path: Path) -> None:
        """Only the parent directory with the MCP marker is detected."""
        parent_marker = tmp_path / "package.json"
        parent_marker.write_text('{"dependencies": {"@modelcontextprotocol/sdk": "^1.0"}}')

        child_dir = tmp_path / "src"
        child_dir.mkdir()
        child_script = child_dir / "server.ts"
        child_script.write_text("console.log('hello')")

        detector = MCPProjectDetector()
        result = detector.detect([parent_marker])

        assert tmp_path in result
        assert child_dir not in result

    def test_nested_mcp_projects_both_detected(self, tmp_path: Path) -> None:
        """Two separate MCP project directories at different levels are both detected."""
        parent_dir = tmp_path / "parent-project"
        parent_dir.mkdir()
        parent_marker = parent_dir / "pyproject.toml"
        parent_marker.write_text('[project]\ndependencies = ["fastmcp"]')

        child_dir = parent_dir / "subproject"
        child_dir.mkdir()
        child_marker = child_dir / "package.json"
        child_marker.write_text('{"dependencies": {"@modelcontextprotocol/sdk": "^2.0"}}')

        detector = MCPProjectDetector()
        result = detector.detect([parent_marker, child_marker])

        assert parent_dir in result
        assert child_dir in result

    def test_sibling_directories_independent_detection(self, tmp_path: Path) -> None:
        """Two sibling directories are detected independently."""
        dir_a = tmp_path / "project-a"
        dir_a.mkdir()
        marker_a = dir_a / "Cargo.toml"
        marker_a.write_text('[dependencies]\nmcp-server = "0.1"')

        dir_b = tmp_path / "project-b"
        dir_b.mkdir()
        marker_b = dir_b / "package.json"
        marker_b.write_text('{"dependencies": {"express": "^4.0"}}')

        detector = MCPProjectDetector()
        result = detector.detect([marker_a, marker_b])

        assert dir_a in result
        assert dir_b not in result


class TestPythonEcosystem:
    """Test Python ecosystem detection (Req 4.2)."""

    def test_pyproject_toml_with_mcp(self, tmp_path: Path) -> None:
        """pyproject.toml with 'mcp' in dependencies triggers detection."""
        marker = tmp_path / "pyproject.toml"
        marker.write_text('[project]\nname = "server"\ndependencies = ["mcp>=0.1", "click"]\n')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_pyproject_toml_with_fastmcp(self, tmp_path: Path) -> None:
        """pyproject.toml with 'fastmcp' in dependencies triggers detection."""
        marker = tmp_path / "pyproject.toml"
        marker.write_text('[project]\nname = "server"\ndependencies = ["fastmcp>=1.0"]\n')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_pyproject_toml_with_modelcontextprotocol(self, tmp_path: Path) -> None:
        """pyproject.toml with 'modelcontextprotocol' triggers detection."""
        marker = tmp_path / "pyproject.toml"
        marker.write_text('[project]\ndependencies = ["modelcontextprotocol"]\n')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_setup_py_with_mcp(self, tmp_path: Path) -> None:
        """setup.py with 'mcp' as a dependency triggers detection."""
        marker = tmp_path / "setup.py"
        marker.write_text('from setuptools import setup\nsetup(install_requires=["mcp"])\n')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_pyproject_toml_without_mcp(self, tmp_path: Path) -> None:
        """pyproject.toml without any MCP references does NOT trigger detection."""
        marker = tmp_path / "pyproject.toml"
        marker.write_text('[project]\nname = "my-app"\ndependencies = ["flask", "click"]\n')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result


class TestJavaScriptEcosystem:
    """Test JavaScript/TypeScript ecosystem detection (Req 4.3)."""

    def test_package_json_with_modelcontextprotocol_sdk(self, tmp_path: Path) -> None:
        """package.json with @modelcontextprotocol/sdk triggers detection."""
        marker = tmp_path / "package.json"
        marker.write_text(
            '{"name": "mcp-server", "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}'
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_package_json_with_mcp_server(self, tmp_path: Path) -> None:
        """package.json with mcp-server in dependencies triggers detection."""
        marker = tmp_path / "package.json"
        marker.write_text('{"name": "my-mcp", "devDependencies": {"mcp-server": "^2.0"}}')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_package_json_without_mcp_deps(self, tmp_path: Path) -> None:
        """package.json WITHOUT MCP deps does NOT trigger detection."""
        marker = tmp_path / "package.json"
        marker.write_text(
            '{"name": "my-app", "dependencies": {"express": "^4.18", "lodash": "^4.17"}}'
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result


class TestJavaKotlinEcosystem:
    """Test Java/Kotlin ecosystem detection (Req 4.4)."""

    def test_pom_xml_with_modelcontextprotocol(self, tmp_path: Path) -> None:
        """pom.xml with io.modelcontextprotocol triggers detection."""
        marker = tmp_path / "pom.xml"
        marker.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>io.modelcontextprotocol</groupId>\n"
            "      <artifactId>sdk</artifactId>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>"
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_build_gradle_with_mcp_sdk(self, tmp_path: Path) -> None:
        """build.gradle with mcp-sdk triggers detection."""
        marker = tmp_path / "build.gradle"
        marker.write_text(
            "plugins {\n  id 'java'\n}\n\n"
            "dependencies {\n"
            "  implementation 'io.modelcontextprotocol:mcp-sdk:1.0'\n"
            "}"
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_build_gradle_kts_with_modelcontextprotocol(self, tmp_path: Path) -> None:
        """build.gradle.kts with modelcontextprotocol triggers detection."""
        marker = tmp_path / "build.gradle.kts"
        marker.write_text(
            "plugins {\n  java\n}\n\n"
            "dependencies {\n"
            '  implementation("modelcontextprotocol:sdk:1.0")\n'
            "}"
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_pom_xml_without_mcp(self, tmp_path: Path) -> None:
        """pom.xml without MCP references does NOT trigger detection."""
        marker = tmp_path / "pom.xml"
        marker.write_text(
            "<project>\n"
            "  <dependencies>\n"
            "    <dependency>\n"
            "      <groupId>org.springframework</groupId>\n"
            "      <artifactId>spring-core</artifactId>\n"
            "    </dependency>\n"
            "  </dependencies>\n"
            "</project>"
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result

    def test_build_gradle_without_mcp(self, tmp_path: Path) -> None:
        """build.gradle without MCP references does NOT trigger detection."""
        marker = tmp_path / "build.gradle"
        marker.write_text(
            "plugins {\n  id 'java'\n}\n\n"
            "dependencies {\n"
            "  implementation 'org.springframework:spring-boot:3.0'\n"
            "}"
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result


class TestRustEcosystem:
    """Test Rust ecosystem detection (Req 4.5)."""

    def test_cargo_toml_with_mcp_sdk(self, tmp_path: Path) -> None:
        """Cargo.toml with mcp-sdk in dependencies triggers detection."""
        marker = tmp_path / "Cargo.toml"
        marker.write_text(
            '[package]\nname = "my-server"\n\n[dependencies]\nmcp-sdk = "0.1"\ntokio = "1.0"\n'
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_cargo_toml_with_mcp_server(self, tmp_path: Path) -> None:
        """Cargo.toml with mcp-server in dependencies triggers detection."""
        marker = tmp_path / "Cargo.toml"
        marker.write_text('[package]\nname = "my-server"\n\n[dependencies]\nmcp-server = "0.2"\n')

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_cargo_toml_with_modelcontextprotocol(self, tmp_path: Path) -> None:
        """Cargo.toml with modelcontextprotocol triggers detection."""
        marker = tmp_path / "Cargo.toml"
        marker.write_text(
            '[package]\nname = "server"\n\n[dependencies]\nmodelcontextprotocol = "0.1"\n'
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path in result

    def test_cargo_toml_without_mcp(self, tmp_path: Path) -> None:
        """Cargo.toml without MCP references does NOT trigger detection."""
        marker = tmp_path / "Cargo.toml"
        marker.write_text(
            '[package]\nname = "my-app"\n\n[dependencies]\ntokio = "1.0"\nserde = "1.0"\n'
        )

        detector = MCPProjectDetector()
        result = detector.detect([marker])

        assert tmp_path not in result


class TestMarkerWithoutMCPRefs:
    """Test that markers without MCP references do not classify (Req 4.7)."""

    def test_non_marker_files_ignored(self, tmp_path: Path) -> None:
        """Files not matching BUILD_MARKERS are ignored entirely."""
        non_marker = tmp_path / "README.md"
        non_marker.write_text("# My MCP Server\n@modelcontextprotocol/sdk")

        detector = MCPProjectDetector()
        result = detector.detect([non_marker])

        assert len(result) == 0

    def test_unknown_filename_is_ignored(self, tmp_path: Path) -> None:
        """A file with unknown name that contains MCP strings is not checked."""
        unknown = tmp_path / "requirements.txt"
        unknown.write_text("mcp>=1.0\nfastmcp>=0.5")

        detector = MCPProjectDetector()
        result = detector.detect([unknown])

        assert tmp_path not in result

    def test_no_files_returns_empty_set(self) -> None:
        """An empty list of discovered files returns empty set."""
        detector = MCPProjectDetector()
        result = detector.detect([])

        assert result == set()


class TestMultipleMarkersInSameDir:
    """Test behavior with multiple markers in the same directory."""

    def test_any_positive_marker_detects_directory(self, tmp_path: Path) -> None:
        """If one marker has MCP refs and another doesn't, directory is detected."""
        package_json = tmp_path / "package.json"
        package_json.write_text('{"dependencies": {"express": "^4.0"}}')

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["fastmcp"]\n')

        detector = MCPProjectDetector()
        result = detector.detect([package_json, pyproject])

        assert tmp_path in result

    def test_multiple_mcp_markers_same_dir(self, tmp_path: Path) -> None:
        """Multiple MCP-positive markers in same dir still yield one directory entry."""
        package_json = tmp_path / "package.json"
        package_json.write_text('{"dependencies": {"@modelcontextprotocol/sdk": "^1.0"}}')

        cargo_toml = tmp_path / "Cargo.toml"
        cargo_toml.write_text('[dependencies]\nmcp-sdk = "0.1"\n')

        detector = MCPProjectDetector()
        result = detector.detect([package_json, cargo_toml])

        assert tmp_path in result
        assert len(result) == 1
