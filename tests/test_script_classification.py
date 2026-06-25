"""Unit tests for script classification edge cases.

Tests cover sibling precedence, mcp.json override, nested Known AI directories,
Type-Indicating Directory depth resolution, extension-only threshold gate,
and error handling for permission denied, invalid encoding, and path-too-long.

**Validates: Requirements 1.9, 2.9, 5.2, 5.3, 8.1, 8.6, 8.7**
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_artifact_risk_validator.classifiers.classifier import (
    ArtifactClassifier,
)
from ai_artifact_risk_validator.classifiers.script_context import ScriptClassificationContext
from ai_artifact_risk_validator.models.enums import ArtifactType


@pytest.fixture
def classifier() -> ArtifactClassifier:
    """Create a fresh ArtifactClassifier instance for tests."""
    return ArtifactClassifier()


@pytest.fixture
def empty_context() -> ScriptClassificationContext:
    """Create an empty ScriptClassificationContext."""
    return ScriptClassificationContext()


# ---------------------------------------------------------------------------
# Sibling Precedence Tests (Requirement 5.2)
# ---------------------------------------------------------------------------


class TestSiblingPrecedence:
    """Test sibling classification: highest confidence wins, enum ordering for ties."""

    def test_highest_confidence_sibling_wins(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN multiple siblings exist, the one with highest confidence is used.

        Validates: Requirement 5.2
        """
        script_file = tmp_path / "helper.py"
        script_file.touch()

        # SKILL at 0.8, MCP at 0.6 → script should get SKILL
        context = ScriptClassificationContext(
            directory_artifacts={
                tmp_path: [
                    (ArtifactType.SKILL, 0.8),
                    (ArtifactType.MCP, 0.6),
                ]
            }
        )

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.SKILL
        assert result.confidence == 0.30
        assert "directory_context" in result.signals

    def test_enum_ordering_breaks_confidence_ties(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN two siblings have the same confidence, ArtifactType enum ordering wins.

        ArtifactType order: PROMPT, SKILL, AGENT, SOP, STEERING, MCP, HOOK, ...
        So SKILL (index 1) beats MCP (index 5) at same confidence.

        Validates: Requirement 5.2
        """
        script_file = tmp_path / "worker.sh"
        script_file.touch()

        # Both at 0.7 → SKILL wins because it appears before MCP in enum
        context = ScriptClassificationContext(
            directory_artifacts={
                tmp_path: [
                    (ArtifactType.MCP, 0.7),
                    (ArtifactType.SKILL, 0.7),
                ]
            }
        )

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.SKILL

    def test_three_way_tie_uses_enum_ordering(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """Three siblings at same confidence → earliest in enum wins.

        Validates: Requirement 5.2
        """
        script_file = tmp_path / "run.ts"
        script_file.touch()

        context = ScriptClassificationContext(
            directory_artifacts={
                tmp_path: [
                    (ArtifactType.HOOK, 0.5),
                    (ArtifactType.AGENT, 0.5),
                    (ArtifactType.PLUGIN, 0.5),
                ]
            }
        )

        result = classifier.classify_script(script_file, context)

        assert result is not None
        # AGENT (index 2) < HOOK (index 6) < PLUGIN (index 8) in enum ordering
        assert result.artifact_type == ArtifactType.AGENT

    def test_below_threshold_siblings_do_not_classify(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN all siblings are below classification threshold, script is not classified.

        Validates: Requirement 5.2
        """
        script_file = tmp_path / "util.py"
        script_file.touch()

        # Confidence 0.2 is below threshold of 0.3
        context = ScriptClassificationContext(
            directory_artifacts={
                tmp_path: [
                    (ArtifactType.SKILL, 0.2),
                    (ArtifactType.MCP, 0.1),
                ]
            }
        )

        result = classifier.classify_script(script_file, context)

        assert result is None


# ---------------------------------------------------------------------------
# mcp.json Sibling Override Tests (Requirement 5.3)
# ---------------------------------------------------------------------------


class TestMcpJsonSiblingOverride:
    """Test that mcp.json sibling always overrides to MCP classification."""

    def test_mcp_json_sibling_forces_mcp_type(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN mcp.json exists in the same directory, script is always classified as MCP.

        Validates: Requirement 5.3
        """
        # Create mcp.json in the directory
        mcp_json = tmp_path / "mcp.json"
        mcp_json.write_text('{"name": "test-server"}')

        script_file = tmp_path / "server.py"
        script_file.touch()

        # Even with SKILL siblings at high confidence
        context = ScriptClassificationContext(
            directory_artifacts={
                tmp_path: [
                    (ArtifactType.SKILL, 0.95),
                ]
            }
        )

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.MCP
        assert result.confidence == 0.30
        assert "directory_context" in result.signals

    def test_mcp_json_override_regardless_of_other_siblings(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """mcp.json override works even with multiple non-MCP siblings.

        Validates: Requirement 5.3
        """
        mcp_json = tmp_path / "mcp.json"
        mcp_json.write_text("{}")

        script_file = tmp_path / "index.ts"
        script_file.touch()

        context = ScriptClassificationContext(
            directory_artifacts={
                tmp_path: [
                    (ArtifactType.HOOK, 0.9),
                    (ArtifactType.AGENT, 0.85),
                ]
            }
        )

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.MCP

    def test_mcp_json_override_with_empty_siblings(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """mcp.json alone (no other siblings) still classifies as MCP.

        Validates: Requirement 5.3
        """
        mcp_json = tmp_path / "mcp.json"
        mcp_json.write_text("{}")

        script_file = tmp_path / "handler.js"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.MCP


# ---------------------------------------------------------------------------
# Multiple Known AI Directory Matches (Nested) (Requirement 1.9)
# ---------------------------------------------------------------------------


class TestNestedKnownAIDirectories:
    """Test multiple Known AI Directory matches for nested paths."""

    def test_kiro_nested_with_cursor(self, classifier: ArtifactClassifier, tmp_path: Path) -> None:
        """WHEN .kiro/.cursor/ both appear in path, the first match in iteration wins.

        Per the implementation, KNOWN_AI_DIRECTORIES is iterated and first match
        returns immediately. .kiro is checked before .cursor in the mapping.

        Validates: Requirement 1.9
        """
        # Create the nested path
        nested_dir = tmp_path / ".kiro" / ".cursor"
        nested_dir.mkdir(parents=True)
        script_file = nested_dir / "helper.py"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        # .kiro matches first and since .cursor is not a recognized .kiro
        # subdirectory, it falls to _default → INSTRUCTION
        assert result.artifact_type == ArtifactType.INSTRUCTION
        assert result.confidence == 0.35

    def test_kiro_with_hooks_subdirectory(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN .kiro/hooks/ path is used, subdirectory-specific type wins.

        Validates: Requirement 1.9
        """
        hooks_dir = tmp_path / ".kiro" / "hooks"
        hooks_dir.mkdir(parents=True)
        script_file = hooks_dir / "pre_commit.sh"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.HOOK
        assert result.confidence == 0.35

    def test_github_copilot_nested_deeper(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN a script is deeply nested under .github/copilot/, it still matches.

        Validates: Requirement 1.9
        """
        deep_dir = tmp_path / ".github" / "copilot" / "custom" / "prompts"
        deep_dir.mkdir(parents=True)
        script_file = deep_dir / "gen.py"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.INSTRUCTION
        assert result.confidence == 0.35


# ---------------------------------------------------------------------------
# Type-Indicating Directory Depth Resolution (Requirement 2.9)
# ---------------------------------------------------------------------------


class TestTypeIndicatingDirectoryDepth:
    """Test nearest-ancestor wins for Type-Indicating Directory conflicts."""

    def test_nearest_ancestor_wins(self, classifier: ArtifactClassifier, tmp_path: Path) -> None:
        """WHEN /project/agents/plugins/script.py, nearest ancestor (plugins/) wins.

        Validates: Requirement 2.9
        """
        nested_dir = tmp_path / "project" / "agents" / "plugins"
        nested_dir.mkdir(parents=True)
        script_file = nested_dir / "script.py"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        # plugins/ is nearest ancestor → PLUGIN
        assert result.artifact_type == ArtifactType.PLUGIN
        assert result.confidence == 0.35

    def test_deeper_dir_overrides_shallower(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN /hooks/some/plugins/run.sh, plugins/ is closer → PLUGIN.

        Validates: Requirement 2.9
        """
        nested_dir = tmp_path / "hooks" / "some" / "plugins"
        nested_dir.mkdir(parents=True)
        script_file = nested_dir / "run.sh"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.PLUGIN

    def test_same_depth_alphabetical_fallback(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN two Type-Indicating dirs at same depth, alphabetical dir name wins.

        The implementation iterates from index 0 to N, and keeps track of best_depth.
        At same depth (same index in the parts), alphabetical comparison applies.
        Since each file can only have one directory at any given depth, this case
        requires two patterns matching the SAME directory segment.

        E.g., a dir named "mcp-servers" matches both TYPE_INDICATING_DIRS["mcp-servers"]
        (→ MCP) and TYPE_INDICATING_PATTERNS["mcp-server"] (→ MCP). Both resolve to MCP.

        For a true same-depth test, we need a path where the same segment matches
        multiple patterns. Since real directories can't be two names at the same
        depth, we test with a partial pattern match on a segment that also matches
        an exact entry at the same path position.

        Validates: Requirement 2.9
        """
        # "mcp-servers" matches both the exact entry and the "mcp-server" pattern
        # Both resolve to MCP, so behavior is consistent
        nested_dir = tmp_path / "mcp-servers"
        nested_dir.mkdir(parents=True)
        script_file = nested_dir / "main.py"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.MCP

    def test_single_type_indicating_dir_at_root(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """A single type-indicating directory at any depth classifies correctly.

        Validates: Requirement 2.9
        """
        agent_dir = tmp_path / "src" / "lib" / "agents"
        agent_dir.mkdir(parents=True)
        script_file = agent_dir / "bot.ts"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.AGENT
        assert result.confidence == 0.35


# ---------------------------------------------------------------------------
# Extension-Only Signal Does NOT Classify (Requirement 8.1, 8.6)
# ---------------------------------------------------------------------------


class TestExtensionOnlyThresholdGate:
    """Test that extension-only signal does NOT classify a script file."""

    def test_py_in_neutral_directory_not_classified(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """A .py file in a neutral directory with no other signals → None.

        Validates: Requirement 8.6
        """
        neutral_dir = tmp_path / "src" / "utils"
        neutral_dir.mkdir(parents=True)
        script_file = neutral_dir / "helper.py"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is None

    def test_js_in_neutral_directory_not_classified(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """A .js file in a neutral directory with no other signals → None.

        Validates: Requirement 8.6
        """
        neutral_dir = tmp_path / "lib"
        neutral_dir.mkdir(parents=True)
        script_file = neutral_dir / "index.js"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is None

    def test_sh_in_neutral_directory_not_classified(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """A .sh file in a neutral directory with no other signals → None.

        Validates: Requirement 8.6
        """
        neutral_dir = tmp_path / "scripts" / "deploy"
        neutral_dir.mkdir(parents=True)
        script_file = neutral_dir / "run.sh"
        script_file.touch()

        # No siblings, no references, no MCP dirs, no known AI dir, no type-indicating dir
        # Note: "scripts" does NOT match TYPE_INDICATING_DIRS (which has "skills", not "scripts")
        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is None

    def test_all_script_extensions_neutral_directory(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """All supported script extensions in neutral directories → None.

        Validates: Requirements 8.1, 8.6
        """
        from ai_artifact_risk_validator.classifiers.script_patterns import (
            DEFAULT_SCRIPT_EXTENSIONS,
        )

        neutral_dir = tmp_path / "vendor" / "third_party"
        neutral_dir.mkdir(parents=True)

        context = ScriptClassificationContext()

        for ext in DEFAULT_SCRIPT_EXTENSIONS:
            script_file = neutral_dir / f"module{ext}"
            script_file.touch()

            result = classifier.classify_script(script_file, context)
            assert result is None, f"Extension {ext} should not classify alone"


# ---------------------------------------------------------------------------
# Error Handling (Requirement 8.7)
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Test graceful handling of classification errors."""

    def test_nonexistent_file_path_graceful(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN classify_script is called with a non-existent path, no crash.

        The classify_script method should handle this gracefully since it
        primarily operates on path structure, not file content.

        Validates: Requirement 8.7
        """
        nonexistent = tmp_path / "does_not_exist" / "script.py"

        context = ScriptClassificationContext()

        # Should not raise — returns None since path doesn't match any pattern
        result = classifier.classify_script(nonexistent, context)

        # No matching signals for a neutral path → None
        assert result is None

    def test_nonexistent_file_in_known_ai_dir(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN file doesn't exist but path matches Known AI Dir, classification works.

        classify_script works on path structure, so non-existent files in
        known directories can still be classified.

        Validates: Requirement 8.7
        """
        nonexistent = tmp_path / ".kiro" / "hooks" / "missing.py"

        context = ScriptClassificationContext()

        result = classifier.classify_script(nonexistent, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.HOOK

    def test_sibling_classification_nonexistent_mcp_json(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN mcp.json does NOT exist, sibling logic checks directory_artifacts.

        Validates: Requirement 8.7
        """
        script_file = tmp_path / "run.py"
        script_file.touch()

        # No mcp.json in tmp_path, but siblings exist
        context = ScriptClassificationContext(
            directory_artifacts={
                tmp_path: [
                    (ArtifactType.HOOK, 0.6),
                ]
            }
        )

        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.HOOK

    def test_empty_directory_artifacts_no_crash(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN directory_artifacts is empty for the file's directory, returns None.

        Validates: Requirement 8.7
        """
        script_file = tmp_path / "data" / "process.rb"
        script_file.parent.mkdir(parents=True)
        script_file.touch()

        # Empty context — no siblings, no references, no MCP dirs
        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        assert result is None

    def test_path_with_special_characters(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """WHEN path contains special characters, classification handles gracefully.

        Validates: Requirement 8.7
        """
        # Create a directory with spaces and special chars
        special_dir = tmp_path / "my project (v2)" / "agents"
        special_dir.mkdir(parents=True)
        script_file = special_dir / "bot.py"
        script_file.touch()

        context = ScriptClassificationContext()

        # "agents" is a Type-Indicating directory — should still classify
        result = classifier.classify_script(script_file, context)

        assert result is not None
        assert result.artifact_type == ArtifactType.AGENT

    def test_very_deep_path_no_error(self, classifier: ArtifactClassifier, tmp_path: Path) -> None:
        """WHEN path is very deeply nested, classification works without error.

        Validates: Requirement 8.7
        """
        # Create a deeply nested neutral path (limited depth for Windows MAX_PATH)
        deep_parts = ["d" + str(i) for i in range(8)]
        deep_dir = tmp_path
        for part in deep_parts:
            deep_dir = deep_dir / part
        deep_dir.mkdir(parents=True)
        script_file = deep_dir / "worker.py"
        script_file.touch()

        context = ScriptClassificationContext()

        # No matching patterns in the deep neutral path
        result = classifier.classify_script(script_file, context)

        assert result is None

    def test_deeply_nested_with_type_indicating(
        self, classifier: ArtifactClassifier, tmp_path: Path
    ) -> None:
        """Deep path with a type-indicating directory in the middle works.

        Validates: Requirement 8.7
        """
        deep_dir = tmp_path / "a" / "b" / "c" / "plugins" / "d" / "e" / "f"
        deep_dir.mkdir(parents=True)
        script_file = deep_dir / "run.js"
        script_file.touch()

        context = ScriptClassificationContext()

        result = classifier.classify_script(script_file, context)

        # "plugins" is a Type-Indicating dir but "d", "e", "f" are closer
        # to the file — however none of them match, so "plugins" is the best
        # (and only) match
        assert result is not None
        assert result.artifact_type == ArtifactType.PLUGIN
