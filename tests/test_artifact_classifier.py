"""Unit tests for ArtifactClassifier.

Tests all 14 artifact types with representative file paths, extensions, and
content markers. Also tests confidence scoring, unclassifiable files, and
custom classification patterns.

Validates: Requirements 9.1, 9.2, 9.17, 9.18, 9.19
"""

import tempfile
from pathlib import Path

import pytest

from ai_artifact_risk_validator.classifiers import ArtifactClassifier, ClassificationResult
from ai_artifact_risk_validator.models.enums import ArtifactType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def classifier():
    """Create a default ArtifactClassifier instance."""
    return ArtifactClassifier()


# ---------------------------------------------------------------------------
# Test: Classify all 14 artifact types (Requirement 9.1)
# ---------------------------------------------------------------------------


class TestPromptClassification:
    """Requirement 9.3: Detect Prompt artifacts."""

    def test_prompt_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            prompts_dir = Path(tmpdir) / "prompts"
            prompts_dir.mkdir()
            file_path = prompts_dir / "system.prompt.md"
            content = "## System Prompt\nrole: system"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.PROMPT
            assert result.confidence > 0.0
            assert len(result.signals) >= 1


class TestSkillClassification:
    """Requirement 9.4: Detect Skill artifacts."""

    def test_skill_by_path_and_content_with_sibling(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            skills_dir = Path(tmpdir) / "skills"
            skills_dir.mkdir()
            # Create sibling SKILL.md for directory context
            skill_marker = skills_dir / "SKILL.md"
            skill_marker.write_text("# Skill definition")

            file_path = skills_dir / "my-skill.md"
            content = "This skill has invocation criteria for activation."
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.SKILL
            assert result.confidence > 0.0


class TestAgentClassification:
    """Requirement 9.5: Detect Agent artifacts."""

    def test_agent_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / "agents"
            agents_dir.mkdir()
            file_path = agents_dir / "assistant.md"
            content = "AGENT.md defines this agent with tool declarations for execution."
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.AGENT
            assert result.confidence > 0.0


class TestSOPClassification:
    """Requirement 9.6: Detect SOP artifacts."""

    def test_sop_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            sops_dir = Path(tmpdir) / "sops"
            sops_dir.mkdir()
            file_path = sops_dir / "deploy.sop.md"
            content = "# Deploy SOP\nstep 1: prepare environment\nstep 2: deploy"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.SOP
            assert result.confidence > 0.0


class TestSteeringClassification:
    """Requirement 9.7: Detect Steering artifacts."""

    def test_steering_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            steering_dir = Path(tmpdir) / ".kiro" / "steering"
            steering_dir.mkdir(parents=True)
            file_path = steering_dir / "code.md"
            content = "---\npriority: high\ninclusion: auto\n---\nCoding standards."
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.STEERING
            assert result.confidence > 0.0


class TestMCPClassification:
    """Requirement 9.8: Detect MCP Server artifacts."""

    def test_mcp_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp_dir = Path(tmpdir) / "mcp-servers"
            mcp_dir.mkdir()
            file_path = mcp_dir / "config.json"
            content = '{"transport": "stdio", "tools": [{"name": "search"}]}'
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.MCP
            assert result.confidence > 0.0


class TestHookClassification:
    """Requirement 9.9: Detect Hook artifacts."""

    def test_hook_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = Path(tmpdir) / ".hooks"
            hooks_dir.mkdir()
            file_path = hooks_dir / "pre-commit.yaml"
            content = "eventType: fileEdited\naction: runCommand"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.HOOK
            assert result.confidence > 0.0


class TestInstructionClassification:
    """Requirement 9.10: Detect Instruction artifacts."""

    def test_instruction_by_filename_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "copilot-instructions.md"
            content = "---\napplyTo: '**/*.ts'\n---\nUse TypeScript strict mode."
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.INSTRUCTION
            assert result.confidence > 0.0


class TestPluginClassification:
    """Requirement 9.11: Detect Plugin artifacts."""

    def test_plugin_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugins_dir = Path(tmpdir) / "plugins"
            plugins_dir.mkdir()
            file_path = plugins_dir / "ext.json"
            content = '{"contributes": {"commands": []}, "activationEvents": ["onStartup"]}'
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.PLUGIN
            assert result.confidence > 0.0


class TestMemoryClassification:
    """Requirement 9.12: Detect Memory File artifacts."""

    def test_memory_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_dir = Path(tmpdir) / ".memory"
            memory_dir.mkdir()
            file_path = memory_dir / "session.json"
            content = '{"type": "session storage", "data": {"memory": "context data"}}'
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.MEMORY
            assert result.confidence > 0.0


class TestRAGClassification:
    """Requirement 9.13: Detect Context/RAG Source artifacts."""

    def test_rag_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge_dir = Path(tmpdir) / "knowledge"
            knowledge_dir.mkdir()
            file_path = knowledge_dir / "docs.md"
            content = "This is a knowledge base document with embedding index references."
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.RAG
            assert result.confidence > 0.0


class TestEvalHarnessClassification:
    """Requirement 9.14: Detect Evaluation Harness artifacts."""

    def test_eval_harness_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            eval_dir = Path(tmpdir) / "eval"
            eval_dir.mkdir()
            file_path = eval_dir / "benchmark.yaml"
            content = "benchmark config:\n  expected output: correct answer"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.EVAL_HARNESS
            assert result.confidence > 0.0


class TestOrchestrationClassification:
    """Requirement 9.15: Detect Orchestration Workflow artifacts."""

    def test_orchestration_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            workflows_dir = Path(tmpdir) / "workflows"
            workflows_dir.mkdir()
            file_path = workflows_dir / "deploy.yaml"
            content = "pipeline:\n  stage: build\n  stage: deploy"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.ORCHESTRATION
            assert result.confidence > 0.0


class TestAPISchemaClassification:
    """Requirement 9.16: Detect API Schema artifacts."""

    def test_api_schema_by_path_and_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            file_path = api_dir / "openapi.yaml"
            content = 'openapi: "3.0.0"\n$schema: "http://json-schema.org/draft-07/schema#"'
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.API_SCHEMA
            assert result.confidence > 0.0


# ---------------------------------------------------------------------------
# Test: Confidence scoring when multiple types match (Requirement 9.17)
# ---------------------------------------------------------------------------


class TestConfidenceScoring:
    """Requirement 9.17: Confidence scoring when multiple types might match."""

    def test_confidence_between_0_and_1(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            prompts_dir = Path(tmpdir) / "prompts"
            prompts_dir.mkdir()
            file_path = prompts_dir / "system.prompt.md"
            content = "## System Prompt\nrole: system\nYou are an assistant."
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert 0.0 <= result.confidence <= 1.0

    def test_higher_confidence_with_more_signals(self, classifier):
        """A file matching extension + path + content should have higher confidence
        than a file matching only one signal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # High-signal file: extension + path + content
            prompts_dir = Path(tmpdir) / "prompts"
            prompts_dir.mkdir()
            high_signal_path = prompts_dir / "system.prompt.md"
            high_content = "## System Prompt\nrole: system"
            high_signal_path.write_text(high_content)

            # Low-signal file: only path match
            low_signal_path = prompts_dir / "readme.txt"
            low_content = "This is a readme in the prompts folder."
            low_signal_path.write_text(low_content)

            high_result = classifier.classify(high_signal_path, content=high_content)
            low_result = classifier.classify(low_signal_path, content=low_content)

            assert high_result is not None
            # Low result may or may not classify, but if it does, confidence is lower
            if low_result is not None:
                assert high_result.confidence >= low_result.confidence

    def test_highest_confidence_wins(self, classifier):
        """When a file could match multiple types, the highest score wins."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # A YAML in workflows/ with pipeline: content - should be orchestration
            workflows_dir = Path(tmpdir) / "workflows"
            workflows_dir.mkdir()
            file_path = workflows_dir / "ci.yaml"
            content = "pipeline:\n  stage: build\n  stage: test"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.ORCHESTRATION

    def test_signals_list_contains_matched_signals(self, classifier):
        """The result should include which signals matched."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mcp_dir = Path(tmpdir) / "mcp-servers"
            mcp_dir.mkdir()
            file_path = mcp_dir / "server.json"
            content = '{"transport": "stdio", "tools": [{"name": "read_file"}]}'
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert "path" in result.signals
            assert "content" in result.signals


# ---------------------------------------------------------------------------
# Test: None return for unclassifiable files (Requirement 9.18)
# ---------------------------------------------------------------------------


class TestUnclassifiable:
    """Requirement 9.18: Return None for files that don't match any artifact type."""

    def test_unclassifiable_random_csv(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "data.csv"
            content = "name,age,city\nAlice,30,NYC\nBob,25,LA"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is None

    def test_unclassifiable_generic_text(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "notes.txt"
            content = "Some random notes about shopping."
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is None

    def test_unclassifiable_binary_like_content(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "image.bin"
            content = "\x00\x01\x02\x03 binary garbage"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is None


# ---------------------------------------------------------------------------
# Test: Custom classification patterns (Requirement 9.19)
# ---------------------------------------------------------------------------


class TestCustomPatterns:
    """Requirement 9.19: Support custom classification patterns via configuration."""

    def test_custom_path_pattern_adds_detection(self):
        """Custom patterns should allow classifying files in non-standard directories."""
        custom_patterns = {
            "prompt": [r"my-prompts/"],
        }
        classifier = ArtifactClassifier(custom_patterns=custom_patterns)

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir) / "my-prompts"
            custom_dir.mkdir()
            file_path = custom_dir / "greeting.md"
            content = "## System Prompt\nrole: system\nHello!"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.PROMPT

    def test_custom_pattern_for_mcp(self):
        """Custom pattern can route files from a custom MCP directory."""
        custom_patterns = {
            "mcp": [r"my-tools/"],
        }
        classifier = ArtifactClassifier(custom_patterns=custom_patterns)

        with tempfile.TemporaryDirectory() as tmpdir:
            tools_dir = Path(tmpdir) / "my-tools"
            tools_dir.mkdir()
            file_path = tools_dir / "config.json"
            content = '{"transport": "http", "tools": [{"name": "query"}]}'
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert result.artifact_type == ArtifactType.MCP

    def test_custom_pattern_unknown_type_ignored(self):
        """Custom patterns with unknown artifact type names are silently ignored."""
        custom_patterns = {
            "nonexistent_type": [r"foo/"],
        }
        # Should not raise
        classifier = ArtifactClassifier(custom_patterns=custom_patterns)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "foo" / "bar.txt"
            file_path.parent.mkdir()
            file_path.write_text("some content")

            # Should still work, just won't match the unknown type
            result = classifier.classify(file_path, content="some content")
            # May or may not classify - main thing is no error
            assert result is None or isinstance(result, ClassificationResult)

    def test_custom_pattern_empty_dict(self):
        """Empty custom patterns dict should not cause errors."""
        classifier = ArtifactClassifier(custom_patterns={})

        with tempfile.TemporaryDirectory() as tmpdir:
            prompts_dir = Path(tmpdir) / "prompts"
            prompts_dir.mkdir()
            file_path = prompts_dir / "test.prompt.md"
            content = "## System Prompt\nrole: system"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)
            assert result is not None
            assert result.artifact_type == ArtifactType.PROMPT


# ---------------------------------------------------------------------------
# Test: Additional edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Additional edge cases for classifier robustness."""

    def test_classify_with_no_content_reads_from_file(self, classifier):
        """When content is None, classifier reads from the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = Path(tmpdir) / ".hooks"
            hooks_dir.mkdir()
            file_path = hooks_dir / "lint.yaml"
            file_path.write_text("eventType: fileEdited\naction: askAgent")

            result = classifier.classify(file_path, content=None)

            assert result is not None
            assert result.artifact_type == ArtifactType.HOOK

    def test_classify_nonexistent_file_no_crash(self, classifier):
        """Classifying a non-existent file path with no content should not crash."""
        file_path = Path("/nonexistent/path/file.txt")
        result = classifier.classify(file_path, content=None)
        # Without content and without matching path/extension, returns None
        assert result is None or isinstance(result, ClassificationResult)

    def test_classify_empty_content(self, classifier):
        """Empty content should not cause errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "empty.md"
            file_path.write_text("")

            result = classifier.classify(file_path, content="")
            # Empty content in root dir without matching signals → None
            assert result is None or isinstance(result, ClassificationResult)

    def test_result_model_validation(self, classifier):
        """ClassificationResult should validate its fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            prompts_dir = Path(tmpdir) / "prompts"
            prompts_dir.mkdir()
            file_path = prompts_dir / "test.prompt.md"
            content = "## System Prompt\nrole: system"
            file_path.write_text(content)

            result = classifier.classify(file_path, content=content)

            assert result is not None
            assert isinstance(result, ClassificationResult)
            assert isinstance(result.artifact_type, ArtifactType)
            assert isinstance(result.confidence, float)
            assert isinstance(result.signals, list)
            assert all(isinstance(s, str) for s in result.signals)
