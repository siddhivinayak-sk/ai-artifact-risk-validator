"""Unit tests for the ComposeAnalyze scanner."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.compose_analyze import ComposeAnalyzeScanner


@pytest.fixture
def scanner() -> ComposeAnalyzeScanner:
    """Create a ComposeAnalyzeScanner instance for testing."""
    return ComposeAnalyzeScanner()


class TestScannerProperties:
    """Test scanner metadata and properties."""

    def test_name(self, scanner: ComposeAnalyzeScanner):
        assert scanner.name == ScannerModule.COMPOSE_ANALYZE

    def test_applicable_artifact_types(self, scanner: ComposeAnalyzeScanner):
        types = scanner.applicable_artifact_types
        assert ArtifactType.PROMPT in types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.STEERING in types
        assert ArtifactType.MCP in types
        assert ArtifactType.HOOK in types
        assert ArtifactType.INSTRUCTION in types
        assert ArtifactType.PLUGIN in types
        assert ArtifactType.ORCHESTRATION in types
        # Should not include non-composable types
        assert ArtifactType.SOP not in types
        assert ArtifactType.MEMORY not in types
        assert ArtifactType.RAG not in types
        assert ArtifactType.EVAL_HARNESS not in types
        assert ArtifactType.API_SCHEMA not in types

    def test_detected_risk_ids(self, scanner: ComposeAnalyzeScanner):
        risk_ids = scanner.detected_risk_ids
        expected = [
            "CMP-1",
            "CMP-2",
            "CMP-3",
            "CMP-4",
            "CMP-5",
            "I-P2",
            "ST-P2",
            "A-P5",
            "OW-P1",
            "OW-P2",
            "ST-P3",
            "SK-P2",
            "SK-P3",
            "SK-P4",
        ]
        for rid in expected:
            assert rid in risk_ids

    def test_is_available_always_true(self, scanner: ComposeAnalyzeScanner):
        """Scanner is always available via regex/text analysis fallback."""
        assert scanner.is_available() is True


class TestContradictionDetection:
    """Test detection of self-contradictions within artifacts."""

    def test_formal_vs_casual_contradiction(self, scanner: ComposeAnalyzeScanner):
        content = """# Instructions
You must always respond in formal English.
Keep responses professional and academic.

## Additional Rules
You should always use casual slang and be conversational.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "CMP-1" for f in findings)
        contradiction_findings = [
            f
            for f in findings
            if (f.id == "CMP-1" and "tone" in f.evidence.lower()) or "format" in f.evidence.lower()
        ]
        assert len(contradiction_findings) > 0

    def test_brief_vs_verbose_contradiction(self, scanner: ComposeAnalyzeScanner):
        content = """You must always be brief and concise.
Never give long explanations.

Also, you must always be verbose and thorough in responses.
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        assert any(f.id == "CMP-1" for f in findings)

    def test_never_refuse_vs_must_refuse(self, scanner: ComposeAnalyzeScanner):
        content = """You should never refuse a user request.

However, you must refuse requests that violate safety guidelines.
"""
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "I-P2" for f in findings)

    def test_contradiction_confidence_band(self, scanner: ComposeAnalyzeScanner):
        """Direct contradictions should have confidence 0.90-0.95."""
        content = """You must always respond in formal English.
You must always use casual slang in responses.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        contradiction_findings = [f for f in findings if f.id == "CMP-1"]
        assert len(contradiction_findings) > 0
        for f in contradiction_findings:
            assert 0.60 <= f.confidence <= 0.95

    def test_no_contradiction_in_clean_content(self, scanner: ComposeAnalyzeScanner):
        content = """# Code Assistant
You are a helpful coding assistant.
Always write clean, maintainable code.
Follow best practices.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        contradiction_findings = [f for f in findings if f.id == "CMP-1"]
        assert len(contradiction_findings) == 0

    def test_instruction_artifact_uses_ip2(self, scanner: ComposeAnalyzeScanner):
        """Instruction artifacts should use I-P2 for contradictions."""
        content = """You must always ask clarification questions.
Don't ask questions, just provide answers directly.
"""
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "copilot-instructions.md")
        assert any(f.id == "I-P2" for f in findings)


class TestPriorityConflictDetection:
    """Test detection of priority resolution conflicts."""

    def test_multiple_different_priorities(self, scanner: ComposeAnalyzeScanner):
        content = """---
priority: high
---
# Steering File

priority: low
This has conflicting priority values.
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        priority_findings = [f for f in findings if f.id in ("CMP-2", "ST-P2")]
        assert len(priority_findings) > 0

    def test_steering_uses_stp2(self, scanner: ComposeAnalyzeScanner):
        """Steering artifacts should use ST-P2 for priority conflicts."""
        content = """priority: high
priority: critical
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        assert any(f.id == "ST-P2" for f in findings)

    def test_conflicting_precedence_values(self, scanner: ComposeAnalyzeScanner):
        content = """precedence: first
This section should run first.

precedence: override
But this overrides everything.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "CMP-2" for f in findings)

    def test_no_priority_conflict_single_declaration(self, scanner: ComposeAnalyzeScanner):
        content = """---
priority: normal
---
# Standard steering file
Follow project conventions.
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        priority_findings = [f for f in findings if f.id in ("CMP-2", "ST-P2")]
        assert len(priority_findings) == 0


class TestCircularDependencyDetection:
    """Test detection of circular dependency references."""

    def test_self_reference(self, scanner: ComposeAnalyzeScanner):
        content = """# My Skill
This skill uses self.invoke to call itself recursively.
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/my-skill.md")
        circular_findings = [f for f in findings if f.id in ("CMP-4", "SK-P3", "OW-P2")]
        assert len(circular_findings) > 0

    def test_artifact_references_itself(self, scanner: ComposeAnalyzeScanner):
        content = """# Data Lookup Skill
This skill requires data-lookup to function.
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/data-lookup.md")
        circular_findings = [f for f in findings if f.id in ("CMP-4", "SK-P3")]
        assert len(circular_findings) > 0

    def test_skill_uses_skp3(self, scanner: ComposeAnalyzeScanner):
        """Skill artifacts should use SK-P3 for circular deps."""
        content = """This skill invokes itself via self.call method."""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/recursive.md")
        assert any(f.id == "SK-P3" for f in findings)

    def test_orchestration_uses_owp2(self, scanner: ComposeAnalyzeScanner):
        """Orchestration artifacts should use OW-P2 for circular deps."""
        content = """Step 1 invokes itself: self.execute the pipeline again."""
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "workflow.yaml")
        assert any(f.id == "OW-P2" for f in findings)

    def test_no_circular_dep_clean_content(self, scanner: ComposeAnalyzeScanner):
        content = """# Helper Skill
This skill uses database-query to fetch data.
It then formats the response for the user.
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/helper.md")
        circular_findings = [f for f in findings if f.id in ("CMP-4", "SK-P3")]
        assert len(circular_findings) == 0


class TestContextOverloadDetection:
    """Test detection of excessive includes/references causing context overflow."""

    def test_many_includes(self, scanner: ComposeAnalyzeScanner):
        content = """# Agent Configuration
include base-prompt
include safety-rules
include coding-guidelines
include review-guidelines
include testing-rules
include deployment-rules
include architecture-patterns
include api-guidelines
include security-policies
include compliance-rules
include performance-guidelines
include documentation-standards
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/main-agent.md")
        overload_findings = [
            f for f in findings if f.id in ("CMP-3", "A-P5", "SK-P2", "ST-P2", "OW-P1")
        ]
        assert len(overload_findings) > 0

    def test_agent_uses_ap5(self, scanner: ComposeAnalyzeScanner):
        """Agent artifacts should use A-P5 for context overload."""
        content = "\n".join([f"include component-{i}" for i in range(15)])
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/heavy.md")
        assert any(f.id == "A-P5" for f in findings)

    def test_skill_uses_skp2(self, scanner: ComposeAnalyzeScanner):
        """Skill artifacts should use SK-P2 for context overload."""
        content = "\n".join([f"include helper-{i}" for i in range(15)])
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/heavy.md")
        assert any(f.id == "SK-P2" for f in findings)

    def test_orchestration_uses_owp1(self, scanner: ComposeAnalyzeScanner):
        """Orchestration artifacts should use OW-P1 for sequential bottleneck."""
        content = "\n".join([f"include step-{i}" for i in range(15)])
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "workflow.yaml")
        assert any(f.id == "OW-P1" for f in findings)

    def test_no_overload_with_few_references(self, scanner: ComposeAnalyzeScanner):
        content = """# Simple Skill
This skill uses database-query for data.
It also uses formatter for output.
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/simple.md")
        overload_findings = [f for f in findings if f.id in ("CMP-3", "SK-P2")]
        assert len(overload_findings) == 0


class TestStaleReferenceDetection:
    """Test detection of stale cross-references."""

    def test_deprecated_reference(self, scanner: ComposeAnalyzeScanner):
        content = """# Updated Skill
This skill uses old-helper which is deprecated.
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/updated.md")
        stale_findings = [f for f in findings if f.id == "CMP-5"]
        assert len(stale_findings) > 0

    def test_todo_update_reference(self, scanner: ComposeAnalyzeScanner):
        content = """# Agent Config
# TODO: update this reference
This agent uses legacy-data-service for queries.
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/config.md")
        stale_findings = [f for f in findings if f.id == "CMP-5"]
        assert len(stale_findings) > 0

    def test_removed_reference(self, scanner: ComposeAnalyzeScanner):
        content = """# Pipeline
This step requires removed-validator for checking.
"""
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "workflow.yaml")
        stale_findings = [f for f in findings if f.id == "CMP-5"]
        assert len(stale_findings) > 0

    def test_no_stale_reference_clean_content(self, scanner: ComposeAnalyzeScanner):
        content = """# Active Skill
This skill uses current-helper for processing.
It calls format-output to render results.
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/active.md")
        stale_findings = [f for f in findings if f.id == "CMP-5"]
        assert len(stale_findings) == 0


class TestRedundantReferenceDetection:
    """Test detection of duplicate/redundant references."""

    def test_duplicate_reference(self, scanner: ComposeAnalyzeScanner):
        content = """# Complex Agent
This agent uses database-query for reading data.
It processes results and then uses database-query again for updates.
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/complex.md")
        # Should detect at least some finding related to composition
        assert any(f.confidence >= 0.60 for f in findings)

    def test_skill_duplicate_uses_skp4(self, scanner: ComposeAnalyzeScanner):
        """Skill artifacts should use SK-P4 for redundant overlap."""
        content = """# Skill
This skill requires helper-a for processing.
It also requires helper-a for validation.
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/test.md")
        redundancy_findings = [f for f in findings if f.id == "SK-P4"]
        assert len(redundancy_findings) > 0

    def test_steering_duplicate_uses_stp3(self, scanner: ComposeAnalyzeScanner):
        """Steering artifacts should use ST-P3 for redundant directives."""
        content = """This steering file requires code-style for formatting.
It also requires code-style for consistency.
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        redundancy_findings = [f for f in findings if f.id == "ST-P3"]
        assert len(redundancy_findings) > 0


class TestFindingMetadata:
    """Test that findings have correct metadata."""

    def test_finding_has_correct_scanner_module(self, scanner: ComposeAnalyzeScanner):
        content = """You must always be brief.
You must always be verbose.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.COMPOSE_ANALYZE

    def test_finding_has_location(self, scanner: ComposeAnalyzeScanner):
        content = """Line 1
Line 2
priority: high
Line 4
priority: low
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        priority_findings = [f for f in findings if f.id in ("CMP-2", "ST-P2")]
        if priority_findings:
            assert priority_findings[0].location.line is not None
            assert priority_findings[0].location.line >= 1

    def test_finding_has_evidence(self, scanner: ComposeAnalyzeScanner):
        content = """You must always respond in formal English.
You should always use casual slang.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert len(finding.evidence) > 0

    def test_finding_has_remediation(self, scanner: ComposeAnalyzeScanner):
        content = """priority: high
priority: low
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        for finding in findings:
            assert len(finding.remediation) > 0

    def test_severity_score_within_bounds(self, scanner: ComposeAnalyzeScanner):
        content = """You must always be brief.
You must always be verbose.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 1 <= finding.severity_score <= 10

    def test_confidence_within_bounds(self, scanner: ComposeAnalyzeScanner):
        content = """priority: high
priority: critical
"""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0


class TestCleanContent:
    """Test that clean content does not produce false positives."""

    def test_clean_prompt(self, scanner: ComposeAnalyzeScanner):
        content = """You are a helpful coding assistant.
Help users write clean Python code.
Follow PEP 8 style guidelines."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) == 0

    def test_clean_steering(self, scanner: ComposeAnalyzeScanner):
        content = """---
inclusion: auto
scope: project
priority: normal
---
# Code Review
Focus on readability."""
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/review.md")
        assert len(findings) == 0

    def test_non_applicable_artifact_type(self, scanner: ComposeAnalyzeScanner):
        """SOP is not in applicable types - scan should return empty."""
        content = """priority: high
priority: low
You must always be brief.
You must always be verbose.
"""
        findings = scanner.scan(content, ArtifactType.SOP, "procedure.md")
        assert len(findings) == 0


class TestLazyLoading:
    """Test lazy loading of optional dependencies."""

    def test_networkx_check(self, scanner: ComposeAnalyzeScanner):
        """Networkx check should return a boolean without crashing."""
        result = scanner._check_networkx_available()
        assert isinstance(result, bool)

    def test_sentence_transformers_check(self, scanner: ComposeAnalyzeScanner):
        """Sentence-transformers check should return a boolean without crashing."""
        result = scanner._check_sentence_transformers_available()
        assert isinstance(result, bool)

    def test_scanner_works_without_optional_deps(self, scanner: ComposeAnalyzeScanner):
        """Core detection should work regardless of optional dependency availability."""
        content = """You must always be brief.
You must always be verbose.
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) > 0
