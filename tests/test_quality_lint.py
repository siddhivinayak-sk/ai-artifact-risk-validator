"""Unit tests for QualityLintScanner."""

import pytest

from ai_artifact_risk_validator.models import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.quality_lint import QualityLintScanner


@pytest.fixture
def scanner() -> QualityLintScanner:
    return QualityLintScanner()


class TestScannerProperties:
    """Test scanner metadata properties."""

    def test_name(self, scanner: QualityLintScanner):
        assert scanner.name == ScannerModule.QUALITY_LINT

    def test_applicable_artifact_types(self, scanner: QualityLintScanner):
        # QualityLint applies to ALL 14 artifact types
        assert len(scanner.applicable_artifact_types) == 14
        assert ArtifactType.PROMPT in scanner.applicable_artifact_types
        assert ArtifactType.SKILL in scanner.applicable_artifact_types
        assert ArtifactType.AGENT in scanner.applicable_artifact_types
        assert ArtifactType.SOP in scanner.applicable_artifact_types
        assert ArtifactType.STEERING in scanner.applicable_artifact_types
        assert ArtifactType.MCP in scanner.applicable_artifact_types
        assert ArtifactType.HOOK in scanner.applicable_artifact_types
        assert ArtifactType.INSTRUCTION in scanner.applicable_artifact_types
        assert ArtifactType.PLUGIN in scanner.applicable_artifact_types
        assert ArtifactType.MEMORY in scanner.applicable_artifact_types
        assert ArtifactType.RAG in scanner.applicable_artifact_types
        assert ArtifactType.EVAL_HARNESS in scanner.applicable_artifact_types
        assert ArtifactType.ORCHESTRATION in scanner.applicable_artifact_types
        assert ArtifactType.API_SCHEMA in scanner.applicable_artifact_types

    def test_detected_risk_ids(self, scanner: QualityLintScanner):
        expected_ids = {
            "P-Q1",
            "P-Q2",
            "P-Q3",
            "P-Q4",
            "P-Q5",
            "P-Q6",
            "P-Q7",
            "SK-Q1",
            "SK-Q2",
            "SK-Q3",
            "SOP-Q1",
            "SOP-Q2",
            "SOP-Q3",
            "SOP-Q4",
            "SOP-Q5",
            "I-Q2",
            "I-Q3",
            "ST-Q2",
            "MCP-Q2",
            "MCP-Q3",
            "H-Q1",
            "H-Q2",
            "H-Q3",
            "EV-Q1",
            "EV-Q2",
            "M-Q1",
            "RAG-Q1",
            "PL-Q2",
            "PL-Q3",
            "GOV-3",
            "GOV-4",
            "GOV-5",
            "A-R1",
            "A-R2",
            "A-R3",
            "MCP-P1",
            "MCP-P2",
            "MCP-P4",
            "P-Q8",
            "P-Q9",
        }
        assert set(scanner.detected_risk_ids) == expected_ids

    def test_is_available(self, scanner: QualityLintScanner):
        assert scanner.is_available() is True


class TestAmbiguityDetection:
    """Tests for ambiguity detection (P-Q1, SK-Q1, SOP-Q1, etc.)."""

    def test_detects_maybe(self, scanner: QualityLintScanner):
        content = "# Prompt\nYou should maybe include a greeting.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "prompts/greet.prompt.md")
        assert len(findings) >= 1
        ambiguity_findings = [f for f in findings if f.id == "P-Q1"]
        assert len(ambiguity_findings) == 1
        assert "maybe" in ambiguity_findings[0].evidence.lower()

    def test_detects_possibly(self, scanner: QualityLintScanner):
        content = "# Instructions\nThe model will possibly respond with code.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        ambiguity = [f for f in findings if f.id == "P-Q1"]
        assert len(ambiguity) == 1

    def test_detects_try_to(self, scanner: QualityLintScanner):
        content = "# Skill\nTry to complete the task quickly.\n"
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/fast.md")
        ambiguity = [f for f in findings if f.id == "SK-Q1"]
        assert len(ambiguity) == 1

    def test_detects_etc(self, scanner: QualityLintScanner):
        content = "# SOP\nInclude headers, footers, etc.\n"
        findings = scanner.scan(content, ArtifactType.SOP, "sops/format.md")
        ambiguity = [f for f in findings if f.id == "SOP-Q1"]
        assert len(ambiguity) == 1

    def test_no_ambiguity_in_clear_text(self, scanner: QualityLintScanner):
        content = "# Prompt\nAlways respond with JSON format.\nInclude a timestamp field.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "prompts/json.prompt.md")
        ambiguity = [f for f in findings if f.id == "P-Q1"]
        assert len(ambiguity) == 0

    def test_multiple_ambiguities_report_count(self, scanner: QualityLintScanner):
        content = (
            "# Prompt\n"
            "Maybe include a greeting.\n"
            "You could try to be helpful.\n"
            "Perhaps add context.\n"
            "Use something if possible.\n"
            "It is generally fine.\n"
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        ambiguity = [f for f in findings if f.id == "P-Q1"]
        assert len(ambiguity) == 1
        assert "5" in ambiguity[0].description  # 5 instances

    def test_ambiguity_for_instruction(self, scanner: QualityLintScanner):
        content = "# Instructions\nMaybe use type hints sometimes.\n"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        ambiguity = [f for f in findings if f.id == "I-Q2"]
        assert len(ambiguity) == 1

    def test_ambiguity_for_steering(self, scanner: QualityLintScanner):
        content = "# Style\nPerhaps use camelCase for variables.\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/style.md")
        ambiguity = [f for f in findings if f.id == "ST-Q2"]
        assert len(ambiguity) == 1

    def test_ambiguity_confidence_is_moderate(self, scanner: QualityLintScanner):
        content = "# Prompt\nMaybe respond nicely.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        ambiguity = [f for f in findings if f.id == "P-Q1"]
        assert len(ambiguity) == 1
        assert 0.70 <= ambiguity[0].confidence <= 0.85


class TestContradictionDetection:
    """Tests for contradiction detection (P-Q2, SOP-Q2, A-R2, etc.)."""

    def test_detects_always_vs_never(self, scanner: QualityLintScanner):
        content = (
            "# Prompt\nAlways include a greeting.\nNever include a greeting in short responses.\n"
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        contradictions = [f for f in findings if f.id == "P-Q2"]
        assert len(contradictions) == 1

    def test_detects_verbose_vs_concise(self, scanner: QualityLintScanner):
        content = "# Agent\nProvide detailed explanations.\nKeep responses concise and brief.\n"
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/helper.md")
        contradictions = [f for f in findings if f.id == "A-R2"]
        assert len(contradictions) == 1

    def test_no_contradiction_without_conflict(self, scanner: QualityLintScanner):
        content = "# Prompt\nAlways include a greeting.\nAlways include a timestamp.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        contradictions = [f for f in findings if f.id == "P-Q2"]
        assert len(contradictions) == 0

    def test_contradiction_confidence(self, scanner: QualityLintScanner):
        content = (
            "# SOP\nAlways use formal language.\nNever use formal language with casual users.\n"
        )
        findings = scanner.scan(content, ArtifactType.SOP, "sops/tone.md")
        contradictions = [f for f in findings if f.id == "SOP-Q2"]
        assert len(contradictions) == 1
        assert contradictions[0].confidence == 0.70


class TestMissingMetadataDetection:
    """Tests for missing metadata detection (P-Q3, SK-Q2, GOV-3, etc.)."""

    def test_detects_missing_metadata(self, scanner: QualityLintScanner):
        content = "# Just some content\nNo metadata at all here.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        metadata_findings = [f for f in findings if f.id == "P-Q3"]
        assert len(metadata_findings) == 1

    def test_no_finding_with_metadata_present(self, scanner: QualityLintScanner):
        content = (
            "---\n"
            "title: My Prompt\n"
            "version: 1.0\n"
            "author: John\n"
            "date: 2025-01-01\n"
            "---\n"
            "# Content\nSome instructions.\n"
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        metadata_findings = [f for f in findings if f.id == "P-Q3"]
        assert len(metadata_findings) == 0

    def test_partial_metadata_with_version(self, scanner: QualityLintScanner):
        content = "version: 1.0\nauthor: Jane\n# Content\nSome text.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        metadata_findings = [f for f in findings if f.id == "P-Q3"]
        assert len(metadata_findings) == 0

    def test_metadata_confidence_is_high(self, scanner: QualityLintScanner):
        content = "# Raw content\nNo version, no author, no date.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        metadata_findings = [f for f in findings if f.id == "P-Q3"]
        assert len(metadata_findings) == 1
        assert metadata_findings[0].confidence == 0.95

    def test_json_metadata_detection(self, scanner: QualityLintScanner):
        content = '{"name": "my-hook", "version": "1.0", "description": "A hook", "author": "dev"}'
        findings = scanner.scan(content, ArtifactType.HOOK, "hooks/my-hook.json")
        metadata_findings = [f for f in findings if f.id == "H-Q2"]
        assert len(metadata_findings) == 0

    def test_missing_metadata_for_agent(self, scanner: QualityLintScanner):
        content = "# Agent instructions\nDo various things.\n"
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/my-agent.md")
        metadata_findings = [f for f in findings if f.id == "GOV-3"]
        assert len(metadata_findings) == 1


class TestStalenessDetection:
    """Tests for staleness detection (P-Q4, SOP-Q3, M-Q1, etc.)."""

    def test_detects_old_date(self, scanner: QualityLintScanner):
        content = "# Prompt\nCreated: 2020-01-15\nThis prompt does things.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        staleness = [f for f in findings if f.id == "P-Q4"]
        assert len(staleness) == 1
        assert "2020-01-15" in staleness[0].evidence

    def test_detects_deprecated_reference(self, scanner: QualityLintScanner):
        content = "# SOP\nUse the deprecated API endpoint for legacy support.\n"
        findings = scanner.scan(content, ArtifactType.SOP, "sops/legacy.md")
        staleness = [f for f in findings if f.id == "SOP-Q3"]
        assert len(staleness) == 1
        assert "deprecated" in staleness[0].evidence.lower()

    def test_no_staleness_with_recent_date(self, scanner: QualityLintScanner):
        content = "# Memory\nUpdated: 2026-05-01\nCurrent session data.\n"
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory/session.md")
        staleness = [f for f in findings if f.id == "M-Q1"]
        assert len(staleness) == 0

    def test_staleness_for_rag(self, scanner: QualityLintScanner):
        content = "# Knowledge Base\nLast updated: 2020-03-01\nOutdated info here.\n"
        findings = scanner.scan(content, ArtifactType.RAG, "rag/knowledge.md")
        staleness = [f for f in findings if f.id == "RAG-Q1"]
        assert len(staleness) == 1

    def test_staleness_confidence(self, scanner: QualityLintScanner):
        content = "# Prompt\ndate: 2019-06-01\nOld content.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        staleness = [f for f in findings if f.id == "P-Q4"]
        assert len(staleness) == 1
        assert staleness[0].confidence == 0.80


class TestIncompleteRefsDetection:
    """Tests for incomplete references (P-Q5)."""

    def test_detects_todo_placeholder(self, scanner: QualityLintScanner):
        content = "# Prompt\nTODO: Add the actual instructions here.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        refs = [f for f in findings if f.id == "P-Q5"]
        assert len(refs) == 1
        assert "TODO" in refs[0].evidence

    def test_detects_fixme(self, scanner: QualityLintScanner):
        content = "# Prompt\n# FIXME: This needs to be rewritten.\nSome content.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        refs = [f for f in findings if f.id == "P-Q5"]
        assert len(refs) == 1

    def test_detects_empty_link(self, scanner: QualityLintScanner):
        content = "# Prompt\nSee [documentation]() for details.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        refs = [f for f in findings if f.id == "P-Q5"]
        assert len(refs) == 1
        assert "link" in refs[0].evidence.lower()

    def test_detects_template_link(self, scanner: QualityLintScanner):
        content = "# Prompt\nRefer to [API docs]({{API_URL}}) for usage.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        refs = [f for f in findings if f.id == "P-Q5"]
        assert len(refs) == 1

    def test_no_finding_for_valid_links(self, scanner: QualityLintScanner):
        content = "# Prompt\nSee [docs](https://example.com/docs) for more.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        refs = [f for f in findings if f.id == "P-Q5"]
        assert len(refs) == 0

    def test_no_finding_for_clean_content(self, scanner: QualityLintScanner):
        content = "# Prompt\nAlways respond in JSON format.\nInclude timestamps.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        refs = [f for f in findings if f.id == "P-Q5"]
        assert len(refs) == 0


class TestMissingErrorHandling:
    """Tests for missing error handling detection (P-Q6, A-R3)."""

    def test_detects_missing_error_handling(self, scanner: QualityLintScanner):
        # Content >200 chars with no error handling keywords
        content = (
            "# Prompt\n"
            "You are a helpful assistant that provides code reviews.\n"
            "When the user submits code, analyze it for quality issues.\n"
            "Provide suggestions for improvement and best practices.\n"
            "Format your response as a numbered list of suggestions.\n"
            "Each suggestion should include the line number and explanation.\n"
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        error_findings = [f for f in findings if f.id == "P-Q6"]
        assert len(error_findings) == 1

    def test_no_finding_with_error_handling(self, scanner: QualityLintScanner):
        content = (
            "# Prompt\n"
            "You are a helpful assistant.\n"
            "If the user provides invalid input, return an error message.\n"
            "Handle edge cases by asking for clarification.\n"
            "Provide a fallback response when unsure.\n"
            "This is extra content to make it longer than 200 chars.\n"
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        error_findings = [f for f in findings if f.id == "P-Q6"]
        assert len(error_findings) == 0

    def test_short_content_not_flagged(self, scanner: QualityLintScanner):
        content = "# Prompt\nBe helpful.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        error_findings = [f for f in findings if f.id == "P-Q6"]
        assert len(error_findings) == 0

    def test_agent_error_handling(self, scanner: QualityLintScanner):
        content = (
            "# Agent\n"
            "This agent processes user requests for data analysis.\n"
            "It connects to databases and retrieves information.\n"
            "The agent formats results as tables or charts.\n"
            "It supports multiple database engines and formats.\n"
            "Responses should be clear and well-structured.\n"
        )
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/data.md")
        error_findings = [f for f in findings if f.id == "A-R3"]
        assert len(error_findings) == 1


class TestPoorStructure:
    """Tests for poor structure detection (P-Q7, SK-Q3, I-Q3, etc.)."""

    def test_detects_no_headers(self, scanner: QualityLintScanner):
        # Long content with no headers (>500 chars, >20 lines)
        lines = [f"This is line number {i}." for i in range(25)]
        content = "\n".join(lines)
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        structure_findings = [f for f in findings if f.id == "P-Q7"]
        assert len(structure_findings) == 1
        assert "No section headers" in structure_findings[0].evidence

    def test_no_finding_for_well_structured(self, scanner: QualityLintScanner):
        content = (
            "# Main Section\n\n"
            "Some introductory text that explains the purpose.\n\n"
            "## Sub-Section 1\n\n"
            "Details about sub-section 1 content.\n"
            "More details and explanation text.\n\n"
            "## Sub-Section 2\n\n"
            "Details about sub-section 2 content.\n"
            "Even more content to make it substantial.\n"
            "Additional lines to fill space.\n"
            "And more lines for good measure.\n"
            "This needs to be over 500 characters total.\n"
            "So we add even more content here.\n"
            "And a bit more to be safe.\n"
            "Final lines to ensure length.\n"
            "One more line to be sure.\n"
            "And another for the road.\n"
            "Almost there now.\n"
            "Done with the content.\n"
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        structure_findings = [f for f in findings if f.id == "P-Q7"]
        assert len(structure_findings) == 0

    def test_short_content_not_flagged(self, scanner: QualityLintScanner):
        content = "Simple short content."
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        structure_findings = [f for f in findings if f.id == "P-Q7"]
        assert len(structure_findings) == 0

    def test_instruction_poor_structure(self, scanner: QualityLintScanner):
        lines = [f"Instruction line number {i}." for i in range(25)]
        content = "\n".join(lines)
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        structure_findings = [f for f in findings if f.id == "I-Q3"]
        assert len(structure_findings) == 1


class TestAllFindingsHaveCorrectModule:
    """Tests that all generated findings use the correct scanner module."""

    def test_all_findings_have_quality_lint_module(self, scanner: QualityLintScanner):
        # Generate findings from ambiguity
        content = "# Prompt\nMaybe do something.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.QUALITY_LINT

    def test_all_findings_have_quality_category(self, scanner: QualityLintScanner):
        content = (
            "# Prompt\nMaybe do something.\nAlways include greetings.\nNever include greetings.\n"
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        from ai_artifact_risk_validator.models import RiskCategory

        for finding in findings:
            assert finding.category == RiskCategory.QUALITY


class TestMCPSpecificRiskIds:
    """Tests for MCP-P1, MCP-P2, MCP-P4 risk IDs."""

    def test_mcp_ambiguity_uses_mcp_p1(self, scanner: QualityLintScanner):
        content = "# MCP Config\nMaybe connect to the server.\n"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp/config.json")
        ambiguity = [f for f in findings if f.id == "MCP-P1"]
        assert len(ambiguity) == 1

    def test_mcp_contradiction_uses_mcp_p2(self, scanner: QualityLintScanner):
        content = "# MCP\nAlways use strict mode.\nUse flexible mode for testing.\n"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp/config.json")
        contradiction = [f for f in findings if f.id == "MCP-P2"]
        assert len(contradiction) == 1

    def test_mcp_staleness_uses_mcp_p4(self, scanner: QualityLintScanner):
        content = "# MCP Server\nLast updated: 2020-01-01\nOld config.\n"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp/server.json")
        staleness = [f for f in findings if f.id == "MCP-P4"]
        assert len(staleness) == 1


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_content(self, scanner: QualityLintScanner):
        findings = scanner.scan("", ArtifactType.PROMPT, "p.prompt.md")
        # Empty content should not crash
        assert isinstance(findings, list)

    def test_binary_like_content(self, scanner: QualityLintScanner):
        content = "\x00\x01\x02\x03" * 100
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        assert isinstance(findings, list)

    def test_very_long_content(self, scanner: QualityLintScanner):
        content = "# Title\nversion: 1.0\nauthor: test\n" + ("Line of content.\n" * 1000)
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        assert isinstance(findings, list)

    def test_unicode_content(self, scanner: QualityLintScanner):
        content = "# Título\nQuizás incluir saludos. Maybe add greetings.\n"
        findings = scanner.scan(content, ArtifactType.PROMPT, "p.prompt.md")
        ambiguity = [f for f in findings if f.id == "P-Q1"]
        assert len(ambiguity) == 1
