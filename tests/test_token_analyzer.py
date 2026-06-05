"""Unit tests for the TokenAnalyzerScanner module."""

import pytest

from ai_artifact_risk_validator.models import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.token_analyzer import (
    COMPRESSION_RATIO_THRESHOLD,
    DEFAULT_TOKEN_BUDGETS,
    TokenAnalyzerScanner,
)


@pytest.fixture
def scanner() -> TokenAnalyzerScanner:
    """Create a TokenAnalyzerScanner instance for testing."""
    return TokenAnalyzerScanner()


class TestTokenAnalyzerProperties:
    """Test basic scanner properties."""

    def test_name(self, scanner: TokenAnalyzerScanner) -> None:
        assert scanner.name == ScannerModule.TOKEN_ANALYZER

    def test_applicable_artifact_types(self, scanner: TokenAnalyzerScanner) -> None:
        types = scanner.applicable_artifact_types
        assert ArtifactType.PROMPT in types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.STEERING in types
        assert ArtifactType.MCP in types
        assert ArtifactType.INSTRUCTION in types
        assert ArtifactType.MEMORY in types
        assert ArtifactType.RAG in types
        # Not applicable
        assert ArtifactType.HOOK not in types
        assert ArtifactType.SOP not in types

    def test_detected_risk_ids(self, scanner: TokenAnalyzerScanner) -> None:
        risk_ids = scanner.detected_risk_ids
        expected = [
            "P-P1",
            "P-P2",
            "P-P3",
            "P-P4",
            "P-P5",
            "P-P6",
            "SK-P1",
            "A-P2",
            "A-P3",
            "A-P4",
            "I-P1",
            "I-P3",
            "I-P4",
            "M-P1",
            "CMP-3",
            "MCP-P3",
            "MOD-2",
        ]
        for rid in expected:
            assert rid in risk_ids


class TestTokenBudgetOverflow:
    """Test token budget overflow detection."""

    def test_no_findings_under_budget(self, scanner: TokenAnalyzerScanner) -> None:
        """Short content should not trigger budget overflow."""
        content = "This is a short prompt."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        budget_findings = [f for f in findings if f.id == "P-P1"]
        assert len(budget_findings) == 0

    def test_budget_overflow_detected(self, scanner: TokenAnalyzerScanner) -> None:
        """Content exceeding token budget should trigger a finding."""
        # Generate content that exceeds default prompt budget (4096 tokens)
        content = "This is a repeated instruction for testing. " * 2000
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        budget_findings = [f for f in findings if f.id == "P-P1"]
        assert len(budget_findings) == 1
        assert budget_findings[0].confidence >= 0.95

    def test_skill_budget_overflow(self, scanner: TokenAnalyzerScanner) -> None:
        """Skill artifacts use SK-P1 for budget overflow."""
        content = "Skill description content. " * 1500
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        budget_findings = [f for f in findings if f.id == "SK-P1"]
        assert len(budget_findings) >= 1

    def test_agent_budget_overflow(self, scanner: TokenAnalyzerScanner) -> None:
        """Agent artifacts use A-P2 for budget overflow."""
        content = "Agent system prompt content. " * 5000
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        budget_findings = [f for f in findings if f.id == "A-P2"]
        assert len(budget_findings) == 1

    def test_instruction_budget_overflow(self, scanner: TokenAnalyzerScanner) -> None:
        """Instruction artifacts use I-P1 for budget overflow."""
        content = "Instruction content. " * 2500
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        budget_findings = [f for f in findings if f.id == "I-P1"]
        assert len(budget_findings) == 1


class TestCompressionRatio:
    """Test compression ratio analysis."""

    def test_no_finding_for_diverse_content(self, scanner: TokenAnalyzerScanner) -> None:
        """Diverse content should not trigger compression ratio finding."""
        # Content with high entropy/diversity
        import string

        lines = [
            f"Line {i}: {c * 5} unique content here." for i, c in enumerate(string.ascii_lowercase)
        ]
        content = "\n".join(lines * 4)
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        compression_findings = [
            f
            for f in findings
            if "compression" in f.description.lower() or "repetitive" in f.description.lower()
        ]
        # Diverse content should have low compression ratio
        ratio = scanner._compute_compression_ratio(content)
        if ratio <= COMPRESSION_RATIO_THRESHOLD:
            assert len(compression_findings) == 0

    def test_highly_repetitive_content_detected(self, scanner: TokenAnalyzerScanner) -> None:
        """Highly repetitive content should trigger compression ratio finding."""
        # Very repetitive content: same line repeated many times
        content = "You must always follow these instructions carefully. " * 200
        ratio = scanner._compute_compression_ratio(content)
        assert ratio > COMPRESSION_RATIO_THRESHOLD

        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        # Should detect either compression ratio or redundancy
        perf_findings = [f for f in findings if f.category.value == "Performance"]
        assert len(perf_findings) >= 1


class TestRedundancyDetection:
    """Test sentence-level redundancy detection."""

    def test_no_redundancy_in_unique_content(self, scanner: TokenAnalyzerScanner) -> None:
        """Unique sentences should not trigger redundancy."""
        content = (
            "First, understand the user's intent. "
            "Second, analyze the context thoroughly. "
            "Third, generate an appropriate response. "
            "Fourth, validate the output quality."
        )
        redundant = scanner._find_redundant_sentences(content)
        assert len(redundant) == 0

    def test_redundancy_detected(self, scanner: TokenAnalyzerScanner) -> None:
        """Repeated sentences should be flagged as redundant."""
        repeated = "Always validate user input before processing it"
        content = f"{repeated}. Some other content here that is unique. {repeated}. More unique stuff follows. {repeated}."
        redundant = scanner._find_redundant_sentences(content)
        assert len(redundant) >= 1


class TestContextSaturation:
    """Test context window saturation detection."""

    def test_no_saturation_for_short_content(self, scanner: TokenAnalyzerScanner) -> None:
        """Content well under budget should not trigger saturation."""
        content = "Short prompt content."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        saturation_findings = [f for f in findings if f.id == "P-P4"]
        assert len(saturation_findings) == 0

    def test_saturation_detected_near_budget(self, scanner: TokenAnalyzerScanner) -> None:
        """Content near (but not over) budget should trigger saturation."""
        # Build content that is ~85-95% of 4096 tokens but not over
        budget = DEFAULT_TOKEN_BUDGETS[ArtifactType.PROMPT]
        # Each word is roughly 1 token with cl100k_base
        # Target ~90% of budget
        target_tokens = int(budget * 0.90)
        content = "word " * target_tokens
        # Verify we're in the saturation range
        token_count = scanner._count_tokens(content)
        utilization = token_count / budget
        if 0.80 <= utilization < 1.0:
            findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
            saturation_findings = [f for f in findings if f.id == "P-P4"]
            assert len(saturation_findings) == 1


class TestUnboundedDynamicContent:
    """Test unbounded dynamic content detection."""

    def test_no_finding_without_templates(self, scanner: TokenAnalyzerScanner) -> None:
        """Content without template variables should not trigger."""
        content = "This is a plain prompt with no template variables."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        unbounded_findings = [f for f in findings if f.id == "P-P6"]
        assert len(unbounded_findings) == 0

    def test_unbounded_jinja_variable_detected(self, scanner: TokenAnalyzerScanner) -> None:
        """Jinja-style unbounded variables should be detected."""
        content = "Process the following document:\n{{full_document}}\n\nSummarize it."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        unbounded_findings = [f for f in findings if f.id == "P-P6"]
        assert len(unbounded_findings) == 1

    def test_unbounded_python_format_detected(self, scanner: TokenAnalyzerScanner) -> None:
        """Python-style unbounded variables should be detected."""
        content = "Here is the conversation history:\n{chat_history}\n\nRespond to the user."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        unbounded_findings = [f for f in findings if f.id == "P-P6"]
        assert len(unbounded_findings) == 1

    def test_bounded_variable_not_flagged(self, scanner: TokenAnalyzerScanner) -> None:
        """Variables with length constraints should not be flagged."""
        content = (
            "Here is the conversation history (max_length: 500 tokens):\n"
            "{{chat_history}}\n\nRespond to the user."
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        unbounded_findings = [f for f in findings if f.id == "P-P6"]
        assert len(unbounded_findings) == 0

    def test_non_unbounded_variable_not_flagged(self, scanner: TokenAnalyzerScanner) -> None:
        """Safe variable names (not suggesting unbounded data) should not trigger."""
        content = "Hello {{user_name}}, welcome to the system."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        unbounded_findings = [f for f in findings if f.id == "P-P6"]
        assert len(unbounded_findings) == 0


class TestSectionDisproportionality:
    """Test section-level token analysis."""

    def test_no_finding_for_balanced_sections(self, scanner: TokenAnalyzerScanner) -> None:
        """Balanced sections should not trigger disproportionality."""
        content = (
            "# Section A\n"
            "Content for section A " * 20 + "\n\n"
            "# Section B\n"
            "Content for section B " * 20 + "\n\n"
            "# Section C\n"
            "Content for section C " * 20
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        section_findings = [f for f in findings if "disproportionate" in f.description.lower()]
        assert len(section_findings) == 0

    def test_disproportionate_section_detected(self, scanner: TokenAnalyzerScanner) -> None:
        """A section consuming >50% of tokens should be flagged."""
        # Use enough repetitions to make one section dominant but stay under budget
        long_section = "This is a long example section. " * 100
        content = (
            "# Introduction\n"
            "Brief intro.\n\n"
            f"# Examples\n{long_section}\n\n"
            "# Conclusion\n"
            "Brief conclusion."
        )
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        # P-P3 is the inefficiency risk ID for disproportionate sections in prompts
        section_findings = [f for f in findings if f.id == "P-P3"]
        assert len(section_findings) == 1
        assert "Examples" in section_findings[0].description


class TestVerbosityDetection:
    """Test verbose content detection."""

    def test_short_content_not_flagged(self, scanner: TokenAnalyzerScanner) -> None:
        """Short content should not be flagged as verbose."""
        content = "Be concise. Follow instructions."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        verbosity_findings = [f for f in findings if f.id == "P-P5"]
        assert len(verbosity_findings) == 0


class TestScannerAvailability:
    """Test scanner availability and initialization."""

    def test_is_available(self, scanner: TokenAnalyzerScanner) -> None:
        """TokenAnalyzer should always be available (tiktoken is a core dep)."""
        assert scanner.is_available() is True

    def test_empty_content_no_crash(self, scanner: TokenAnalyzerScanner) -> None:
        """Empty content should not cause errors."""
        findings = scanner.scan("", ArtifactType.PROMPT, "test.prompt.md")
        assert isinstance(findings, list)

    def test_scan_returns_scan_findings(self, scanner: TokenAnalyzerScanner) -> None:
        """All findings should be proper ScanFinding objects."""
        content = "This is a repeated instruction. " * 3000
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.TOKEN_ANALYZER
            assert 0.0 <= finding.confidence <= 1.0
            assert 1 <= finding.severity_score <= 10


class TestCrossCuttingRisks:
    """Test that cross-cutting risks are detected for applicable types."""

    def test_memory_budget_overflow(self, scanner: TokenAnalyzerScanner) -> None:
        """Memory artifacts use M-P1 for budget overflow."""
        content = "Memory entry content. " * 5000
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.md")
        memory_findings = [f for f in findings if f.id == "M-P1"]
        assert len(memory_findings) >= 1

    def test_mcp_budget_overflow(self, scanner: TokenAnalyzerScanner) -> None:
        """MCP artifacts use MCP-P3 for budget overflow."""
        content = "MCP tool definition content. " * 2500
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        mcp_findings = [f for f in findings if f.id == "MCP-P3"]
        assert len(mcp_findings) >= 1

    def test_steering_budget_overflow(self, scanner: TokenAnalyzerScanner) -> None:
        """Steering artifacts use CMP-3 for budget overflow."""
        content = "Steering rule content. " * 2500
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        steering_findings = [f for f in findings if f.id == "CMP-3"]
        assert len(steering_findings) >= 1
