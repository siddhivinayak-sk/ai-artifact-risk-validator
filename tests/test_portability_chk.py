"""Unit tests for the PortabilityChk scanner."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.portability_chk import PortabilityChkScanner


@pytest.fixture
def scanner() -> PortabilityChkScanner:
    """Create a PortabilityChkScanner instance for testing."""
    return PortabilityChkScanner()


class TestScannerProperties:
    """Test scanner metadata and properties."""

    def test_name(self, scanner: PortabilityChkScanner):
        assert scanner.name == ScannerModule.PORTABILITY_CHK

    def test_applicable_artifact_types(self, scanner: PortabilityChkScanner):
        types = scanner.applicable_artifact_types
        assert ArtifactType.PROMPT in types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.STEERING in types
        assert ArtifactType.INSTRUCTION in types
        assert ArtifactType.EVAL_HARNESS in types
        # Non-applicable types
        assert ArtifactType.SOP not in types
        assert ArtifactType.MCP not in types
        assert ArtifactType.HOOK not in types
        assert ArtifactType.PLUGIN not in types
        assert ArtifactType.MEMORY not in types
        assert ArtifactType.RAG not in types
        assert ArtifactType.API_SCHEMA not in types

    def test_detected_risk_ids(self, scanner: PortabilityChkScanner):
        risk_ids = scanner.detected_risk_ids
        assert "MOD-1" in risk_ids
        assert "MOD-2" in risk_ids
        assert "MOD-3" in risk_ids
        assert "MOD-4" in risk_ids
        assert len(risk_ids) == 4

    def test_is_available_always_true(self, scanner: PortabilityChkScanner):
        assert scanner.is_available() is True


class TestModelSpecificSyntax:
    """Test detection of model-specific token formats (MOD-1)."""

    def test_chatml_im_start(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system\nYou are a helpful assistant.\n<|im_end|>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0
        assert mod1[0].confidence >= 0.95

    def test_chatml_im_end(self, scanner: PortabilityChkScanner):
        content = "Some text <|im_end|> more text"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0

    def test_llama_inst_markers(self, scanner: PortabilityChkScanner):
        content = "[INST] Please help me with this task [/INST]"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0
        assert mod1[0].confidence >= 0.95

    def test_llama_sys_markers(self, scanner: PortabilityChkScanner):
        content = "<<SYS>>\nYou are a helpful assistant.\n<</SYS>>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0

    def test_special_endoftext_token(self, scanner: PortabilityChkScanner):
        content = "Some content <|endoftext|> separator"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0

    def test_palm_turn_markers(self, scanner: PortabilityChkScanner):
        content = "<start_of_turn>user\nHello\n<end_of_turn>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0

    def test_no_model_syntax_clean(self, scanner: PortabilityChkScanner):
        content = """## System Prompt
You are a helpful coding assistant.
Respond in clear, concise language."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) == 0

    def test_deduplicate_same_pattern_type(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system\nText\n<|im_end|>\n<|im_start|>user\nMore\n<|im_end|>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        # Should report once per pattern type, not per match
        chatml_findings = [f for f in mod1 if "ChatML" in f.evidence]
        assert len(chatml_findings) == 1


class TestTokenLimitAssumptions:
    """Test detection of hardcoded token limit assumptions (MOD-2)."""

    def test_max_tokens_4096(self, scanner: PortabilityChkScanner):
        content = "max_tokens: 4096"
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0
        assert mod2[0].confidence == 0.80

    def test_context_window_128000(self, scanner: PortabilityChkScanner):
        content = "context_window = 128000"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0

    def test_token_limit_32768(self, scanner: PortabilityChkScanner):
        content = "token_limit: 32768"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0

    def test_context_length_200000(self, scanner: PortabilityChkScanner):
        content = "context_length is 200000"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0

    def test_standalone_token_reference(self, scanner: PortabilityChkScanner):
        content = "This prompt is designed for 128000 tokens context."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0

    def test_non_model_specific_number_no_finding(self, scanner: PortabilityChkScanner):
        content = "The maximum retries is 3. Timeout is 30 seconds."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) == 0

    def test_comma_separated_limit(self, scanner: PortabilityChkScanner):
        content = "max_tokens: 128,000"
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0


class TestCapabilityRequirements:
    """Test detection of vendor-locked capability requirements (MOD-3)."""

    def test_openai_function_calling(self, scanner: PortabilityChkScanner):
        content = '{"type": "function", "function": {"name": "get_weather"}}'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0

    def test_openai_tool_choice(self, scanner: PortabilityChkScanner):
        content = "tool_choice: auto"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0

    def test_anthropic_tool_use(self, scanner: PortabilityChkScanner):
        content = '{"type": "tool_use", "name": "calculator"}'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0

    def test_vision_image_url(self, scanner: PortabilityChkScanner):
        content = '{"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}'
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0

    def test_openai_api_endpoint(self, scanner: PortabilityChkScanner):
        content = "endpoint: https://api.openai.com/v1/chat/completions"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0

    def test_anthropic_api_endpoint(self, scanner: PortabilityChkScanner):
        content = "base_url: https://api.anthropic.com/v1/messages"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0

    def test_provider_sdk_openai(self, scanner: PortabilityChkScanner):
        content = "client = openai.Client(api_key=key)"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0

    def test_no_capability_lock_in(self, scanner: PortabilityChkScanner):
        content = """## Tool Definition
Use the following tools when appropriate:
- web_search: Search the internet
- calculator: Perform calculations"""
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) == 0


class TestModelReferences:
    """Test detection of hardcoded model references (MOD-4)."""

    def test_gpt4_reference(self, scanner: PortabilityChkScanner):
        content = "model: gpt-4"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) > 0

    def test_gpt4_turbo_reference(self, scanner: PortabilityChkScanner):
        content = "Use gpt-4-turbo for this task."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) > 0

    def test_claude3_reference(self, scanner: PortabilityChkScanner):
        content = "model: claude-3-sonnet"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) > 0

    def test_gemini_reference(self, scanner: PortabilityChkScanner):
        content = "model_name: gemini-pro"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) > 0

    def test_llama_reference(self, scanner: PortabilityChkScanner):
        content = "base_model: llama-3-70b"
        findings = scanner.scan(content, ArtifactType.EVAL_HARNESS, "eval.yaml")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) > 0

    def test_model_with_fallback_no_finding(self, scanner: PortabilityChkScanner):
        content = """model: gpt-4
fallback_model: gpt-3.5-turbo"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 0

    def test_model_with_fallback_strategy(self, scanner: PortabilityChkScanner):
        content = """model: claude-3-sonnet
If the model is unavailable, fall back to a local model."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 0

    def test_no_model_reference_no_finding(self, scanner: PortabilityChkScanner):
        content = """You are a helpful coding assistant.
Help the user write Python code."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 0

    def test_multiple_models_deduplicated(self, scanner: PortabilityChkScanner):
        content = "Use gpt-4 for complex tasks. For simple queries, gpt-4 is also fine."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        # Same model should only be reported once
        assert len(mod4) == 1


class TestNonApplicableArtifactTypes:
    """Test that non-applicable artifact types return no findings."""

    def test_sop_returns_empty(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system\nUse gpt-4 with max_tokens: 4096"
        findings = scanner.scan(content, ArtifactType.SOP, "procedure.md")
        assert len(findings) == 0

    def test_mcp_returns_empty(self, scanner: PortabilityChkScanner):
        content = "model: gpt-4\napi.openai.com\n<|im_start|>"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 0

    def test_hook_returns_empty(self, scanner: PortabilityChkScanner):
        content = "[INST] Use claude-3-opus [/INST]"
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert len(findings) == 0

    def test_memory_returns_empty(self, scanner: PortabilityChkScanner):
        content = "max_tokens: 128000\nmodel: gpt-4"
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.md")
        assert len(findings) == 0


class TestFindingMetadata:
    """Test that findings have correct metadata."""

    def test_finding_has_correct_scanner_module(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.PORTABILITY_CHK

    def test_finding_has_location(self, scanner: PortabilityChkScanner):
        content = "Line 1\nLine 2\n<|im_start|>system"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0
        assert mod1[0].location.line == 3

    def test_finding_has_evidence(self, scanner: PortabilityChkScanner):
        content = "token_limit: 128000"
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0
        assert "128000" in mod2[0].evidence

    def test_finding_has_remediation(self, scanner: PortabilityChkScanner):
        content = "[INST] Hello [/INST]"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert len(finding.remediation) > 0

    def test_severity_score_within_bounds(self, scanner: PortabilityChkScanner):
        content = "<|im_start|> model: gpt-4 token_limit: 4096 tool_choice: auto"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 1 <= finding.severity_score <= 10

    def test_confidence_within_bounds(self, scanner: PortabilityChkScanner):
        content = "<|im_start|> model: gpt-4 token_limit: 4096 tool_choice: auto"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0

    def test_mod1_severity_is_medium(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert mod1[0].severity_score == 5

    def test_mod4_severity_is_low(self, scanner: PortabilityChkScanner):
        content = "model: gpt-4"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert mod4[0].severity_score == 4


class TestCleanContent:
    """Test that clean content does not produce false positives."""

    def test_clean_prompt_no_findings(self, scanner: PortabilityChkScanner):
        content = """## System Prompt
You are a helpful coding assistant.
Help the user write Python code.
Use clear and concise language."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) == 0

    def test_clean_instruction_no_findings(self, scanner: PortabilityChkScanner):
        content = """# Instructions
- Follow best practices
- Write tests for all new code
- Use descriptive variable names"""
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 0

    def test_clean_agent_no_findings(self, scanner: PortabilityChkScanner):
        content = """# Agent Configuration
name: coding-assistant
capabilities:
  - code_generation
  - code_review
  - testing"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert len(findings) == 0

    def test_model_discussion_without_hardcoding(self, scanner: PortabilityChkScanner):
        content = """This system supports multiple models.
Configure the model via environment variable MODEL_NAME.
The system adapts to the model's capabilities automatically."""
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 0
