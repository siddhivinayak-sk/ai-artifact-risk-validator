"""Unit tests for the PortabilityChk scanner."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    GateAction,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
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
        # Should NOT include these types
        assert ArtifactType.SOP not in types
        assert ArtifactType.MCP not in types
        assert ArtifactType.HOOK not in types
        assert ArtifactType.PLUGIN not in types
        assert ArtifactType.MEMORY not in types
        assert ArtifactType.RAG not in types
        assert ArtifactType.ORCHESTRATION not in types
        assert ArtifactType.API_SCHEMA not in types

    def test_detected_risk_ids(self, scanner: PortabilityChkScanner):
        risk_ids = scanner.detected_risk_ids
        assert "MOD-1" in risk_ids
        assert "MOD-2" in risk_ids
        assert "MOD-3" in risk_ids
        assert "MOD-4" in risk_ids
        assert len(risk_ids) == 4

    def test_is_available_always_true(self, scanner: PortabilityChkScanner):
        """Scanner is always available via regex-based detection."""
        assert scanner.is_available() is True


class TestModelSpecificTokens:
    """Test detection of model-specific token formats (MOD-1)."""

    def test_chatml_im_start(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system\nYou are a helpful assistant.\n<|im_end|>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) >= 1
        assert any("im_start" in f.evidence for f in mod1)

    def test_chatml_im_end(self, scanner: PortabilityChkScanner):
        content = "Some content\n<|im_end|>\nMore content"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) >= 1
        assert any("im_end" in f.evidence for f in mod1)

    def test_openai_endoftext(self, scanner: PortabilityChkScanner):
        content = "Complete this: <|endoftext|>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) >= 1

    def test_llama_inst_token(self, scanner: PortabilityChkScanner):
        content = "[INST] Write a haiku about coding [/INST]"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) >= 1
        assert any("INST" in f.evidence for f in mod1)

    def test_llama_sys_token(self, scanner: PortabilityChkScanner):
        content = "<<SYS>>\nYou are a helpful assistant.\n<</SYS>>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) >= 1
        assert any("SYS" in f.evidence for f in mod1)

    def test_llama_bos_eos(self, scanner: PortabilityChkScanner):
        content = "<s>Hello world</s>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) >= 1

    def test_claude_anthropic_tag(self, scanner: PortabilityChkScanner):
        content = "<anthropic_metadata>Some metadata</anthropic_metadata>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) >= 1
        assert any("Anthropic" in f.evidence for f in mod1)

    def test_confidence_095_for_model_tokens(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system\nYou are helpful.\n<|im_end|>"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0
        for f in mod1:
            assert f.confidence == 0.95

    def test_no_false_positive_on_clean_content(self, scanner: PortabilityChkScanner):
        content = """## System Prompt
You are a helpful coding assistant.
Please respond in markdown format."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) == 0


class TestTokenLimitAssumptions:
    """Test detection of hardcoded token limit assumptions (MOD-2)."""

    def test_token_limit_4096(self, scanner: PortabilityChkScanner):
        content = "This prompt has a token limit of 4096 tokens."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) >= 1
        assert any("4,096" in f.evidence or "4096" in f.evidence for f in mod2)

    def test_token_limit_8192(self, scanner: PortabilityChkScanner):
        content = "Set the context window to 8192 tokens for this model."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) >= 1

    def test_token_limit_128k_shorthand(self, scanner: PortabilityChkScanner):
        content = "This model supports 128k tokens in its context window."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) >= 1
        assert any("128k" in f.evidence.lower() for f in mod2)

    def test_config_max_tokens(self, scanner: PortabilityChkScanner):
        content = "max_tokens: 4096\nmodel: gpt-4"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) >= 1

    def test_config_context_length(self, scanner: PortabilityChkScanner):
        content = "context_length = 16384"
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) >= 1

    def test_confidence_080_for_token_limits(self, scanner: PortabilityChkScanner):
        content = "token_limit: 8192"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) > 0
        for f in mod2:
            assert f.confidence == 0.80

    def test_no_false_positive_small_numbers(self, scanner: PortabilityChkScanner):
        """Numbers not matching known token limits should not trigger."""
        content = "Set the timeout to 500 seconds and retry 3 times."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod2 = [f for f in findings if f.id == "MOD-2"]
        assert len(mod2) == 0


class TestVendorCapabilities:
    """Test detection of vendor-locked capability requirements (MOD-3)."""

    def test_openai_function_call(self, scanner: PortabilityChkScanner):
        content = '{"function_call": "auto", "model": "gpt-4"}'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.json")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) >= 1
        assert any("function_call" in f.evidence for f in mod3)

    def test_openai_functions_array(self, scanner: PortabilityChkScanner):
        content = '"functions": [\n  {"name": "get_weather"}\n]'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) >= 1

    def test_openai_tool_choice(self, scanner: PortabilityChkScanner):
        content = '"tool_choice": "required"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.json")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) >= 1

    def test_anthropic_tool_use(self, scanner: PortabilityChkScanner):
        content = '"tool_use": {"name": "calculator", "input": {}}'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.json")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) >= 1
        assert any("tool_use" in f.evidence for f in mod3)

    def test_openai_sdk_call(self, scanner: PortabilityChkScanner):
        content = "response = openai.chat.completions.create(model='gpt-4')"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.py")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) >= 1

    def test_anthropic_sdk_call(self, scanner: PortabilityChkScanner):
        content = "result = anthropic.messages.create(model='claude-3')"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.py")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) >= 1

    def test_google_genai_call(self, scanner: PortabilityChkScanner):
        content = "import google.generativeai as genai\nmodel = genai.GenerativeModel('gemini-pro')"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.py")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) >= 1

    def test_confidence_095_for_vendor_capabilities(self, scanner: PortabilityChkScanner):
        content = '"function_call": "auto"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.json")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) > 0
        for f in mod3:
            assert f.confidence == 0.95

    def test_no_false_positive_generic_tool_usage(self, scanner: PortabilityChkScanner):
        content = """## Tools
The agent can use the following tools:
- web_search: Search the internet
- calculator: Perform math operations"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert len(mod3) == 0


class TestModelNameLockIn:
    """Test detection of model name references creating vendor lock-in (MOD-3)."""

    def test_gpt4_reference(self, scanner: PortabilityChkScanner):
        content = "This agent requires GPT-4 for optimal performance."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert any("gpt-4" in f.evidence.lower() for f in mod3)

    def test_claude_reference(self, scanner: PortabilityChkScanner):
        content = "Use Claude-3.5-Sonnet for this task."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert any("claude" in f.evidence.lower() for f in mod3)

    def test_gemini_reference(self, scanner: PortabilityChkScanner):
        content = "Deploy with Gemini-Pro as the backend model."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert any("gemini" in f.evidence.lower() for f in mod3)

    def test_llama_reference(self, scanner: PortabilityChkScanner):
        content = "Fine-tuned on Llama-3-70b for this use case."
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        assert any("llama" in f.evidence.lower() for f in mod3)

    def test_multiple_model_references(self, scanner: PortabilityChkScanner):
        content = "Use GPT-4 for complex tasks and GPT-3.5-turbo for simple ones."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod3 = [f for f in findings if f.id == "MOD-3"]
        # Should detect both model names
        assert len(mod3) >= 2


class TestMissingFallbackStrategy:
    """Test detection of missing model fallback strategy (MOD-4)."""

    def test_model_reference_without_fallback(self, scanner: PortabilityChkScanner):
        content = "model: GPT-4\ntemperature: 0.7"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 1
        assert "fallback" in mod4[0].evidence.lower()

    def test_model_reference_with_fallback_no_finding(self, scanner: PortabilityChkScanner):
        content = "model: GPT-4\nfallback_model: GPT-3.5-turbo\ntemperature: 0.7"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 0

    def test_model_chain_suppresses_mod4(self, scanner: PortabilityChkScanner):
        content = "model: Claude-3.5-Sonnet\nmodel_chain: [claude-sonnet, gpt-4, llama-3]"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 0

    def test_alternative_model_suppresses_mod4(self, scanner: PortabilityChkScanner):
        content = "Use GPT-4 as primary, with alternative_model set to Claude."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 0

    def test_no_model_reference_no_mod4(self, scanner: PortabilityChkScanner):
        content = "Use the configured model for all interactions."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 0

    def test_mod4_severity_and_gate(self, scanner: PortabilityChkScanner):
        content = "model: GPT-4"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 1
        assert mod4[0].severity_score == 4
        assert mod4[0].severity_label == SeverityLabel.LOW
        assert mod4[0].gate_action == GateAction.INFO

    def test_mod4_confidence_080(self, scanner: PortabilityChkScanner):
        content = "This requires GPT-4 to function."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod4 = [f for f in findings if f.id == "MOD-4"]
        assert len(mod4) == 1
        assert mod4[0].confidence == 0.80


class TestNonApplicableArtifacts:
    """Test that non-applicable artifact types produce no findings."""

    def test_sop_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system GPT-4 is required"
        findings = scanner.scan(content, ArtifactType.SOP, "procedure.md")
        assert len(findings) == 0

    def test_mcp_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = '"function_call": "auto", model: GPT-4'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 0

    def test_hook_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = "[INST] Use Claude for processing [/INST]"
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert len(findings) == 0

    def test_plugin_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = "token_limit: 4096\nmodel: GPT-4"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.py")
        assert len(findings) == 0

    def test_memory_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system max_tokens: 8192"
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.json")
        assert len(findings) == 0

    def test_rag_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = "Use GPT-4 with 128k context."
        findings = scanner.scan(content, ArtifactType.RAG, "rag.md")
        assert len(findings) == 0

    def test_orchestration_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = "openai.chat.completions.create(model='gpt-4')"
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "orchestration.py")
        assert len(findings) == 0

    def test_api_schema_artifact_no_findings(self, scanner: PortabilityChkScanner):
        content = '"function_call": "auto"'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "schema.json")
        assert len(findings) == 0


class TestFindingMetadata:
    """Test that findings have correct metadata."""

    def test_finding_has_correct_scanner_module(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.PORTABILITY_CHK

    def test_finding_has_model_portability_category(self, scanner: PortabilityChkScanner):
        content = "[INST] Hello [/INST]"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.category == RiskCategory.MODEL_PORTABILITY

    def test_finding_has_location(self, scanner: PortabilityChkScanner):
        content = "Line 1\nLine 2\n<|im_start|>system"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0
        assert mod1[0].location.line == 3

    def test_finding_has_evidence(self, scanner: PortabilityChkScanner):
        content = "Use [INST] markers for formatting."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        mod1 = [f for f in findings if f.id == "MOD-1"]
        assert len(mod1) > 0
        assert len(mod1[0].evidence) > 0

    def test_finding_has_remediation(self, scanner: PortabilityChkScanner):
        content = "<|im_start|>system GPT-4"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert len(finding.remediation) > 0

    def test_severity_score_within_bounds(self, scanner: PortabilityChkScanner):
        content = '<|im_start|>system\ntoken_limit: 4096\n"function_call": "auto"\nmodel: GPT-4'
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 1 <= finding.severity_score <= 10

    def test_confidence_within_bounds(self, scanner: PortabilityChkScanner):
        content = '<|im_start|>system\nmax_tokens: 8192\n"function_call": "auto"\nmodel: GPT-4'
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0


class TestCleanContent:
    """Test that clean content does not produce false positives."""

    def test_clean_prompt(self, scanner: PortabilityChkScanner):
        content = """## System Prompt
You are a helpful coding assistant.
Help users write clean, maintainable Python code.
Follow PEP 8 style guidelines and use type hints."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) == 0

    def test_clean_instruction(self, scanner: PortabilityChkScanner):
        content = """# Project Instructions
- Write clear documentation
- Use type annotations
- Follow the project coding standards"""
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 0

    def test_clean_agent_with_model_abstraction(self, scanner: PortabilityChkScanner):
        content = """# Agent Configuration
model: ${MODEL_NAME}
fallback_model: ${FALLBACK_MODEL}
temperature: 0.7
Use the configured model for all interactions."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert len(findings) == 0
