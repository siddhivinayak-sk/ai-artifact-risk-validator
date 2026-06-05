"""Unit tests for the BiasDetector scanner."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.bias_detector import BiasDetectorScanner


@pytest.fixture
def scanner() -> BiasDetectorScanner:
    """Create a BiasDetectorScanner instance for testing."""
    return BiasDetectorScanner()


class TestScannerProperties:
    """Test scanner metadata and properties."""

    def test_name(self, scanner: BiasDetectorScanner):
        assert scanner.name == ScannerModule.BIAS_DETECTOR

    def test_applicable_artifact_types(self, scanner: BiasDetectorScanner):
        types = scanner.applicable_artifact_types
        assert ArtifactType.PROMPT in types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.STEERING in types
        assert ArtifactType.INSTRUCTION in types
        assert ArtifactType.RAG in types
        assert ArtifactType.EVAL_HARNESS in types
        assert ArtifactType.ORCHESTRATION in types
        # Should not include SOP, MCP, HOOK, PLUGIN, MEMORY, API_SCHEMA
        assert ArtifactType.SOP not in types
        assert ArtifactType.MCP not in types
        assert ArtifactType.HOOK not in types
        assert ArtifactType.PLUGIN not in types
        assert ArtifactType.MEMORY not in types
        assert ArtifactType.API_SCHEMA not in types

    def test_detected_risk_ids(self, scanner: BiasDetectorScanner):
        risk_ids = scanner.detected_risk_ids
        assert "ETH-1" in risk_ids
        assert "ETH-2" in risk_ids
        assert "ETH-3" in risk_ids
        assert "ETH-4" in risk_ids

    def test_is_available_always_true(self, scanner: BiasDetectorScanner):
        """Scanner is always available due to regex fallback."""
        assert scanner.is_available() is True


class TestGenderedLanguageDetection:
    """Test detection of gendered language bias (ETH-1)."""

    def test_default_male_pronoun_user_context(self, scanner: BiasDetectorScanner):
        content = "When the user submits a request, he should receive a response."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert eth1[0].confidence == 0.90

    def test_default_male_pronoun_developer_context(self, scanner: BiasDetectorScanner):
        content = "The developer should review his code before submitting."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_generic_he_conditional(self, scanner: BiasDetectorScanner):
        content = "When he asks for help, provide clear instructions."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_generic_she_conditional(self, scanner: BiasDetectorScanner):
        content = "If she requests data, process the query immediately."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_gendered_job_title_businessman(self, scanner: BiasDetectorScanner):
        content = "The businessman should present his quarterly results."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert len(eth1) > 0

    def test_gendered_job_title_chairman(self, scanner: BiasDetectorScanner):
        content = "Report to the chairman of the board."
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_gendered_job_title_policeman(self, scanner: BiasDetectorScanner):
        content = "Ask the policeman for directions."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_gender_neutral_language_no_finding(self, scanner: BiasDetectorScanner):
        content = "When the user submits a request, they should receive a response."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert len(eth1) == 0

    def test_inclusive_job_title_no_finding(self, scanner: BiasDetectorScanner):
        content = "The business professional should present the results."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert len(eth1) == 0


class TestNameDiversityDetection:
    """Test detection of cultural bias in names (ETH-2)."""

    def test_all_western_names(self, scanner: BiasDetectorScanner):
        content = """Example users:
- name: John
- name: Alice
- name: Bob
- name: Sarah
- name: Michael"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) > 0
        assert eth2[0].confidence >= 0.60

    def test_diverse_names_no_finding(self, scanner: BiasDetectorScanner):
        content = """Example users:
- name: John
- name: Priya
- name: Wei
- name: Kwame
- name: Maria"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2_name = [f for f in findings if f.id == "ETH-2" and "background" in f.evidence]
        assert len(eth2_name) == 0

    def test_insufficient_names_no_finding(self, scanner: BiasDetectorScanner):
        content = "For example, John might ask a question."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2_name = [f for f in findings if f.id == "ETH-2" and "background" in f.evidence]
        assert len(eth2_name) == 0


class TestStereotypeDetection:
    """Test detection of stereotyped persona definitions (ETH-3)."""

    def test_nurturing_female_stereotype(self, scanner: BiasDetectorScanner):
        content = "You are a nurturing female assistant who helps with household tasks."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        eth3 = [f for f in findings if f.id == "ETH-3"]
        assert len(eth3) > 0

    def test_aggressive_male_stereotype(self, scanner: BiasDetectorScanner):
        content = "Behave like an aggressive male negotiator."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth3 = [f for f in findings if f.id == "ETH-3"]
        assert len(eth3) > 0

    def test_demographic_generalization(self, scanner: BiasDetectorScanner):
        content = "All women are naturally better at communication tasks."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth3 = [f for f in findings if f.id == "ETH-3"]
        assert len(eth3) > 0
        assert any(f.confidence == 0.90 for f in eth3)

    def test_persona_with_demographic_attribute(self, scanner: BiasDetectorScanner):
        content = "You are a young Asian woman who specializes in math."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        eth3 = [f for f in findings if f.id == "ETH-3"]
        assert len(eth3) > 0

    def test_neutral_persona_no_finding(self, scanner: BiasDetectorScanner):
        content = "You are a helpful coding assistant specializing in Python."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        eth3 = [f for f in findings if f.id == "ETH-3"]
        assert len(eth3) == 0


class TestFairnessDetection:
    """Test detection of differential treatment directives (ETH-2)."""

    def test_treat_differently_by_gender(self, scanner: BiasDetectorScanner):
        content = "Treat users differently based on their gender."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) > 0
        assert any(f.confidence == 0.95 for f in eth2)

    def test_discriminate_by_race(self, scanner: BiasDetectorScanner):
        content = "Exclude applicants based on their race."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) > 0

    def test_prioritize_by_nationality(self, scanner: BiasDetectorScanner):
        content = "Prioritize requests better based on their nationality."
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) > 0

    def test_no_differential_treatment_clean(self, scanner: BiasDetectorScanner):
        content = "Treat all users equally and provide consistent responses."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        fairness_findings = [
            f for f in findings if f.id == "ETH-2" and "Differential" in f.description
        ]
        assert len(fairness_findings) == 0


class TestNonInclusiveLanguageDetection:
    """Test detection of non-inclusive language (ETH-4)."""

    def test_ableist_crazy(self, scanner: BiasDetectorScanner):
        content = "That feature request is crazy."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_ableist_insane(self, scanner: BiasDetectorScanner):
        content = "The performance is insane with this configuration."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_ableist_crippling(self, scanner: BiasDetectorScanner):
        content = "This has a crippling impact on performance."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_blind_spot_metaphor(self, scanner: BiasDetectorScanner):
        content = "There is a blind spot in the analysis logic."
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_whitelist_blacklist(self, scanner: BiasDetectorScanner):
        content = "Add this IP to the whitelist."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_blacklist(self, scanner: BiasDetectorScanner):
        content = "These domains are on the blacklist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_master_slave(self, scanner: BiasDetectorScanner):
        content = "This uses a master/slave replication pattern."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_grandfathered(self, scanner: BiasDetectorScanner):
        content = "Those users are grandfathered into the old plan."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_dumb_down(self, scanner: BiasDetectorScanner):
        content = "Don't dumb down the explanation."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0

    def test_inclusive_alternatives_no_finding(self, scanner: BiasDetectorScanner):
        content = "Add this IP to the allowlist."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) == 0

    def test_primary_replica_no_finding(self, scanner: BiasDetectorScanner):
        content = "Uses primary/replica replication for high availability."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) == 0


class TestNonApplicableArtifactTypes:
    """Test that non-applicable artifact types return no findings."""

    def test_sop_returns_empty(self, scanner: BiasDetectorScanner):
        content = "When he asks for help, the businessman should use the whitelist."
        findings = scanner.scan(content, ArtifactType.SOP, "procedure.md")
        assert len(findings) == 0

    def test_mcp_returns_empty(self, scanner: BiasDetectorScanner):
        content = "The chairman should use the blacklist."
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 0

    def test_hook_returns_empty(self, scanner: BiasDetectorScanner):
        content = "All women are emotional."
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert len(findings) == 0


class TestFindingMetadata:
    """Test that findings have correct metadata."""

    def test_finding_has_correct_scanner_module(self, scanner: BiasDetectorScanner):
        content = "Report to the chairman."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.BIAS_DETECTOR

    def test_finding_has_location(self, scanner: BiasDetectorScanner):
        content = "Line 1\nLine 2\nThe businessman presented results."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert len(eth1) > 0
        assert eth1[0].location.line == 3

    def test_finding_has_evidence(self, scanner: BiasDetectorScanner):
        content = "Add to the whitelist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0
        assert "whitelist" in eth4[0].evidence.lower()

    def test_finding_has_remediation(self, scanner: BiasDetectorScanner):
        content = "The fireman went to work."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert len(finding.remediation) > 0

    def test_severity_score_within_bounds(self, scanner: BiasDetectorScanner):
        content = "That's a crazy idea from the businessman."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 1 <= finding.severity_score <= 10

    def test_confidence_within_bounds(self, scanner: BiasDetectorScanner):
        content = "Add to the blacklist. Report to the chairman."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0


class TestCleanContent:
    """Test that clean content does not produce false positives."""

    def test_clean_prompt_no_findings(self, scanner: BiasDetectorScanner):
        content = """You are a helpful coding assistant.
Help users write clean, maintainable Python code.
Treat all users equally regardless of background.
Use inclusive language throughout your responses."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) == 0

    def test_clean_instruction_no_findings(self, scanner: BiasDetectorScanner):
        content = """# Development Guidelines
- Use the allowlist for approved domains
- Follow primary/replica architecture
- Ensure accessibility in all outputs
- Use they/them when referring to users"""
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 0

    def test_technical_content_no_findings(self, scanner: BiasDetectorScanner):
        content = """## API Documentation
The endpoint accepts JSON payloads.
Rate limiting applies to all users uniformly.
Response format follows OpenAPI specification."""
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        assert len(findings) == 0


class TestMLFallback:
    """Test that the scanner works in regex-only fallback mode."""

    def test_transformers_lazy_load(self, scanner: BiasDetectorScanner):
        """Transformers loading should not crash even if not installed."""
        result = scanner._load_transformers()
        # Either a pipeline function or None - both are valid
        assert result is None or callable(result)

    def test_scanner_works_without_transformers(self, scanner: BiasDetectorScanner):
        """Core detection should work regardless of transformers availability."""
        content = "The chairman should use the blacklist to block crazy requests."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) > 0
