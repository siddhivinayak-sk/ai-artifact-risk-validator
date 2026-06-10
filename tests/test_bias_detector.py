"""Unit tests for the BiasDetector scanner."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    GateAction,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
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
        # Should NOT include these types
        assert ArtifactType.SOP not in types
        assert ArtifactType.MCP not in types
        assert ArtifactType.HOOK not in types
        assert ArtifactType.PLUGIN not in types
        assert ArtifactType.MEMORY not in types

    def test_detected_risk_ids(self, scanner: BiasDetectorScanner):
        risk_ids = scanner.detected_risk_ids
        assert "ETH-1" in risk_ids
        assert "ETH-2" in risk_ids
        assert "ETH-3" in risk_ids
        assert "ETH-4" in risk_ids
        assert len(risk_ids) == 4

    def test_is_available_always_true(self, scanner: BiasDetectorScanner):
        """Scanner is always available via regex-based detection."""
        assert scanner.is_available() is True


class TestNonInclusiveTerminology:
    """Test detection of non-inclusive terms (ETH-4)."""

    def test_blacklist_detected(self, scanner: BiasDetectorScanner):
        content = "Add this IP to the blacklist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-4" for f in findings)
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert "blocklist" in eth4[0].evidence.lower()

    def test_whitelist_detected(self, scanner: BiasDetectorScanner):
        content = "Only whitelist approved domains."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-4" for f in findings)
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert "allowlist" in eth4[0].evidence.lower()

    def test_master_slave_detected(self, scanner: BiasDetectorScanner):
        content = "Configure the master database and slave replicas."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) >= 2  # both master and slave detected

    def test_grandfathered_detected(self, scanner: BiasDetectorScanner):
        content = "Users with the old plan are grandfathered in."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-4" for f in findings)
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert "legacy" in eth4[0].evidence.lower() or "exempted" in eth4[0].evidence.lower()

    def test_sanity_check_detected(self, scanner: BiasDetectorScanner):
        content = "Run a sanity check before deploying."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "ETH-4" for f in findings)

    def test_confidence_is_090(self, scanner: BiasDetectorScanner):
        content = "Add to the blacklist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert eth4[0].confidence == 0.90

    def test_non_inclusive_term_severity(self, scanner: BiasDetectorScanner):
        content = "Update the whitelist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert eth4[0].severity_score == 5
        assert eth4[0].gate_action == GateAction.WARN

    def test_no_false_positive_on_clean_content(self, scanner: BiasDetectorScanner):
        content = "Add this to the blocklist. Use the allowlist for approved items."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) == 0


class TestGenderedLanguage:
    """Test detection of gendered language (ETH-1)."""

    def test_generic_he_pronoun(self, scanner: BiasDetectorScanner):
        content = "When the user asks a question, he should receive a helpful response."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_generic_his_pronoun(self, scanner: BiasDetectorScanner):
        content = "Each developer should commit his code before leaving."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_he_or_she_binary(self, scanner: BiasDetectorScanner):
        content = "The user can configure he or she preferences in settings."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_gendered_title_businessman(self, scanner: BiasDetectorScanner):
        content = "Act as a businessman reviewing the quarterly report."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert any("business professional" in f.evidence.lower() for f in eth1)

    def test_gendered_title_chairman(self, scanner: BiasDetectorScanner):
        content = "The chairman will review the proposal."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_gendered_title_fireman(self, scanner: BiasDetectorScanner):
        content = "Call the fireman for assistance."
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_gendered_title_policeman(self, scanner: BiasDetectorScanner):
        content = "Report the issue to the policeman."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_manpower_detected(self, scanner: BiasDetectorScanner):
        content = "We need more manpower to complete this project."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-1" for f in findings)

    def test_confidence_090_for_gendered_pronoun(self, scanner: BiasDetectorScanner):
        content = "When the user asks, he should get an answer."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert len(eth1) > 0
        assert eth1[0].confidence == 0.90

    def test_no_false_positive_gender_neutral(self, scanner: BiasDetectorScanner):
        content = "When the user asks a question, they should receive a helpful response."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth1 = [f for f in findings if f.id == "ETH-1"]
        assert len(eth1) == 0


class TestStereotypingDetection:
    """Test detection of stereotyping language (ETH-3)."""

    def test_nurturing_female_assistant(self, scanner: BiasDetectorScanner):
        content = "You are a nurturing female assistant who helps with caregiving."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "ETH-3" for f in findings)

    def test_aggressive_male_stereotype(self, scanner: BiasDetectorScanner):
        content = "Behave like an aggressive male negotiator."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-3" for f in findings)

    def test_group_generalization(self, scanner: BiasDetectorScanner):
        content = "All women are more emotional in their responses."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-3" for f in findings)

    def test_confidence_075(self, scanner: BiasDetectorScanner):
        content = "Act as a nurturing female assistant."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth3 = [f for f in findings if f.id == "ETH-3"]
        assert len(eth3) > 0
        assert eth3[0].confidence == 0.75

    def test_no_false_positive_neutral_persona(self, scanner: BiasDetectorScanner):
        content = "You are a helpful coding assistant focused on Python development."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        eth3 = [f for f in findings if f.id == "ETH-3"]
        assert len(eth3) == 0


class TestCulturalBias:
    """Test detection of cultural bias in examples (ETH-2)."""

    def test_only_western_names(self, scanner: BiasDetectorScanner):
        content = """Examples:
- User: "John" asks about weather
- User: "James" requests a report
- User: "Michael" needs help with code
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "ETH-2" for f in findings)

    def test_diverse_names_no_finding(self, scanner: BiasDetectorScanner):
        content = """Examples:
- User: "John" asks about weather
- User: "Priya" requests a report
- User: "Ahmed" needs help with code
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) == 0

    def test_cultural_bias_confidence_band(self, scanner: BiasDetectorScanner):
        content = """Examples:
- name: "John"
- name: "James"
- name: "Michael"
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) > 0
        assert 0.60 <= eth2[0].confidence <= 0.79

    def test_too_few_names_no_finding(self, scanner: BiasDetectorScanner):
        content = "User John asks a question."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) == 0

    def test_severity_for_cultural_bias(self, scanner: BiasDetectorScanner):
        content = """Examples:
- name: "John"
- name: "James"
- name: "Robert"
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) > 0
        assert eth2[0].severity_score == 7
        assert eth2[0].severity_label == SeverityLabel.HIGH


class TestNonApplicableArtifacts:
    """Test that non-applicable artifact types produce no findings."""

    def test_sop_artifact_no_findings(self, scanner: BiasDetectorScanner):
        content = "Add to the blacklist. The businessman should review."
        findings = scanner.scan(content, ArtifactType.SOP, "procedure.md")
        assert len(findings) == 0

    def test_mcp_artifact_no_findings(self, scanner: BiasDetectorScanner):
        content = "Configure master/slave replication in the whitelist."
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 0

    def test_hook_artifact_no_findings(self, scanner: BiasDetectorScanner):
        content = "The blacklist should be updated by the chairman."
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert len(findings) == 0

    def test_plugin_artifact_no_findings(self, scanner: BiasDetectorScanner):
        content = "The slave node is grandfathered in."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.py")
        assert len(findings) == 0

    def test_memory_artifact_no_findings(self, scanner: BiasDetectorScanner):
        content = "The whitelist contains the master key."
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.json")
        assert len(findings) == 0


class TestFindingMetadata:
    """Test that findings have correct metadata."""

    def test_finding_has_correct_scanner_module(self, scanner: BiasDetectorScanner):
        content = "Add to the blacklist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.BIAS_DETECTOR

    def test_finding_has_ethics_category(self, scanner: BiasDetectorScanner):
        content = "Update the whitelist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert finding.category == RiskCategory.ETHICS

    def test_finding_has_location(self, scanner: BiasDetectorScanner):
        content = "Line 1\nLine 2\nAdd to blacklist here."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0
        assert eth4[0].location.line == 3

    def test_finding_has_evidence(self, scanner: BiasDetectorScanner):
        content = "Use the whitelist to filter."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth4 = [f for f in findings if f.id == "ETH-4"]
        assert len(eth4) > 0
        assert len(eth4[0].evidence) > 0

    def test_finding_has_remediation(self, scanner: BiasDetectorScanner):
        content = "Check the blacklist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert len(finding.remediation) > 0

    def test_severity_score_within_bounds(self, scanner: BiasDetectorScanner):
        content = "The blacklist on the master node for the businessman."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 1 <= finding.severity_score <= 10

    def test_confidence_within_bounds(self, scanner: BiasDetectorScanner):
        content = "Whitelist the slave node."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0


class TestTransformersLazyLoading:
    """Test lazy loading of optional transformers dependency."""

    def test_transformers_check_returns_bool(self, scanner: BiasDetectorScanner):
        result = scanner._check_transformers_available()
        assert isinstance(result, bool)

    def test_transformers_check_caches_result(self, scanner: BiasDetectorScanner):
        # First call
        result1 = scanner._check_transformers_available()
        # Second call should use cached value
        result2 = scanner._check_transformers_available()
        assert result1 == result2
        assert scanner._transformers_available is not None

    def test_scanner_works_without_transformers(self, scanner: BiasDetectorScanner):
        """Core detection works regardless of transformers availability."""
        content = "Add to the blacklist."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) > 0


class TestCleanContent:
    """Test that clean content does not produce false positives."""

    def test_clean_prompt(self, scanner: BiasDetectorScanner):
        content = """You are a helpful coding assistant.
Help users write clean, maintainable Python code.
Follow PEP 8 style guidelines and use type hints.
Respond to all users in a professional manner."""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) == 0

    def test_clean_instruction_with_inclusive_terms(self, scanner: BiasDetectorScanner):
        content = """# Project Instructions
- Use the blocklist for denied IPs
- The allowlist controls approved domains
- Deploy to the primary database
- Use placeholder data in tests"""
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 0

    def test_clean_diverse_examples(self, scanner: BiasDetectorScanner):
        content = """Examples:
- User "Priya" asks about weather
- User "Carlos" requests a code review
- User "Yuki" needs help with documentation"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        eth2 = [f for f in findings if f.id == "ETH-2"]
        assert len(eth2) == 0


# ---- Semantic bias tests ----


class TestSemanticBiasAnalyzer:
    def test_not_available_without_deps(self):
        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        _ = analyzer.is_available  # Should not crash

    def test_find_biased_empty_when_unavailable(self):
        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        analyzer._available = False
        result = analyzer.find_biased_sentences(["All women are emotional"])
        assert result == []

    def test_find_biased_with_mock(self):
        from unittest.mock import MagicMock

        import numpy as np

        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._bias_embeddings = np.array([[1.0, 0.0]])
        mock_scorer.score_against_corpus.return_value = 0.75

        results = analyzer.find_biased_sentences(["Women are naturally more nurturing than men"])
        assert len(results) == 1
        assert results[0][0] == 0
        assert results[0][2] == 0.75

    def test_find_biased_skips_short(self):
        from unittest.mock import MagicMock

        import numpy as np

        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._bias_embeddings = np.array([[1.0]])
        mock_scorer.score_against_corpus.return_value = 0.90

        results = analyzer.find_biased_sentences(["short text"])
        assert results == []

    def test_find_biased_below_threshold(self):
        from unittest.mock import MagicMock

        import numpy as np

        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._bias_embeddings = np.array([[1.0]])
        mock_scorer.score_against_corpus.return_value = 0.30

        results = analyzer.find_biased_sentences(["The system processes data efficiently"])
        assert results == []

    def test_find_biased_handles_error(self):
        from unittest.mock import MagicMock

        import numpy as np

        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        analyzer._available = True
        mock_scorer = MagicMock()
        analyzer._scorer = mock_scorer
        analyzer._bias_embeddings = np.array([[1.0]])
        mock_scorer.score_against_corpus.side_effect = RuntimeError("boom")

        results = analyzer.find_biased_sentences(["A long enough sentence to be analysed here"])
        assert results == []

    def test_ensure_loaded_false_when_unavailable(self):
        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        analyzer._available = False
        assert analyzer._ensure_loaded() is False

    def test_ensure_loaded_true_when_already_loaded(self):
        from unittest.mock import MagicMock

        import numpy as np

        from ai_artifact_risk_validator.scanners.bias_detector import SemanticBiasAnalyzer

        analyzer = SemanticBiasAnalyzer()
        analyzer._available = True
        analyzer._scorer = MagicMock()
        analyzer._corpus_mgr = MagicMock()
        analyzer._bias_embeddings = np.array([[1.0]])
        assert analyzer._ensure_loaded() is True


class TestSemanticRefine:
    def test_refine_noop_when_unavailable(self, scanner: BiasDetectorScanner):
        scanner._semantic._available = False
        findings = scanner._detect_stereotyping(
            "a nurturing female assistant", ArtifactType.PROMPT, "p.md"
        )
        refined = scanner._semantic_refine("a nurturing female assistant", findings)
        # Should return findings unchanged
        assert refined == findings

    def test_scan_still_works_without_semantic(self, scanner: BiasDetectorScanner):
        content = "The blacklist should be updated by the chairman."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.md")
        assert len(findings) > 0
