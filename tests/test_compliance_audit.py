"""Unit tests for the ComplianceAudit scanner."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.compliance_audit import ComplianceAuditScanner


@pytest.fixture
def scanner() -> ComplianceAuditScanner:
    """Create a ComplianceAuditScanner instance for testing."""
    return ComplianceAuditScanner()


class TestScannerProperties:
    """Test scanner metadata and properties."""

    def test_name(self, scanner: ComplianceAuditScanner):
        assert scanner.name == ScannerModule.COMPLIANCE_AUDIT

    def test_applicable_artifact_types(self, scanner: ComplianceAuditScanner):
        types = scanner.applicable_artifact_types
        assert ArtifactType.AGENT in types
        assert ArtifactType.SOP in types
        assert ArtifactType.STEERING in types
        assert ArtifactType.MCP in types
        assert ArtifactType.PLUGIN in types
        assert ArtifactType.MEMORY in types
        assert ArtifactType.RAG in types
        # Should not include types outside the compliance matrix
        assert ArtifactType.PROMPT not in types
        assert ArtifactType.SKILL not in types
        assert ArtifactType.HOOK not in types
        assert ArtifactType.INSTRUCTION not in types
        assert ArtifactType.EVAL_HARNESS not in types

    def test_detected_risk_ids(self, scanner: ComplianceAuditScanner):
        risk_ids = scanner.detected_risk_ids
        assert "REG-1" in risk_ids
        assert "REG-2" in risk_ids
        assert "REG-3" in risk_ids
        assert "REG-4" in risk_ids
        assert "REG-5" in risk_ids
        assert "RAG-S3" in risk_ids

    def test_is_available_always_true(self, scanner: ComplianceAuditScanner):
        """Scanner is always available due to regex fallback."""
        assert scanner.is_available() is True


class TestMissingDataResidency:
    """Test detection of missing data residency declarations (REG-1)."""

    def test_external_api_without_residency(self, scanner: ComplianceAuditScanner):
        content = """Agent configuration:
  endpoint: https://api.openai.com/v1/chat
  model: gpt-4
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1 = [f for f in findings if f.id == "REG-1"]
        assert len(reg1) > 0
        assert reg1[0].confidence >= 0.70

    def test_cross_region_reference_without_residency(self, scanner: ComplianceAuditScanner):
        content = """Data is transferred cross-border to international servers."""
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        reg1 = [f for f in findings if f.id == "REG-1"]
        assert len(reg1) > 0

    def test_cloud_region_without_residency(self, scanner: ComplianceAuditScanner):
        content = """deployment:
  region: us-east-1
  storage: s3-bucket
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1 = [f for f in findings if f.id == "REG-1"]
        assert len(reg1) > 0

    def test_external_api_with_residency_declaration(self, scanner: ComplianceAuditScanner):
        content = """Agent configuration:
  endpoint: https://api.openai.com/v1/chat
  model: gpt-4
  data_residency: EU
  processing_location: eu-west-1
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1 = [f for f in findings if f.id == "REG-1"]
        assert len(reg1) == 0

    def test_no_data_flow_no_finding(self, scanner: ComplianceAuditScanner):
        content = """Agent configuration:
  name: local-agent
  description: Processes data locally
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1 = [f for f in findings if f.id == "REG-1"]
        assert len(reg1) == 0


class TestLicenseComplianceViolation:
    """Test detection of license compliance issues (REG-2)."""

    def test_gpl_license_detected(self, scanner: ComplianceAuditScanner):
        content = """This module uses code licensed under GPL v3."""
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0
        assert reg2[0].confidence == 0.95

    def test_agpl_license_detected(self, scanner: ComplianceAuditScanner):
        content = """Licensed under the GNU Affero General Public License."""
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0

    def test_creative_commons_restrictive(self, scanner: ComplianceAuditScanner):
        content = """Source material licensed under CC-BY-NC-SA."""
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0
        assert reg2[0].confidence == 0.85

    def test_sspl_license_detected(self, scanner: ComplianceAuditScanner):
        content = """Database licensed under SSPL."""
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0
        assert reg2[0].confidence == 0.95

    def test_proprietary_license_reference(self, scanner: ComplianceAuditScanner):
        content = """All rights reserved. No redistribution allowed."""
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0

    def test_mit_license_no_finding(self, scanner: ComplianceAuditScanner):
        content = """This tool is available under the MIT License."""
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) == 0

    def test_no_license_reference_no_finding(self, scanner: ComplianceAuditScanner):
        content = """A simple agent that processes data."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) == 0


class TestMissingRetentionPolicy:
    """Test detection of missing data retention policy (REG-3)."""

    def test_data_storage_without_retention(self, scanner: ComplianceAuditScanner):
        content = """Memory configuration:
  store user data in local database
  persist conversation history
"""
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        reg3 = [f for f in findings if f.id == "REG-3"]
        assert len(reg3) > 0
        assert reg3[0].confidence == 0.75

    def test_caching_without_retention(self, scanner: ComplianceAuditScanner):
        content = """Cache responses for faster retrieval. Save session state."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg3 = [f for f in findings if f.id == "REG-3"]
        assert len(reg3) > 0

    def test_data_handling_with_retention_policy(self, scanner: ComplianceAuditScanner):
        content = """Memory configuration:
  store user data in local database
  retention_policy: 30 days
  auto_delete: true
"""
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        reg3 = [f for f in findings if f.id == "REG-3"]
        assert len(reg3) == 0

    def test_data_handling_with_ttl(self, scanner: ComplianceAuditScanner):
        content = """Cache configuration:
  cache responses locally
  ttl: 3600
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg3 = [f for f in findings if f.id == "REG-3"]
        assert len(reg3) == 0

    def test_no_data_handling_no_finding(self, scanner: ComplianceAuditScanner):
        content = """A simple configuration for routing requests."""
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        reg3 = [f for f in findings if f.id == "REG-3"]
        assert len(reg3) == 0


class TestPIIWithoutConsent:
    """Test detection of PII processing without consent (REG-4)."""

    def test_email_without_consent(self, scanner: ComplianceAuditScanner):
        content = """User profile:
  email: user@example.com
  name: John Doe
"""
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        reg4 = [f for f in findings if f.id == "REG-4"]
        assert len(reg4) > 0

    def test_ssn_reference_without_consent(self, scanner: ComplianceAuditScanner):
        content = """Collect social_security number for identity verification."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg4 = [f for f in findings if f.id == "REG-4"]
        assert len(reg4) > 0

    def test_personal_data_processing(self, scanner: ComplianceAuditScanner):
        content = """The system collects personal data from users."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg4 = [f for f in findings if f.id == "REG-4"]
        assert len(reg4) > 0

    def test_pii_with_consent_framework(self, scanner: ComplianceAuditScanner):
        content = """User profile:
  email: user@example.com
  consent_framework: explicit opt-in
  privacy_policy: https://example.com/privacy
"""
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        reg4 = [f for f in findings if f.id == "REG-4"]
        assert len(reg4) == 0

    def test_pii_with_gdpr_reference(self, scanner: ComplianceAuditScanner):
        content = """User profile:
  email: user@example.com
  compliance: GDPR compliant
"""
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        reg4 = [f for f in findings if f.id == "REG-4"]
        assert len(reg4) == 0

    def test_no_pii_no_finding(self, scanner: ComplianceAuditScanner):
        content = """A simple agent for code review tasks."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg4 = [f for f in findings if f.id == "REG-4"]
        assert len(reg4) == 0


class TestMissingRegulationAlignment:
    """Test detection of missing AI regulation alignment (REG-5)."""

    def test_healthcare_domain_without_alignment(self, scanner: ComplianceAuditScanner):
        content = """Agent for patient diagnosis assistance.
Processes medical records and provides treatment suggestions."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg5 = [f for f in findings if f.id == "REG-5"]
        assert len(reg5) > 0
        assert reg5[0].confidence >= 0.70

    def test_financial_domain_without_alignment(self, scanner: ComplianceAuditScanner):
        content = """Credit scoring agent.
Makes loan approval decisions based on financial data."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg5 = [f for f in findings if f.id == "REG-5"]
        assert len(reg5) > 0

    def test_hr_domain_without_alignment(self, scanner: ComplianceAuditScanner):
        content = """Automated hiring agent.
Performs candidate screening and resume evaluation."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg5 = [f for f in findings if f.id == "REG-5"]
        assert len(reg5) > 0

    def test_high_risk_with_regulation_alignment(self, scanner: ComplianceAuditScanner):
        content = """Agent for patient diagnosis assistance.
ai_risk_classification: high-risk
human_oversight: required
eu_ai_act: compliant
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg5 = [f for f in findings if f.id == "REG-5"]
        # Should not flag since regulation alignment is declared
        assert len(reg5) == 0

    def test_non_high_risk_domain_no_finding(self, scanner: ComplianceAuditScanner):
        content = """Agent for code formatting and linting."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg5 = [f for f in findings if f.id == "REG-5"]
        assert len(reg5) == 0


class TestRAGComplianceSensitiveData:
    """Test detection of compliance-sensitive data in RAG (RAG-S3)."""

    def test_gdpr_data_in_rag(self, scanner: ComplianceAuditScanner):
        content = """Knowledge base entry:
Contains personal data subject to GDPR regulations.
User has right to be forgotten."""
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        rags3 = [f for f in findings if f.id == "RAG-S3"]
        assert len(rags3) > 0
        assert rags3[0].confidence >= 0.80

    def test_hipaa_data_in_rag(self, scanner: ComplianceAuditScanner):
        content = """Patient records knowledge base.
Contains protected health information (PHI) covered by HIPAA."""
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        rags3 = [f for f in findings if f.id == "RAG-S3"]
        assert len(rags3) > 0

    def test_pci_dss_data_in_rag(self, scanner: ComplianceAuditScanner):
        content = """Payment processing documentation.
Includes cardholder data covered by PCI-DSS."""
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        rags3 = [f for f in findings if f.id == "RAG-S3"]
        assert len(rags3) > 0

    def test_non_rag_artifact_no_rag_s3(self, scanner: ComplianceAuditScanner):
        """RAG-S3 only applies to RAG artifacts."""
        content = """Contains protected health information covered by HIPAA."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        rags3 = [f for f in findings if f.id == "RAG-S3"]
        assert len(rags3) == 0

    def test_clean_rag_no_finding(self, scanner: ComplianceAuditScanner):
        content = """Technical documentation about API endpoints.
Standard REST patterns and usage examples."""
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        rags3 = [f for f in findings if f.id == "RAG-S3"]
        assert len(rags3) == 0


class TestNonApplicableArtifactTypes:
    """Test that non-applicable artifact types return no findings."""

    def test_prompt_returns_empty(self, scanner: ComplianceAuditScanner):
        content = "This contains GPL code and stores user data."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) == 0

    def test_skill_returns_empty(self, scanner: ComplianceAuditScanner):
        content = "Licensed under AGPL. Processes personal data."
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert len(findings) == 0

    def test_hook_returns_empty(self, scanner: ComplianceAuditScanner):
        content = "Collects social_security and stores it."
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert len(findings) == 0


class TestFindingMetadata:
    """Test that findings have correct metadata."""

    def test_finding_has_correct_scanner_module(self, scanner: ComplianceAuditScanner):
        content = "Licensed under GPL v3. Store user data."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.COMPLIANCE_AUDIT

    def test_finding_has_location(self, scanner: ComplianceAuditScanner):
        content = "Line 1\nLine 2\nLicensed under AGPL.\nLine 4"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0
        assert reg2[0].location.line == 3

    def test_finding_has_evidence(self, scanner: ComplianceAuditScanner):
        content = "Code is SSPL licensed."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0
        assert "SSPL" in reg2[0].evidence

    def test_finding_has_remediation(self, scanner: ComplianceAuditScanner):
        content = "Licensed under GPL. Store personal data."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        for finding in findings:
            assert len(finding.remediation) > 0

    def test_severity_score_within_bounds(self, scanner: ComplianceAuditScanner):
        content = "GPL license. Store user data. Collect social_security."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        for finding in findings:
            assert 1 <= finding.severity_score <= 10

    def test_confidence_within_bounds(self, scanner: ComplianceAuditScanner):
        content = "Licensed under AGPL. endpoint: https://api.example.com"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0


class TestCleanContent:
    """Test that clean content does not produce false positives."""

    def test_clean_agent_no_findings(self, scanner: ComplianceAuditScanner):
        content = """Agent for code review:
  Analyzes pull requests for quality issues.
  Returns structured feedback."""
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert len(findings) == 0

    def test_clean_steering_no_findings(self, scanner: ComplianceAuditScanner):
        content = """Steering configuration:
  priority: high
  scope: "**/*.py"
  instruction: Follow PEP 8 conventions."""
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        assert len(findings) == 0

    def test_clean_mcp_no_findings(self, scanner: ComplianceAuditScanner):
        content = """{
  "name": "code-formatter",
  "tools": ["format", "lint"],
  "transport": "stdio"
}"""
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 0


class TestPresidioLazyLoading:
    """Test that the scanner works with lazy-loaded presidio."""

    def test_presidio_lazy_load(self, scanner: ComplianceAuditScanner):
        """Presidio loading should not crash even if not installed."""
        result = scanner._load_presidio()
        # Either the AnalyzerEngine class or None - both are valid
        assert result is None or callable(result)

    def test_scanner_works_without_presidio(self, scanner: ComplianceAuditScanner):
        """Core detection should work regardless of presidio availability."""
        content = "Collect social_security numbers and store user data."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert len(findings) > 0


class TestConfidenceBands:
    """Test confidence scoring aligns with design specification."""

    def test_license_violation_high_confidence(self, scanner: ComplianceAuditScanner):
        """License violations should have confidence of 0.95."""
        content = "Licensed under GPL v3."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        reg2 = [f for f in findings if f.id == "REG-2"]
        assert len(reg2) > 0
        assert reg2[0].confidence == 0.95

    def test_residency_concern_moderate_confidence(self, scanner: ComplianceAuditScanner):
        """Residency concerns should have confidence 0.70-0.85."""
        content = "endpoint: https://api.service.com/data"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1 = [f for f in findings if f.id == "REG-1"]
        assert len(reg1) > 0
        assert 0.70 <= reg1[0].confidence <= 0.85
