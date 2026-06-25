"""Tests for the ComplianceAudit scanner."""

from __future__ import annotations

import pytest

from ai_artifact_risk_validator.models import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.compliance_audit import ComplianceAuditScanner


@pytest.fixture
def scanner() -> ComplianceAuditScanner:
    """Create a ComplianceAuditScanner instance."""
    return ComplianceAuditScanner()


class TestComplianceAuditScannerProperties:
    """Test scanner properties and metadata."""

    def test_name(self, scanner: ComplianceAuditScanner) -> None:
        assert scanner.name == ScannerModule.COMPLIANCE_AUDIT

    def test_applicable_artifact_types(self, scanner: ComplianceAuditScanner) -> None:
        expected = [
            ArtifactType.AGENT,
            ArtifactType.SOP,
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.PLUGIN,
            ArtifactType.MEMORY,
            ArtifactType.RAG,
        ]
        assert scanner.applicable_artifact_types == expected

    def test_not_applicable_types(self, scanner: ComplianceAuditScanner) -> None:
        """Types that should NOT be scanned by this scanner."""
        excluded = [
            ArtifactType.PROMPT,
            ArtifactType.SKILL,
            ArtifactType.HOOK,
            ArtifactType.INSTRUCTION,
            ArtifactType.EVAL_HARNESS,
            ArtifactType.ORCHESTRATION,
            ArtifactType.API_SCHEMA,
        ]
        for artifact_type in excluded:
            assert artifact_type not in scanner.applicable_artifact_types

    def test_detected_risk_ids(self, scanner: ComplianceAuditScanner) -> None:
        assert scanner.detected_risk_ids == ["REG-1", "REG-2", "REG-3", "REG-4", "REG-5", "RAG-S3"]

    def test_is_available(self, scanner: ComplianceAuditScanner) -> None:
        assert scanner.is_available() is True


class TestLicenseDetection:
    """Test license scanning (REG-2)."""

    def test_detects_gpl_license(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Knowledge Base Config
        source: external-docs
        license: GPL-3.0
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 1
        assert reg2_findings[0].confidence == 0.95
        assert "GPL" in reg2_findings[0].evidence

    def test_detects_agpl_license(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        This component uses a library licensed under AGPL-3.0.
        """
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.yaml")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 1
        assert "AGPL" in reg2_findings[0].evidence

    def test_detects_copyleft_keyword(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        Warning: this dataset is released under a copyleft license.
        """
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 1

    def test_detects_creative_commons_restrictive(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        Source material is licensed CC-BY-NC-SA.
        """
        findings = scanner.scan(content, ArtifactType.RAG, "source.md")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 1

    def test_no_finding_for_permissive_license(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        license: MIT License
        SPDX-License-Identifier: Apache-2.0
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 0

    def test_no_finding_for_clean_content(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Agent Config
        name: my-agent
        description: A simple helper agent
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 0


class TestDataResidencyDetection:
    """Test data residency flow mapping (REG-1)."""

    def test_detects_region_without_declaration(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        endpoint: https://api.example.com
        region: us-east-1
        storage: s3://my-bucket
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert len(reg1_findings) == 1
        assert "us-east-1" in reg1_findings[0].evidence

    def test_detects_cross_region_transfer(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        The data is replicated across regions for redundancy.
        cross-region replication enabled.
        """
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.yaml")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert len(reg1_findings) == 1
        assert reg1_findings[0].confidence == 0.80

    def test_detects_multi_region(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        deployment: multi-region
        failover: enabled
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert len(reg1_findings) == 1

    def test_no_finding_with_residency_declaration(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        region: eu-west-1
        data_residency: EU
        data residency declaration: All data stays in EU.
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert len(reg1_findings) == 0

    def test_no_finding_without_region_reference(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        name: simple-agent
        description: Does basic tasks
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert len(reg1_findings) == 0

    def test_confidence_band_for_residency(self, scanner: ComplianceAuditScanner) -> None:
        """Residency concern confidence should be 0.70-0.85."""
        content = """
        region: eu-west-1
        Data will be replicated to the backup region.
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert len(reg1_findings) == 1
        assert 0.70 <= reg1_findings[0].confidence <= 0.85


class TestRetentionPolicyDetection:
    """Test retention policy checking (REG-3)."""

    def test_detects_missing_retention_for_storage(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Memory Configuration
        store conversation history for context
        database: mongodb
        """
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        reg3_findings = [f for f in findings if f.id == "REG-3"]
        assert len(reg3_findings) == 1

    def test_detects_missing_retention_for_user_data(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # SOP: Customer Data Processing
        persist user data in the records table.
        """
        findings = scanner.scan(content, ArtifactType.SOP, "sop.md")
        reg3_findings = [f for f in findings if f.id == "REG-3"]
        assert len(reg3_findings) == 1

    def test_no_finding_with_ttl(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        store conversation history for context
        ttl: 30 days
        auto-delete after expiration
        """
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        reg3_findings = [f for f in findings if f.id == "REG-3"]
        assert len(reg3_findings) == 0

    def test_no_finding_with_retention_policy(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        database: postgres
        store user data in profiles table
        retention_policy: 90 days
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg3_findings = [f for f in findings if f.id == "REG-3"]
        assert len(reg3_findings) == 0

    def test_no_finding_without_data_storage(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Simple Agent
        respond to queries in real-time
        no persistent state required
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg3_findings = [f for f in findings if f.id == "REG-3"]
        assert len(reg3_findings) == 0


class TestPiiDetection:
    """Test PII handling detection (REG-4)."""

    def test_detects_pii_handling_without_consent(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Agent Config
        collects personal data from users
        processes user information for recommendations
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg4_findings = [f for f in findings if f.id == "REG-4"]
        assert len(reg4_findings) == 1

    def test_detects_email_pii(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # RAG Knowledge
        Contact: john.doe@example.com
        """
        findings = scanner.scan(content, ArtifactType.RAG, "contacts.md")
        reg4_findings = [f for f in findings if f.id == "REG-4"]
        assert len(reg4_findings) == 1

    def test_detects_pii_keyword(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        This agent handles PII and sensitive information.
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg4_findings = [f for f in findings if f.id == "REG-4"]
        assert len(reg4_findings) == 1

    def test_no_finding_with_consent_framework(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        collects personal data from users
        consent_framework: GDPR consent management
        privacy_policy: https://example.com/privacy
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg4_findings = [f for f in findings if f.id == "REG-4"]
        assert len(reg4_findings) == 0

    def test_no_finding_without_pii(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # MCP Config
        tools:
          - name: weather
            description: Get current weather
        """
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.yaml")
        reg4_findings = [f for f in findings if f.id == "REG-4"]
        assert len(reg4_findings) == 0


class TestRegulatoryMarkerDetection:
    """Test regulatory compliance marker detection (REG-5)."""

    def test_detects_healthcare_without_hipaa(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Healthcare Agent
        This agent processes patient data and medical records.
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "health-agent.yaml")
        reg5_findings = [f for f in findings if f.id == "REG-5"]
        assert len(reg5_findings) == 1
        assert "patient data" in reg5_findings[0].evidence

    def test_detects_financial_without_compliance(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Lending Agent
        Makes financial decisions about loan applications.
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "lending-agent.yaml")
        reg5_findings = [f for f in findings if f.id == "REG-5"]
        assert len(reg5_findings) == 1

    def test_detects_hiring_without_compliance(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # HR Screening Agent
        Assists with hiring decisions and recruitment screening.
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "hr-agent.yaml")
        reg5_findings = [f for f in findings if f.id == "REG-5"]
        assert len(reg5_findings) == 1

    def test_no_finding_with_regulatory_reference(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        processes patient data and medical records
        HIPAA compliant implementation
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "health-agent.yaml")
        reg5_findings = [f for f in findings if f.id == "REG-5"]
        assert len(reg5_findings) == 0

    def test_no_finding_with_risk_classification(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        processes patient data
        ai_classification: high-risk
        human_oversight: required
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "health-agent.yaml")
        reg5_findings = [f for f in findings if f.id == "REG-5"]
        assert len(reg5_findings) == 0

    def test_no_finding_without_high_risk_domain(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Weather Agent
        Provides weather forecasts
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "weather-agent.yaml")
        reg5_findings = [f for f in findings if f.id == "REG-5"]
        assert len(reg5_findings) == 0


class TestRagComplianceSensitiveData:
    """Test RAG-S3 detection."""

    def test_detects_phi_in_rag(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Knowledge Base Entry
        Contains patient medical records from 2023.
        protected health information included for training.
        """
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        rag_findings = [f for f in findings if f.id == "RAG-S3"]
        assert len(rag_findings) == 1
        assert rag_findings[0].confidence == 0.80

    def test_detects_pii_in_rag(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Customer Data
        This RAG source contains personally identifiable information.
        """
        findings = scanner.scan(content, ArtifactType.RAG, "customers.md")
        rag_findings = [f for f in findings if f.id == "RAG-S3"]
        assert len(rag_findings) == 1

    def test_detects_financial_data_in_rag(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        # Financial Records
        Contains credit record and banking data for all customers.
        """
        findings = scanner.scan(content, ArtifactType.RAG, "finance.md")
        rag_findings = [f for f in findings if f.id == "RAG-S3"]
        assert len(rag_findings) == 1

    def test_no_finding_with_compliance_controls(self, scanner: ComplianceAuditScanner) -> None:
        content = """
        Contains patient medical records.
        HIPAA compliance controls in place.
        """
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        rag_findings = [f for f in findings if f.id == "RAG-S3"]
        assert len(rag_findings) == 0

    def test_not_triggered_for_non_rag(self, scanner: ComplianceAuditScanner) -> None:
        """RAG-S3 should only fire for RAG artifact types."""
        content = """
        Contains patient medical records.
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        rag_findings = [f for f in findings if f.id == "RAG-S3"]
        assert len(rag_findings) == 0


class TestNonApplicableTypes:
    """Test that scanner returns empty for non-applicable artifact types."""

    def test_prompt_returns_empty(self, scanner: ComplianceAuditScanner) -> None:
        content = "GPL-3.0 licensed content with patient data"
        findings = scanner.scan(content, ArtifactType.PROMPT, "prompt.md")
        assert findings == []

    def test_skill_returns_empty(self, scanner: ComplianceAuditScanner) -> None:
        content = "GPL-3.0 licensed content with patient data"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.py")
        assert findings == []

    def test_hook_returns_empty(self, scanner: ComplianceAuditScanner) -> None:
        content = "GPL-3.0 licensed content with patient data"
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert findings == []

    def test_instruction_returns_empty(self, scanner: ComplianceAuditScanner) -> None:
        content = "GPL-3.0 licensed content with patient data"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert findings == []

    def test_eval_harness_returns_empty(self, scanner: ComplianceAuditScanner) -> None:
        content = "GPL-3.0 licensed content with patient data"
        findings = scanner.scan(content, ArtifactType.EVAL_HARNESS, "eval.yaml")
        assert findings == []

    def test_orchestration_returns_empty(self, scanner: ComplianceAuditScanner) -> None:
        content = "GPL-3.0 licensed content with patient data"
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "orch.yaml")
        assert findings == []

    def test_api_schema_returns_empty(self, scanner: ComplianceAuditScanner) -> None:
        content = "GPL-3.0 licensed content with patient data"
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.yaml")
        assert findings == []


class TestPresidioLazyLoading:
    """Test lazy loading of presidio-analyzer."""

    def test_presidio_check_returns_bool(self, scanner: ComplianceAuditScanner) -> None:
        """presidio check should return a boolean (likely False in test env)."""
        result = scanner._check_presidio_available()
        assert isinstance(result, bool)

    def test_presidio_check_caches_result(self, scanner: ComplianceAuditScanner) -> None:
        """Subsequent calls should use cached result."""
        result1 = scanner._check_presidio_available()
        result2 = scanner._check_presidio_available()
        assert result1 == result2
        assert scanner._presidio_available is not None


class TestFindingMetadata:
    """Test that findings have correct metadata structure."""

    def test_finding_has_correct_scanner_module(self, scanner: ComplianceAuditScanner) -> None:
        content = "This uses a GPL-3.0 licensed library."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        for finding in findings:
            assert finding.scanner_module == ScannerModule.COMPLIANCE_AUDIT

    def test_license_finding_confidence(self, scanner: ComplianceAuditScanner) -> None:
        """License violation confidence should be 0.95."""
        content = "Licensed under AGPL-3.0."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.yaml")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 1
        assert reg2_findings[0].confidence == 0.95

    def test_finding_has_line_number(self, scanner: ComplianceAuditScanner) -> None:
        content = "line1\nline2\nGPL-3.0 here\nline4"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 1
        assert reg2_findings[0].location.line == 3

    def test_finding_evidence_truncated(self, scanner: ComplianceAuditScanner) -> None:
        """Evidence should be truncated to 200 chars."""
        content = "Licensed under " + "GPL-3.0 " * 100
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        reg2_findings = [f for f in findings if f.id == "REG-2"]
        assert len(reg2_findings) == 1
        assert len(reg2_findings[0].evidence) <= 200
