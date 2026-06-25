"""Example-based unit tests for Scanner False Positive Reduction — Phase 2.

Regression tests using specific examples from the false positive report. Each test
embeds a real-world example in realistic artifact content and verifies that the
appropriate scanner produces zero false positive findings.

Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5
"""

from __future__ import annotations

import pytest

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner
from ai_artifact_risk_validator.scanners.compliance_audit import ComplianceAuditScanner
from ai_artifact_risk_validator.scanners.provenance_chk import ProvenanceChkScanner
from ai_artifact_risk_validator.scanners.secret_scan import SecretScanScanner

# Risk IDs that should NOT fire for inline code spans
_BACKTICK_RISK_IDS: set[str] = {"SK-S2", "MCP-S1", "A-S3"}

# Risk IDs for provenance findings (High+ severity)
_PROVENANCE_RISK_IDS: set[str] = {"SK-S7", "SK-S8", "A-S8", "A-S9"}

# Secret/PII risk IDs
_SECRET_RISK_IDS: set[str] = {"SK-S5", "SOP-S1", "P-S3", "P-S4", "P-S8"}


class TestReportExamplesInlineCode:
    """Test that inline code spans from the report produce zero backtick execution findings.

    These are exact examples from report.json where single-backtick identifiers
    in Markdown were incorrectly flagged as Ruby backtick execution.

    Validates: Requirement 7.1
    """

    @pytest.mark.parametrize(
        "identifier",
        [
            "fileMatch",
            "spec_dir",
            "readFile",
            "npm install",
            "specId",
            "workflowType",
            "specType",
            ".config.kiro",
            "listDirectory",
            "requirements.md",
            "design.md",
            "pipeline-enforcement.md",
            "TestTCALoader",
            "test_render_mermaid_placeholder",
        ],
    )
    def test_inline_code_span_zero_backtick_findings_skill(self, identifier: str) -> None:
        """Inline code identifiers in Markdown (SKILL) produce zero backtick findings."""
        content = (
            "# API Documentation\n"
            "\n"
            "This module provides utilities for processing artifacts.\n"
            "\n"
            f"The `{identifier}` function handles the core logic.\n"
            "\n"
            "See the configuration section for more details.\n"
        )
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/api_docs.md")
        backtick_findings = [f for f in findings if f.id in _BACKTICK_RISK_IDS]
        assert backtick_findings == [], (
            f"Expected zero backtick findings for `{identifier}`, "
            f"got {len(backtick_findings)}: {[f.evidence for f in backtick_findings]}"
        )

    @pytest.mark.parametrize(
        "identifier",
        [
            "fileMatch",
            "spec_dir",
            "readFile",
            "specId",
            "workflowType",
            "specType",
            "TestTCALoader",
        ],
    )
    def test_inline_code_span_zero_backtick_findings_agent(self, identifier: str) -> None:
        """Inline code identifiers in Markdown (AGENT) produce zero A-S3 findings."""
        content = (
            "# Agent Configuration\n"
            "\n"
            "The agent uses several internal identifiers.\n"
            "\n"
            f"Use the `{identifier}` parameter to configure behavior.\n"
            "\n"
            "Refer to the setup guide for configuration options.\n"
        )
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, ArtifactType.AGENT, "agents/config_agent.md")
        backtick_findings = [f for f in findings if f.id in _BACKTICK_RISK_IDS]
        assert backtick_findings == [], (
            f"Expected zero backtick findings for `{identifier}` (AGENT), "
            f"got {len(backtick_findings)}: {[f.evidence for f in backtick_findings]}"
        )


class TestReportExamplesProvenance:
    """Test that provenance checks on test files and spec JSONs produce zero High+ findings.

    Validates: Requirement 7.2
    """

    @pytest.mark.parametrize(
        "test_path",
        [
            "tests/development/unit/test_validator.py",
            "tests/development/unit/test_scanner.py",
            "tests/development/unit/test_classifier.py",
            "tests/unit/test_config.py",
            "tests/test_provenance.py",
        ],
    )
    def test_provenance_test_files_zero_high_findings(self, test_path: str) -> None:
        """ProvenanceChk on test files produces zero High+ findings."""
        content = (
            "name: test-skill\n"
            "description: A simple skill for testing\n"
            "steps:\n"
            "  - action: run\n"
            "    command: echo hello\n"
        )
        scanner = ProvenanceChkScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, test_path)
        high_findings = [f for f in findings if f.severity_score >= 7]
        assert high_findings == [], (
            f"Expected zero High+ findings for test path '{test_path}', "
            f"got {len(high_findings)}: {[(f.id, f.severity_score) for f in high_findings]}"
        )

    @pytest.mark.parametrize(
        "spec_path",
        [
            "project/.kiro/specs/scanner-fp-reduction/design.approved.json",
            "project/.kiro/specs/auth-feature/design.approved.json",
            "workspace/.kiro/specs/data-pipeline/tasks.md",
            "repo/.kiro/specs/user-login/requirements.md",
        ],
    )
    def test_provenance_spec_jsons_zero_high_findings(self, spec_path: str) -> None:
        """ProvenanceChk on .kiro/specs/* files produces zero High+ findings."""
        content = '{"name": "scanner-fp-reduction", "version": "1.0", "status": "approved"}\n'
        scanner = ProvenanceChkScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, spec_path)
        high_findings = [f for f in findings if f.severity_score >= 7]
        assert high_findings == [], (
            f"Expected zero High+ findings for spec path '{spec_path}', "
            f"got {len(high_findings)}: {[(f.id, f.severity_score) for f in high_findings]}"
        )


class TestReportExamplesCompliance:
    """Test that geographic keywords without transfer context produce zero REG-1 findings.

    Validates: Requirement 7.3
    """

    def test_eu_in_prose_without_transfer_context_zero_reg1(self) -> None:
        """'EU' in general prose without transfer keywords produces zero REG-1."""
        content = (
            "# Architecture Overview\n"
            "\n"
            "The system is designed to serve customers globally.\n"
            "Our EU team has been working on compliance requirements.\n"
            "The API follows RESTful conventions throughout.\n"
            "Performance metrics are collected every minute.\n"
            "Authentication uses OAuth 2.0 tokens.\n"
            "The cache layer improves response times.\n"
            "Logging is handled by the observability stack.\n"
            "Unit tests cover 90 percent of the codebase.\n"
            "Documentation is generated from source comments.\n"
            "Feature flags control gradual rollout.\n"
            "CI pipeline runs on every pull request.\n"
        )
        scanner = ComplianceAuditScanner()
        findings = scanner.scan(content, ArtifactType.STEERING, "steering/architecture.md")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert reg1_findings == [], (
            f"Expected zero REG-1 findings for 'EU' in prose without transfer context, "
            f"got {len(reg1_findings)}: {[f.evidence for f in reg1_findings]}"
        )

    def test_data_migration_heading_zero_reg1(self) -> None:
        """'Data Migration' as a section heading without transfer context → zero REG-1."""
        content = (
            "# Project Requirements\n"
            "\n"
            "## Data Migration\n"
            "\n"
            "The system handles data through a pipeline.\n"
            "Input validation ensures data quality.\n"
            "Logging captures all processing events.\n"
            "Error handling provides clear messages.\n"
            "Monitoring alerts are configured for failures.\n"
            "The API supports pagination for large results.\n"
            "Rate limiting protects the system from abuse.\n"
            "Authentication tokens expire after one hour.\n"
            "Cache invalidation uses event-based approach.\n"
            "Feature flags control gradual rollout.\n"
            "CI pipeline runs on every pull request.\n"
        )
        scanner = ComplianceAuditScanner()
        findings = scanner.scan(content, ArtifactType.STEERING, "steering/requirements.md")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert reg1_findings == [], (
            f"Expected zero REG-1 findings for 'Data Migration' heading, "
            f"got {len(reg1_findings)}: {[f.evidence for f in reg1_findings]}"
        )

    def test_lowercase_us_english_prose_zero_reg1(self) -> None:
        """Lowercase 'us' in English prose (pronoun) produces zero REG-1."""
        content = (
            "# Team Guidelines\n"
            "\n"
            "Let us discuss the architecture decisions.\n"
            "This approach allows us to iterate quickly.\n"
            "The framework gives us flexibility in design.\n"
            "Testing helps us catch bugs early.\n"
            "Code review is important for all of us.\n"
            "The documentation guides us through setup.\n"
            "Performance monitoring tells us about issues.\n"
            "Logging is handled by the observability stack.\n"
            "Unit tests cover 90 percent of the codebase.\n"
            "Feature flags control gradual rollout.\n"
            "CI pipeline runs on every pull request.\n"
        )
        scanner = ComplianceAuditScanner()
        findings = scanner.scan(content, ArtifactType.STEERING, "steering/guidelines.md")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert reg1_findings == [], (
            f"Expected zero REG-1 findings for lowercase 'us' pronoun, "
            f"got {len(reg1_findings)}: {[f.evidence for f in reg1_findings]}"
        )


class TestReportExamplesSecrets:
    """Test that placeholder/example data produces zero secret findings.

    Validates: Requirement 7.4
    """

    def test_example_com_email_zero_secret_findings(self) -> None:
        """`user@example.com` produces zero SK-S5/SOP-S1 findings."""
        content = (
            "# Configuration Example\n"
            "\n"
            "Set the notification email to user@example.com for testing.\n"
            "The admin contact is admin@example.org in development.\n"
            "\n"
            "## Setup Instructions\n"
            "\n"
            "Configure the SMTP settings as shown above.\n"
        )
        scanner = SecretScanScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/config_example.md")
        secret_findings = [f for f in findings if f.id in {"SK-S5", "SOP-S1"}]
        assert secret_findings == [], (
            f"Expected zero SK-S5/SOP-S1 findings for user@example.com, "
            f"got {len(secret_findings)}: {[f.evidence for f in secret_findings]}"
        )

    def test_placeholder_ip_zero_secret_findings(self) -> None:
        """`1.2.3.4` produces zero secret findings."""
        content = (
            "# Network Configuration\n"
            "\n"
            "The server address is 1.2.3.4 in the test environment.\n"
            "Connect to the host at port 8080.\n"
            "\n"
            "## Troubleshooting\n"
            "\n"
            "If connection fails, check the firewall rules.\n"
        )
        scanner = SecretScanScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/network_docs.md")
        secret_findings = [f for f in findings if f.id in {"SK-S5", "SOP-S1"}]
        assert secret_findings == [], (
            f"Expected zero SK-S5/SOP-S1 findings for IP 1.2.3.4, "
            f"got {len(secret_findings)}: {[f.evidence for f in secret_findings]}"
        )

    def test_sequential_digits_zero_secret_findings(self) -> None:
        """`0123456789` produces zero secret findings."""
        content = (
            "# Test Data\n"
            "\n"
            "Use the placeholder account number 0123456789 for testing.\n"
            "This value is used in automated test fixtures.\n"
            "\n"
            "## Notes\n"
            "\n"
            "Replace with real values in production.\n"
        )
        scanner = SecretScanScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/test_data.md")
        secret_findings = [f for f in findings if f.id in {"SK-S5", "SOP-S1"}]
        assert secret_findings == [], (
            f"Expected zero SK-S5/SOP-S1 findings for sequential digits 0123456789, "
            f"got {len(secret_findings)}: {[f.evidence for f in secret_findings]}"
        )

    def test_sharepoint_url_without_credentials_zero_secret_findings(self) -> None:
        """SharePoint URL without credentials produces zero secret findings."""
        content = (
            "# Document Repository\n"
            "\n"
            "Team documents are stored at:\n"
            "https://company.sharepoint.com/sites/Engineering/Shared%20Documents/\n"
            "\n"
            "Access requires corporate SSO authentication.\n"
            "\n"
            "## Folder Structure\n"
            "\n"
            "- Architecture decisions in /Architecture/\n"
            "- Meeting notes in /Meetings/\n"
        )
        scanner = SecretScanScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/team_docs.md")
        secret_findings = [f for f in findings if f.id in {"SK-S5", "SOP-S1"}]
        assert secret_findings == [], (
            f"Expected zero SK-S5/SOP-S1 findings for SharePoint URL without credentials, "
            f"got {len(secret_findings)}: {[f.evidence for f in secret_findings]}"
        )


class TestReportExamplesFalsePositiveSummary:
    """Combined regression test validating the overall false positive reduction.

    Validates: Requirement 7.5
    """

    def test_combined_false_positive_examples_in_single_document(self) -> None:
        """A document with multiple FP examples from the report produces zero FP findings."""
        content = (
            "# Skill Documentation\n"
            "\n"
            "## Overview\n"
            "\n"
            "The `fileMatch` utility finds files matching a pattern.\n"
            "Configuration is read from the `spec_dir` variable.\n"
            "Use `readFile` to load artifact content.\n"
            "Run `npm install` to set up dependencies.\n"
            "\n"
            "## Parameters\n"
            "\n"
            "- `specId`: The unique identifier for a spec\n"
            "- `workflowType`: Either 'sequential' or 'parallel'\n"
            "- `specType`: One of 'feature', 'bugfix', 'fast-task'\n"
            "- `.config.kiro`: The configuration filename\n"
            "\n"
            "## API Reference\n"
            "\n"
            "The `listDirectory` function returns directory contents.\n"
            "Output is written to `requirements.md` or `design.md`.\n"
            "See `pipeline-enforcement.md` for enforcement rules.\n"
            "The `TestTCALoader` class handles test configuration.\n"
            "The `test_render_mermaid_placeholder` verifies rendering.\n"
        )
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/documentation.md")
        backtick_findings = [f for f in findings if f.id in _BACKTICK_RISK_IDS]
        assert backtick_findings == [], (
            f"Expected zero backtick findings for combined FP document, "
            f"got {len(backtick_findings)}: {[f.evidence for f in backtick_findings]}"
        )
