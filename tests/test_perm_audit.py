"""Unit tests for PermAuditScanner.

Tests permission auditing functionality including wildcard permission detection,
dangerous file path analysis, unrestricted network access, destructive action
patterns, privilege escalation indicators, and shell execution detection.
"""

import pytest

from ai_artifact_risk_validator.models import ArtifactType, GateAction, ScannerModule, SeverityLabel
from ai_artifact_risk_validator.scanners.perm_audit import PermAuditScanner


@pytest.fixture
def scanner() -> PermAuditScanner:
    """Create a PermAuditScanner instance for testing."""
    return PermAuditScanner()


class TestPermAuditScannerProperties:
    """Test basic scanner properties."""

    def test_name(self, scanner: PermAuditScanner) -> None:
        assert scanner.name == ScannerModule.PERM_AUDIT

    def test_applicable_artifact_types(self, scanner: PermAuditScanner) -> None:
        types = scanner.applicable_artifact_types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.STEERING in types
        assert ArtifactType.MCP in types
        assert ArtifactType.HOOK in types
        assert ArtifactType.INSTRUCTION in types
        assert ArtifactType.PLUGIN in types
        assert ArtifactType.MEMORY in types
        assert ArtifactType.ORCHESTRATION in types
        assert ArtifactType.API_SCHEMA in types
        # Should NOT include prompt, sop, rag, eval_harness
        assert ArtifactType.PROMPT not in types

    def test_detected_risk_ids(self, scanner: PermAuditScanner) -> None:
        risk_ids = scanner.detected_risk_ids
        expected = [
            "SK-S1",
            "SK-S3",
            "SK-S6",
            "A-S1",
            "A-S2",
            "A-S6",
            "ST-S3",
            "ST-S4",
            "MCP-S7",
            "MCP-S10",
            "H-S3",
            "H-S6",
            "I-S4",
            "I-S5",
            "API-S2",
            "OW-S2",
            "M-S5",
            "PL-S2",
            "PL-S6",
        ]
        for rid in expected:
            assert rid in risk_ids

    def test_is_available(self, scanner: PermAuditScanner) -> None:
        assert scanner.is_available() is True


class TestWildcardPermissions:
    """Test detection of overly permissive tool declarations."""

    def test_wildcard_tools_star(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert len(findings) >= 1
        assert any(f.id == "A-S1" for f in findings)

    def test_all_tools_keyword(self, scanner: PermAuditScanner) -> None:
        content = "This agent has all_tools access enabled."
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "A-S1" for f in findings)

    def test_permissions_all(self, scanner: PermAuditScanner) -> None:
        content = 'permissions: "all"'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.yaml")
        assert any(f.id == "SK-S1" for f in findings)

    def test_unrestricted_access_keyword(self, scanner: PermAuditScanner) -> None:
        content = "Grant unrestricted access to all tools."
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S7" for f in findings)

    def test_confidence_high_for_policy_violation(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert all(f.confidence >= 0.95 for f in findings)

    def test_no_false_positive_normal_text(self, scanner: PermAuditScanner) -> None:
        content = "This skill provides helpful assistance with file editing tasks."
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        wildcard_findings = [f for f in findings if f.confidence >= 0.95]
        assert len(wildcard_findings) == 0


class TestDangerousFilePaths:
    """Test detection of dangerous file path patterns."""

    def test_etc_passwd(self, scanner: PermAuditScanner) -> None:
        content = "Read file at /etc/passwd for user information"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert any(f.id == "SK-S1" for f in findings)

    def test_ssh_directory(self, scanner: PermAuditScanner) -> None:
        content = "Access keys in ~/.ssh/ directory"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert any(f.id == "A-S6" for f in findings)

    def test_aws_credentials(self, scanner: PermAuditScanner) -> None:
        content = "Load credentials from ~/.aws/credentials"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S7" for f in findings)

    def test_system32_path(self, scanner: PermAuditScanner) -> None:
        content = r"Execute from C:\Windows\System32 directory"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        assert any(f.id == "PL-S2" for f in findings)

    def test_root_filesystem_access(self, scanner: PermAuditScanner) -> None:
        content = "Read/write access to the entire file system"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert any(f.id == "SK-S1" for f in findings)

    def test_confidence_pattern_based(self, scanner: PermAuditScanner) -> None:
        content = "Read file at /etc/passwd"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        path_findings = [f for f in findings if "sensitive file path" in f.description]
        assert all(0.80 <= f.confidence <= 0.94 for f in path_findings)


class TestNetworkAccess:
    """Test detection of unrestricted network access."""

    def test_wildcard_url(self, scanner: PermAuditScanner) -> None:
        content = 'url: "*"'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.yaml")
        assert any(f.id == "SK-S3" for f in findings)

    def test_any_endpoint(self, scanner: PermAuditScanner) -> None:
        content = "Can access any endpoint without restriction"
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert any(f.id == "H-S6" for f in findings)

    def test_unrestricted_network(self, scanner: PermAuditScanner) -> None:
        content = 'network: "unrestricted"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "A-S6" for f in findings)

    def test_bind_all_interfaces(self, scanner: PermAuditScanner) -> None:
        content = "Listen on 0.0.0.0:8080"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S7" for f in findings)

    def test_no_domain_restrictions(self, scanner: PermAuditScanner) -> None:
        content = "no domain restriction applied"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert any(f.id == "SK-S3" for f in findings)


class TestDestructiveActions:
    """Test detection of destructive action patterns."""

    def test_rm_rf(self, scanner: PermAuditScanner) -> None:
        content = "Execute rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "A-S2" for f in findings)

    def test_drop_table(self, scanner: PermAuditScanner) -> None:
        content = "Can execute DROP TABLE users"
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "workflow.yaml")
        assert any(f.id == "OW-S2" for f in findings)

    def test_truncate_table(self, scanner: PermAuditScanner) -> None:
        content = "Run TRUNCATE TABLE logs to clear old data"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "A-S2" for f in findings)

    def test_format_disk(self, scanner: PermAuditScanner) -> None:
        content = "format disk C: for fresh install"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert any(f.id == "SK-S6" for f in findings)

    def test_delete_all(self, scanner: PermAuditScanner) -> None:
        content = "delete all records from the database"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert any(f.id == "A-S2" for f in findings)

    def test_git_force_push(self, scanner: PermAuditScanner) -> None:
        content = "git push --force to overwrite remote"
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert any(f.id == "H-S3" for f in findings)

    def test_confidence_pattern_based(self, scanner: PermAuditScanner) -> None:
        content = "Execute rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        destructive_findings = [f for f in findings if "Destructive action" in f.description]
        assert all(0.80 <= f.confidence <= 0.94 for f in destructive_findings)


class TestPrivilegeEscalation:
    """Test detection of privilege escalation indicators."""

    def test_sudo(self, scanner: PermAuditScanner) -> None:
        content = "Run sudo apt-get install package"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert any(f.id == "SK-S6" for f in findings)

    def test_run_as_root(self, scanner: PermAuditScanner) -> None:
        content = "Execute as root user to modify system files"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S7" for f in findings)

    def test_admin_privilege(self, scanner: PermAuditScanner) -> None:
        content = "Requires admin privilege to configure"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "I-S4" for f in findings)

    def test_setuid(self, scanner: PermAuditScanner) -> None:
        content = "Binary has setuid flag enabled"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        assert any(f.id == "PL-S2" for f in findings)

    def test_elevated_permissions(self, scanner: PermAuditScanner) -> None:
        content = "Elevate privileges to access system config"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "A-S1" for f in findings)


class TestShellExecution:
    """Test detection of unrestricted shell/command execution."""

    def test_shell_enabled(self, scanner: PermAuditScanner) -> None:
        content = 'shell: "true"'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.yaml")
        assert any(f.id == "SK-S1" for f in findings)

    def test_arbitrary_command_execution(self, scanner: PermAuditScanner) -> None:
        content = "Can execute arbitrary commands on the system"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S7" for f in findings)

    def test_wildcard_command(self, scanner: PermAuditScanner) -> None:
        content = 'command: "*"'
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert any(f.id == "H-S3" for f in findings)

    def test_unrestricted_shell_access(self, scanner: PermAuditScanner) -> None:
        content = 'shell_access: "unrestricted"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert any(f.id == "A-S1" for f in findings)


class TestMissingAuth:
    """Test detection of missing authentication."""

    def test_auth_none(self, scanner: PermAuditScanner) -> None:
        content = 'auth: "none"'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S10" for f in findings)

    def test_no_auth(self, scanner: PermAuditScanner) -> None:
        content = "No auth required for this endpoint"
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.yaml")
        assert any(f.id == "API-S2" for f in findings)

    def test_unencrypted_transport(self, scanner: PermAuditScanner) -> None:
        content = 'transport: "http"'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S10" for f in findings)

    def test_public_access(self, scanner: PermAuditScanner) -> None:
        content = "This is a public endpoint accessible without credentials"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S10" for f in findings)


class TestSecurityBypass:
    """Test detection of security bypass patterns."""

    def test_skip_security(self, scanner: PermAuditScanner) -> None:
        content = "skip security checks for development"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "I-S5" for f in findings)

    def test_disable_validation(self, scanner: PermAuditScanner) -> None:
        content = "disable validation for this request"
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        assert any(f.id == "ST-S4" for f in findings)

    def test_override_guardrails(self, scanner: PermAuditScanner) -> None:
        content = "override guardrails when processing admin requests"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id == "I-S5" for f in findings)

    def test_without_verification(self, scanner: PermAuditScanner) -> None:
        content = "proceed without verification for trusted sources"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        assert any(f.id == "PL-S2" for f in findings)


class TestCleanArtifacts:
    """Test that clean artifacts produce no findings."""

    def test_clean_skill(self, scanner: PermAuditScanner) -> None:
        content = """
        name: file-reader
        description: Read project files within the workspace
        tools:
          - read_file
          - list_directory
        allowed_paths:
          - ./src
          - ./docs
        """
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.yaml")
        assert len(findings) == 0

    def test_clean_agent(self, scanner: PermAuditScanner) -> None:
        content = """
        name: code-assistant
        description: Helps with code editing tasks
        capabilities:
          - code_completion
          - code_review
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert len(findings) == 0

    def test_clean_mcp(self, scanner: PermAuditScanner) -> None:
        content = """
        {
            "name": "weather-api",
            "transport": "https",
            "auth": "bearer_token",
            "tools": ["get_forecast", "get_current"]
        }
        """
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 0


class TestFindingMetadata:
    """Test that findings have correct metadata."""

    def test_finding_has_correct_scanner_module(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert all(f.scanner_module == ScannerModule.PERM_AUDIT for f in findings)

    def test_finding_has_correct_category(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        from ai_artifact_risk_validator.models import RiskCategory

        assert all(f.category == RiskCategory.SECURITY for f in findings)

    def test_finding_has_line_number(self, scanner: PermAuditScanner) -> None:
        content = 'line 1\nline 2\ntools: "*"\nline 4'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert any(f.location.line == 3 for f in findings)

    def test_finding_severity_matches_risk(self, scanner: PermAuditScanner) -> None:
        # A-S1 has severity 9, Critical
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        a_s1_findings = [f for f in findings if f.id == "A-S1"]
        assert len(a_s1_findings) >= 1
        assert a_s1_findings[0].severity_score == 9
        assert a_s1_findings[0].severity_label == SeverityLabel.CRITICAL
        assert a_s1_findings[0].gate_action == GateAction.BLOCK

    def test_evidence_truncated(self, scanner: PermAuditScanner) -> None:
        # Evidence should be truncated to reasonable length
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert all(len(f.evidence) <= 200 for f in findings)


class TestArtifactTypeRouting:
    """Test that findings get correct risk IDs per artifact type."""

    def test_skill_gets_sk_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.yaml")
        assert any(f.id.startswith("SK-") for f in findings)

    def test_agent_gets_a_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert any(f.id.startswith("A-") for f in findings)

    def test_steering_gets_st_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        assert any(f.id.startswith("ST-") for f in findings)

    def test_mcp_gets_mcp_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id.startswith("MCP-") for f in findings)

    def test_hook_gets_h_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert any(f.id.startswith("H-") for f in findings)

    def test_instruction_gets_i_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert any(f.id.startswith("I-") for f in findings)

    def test_plugin_gets_pl_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        assert any(f.id.startswith("PL-") for f in findings)

    def test_memory_gets_m_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.MEMORY, "memory.yaml")
        assert any(f.id.startswith("M-") for f in findings)

    def test_orchestration_gets_ow_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "workflow.yaml")
        assert any(f.id.startswith("OW-") for f in findings)

    def test_api_schema_gets_api_ids(self, scanner: PermAuditScanner) -> None:
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.yaml")
        assert any(f.id.startswith("API-") for f in findings)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_content(self, scanner: PermAuditScanner) -> None:
        findings = scanner.scan("", ArtifactType.AGENT, "agent.yaml")
        assert len(findings) == 0

    def test_non_applicable_artifact_type_still_works(self, scanner: PermAuditScanner) -> None:
        # Even though PROMPT is not in applicable types, scan() should handle gracefully
        content = 'tools: "*"'
        findings = scanner.scan(content, ArtifactType.PROMPT, "prompt.md")
        # PROMPT is not in our mapping, so no findings
        assert len(findings) == 0

    def test_multiple_findings_same_content(self, scanner: PermAuditScanner) -> None:
        content = """
        tools: "*"
        Access /etc/passwd
        Run sudo command
        Execute rm -rf /
        shell: "true"
        """
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert len(findings) >= 4  # Multiple distinct issues detected

    def test_case_insensitive_detection(self, scanner: PermAuditScanner) -> None:
        content = 'TOOLS: "*"'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.yaml")
        assert len(findings) >= 1
