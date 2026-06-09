"""Integration tests for scanner registry and pipeline with DynamicScanner.

Tests that DynamicScanner registers correctly under DYNAMIC_SCAN module,
pipeline skips dynamic scanning when module is disabled, and end-to-end
scanning of multi-language MCP server projects produces expected findings.

Validates: Requirements 7.1, 7.3, 7.6
"""

from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner
from ai_artifact_risk_validator.scanners.dynamic.scanner import DynamicScanner
from ai_artifact_risk_validator.scanners.registry import ScannerRegistry

# --- Test: DynamicScanner registers correctly under DYNAMIC_SCAN module ---


class TestDynamicScannerRegistration:
    """Tests that DynamicScanner registers correctly under DYNAMIC_SCAN module.

    Validates: Requirements 7.3
    """

    def test_dynamic_scanner_registers_under_dynamic_scan_module(self):
        """DynamicScanner should register under ScannerModule.DYNAMIC_SCAN."""
        registry = ScannerRegistry()
        registry.register(DynamicScanner)

        assert ScannerModule.DYNAMIC_SCAN in registry.registered_scanners

    def test_dynamic_scanner_instance_has_correct_name(self):
        """Registered DynamicScanner instance should report DYNAMIC_SCAN as name."""
        registry = ScannerRegistry()
        registry.register(DynamicScanner)

        scanner = registry.get_scanner_by_name(ScannerModule.DYNAMIC_SCAN)
        assert scanner is not None
        assert scanner.name == ScannerModule.DYNAMIC_SCAN

    def test_dynamic_scanner_applicable_to_mcp_artifacts(self):
        """DynamicScanner should be applicable to MCP artifact type."""
        registry = ScannerRegistry()
        registry.register(DynamicScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.MCP)
        scanner_names = [s.name for s in scanners]
        assert ScannerModule.DYNAMIC_SCAN in scanner_names

    def test_dynamic_scanner_not_applicable_to_non_mcp_artifacts(self):
        """DynamicScanner should not be returned for non-MCP artifacts."""
        registry = ScannerRegistry()
        registry.register(DynamicScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        scanner_names = [s.name for s in scanners]
        assert ScannerModule.DYNAMIC_SCAN not in scanner_names

    def test_dynamic_scanner_coexists_with_code_audit(self):
        """DynamicScanner and CodeAuditScanner can coexist in the registry."""
        registry = ScannerRegistry()
        registry.register(CodeAuditScanner)
        registry.register(DynamicScanner)

        assert ScannerModule.CODE_AUDIT in registry.registered_scanners
        assert ScannerModule.DYNAMIC_SCAN in registry.registered_scanners

        # Both should be returned for MCP artifact type
        scanners = registry.get_scanners_for_artifact(ArtifactType.MCP)
        scanner_names = [s.name for s in scanners]
        assert ScannerModule.CODE_AUDIT in scanner_names
        assert ScannerModule.DYNAMIC_SCAN in scanner_names


# --- Test: Pipeline skips dynamic scanning when module is disabled ---


class TestPipelineSkipsDynamicWhenDisabled:
    """Tests that the pipeline skips dynamic scanning when module is disabled.

    Validates: Requirements 7.6
    """

    def test_disabled_scanners_excludes_dynamic_scan(self):
        """DynamicScanner should be excluded when DYNAMIC_SCAN is in disabled_scanners."""
        config = ValidatorConfig(disabled_scanners=[ScannerModule.DYNAMIC_SCAN])
        registry = ScannerRegistry(config=config)
        registry.register(DynamicScanner)
        registry.register(CodeAuditScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.MCP)
        scanner_names = [s.name for s in scanners]

        assert ScannerModule.DYNAMIC_SCAN not in scanner_names
        # CodeAuditScanner should still be present
        assert ScannerModule.CODE_AUDIT in scanner_names

    def test_enabled_scanners_without_dynamic_scan_excludes_it(self):
        """DynamicScanner should be excluded when not in enabled_scanners list."""
        config = ValidatorConfig(enabled_scanners=[ScannerModule.CODE_AUDIT])
        registry = ScannerRegistry(config=config)
        registry.register(DynamicScanner)
        registry.register(CodeAuditScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.MCP)
        scanner_names = [s.name for s in scanners]

        assert ScannerModule.DYNAMIC_SCAN not in scanner_names
        assert ScannerModule.CODE_AUDIT in scanner_names

    def test_is_scanner_enabled_returns_false_when_disabled(self):
        """_is_scanner_enabled should return False for disabled DYNAMIC_SCAN."""
        config = ValidatorConfig(disabled_scanners=[ScannerModule.DYNAMIC_SCAN])
        registry = ScannerRegistry(config=config)

        assert registry._is_scanner_enabled(ScannerModule.DYNAMIC_SCAN) is False

    def test_is_scanner_enabled_returns_true_when_not_disabled(self):
        """_is_scanner_enabled should return True when no config disables it."""
        registry = ScannerRegistry()

        assert registry._is_scanner_enabled(ScannerModule.DYNAMIC_SCAN) is True

    def test_enabled_scanners_whitelist_includes_dynamic_scan(self):
        """DynamicScanner should be included when DYNAMIC_SCAN is in enabled_scanners."""
        config = ValidatorConfig(
            enabled_scanners=[ScannerModule.DYNAMIC_SCAN, ScannerModule.CODE_AUDIT]
        )
        registry = ScannerRegistry(config=config)
        registry.register(DynamicScanner)
        registry.register(CodeAuditScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.MCP)
        scanner_names = [s.name for s in scanners]

        assert ScannerModule.DYNAMIC_SCAN in scanner_names
        assert ScannerModule.CODE_AUDIT in scanner_names


# --- Test: End-to-end scanning of multi-language MCP server project ---


class TestEndToEndMultiLanguageScan:
    """Tests end-to-end scanning of multi-language MCP server project files.

    Validates: Requirements 7.1, 7.3, 7.6
    """

    def setup_method(self):
        """Set up a CodeAuditScanner for end-to-end tests."""
        self.scanner = CodeAuditScanner()

    def test_rust_file_with_command_usage(self):
        """Scanning a .rs file with Command usage should produce findings."""
        rust_code = """\
use std::process::Command;

fn run_tool(input: &str) {
    let output = Command::new("sh")
        .arg("-c")
        .arg(input)
        .output()
        .expect("failed to execute");
}
"""
        findings = self.scanner.scan(rust_code, ArtifactType.MCP, "server.rs")

        assert len(findings) > 0
        risk_ids = [f.id for f in findings]
        assert "MCP-S1" in risk_ids

    def test_java_file_with_runtime_exec(self):
        """Scanning a .java file with Runtime.exec() should produce findings."""
        java_code = """\
import java.io.*;

public class McpTool {
    public void executeTool(String command) {
        Runtime.getRuntime().exec(command);
    }
}
"""
        findings = self.scanner.scan(java_code, ArtifactType.MCP, "McpTool.java")

        assert len(findings) > 0
        risk_ids = [f.id for f in findings]
        assert "MCP-S1" in risk_ids

    def test_typescript_file_with_child_process(self):
        """Scanning a .ts file with child_process should produce findings."""
        ts_code = """\
import { exec } from 'child_process';

export function runCommand(cmd: string): void {
    child_process.exec(cmd, (error, stdout, stderr) => {
        console.log(stdout);
    });
}
"""
        findings = self.scanner.scan(ts_code, ArtifactType.MCP, "server.ts")

        assert len(findings) > 0
        risk_ids = [f.id for f in findings]
        assert "MCP-S1" in risk_ids

    def test_go_file_with_exec_command(self):
        """Scanning a .go file with exec.Command should produce findings."""
        go_code = """\
package main

import (
    "os/exec"
    "fmt"
)

func runTool(input string) {
    cmd := exec.Command("sh", "-c", input)
    output, _ := cmd.Output()
    fmt.Println(string(output))
}
"""
        findings = self.scanner.scan(go_code, ArtifactType.MCP, "server.go")

        assert len(findings) > 0
        risk_ids = [f.id for f in findings]
        assert "MCP-S1" in risk_ids

    def test_multi_language_project_all_produce_findings(self):
        """Scanning files of different languages should all produce findings."""
        test_cases = [
            (
                "server.rs",
                'use std::process::Command;\nfn run(input: &str) { Command::new("sh").arg(input).output(); }\n',
            ),
            (
                "McpTool.java",
                "import java.io.*;\npublic class McpTool { void run(String cmd) { Runtime.getRuntime().exec(cmd); } }\n",
            ),
            (
                "server.ts",
                "import { exec } from 'child_process';\nchild_process.exec(userInput);\n",
            ),
            (
                "server.go",
                'package main\nimport "os/exec"\nfunc run(input string) { exec.Command("sh", "-c", input) }\n',
            ),
        ]

        for path, code in test_cases:
            findings = self.scanner.scan(code, ArtifactType.MCP, path)
            assert len(findings) > 0, f"Expected findings for {path} but got none"
            risk_ids = [f.id for f in findings]
            assert "MCP-S1" in risk_ids, f"Expected MCP-S1 finding for {path}"

    def test_registry_with_code_audit_serves_multi_language(self):
        """CodeAuditScanner in registry should handle multi-language MCP files."""
        registry = ScannerRegistry()
        registry.register(CodeAuditScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.MCP)
        assert len(scanners) >= 1

        code_audit = next(s for s in scanners if s.name == ScannerModule.CODE_AUDIT)

        # Verify it can scan a Rust file
        rust_code = 'use std::process::Command;\nfn run(input: &str) { Command::new("sh").arg(input).output(); }\n'
        findings = code_audit.scan(rust_code, ArtifactType.MCP, "tool.rs")
        assert len(findings) > 0
