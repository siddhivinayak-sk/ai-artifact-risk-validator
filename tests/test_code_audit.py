"""Unit tests for the CodeAudit scanner module."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.code_audit import (
    CodeAuditScanner,
    _is_python_content,
)


@pytest.fixture
def scanner() -> CodeAuditScanner:
    """Create a CodeAuditScanner instance for testing."""
    return CodeAuditScanner()


class TestScannerMetadata:
    """Tests for scanner properties and metadata."""

    def test_name(self, scanner: CodeAuditScanner) -> None:
        assert scanner.name == ScannerModule.CODE_AUDIT

    def test_applicable_artifact_types(self, scanner: CodeAuditScanner) -> None:
        types = scanner.applicable_artifact_types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.MCP in types
        assert ArtifactType.HOOK in types
        assert ArtifactType.PLUGIN in types
        assert len(types) == 5

    def test_detected_risk_ids(self, scanner: CodeAuditScanner) -> None:
        risk_ids = scanner.detected_risk_ids
        expected = [
            "SK-S2",
            "MCP-S1",
            "MCP-S2",
            "MCP-S8",
            "MCP-S9",
            "H-S1",
            "H-S4",
            "H-S5",
            "PL-S1",
            "PL-S4",
            "PL-S5",
            "PL-S9",
            "A-S3",
            "A-S6",
            "A-S7",
            "RA-S1",
            "RA-S2",
            "AST-S8",
        ]
        assert set(risk_ids) == set(expected)

    def test_is_available_always_true(self, scanner: CodeAuditScanner) -> None:
        assert scanner.is_available() is True


class TestPythonContentDetection:
    """Tests for Python content identification."""

    def test_python_extension(self) -> None:
        assert _is_python_content("anything", "script.py") is True

    def test_non_python_extension_with_python_content(self) -> None:
        content = "import os\nfrom pathlib import Path\ndef main():\n    pass"
        assert _is_python_content(content, "script.ts") is True

    def test_non_python_extension_with_non_python_content(self) -> None:
        content = "const x = 1;\nfunction foo() { return x; }"
        assert _is_python_content(content, "script.js") is False

    def test_empty_content_non_python_path(self) -> None:
        assert _is_python_content("", "script.js") is False


class TestDangerousFunctions:
    """Tests for detection of dangerous built-in function calls."""

    def test_eval_detected(self, scanner: CodeAuditScanner) -> None:
        code = "result = eval(user_input)"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        assert any(f.id == "SK-S2" for f in findings)
        assert any("eval" in f.evidence for f in findings)

    def test_exec_detected(self, scanner: CodeAuditScanner) -> None:
        code = "exec(code_string)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_compile_detected(self, scanner: CodeAuditScanner) -> None:
        code = "compiled = compile(source, '<string>', 'exec')"
        findings = scanner.scan(code, ArtifactType.PLUGIN, "plugin.py")
        assert len(findings) >= 1
        assert any(f.id == "PL-S1" for f in findings)

    def test_dunder_import_detected(self, scanner: CodeAuditScanner) -> None:
        code = "mod = __import__(module_name)"
        findings = scanner.scan(code, ArtifactType.HOOK, "hook.py")
        assert len(findings) >= 1
        assert any(f.id == "H-S1" for f in findings)

    def test_safe_code_no_findings(self, scanner: CodeAuditScanner) -> None:
        code = "x = 1 + 2\nprint(x)"
        findings = scanner.scan(code, ArtifactType.SKILL, "safe.py")
        assert len(findings) == 0

    def test_empty_content_no_findings(self, scanner: CodeAuditScanner) -> None:
        findings = scanner.scan("", ArtifactType.SKILL, "empty.py")
        assert len(findings) == 0

    def test_whitespace_only_no_findings(self, scanner: CodeAuditScanner) -> None:
        findings = scanner.scan("   \n\n  ", ArtifactType.SKILL, "blank.py")
        assert len(findings) == 0


class TestSubprocessDetection:
    """Tests for subprocess and command execution detection."""

    def test_subprocess_call_detected(self, scanner: CodeAuditScanner) -> None:
        code = "import subprocess\nsubprocess.call(['ls', '-la'])"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        assert any(f.id == "SK-S2" for f in findings)

    def test_subprocess_popen_detected(self, scanner: CodeAuditScanner) -> None:
        code = "import subprocess\np = subprocess.Popen(cmd, shell=True)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)
        # Should note shell=True
        assert any("shell=True" in f.evidence for f in findings)

    def test_os_system_detected(self, scanner: CodeAuditScanner) -> None:
        code = "import os\nos.system('rm -rf /')"
        findings = scanner.scan(code, ArtifactType.HOOK, "hook.py")
        assert len(findings) >= 1
        assert any(f.id == "H-S1" for f in findings)

    def test_os_popen_detected(self, scanner: CodeAuditScanner) -> None:
        code = "import os\nresult = os.popen(command)"
        findings = scanner.scan(code, ArtifactType.AGENT, "agent.py")
        assert len(findings) >= 1
        assert any(f.id == "A-S3" for f in findings)


class TestSSRFDetection:
    """Tests for SSRF pattern detection."""

    def test_requests_get_with_variable_url(self, scanner: CodeAuditScanner) -> None:
        code = "import requests\nresponse = requests.get(user_url)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S2" for f in findings)

    def test_requests_post_with_variable_url(self, scanner: CodeAuditScanner) -> None:
        code = "import requests\nresponse = requests.post(endpoint)"
        findings = scanner.scan(code, ArtifactType.PLUGIN, "plugin.py")
        assert len(findings) >= 1
        assert any(f.id == "PL-S5" for f in findings)

    def test_requests_with_literal_url_no_ssrf(self, scanner: CodeAuditScanner) -> None:
        code = "import requests\nresponse = requests.get('https://api.example.com/data')"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        # Literal URL should not trigger SSRF
        assert not any(f.id == "MCP-S2" for f in findings)


class TestPathTraversal:
    """Tests for path traversal detection."""

    def test_os_path_join_with_user_input(self, scanner: CodeAuditScanner) -> None:
        code = "import os\npath = os.path.join(base_dir, user_input)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S9" for f in findings)

    def test_regex_path_traversal_dots(self, scanner: CodeAuditScanner) -> None:
        # Non-Python content with path traversal
        content = "const path = base + '/../../../etc/passwd';"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S9" for f in findings)


class TestDeserialization:
    """Tests for unsafe deserialization detection."""

    def test_pickle_loads_detected(self, scanner: CodeAuditScanner) -> None:
        code = "import pickle\ndata = pickle.loads(payload)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S8" for f in findings)

    def test_pickle_load_detected(self, scanner: CodeAuditScanner) -> None:
        code = "import pickle\nwith open('data.pkl', 'rb') as f:\n    data = pickle.load(f)"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        assert any(f.id == "SK-S2" for f in findings)

    def test_yaml_load_without_loader(self, scanner: CodeAuditScanner) -> None:
        code = "import yaml\ndata = yaml.load(content)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S8" for f in findings)

    def test_yaml_safe_load_no_finding(self, scanner: CodeAuditScanner) -> None:
        code = "import yaml\ndata = yaml.safe_load(content)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert not any(f.id == "MCP-S8" for f in findings)

    def test_yaml_load_with_safe_loader_no_finding(self, scanner: CodeAuditScanner) -> None:
        code = "import yaml\ndata = yaml.load(content, Loader=yaml.SafeLoader)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert not any(f.id == "MCP-S8" for f in findings)

    def test_marshal_loads_detected(self, scanner: CodeAuditScanner) -> None:
        code = "import marshal\nobj = marshal.loads(data)"
        findings = scanner.scan(code, ArtifactType.PLUGIN, "plugin.py")
        assert len(findings) >= 1
        assert any(f.id == "PL-S1" for f in findings)


class TestCodeInjection:
    """Tests for SQL/shell code injection detection."""

    def test_fstring_sql_detected(self, scanner: CodeAuditScanner) -> None:
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        assert any(f.id == "SK-S2" for f in findings)

    def test_format_sql_detected(self, scanner: CodeAuditScanner) -> None:
        code = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))'
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        assert any(f.id == "SK-S2" for f in findings)

    def test_parameterized_query_no_finding(self, scanner: CodeAuditScanner) -> None:
        code = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        # Parameterized queries should not trigger
        code_injection_findings = [
            f for f in findings if "injection" in f.description.lower() or "SQL" in f.description
        ]
        assert len(code_injection_findings) == 0


class TestDynamicImports:
    """Tests for dynamic import detection."""

    def test_importlib_with_variable(self, scanner: CodeAuditScanner) -> None:
        code = "import importlib\nmod = importlib.import_module(module_name)"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        assert any(f.id == "SK-S2" for f in findings)

    def test_importlib_with_literal_no_finding(self, scanner: CodeAuditScanner) -> None:
        code = "import importlib\nmod = importlib.import_module('json')"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        # Literal module name is safe
        dynamic_findings = [f for f in findings if "Dynamic import" in f.description]
        assert len(dynamic_findings) == 0


class TestRegexFallback:
    """Tests for regex-based detection on non-Python content."""

    def test_eval_in_javascript(self, scanner: CodeAuditScanner) -> None:
        content = "const result = eval(userInput);"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.js")
        assert len(findings) >= 1
        assert any(f.id == "PL-S1" for f in findings)

    def test_subprocess_in_typescript(self, scanner: CodeAuditScanner) -> None:
        content = "import { exec } from 'child_process';\nos.system(command);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_insecure_http_url(self, scanner: CodeAuditScanner) -> None:
        content = "const api = 'http://api.external.com/data';"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.js")
        assert len(findings) >= 1
        assert any(f.id == "PL-S9" for f in findings)

    def test_localhost_http_not_flagged(self, scanner: CodeAuditScanner) -> None:
        content = "const api = 'http://localhost:3000/data';"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.js")
        insecure_findings = [f for f in findings if f.id == "PL-S9"]
        assert len(insecure_findings) == 0


class TestArtifactTypeRiskMapping:
    """Tests that risk IDs are correctly mapped by artifact type."""

    def test_skill_gets_sk_s2(self, scanner: CodeAuditScanner) -> None:
        code = "eval(x)"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert any(f.id == "SK-S2" for f in findings)

    def test_mcp_gets_mcp_s1(self, scanner: CodeAuditScanner) -> None:
        code = "eval(x)"
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        assert any(f.id == "MCP-S1" for f in findings)

    def test_hook_gets_h_s1(self, scanner: CodeAuditScanner) -> None:
        code = "eval(x)"
        findings = scanner.scan(code, ArtifactType.HOOK, "hook.py")
        assert any(f.id == "H-S1" for f in findings)

    def test_plugin_gets_pl_s1(self, scanner: CodeAuditScanner) -> None:
        code = "eval(x)"
        findings = scanner.scan(code, ArtifactType.PLUGIN, "plugin.py")
        assert any(f.id == "PL-S1" for f in findings)

    def test_agent_gets_a_s3(self, scanner: CodeAuditScanner) -> None:
        code = "eval(x)"
        findings = scanner.scan(code, ArtifactType.AGENT, "agent.py")
        assert any(f.id == "A-S3" for f in findings)


class TestConfidenceScores:
    """Tests for confidence score assignment."""

    def test_ast_dangerous_call_confidence(self, scanner: CodeAuditScanner) -> None:
        code = "result = eval(user_input)"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        # AST pattern match should be 0.80-0.90
        assert all(0.80 <= f.confidence <= 0.95 for f in findings)

    def test_regex_pattern_confidence(self, scanner: CodeAuditScanner) -> None:
        content = "const result = eval(userInput);"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.js")
        assert len(findings) >= 1
        # Regex pattern match should be 0.80-0.90
        assert all(0.80 <= f.confidence <= 0.90 for f in findings)


class TestFindingStructure:
    """Tests for proper finding model construction."""

    def test_finding_has_required_fields(self, scanner: CodeAuditScanner) -> None:
        code = "eval(x)"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.id == "SK-S2"
        assert finding.artifact_type == ArtifactType.SKILL
        assert finding.artifact_path == "skill.py"
        assert finding.severity_score == 9
        assert finding.scanner_module == ScannerModule.CODE_AUDIT
        assert finding.confidence > 0
        assert finding.location.line == 1
        assert finding.remediation != ""
        assert finding.title != ""
        assert finding.description != ""

    def test_finding_evidence_truncated(self, scanner: CodeAuditScanner) -> None:
        # Evidence should not exceed 200 characters
        long_code = "eval(" + "a" * 300 + ")"
        findings = scanner.scan(long_code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        for f in findings:
            assert len(f.evidence) <= 200


class TestBanditLazyLoading:
    """Tests for lazy loading of optional bandit dependency."""

    def test_bandit_loaded_lazily(self, scanner: CodeAuditScanner) -> None:
        # Bandit should not be loaded until explicitly requested
        assert scanner._bandit_loaded is False
        # Trigger lazy load
        scanner._load_bandit()
        assert scanner._bandit_loaded is True

    def test_scanner_works_without_bandit(self, scanner: CodeAuditScanner) -> None:
        # Scanner should work fine without bandit
        code = "eval(user_input)"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1


class TestComplexScenarios:
    """Tests for complex multi-issue scenarios."""

    def test_multiple_issues_detected(self, scanner: CodeAuditScanner) -> None:
        code = """import subprocess
import pickle
import os

result = eval(user_input)
subprocess.call(cmd, shell=True)
data = pickle.loads(payload)
os.system(command)
"""
        findings = scanner.scan(code, ArtifactType.MCP, "server.py")
        # Should detect multiple issues
        assert len(findings) >= 3

    def test_import_aliasing_resolved(self, scanner: CodeAuditScanner) -> None:
        code = """import subprocess as sp
sp.call(['ls'])
"""
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        assert len(findings) >= 1
        assert any(f.id == "SK-S2" for f in findings)

    def test_syntax_error_falls_to_regex(self, scanner: CodeAuditScanner) -> None:
        # Invalid Python but contains dangerous patterns
        code = "def broken(\n  eval(x)\n  )"
        findings = scanner.scan(code, ArtifactType.SKILL, "skill.py")
        # Should fall back to regex and still detect eval
        assert len(findings) >= 1
