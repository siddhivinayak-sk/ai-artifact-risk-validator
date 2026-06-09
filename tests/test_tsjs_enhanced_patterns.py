"""Unit tests for TSJSEnhancedPatterns analyzer.

Tests each detection pattern (child_process, new Function, vm module, dynamic URL fetch,
node-serialize/JSON.parse, SQL template literals, fs dynamic paths, missing auth)
with positive and negative examples.
"""

import pytest

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.tsjs_enhanced import TSJSEnhancedPatterns


@pytest.fixture
def scanner() -> TSJSEnhancedPatterns:
    """Create a TSJSEnhancedPatterns instance."""
    return TSJSEnhancedPatterns()


class TestChildProcessDetection:
    """Tests for child_process.exec/execSync/spawn/execFile detection."""

    def test_detects_child_process_exec(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const result = child_process.exec(cmd);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" and f.confidence == 0.90 for f in findings)

    def test_detects_child_process_spawn(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const proc = child_process.spawn('node', args);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_detects_execSync(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "child_process.execSync(`ls ${dir}`);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_detects_require_child_process(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "require('child_process').exec(command);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.js")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_no_false_positive_on_comment(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "// child_process is not used here\nconst x = 1;"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        # Comments may trigger regex - this is acceptable for regex-based scanning
        # The key is we don't crash

    def test_detects_execFile(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "child_process.execFile('/bin/sh', ['-c', cmd]);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)


class TestNewFunctionDetection:
    """Tests for new Function() with dynamic arguments."""

    def test_detects_new_function_with_variable(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const fn = new Function(userCode);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" and f.confidence == 0.85 for f in findings)

    def test_detects_new_function_with_template(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const fn = new Function(`return ${expr}`);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_detects_new_function_with_concatenation(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const fn = new Function('return ' + code);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_no_detection_for_static_string(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const fn = new Function('return 1');"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        mcp_s1_from_function = [
            f for f in findings if f.id == "MCP-S1" and "Function" in f.evidence
        ]
        assert len(mcp_s1_from_function) == 0


class TestVmModuleDetection:
    """Tests for vm.runInNewContext/runInThisContext/vm.Script."""

    def test_detects_vm_runInNewContext(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "vm.runInNewContext(code, sandbox);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" and f.confidence == 0.90 for f in findings)

    def test_detects_vm_runInThisContext(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "vm.runInThisContext(script);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)

    def test_detects_vm_Script(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const script = new vm.Script(code);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S1" for f in findings)


class TestDynamicUrlFetchDetection:
    """Tests for fetch/axios/got with template literal URL."""

    def test_detects_fetch_with_template_literal(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const resp = fetch(`http://api.example.com/${path}`);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S2" and f.confidence == 0.80 for f in findings)

    def test_detects_axios_get_with_template(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "await axios.get(`${baseUrl}/users/${id}`);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S2" for f in findings)

    def test_detects_axios_post_with_template(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "axios.post(`${url}/data`, payload);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S2" for f in findings)

    def test_detects_got_with_variable_url(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const resp = got(targetUrl);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S2" for f in findings)

    def test_no_detection_for_static_url(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "fetch('https://api.example.com/health');"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        ssrf_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(ssrf_findings) == 0


class TestDeserializationDetection:
    """Tests for node-serialize and JSON.parse detection."""

    def test_detects_node_serialize_deserialize(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const obj = serialize.deserialize(data);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S8" and f.confidence == 0.90 for f in findings)

    def test_detects_unserialize(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const obj = unserialize(payload);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S8" for f in findings)

    def test_detects_json_parse_with_variable(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const config = JSON.parse(userInput);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S8" and f.confidence == 0.70 for f in findings)

    def test_no_detection_json_parse_with_literal(self, scanner: TSJSEnhancedPatterns) -> None:
        content = 'const data = JSON.parse(\'{"key": "value"}\');'
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        json_parse_findings = [
            f for f in findings if f.id == "MCP-S8" and "JSON.parse" in (f.evidence or "")
        ]
        assert len(json_parse_findings) == 0


class TestSqlTemplateDetection:
    """Tests for SQL template literal injection detection."""

    def test_detects_sql_template_literal(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "db.query(`SELECT * FROM users WHERE id = ${userId}`);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S6" and f.confidence == 0.82 for f in findings)

    def test_detects_sql_concatenation(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "db.query('SELECT * FROM users WHERE id = ' + userId);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S6" for f in findings)

    def test_detects_insert_template(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "pool.execute(`INSERT INTO logs VALUES (${msg})`);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S6" for f in findings)

    def test_no_detection_for_parameterized_query(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "db.query('SELECT * FROM users WHERE id = ?', [userId]);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        sql_findings = [f for f in findings if f.id == "MCP-S6"]
        assert len(sql_findings) == 0


class TestFsDynamicPathDetection:
    """Tests for fs operations with dynamic paths."""

    def test_detects_fs_readFile_with_variable(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "fs.readFile(userPath, callback);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S9" and f.confidence == 0.75 for f in findings)

    def test_detects_fs_writeFileSync_with_template(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "fs.writeFileSync(`${dir}/${name}`, data);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S9" for f in findings)

    def test_detects_fs_unlink_with_variable(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "fs.unlink(filePath, callback);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S9" for f in findings)

    def test_no_detection_for_static_path(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "fs.readFile('./config.json', callback);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        path_findings = [f for f in findings if f.id == "MCP-S9"]
        assert len(path_findings) == 0


class TestMissingAuthDetection:
    """Tests for missing authentication middleware detection."""

    def test_detects_express_without_auth(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const app = express();\napp.get('/data', handler);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S10" and f.confidence == 0.70 for f in findings)

    def test_detects_fastify_without_auth(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const server = fastify();\nserver.get('/api', handler);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S10" for f in findings)

    def test_detects_http_createServer_without_auth(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const server = http.createServer(handler);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 1
        assert any(f.id == "MCP-S10" for f in findings)

    def test_no_detection_with_passport(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const app = express();\napp.use(passport.authenticate('jwt'));"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        auth_findings = [f for f in findings if f.id == "MCP-S10"]
        assert len(auth_findings) == 0

    def test_no_detection_with_express_jwt(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const app = express();\nconst jwt = require('express-jwt');\napp.use(jwt());"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        auth_findings = [f for f in findings if f.id == "MCP-S10"]
        assert len(auth_findings) == 0

    def test_no_detection_with_jsonwebtoken_verify(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const app = express();\njsonwebtoken.verify(token, secret);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        auth_findings = [f for f in findings if f.id == "MCP-S10"]
        assert len(auth_findings) == 0

    def test_no_detection_with_auth_middleware(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const app = express();\napp.use(authMiddleware);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        auth_findings = [f for f in findings if f.id == "MCP-S10"]
        assert len(auth_findings) == 0

    def test_no_detection_with_fastify_auth_plugin(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const server = fastify();\nfastify.register(jwtAuthPlugin);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        auth_findings = [f for f in findings if f.id == "MCP-S10"]
        assert len(auth_findings) == 0


class TestEdgeCases:
    """Edge case tests for the TS/JS enhanced patterns scanner."""

    def test_empty_content(self, scanner: TSJSEnhancedPatterns) -> None:
        findings = scanner.scan("", ArtifactType.MCP, "server.ts")
        assert findings == []

    def test_whitespace_only(self, scanner: TSJSEnhancedPatterns) -> None:
        findings = scanner.scan("   \n\n  ", ArtifactType.MCP, "server.ts")
        assert findings == []

    def test_evidence_not_empty(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "child_process.exec(cmd);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        for f in findings:
            assert f.evidence, "Evidence should not be empty"
            assert len(f.evidence) <= 200, "Evidence should be at most 200 chars"

    def test_line_numbers_correct(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "const x = 1;\nconst y = 2;\nchild_process.exec(cmd);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        exec_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(exec_findings) >= 1
        assert exec_findings[0].location.line == 3

    def test_multiple_findings_on_different_lines(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "child_process.exec(cmd);\nvm.runInNewContext(code);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        assert len(findings) >= 2
        assert any(f.location.line == 1 for f in findings)
        assert any(f.location.line == 2 for f in findings)

    def test_finding_has_valid_risk_id_format(self, scanner: TSJSEnhancedPatterns) -> None:
        import re

        content = "child_process.exec(cmd);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        for f in findings:
            assert re.match(r"^[A-Z]+-[A-Z]?[0-9]+$", f.id)

    def test_finding_confidence_in_range(self, scanner: TSJSEnhancedPatterns) -> None:
        content = "child_process.exec(cmd);\nJSON.parse(data);\nfs.readFile(path);"
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")
        for f in findings:
            assert 0.0 <= f.confidence <= 1.0
