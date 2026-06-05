"""Unit tests for SchemaValidScanner."""

import pytest

from ai_artifact_risk_validator.models import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.schema_valid import SchemaValidScanner


@pytest.fixture
def scanner() -> SchemaValidScanner:
    return SchemaValidScanner()


class TestScannerProperties:
    """Test scanner metadata properties."""

    def test_name(self, scanner: SchemaValidScanner):
        assert scanner.name == ScannerModule.SCHEMA_VALID

    def test_applicable_artifact_types(self, scanner: SchemaValidScanner):
        expected = [
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.INSTRUCTION,
            ArtifactType.PLUGIN,
            ArtifactType.API_SCHEMA,
        ]
        assert scanner.applicable_artifact_types == expected

    def test_detected_risk_ids(self, scanner: SchemaValidScanner):
        assert set(scanner.detected_risk_ids) == {"I-Q1", "ST-Q1", "MCP-Q1", "API-Q1", "PL-Q1"}

    def test_is_available(self, scanner: SchemaValidScanner):
        assert scanner.is_available() is True


class TestInstructionValidation:
    """Tests for I-Q1: instruction frontmatter schema validation."""

    def test_valid_instruction_no_findings(self, scanner: SchemaValidScanner):
        content = '---\napplyTo: "**/*.py"\n---\n\n# Instructions\nUse type hints.\n'
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "copilot-instructions.md")
        assert findings == []

    def test_missing_frontmatter(self, scanner: SchemaValidScanner):
        content = "# Instructions\nJust some text without frontmatter.\n"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 1
        assert findings[0].id == "I-Q1"
        assert "missing" in findings[0].description.lower()

    def test_invalid_yaml_frontmatter(self, scanner: SchemaValidScanner):
        content = "---\napplyTo: [unclosed bracket\n---\n\n# Bad yaml\n"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 1
        assert findings[0].id == "I-Q1"
        assert "invalid YAML" in findings[0].description

    def test_frontmatter_not_a_mapping(self, scanner: SchemaValidScanner):
        content = "---\n- item1\n- item2\n---\n\n# List frontmatter\n"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 1
        assert findings[0].id == "I-Q1"
        assert "mapping" in findings[0].description.lower()

    def test_missing_apply_to_field(self, scanner: SchemaValidScanner):
        content = "---\ntitle: My Instructions\n---\n\n# Instructions\n"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 1
        assert findings[0].id == "I-Q1"
        assert "applyTo" in findings[0].description

    def test_non_md_file_skipped(self, scanner: SchemaValidScanner):
        content = "some content"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.txt")
        assert findings == []

    def test_confidence_is_deterministic(self, scanner: SchemaValidScanner):
        content = "# No frontmatter\n"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "instructions.md")
        assert len(findings) == 1
        assert findings[0].confidence == 1.0


class TestSteeringValidation:
    """Tests for ST-Q1: steering file schema validation."""

    def test_valid_steering_no_findings(self, scanner: SchemaValidScanner):
        content = "---\ninclusion: auto\npriority: 10\n---\n\n# Coding Style\nUse 4 spaces.\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/style.md")
        assert findings == []

    def test_missing_frontmatter(self, scanner: SchemaValidScanner):
        content = "# Steering rules\nSome rules without frontmatter.\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/rules.md")
        assert len(findings) == 1
        assert findings[0].id == "ST-Q1"

    def test_invalid_yaml_frontmatter(self, scanner: SchemaValidScanner):
        content = "---\ninclusion: {\n---\n\n# Bad\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/bad.md")
        assert len(findings) == 1
        assert findings[0].id == "ST-Q1"
        assert "invalid YAML" in findings[0].description

    def test_missing_inclusion_field(self, scanner: SchemaValidScanner):
        content = "---\npriority: 5\n---\n\n# Missing inclusion\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        assert len(findings) == 1
        assert findings[0].id == "ST-Q1"
        assert "inclusion" in findings[0].description

    def test_invalid_inclusion_value(self, scanner: SchemaValidScanner):
        content = "---\ninclusion: invalid_value\n---\n\n# Bad inclusion\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        assert len(findings) == 1
        assert findings[0].id == "ST-Q1"
        assert "invalid_value" in findings[0].description.lower()

    def test_valid_inclusion_manual(self, scanner: SchemaValidScanner):
        content = "---\ninclusion: manual\n---\n\n# Manual steering\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        assert findings == []

    def test_valid_inclusion_always(self, scanner: SchemaValidScanner):
        content = "---\ninclusion: always\n---\n\n# Always steering\n"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/test.md")
        assert findings == []

    def test_non_md_file_skipped(self, scanner: SchemaValidScanner):
        content = "inclusion: auto"
        findings = scanner.scan(content, ArtifactType.STEERING, ".kiro/steering/config.yaml")
        assert findings == []


class TestMCPValidation:
    """Tests for MCP-Q1: MCP server configuration schema validation."""

    def test_valid_mcp_config(self, scanner: SchemaValidScanner):
        content = '{"tools": [{"name": "read_file"}], "transport": "stdio"}'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert findings == []

    def test_valid_mcp_with_mcp_servers(self, scanner: SchemaValidScanner):
        content = '{"mcpServers": {"my-server": {"command": "node"}}}'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert findings == []

    def test_invalid_json(self, scanner: SchemaValidScanner):
        content = '{"tools": [broken json'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 1
        assert findings[0].id == "MCP-Q1"
        assert "invalid JSON" in findings[0].description

    def test_non_object_root(self, scanner: SchemaValidScanner):
        content = '["not", "an", "object"]'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 1
        assert findings[0].id == "MCP-Q1"
        assert "object" in findings[0].description.lower()

    def test_missing_required_fields(self, scanner: SchemaValidScanner):
        content = '{"name": "my-mcp", "version": "1.0"}'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 1
        assert findings[0].id == "MCP-Q1"
        assert "missing required fields" in findings[0].description.lower()

    def test_invalid_transport_type(self, scanner: SchemaValidScanner):
        content = '{"tools": [], "transport": "invalid_transport"}'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 1
        assert findings[0].id == "MCP-Q1"
        assert "invalid_transport" in findings[0].description.lower()

    def test_valid_transport_sse(self, scanner: SchemaValidScanner):
        content = '{"tools": [], "transport": "sse"}'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert findings == []

    def test_tools_wrong_type(self, scanner: SchemaValidScanner):
        content = '{"tools": "not_a_list", "transport": "stdio"}'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert len(findings) == 1
        assert findings[0].id == "MCP-Q1"
        assert "tools" in findings[0].description.lower()

    def test_yaml_mcp_invalid(self, scanner: SchemaValidScanner):
        content = "tools:\n  - name: [unclosed\n"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.yaml")
        assert len(findings) == 1
        assert findings[0].id == "MCP-Q1"

    def test_yaml_mcp_non_mapping(self, scanner: SchemaValidScanner):
        content = "- item1\n- item2\n"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.yml")
        assert len(findings) == 1
        assert findings[0].id == "MCP-Q1"

    def test_severity_is_medium(self, scanner: SchemaValidScanner):
        content = '{"broken": true}'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert findings[0].severity_score == 5


class TestAPISchemaValidation:
    """Tests for API-Q1: OpenAPI and JSON Schema validation."""

    def test_valid_openapi_spec(self, scanner: SchemaValidScanner):
        content = """{
            "openapi": "3.0.3",
            "info": {"title": "My API", "version": "1.0.0"},
            "paths": {"/users": {"get": {"summary": "Get users"}}}
        }"""
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "openapi.json")
        assert findings == []

    def test_valid_openapi_yaml(self, scanner: SchemaValidScanner):
        content = "openapi: '3.0.3'\ninfo:\n  title: My API\n  version: '1.0.0'\npaths:\n  /users:\n    get:\n      summary: Get users\n"
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "openapi.yaml")
        assert findings == []

    def test_invalid_json_api_schema(self, scanner: SchemaValidScanner):
        content = '{"openapi": "3.0.3", bad json'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.json")
        assert len(findings) == 1
        assert findings[0].id == "API-Q1"

    def test_invalid_yaml_api_schema(self, scanner: SchemaValidScanner):
        content = "openapi: 3.0.3\ninfo: {\n"
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.yaml")
        assert len(findings) == 1
        assert findings[0].id == "API-Q1"

    def test_missing_info_object(self, scanner: SchemaValidScanner):
        content = '{"openapi": "3.0.3", "paths": {}}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.json")
        assert any("info" in f.description.lower() for f in findings)

    def test_missing_paths_object(self, scanner: SchemaValidScanner):
        content = '{"openapi": "3.0.3", "info": {"title": "API", "version": "1.0"}}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.json")
        assert any("paths" in f.description.lower() for f in findings)

    def test_missing_info_title_and_version(self, scanner: SchemaValidScanner):
        content = '{"openapi": "3.0.3", "info": {"description": "test"}, "paths": {}}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.json")
        assert any(
            "title" in f.description.lower() or "version" in f.description.lower() for f in findings
        )

    def test_invalid_openapi_version_format(self, scanner: SchemaValidScanner):
        content = '{"openapi": "three", "info": {"title": "API", "version": "1.0"}, "paths": {}}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.json")
        assert any("version format" in f.description.lower() for f in findings)

    def test_missing_schema_identifier(self, scanner: SchemaValidScanner):
        content = '{"type": "object", "properties": {}}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "schema.json")
        assert any("missing identifying marker" in f.description.lower() for f in findings)

    def test_valid_json_schema(self, scanner: SchemaValidScanner):
        content = '{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "schema.json")
        assert findings == []

    def test_empty_schema_ref(self, scanner: SchemaValidScanner):
        content = '{"$schema": "", "type": "object"}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "schema.json")
        assert len(findings) == 1
        assert findings[0].id == "API-Q1"
        assert "$schema" in findings[0].description.lower()

    def test_non_object_root(self, scanner: SchemaValidScanner):
        content = '"just a string"'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "schema.json")
        assert len(findings) == 1
        assert findings[0].id == "API-Q1"

    def test_swagger_2_spec(self, scanner: SchemaValidScanner):
        content = '{"swagger": "2.0", "info": {"title": "Old API", "version": "1.0"}, "paths": {}}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "swagger.json")
        assert findings == []

    def test_openapi_with_webhooks(self, scanner: SchemaValidScanner):
        content = '{"openapi": "3.1.0", "info": {"title": "Webhooks API", "version": "1.0"}, "webhooks": {}}'
        findings = scanner.scan(content, ArtifactType.API_SCHEMA, "api.json")
        assert findings == []


class TestPluginValidation:
    """Tests for PL-Q1: plugin manifest schema validation."""

    def test_valid_plugin_manifest(self, scanner: SchemaValidScanner):
        content = '{"name": "my-plugin", "version": "1.0.0", "contributes": {"commands": []}}'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        assert findings == []

    def test_invalid_json(self, scanner: SchemaValidScanner):
        content = "{name: invalid}"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        assert len(findings) == 1
        assert findings[0].id == "PL-Q1"

    def test_non_object_root(self, scanner: SchemaValidScanner):
        content = "42"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        assert len(findings) == 1
        assert findings[0].id == "PL-Q1"

    def test_missing_name_and_version(self, scanner: SchemaValidScanner):
        content = '{"description": "a plugin"}'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        assert len(findings) == 1
        assert findings[0].id == "PL-Q1"
        assert "name" in findings[0].description.lower()
        assert "version" in findings[0].description.lower()

    def test_missing_contributes_for_plugin_like_manifest(self, scanner: SchemaValidScanner):
        content = '{"name": "my-plugin", "version": "1.0.0", "main": "./out/extension.js", "engines": {"vscode": "^1.60.0"}}'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        assert len(findings) == 1
        assert findings[0].id == "PL-Q1"
        assert "contributes" in findings[0].description.lower()

    def test_non_json_file_skipped(self, scanner: SchemaValidScanner):
        content = "some plugin code"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "plugin.ts")
        assert findings == []

    def test_valid_manifest_with_activation_events(self, scanner: SchemaValidScanner):
        content = (
            '{"name": "my-plugin", "version": "1.0.0", "activationEvents": ["onCommand:myCommand"]}'
        )
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        assert findings == []


class TestScannerModuleField:
    """Tests that all findings have correct scanner module."""

    def test_all_findings_have_schema_valid_module(self, scanner: SchemaValidScanner):
        # Generate findings from multiple artifact types
        all_findings = []
        all_findings.extend(scanner.scan("# no frontmatter", ArtifactType.INSTRUCTION, "i.md"))
        all_findings.extend(scanner.scan("# no frontmatter", ArtifactType.STEERING, "s.md"))
        all_findings.extend(scanner.scan('{"broken": true}', ArtifactType.MCP, "mcp.json"))
        all_findings.extend(scanner.scan('{"type": "object"}', ArtifactType.API_SCHEMA, "a.json"))
        all_findings.extend(scanner.scan('{"description": "x"}', ArtifactType.PLUGIN, "p.json"))

        assert len(all_findings) > 0
        for finding in all_findings:
            assert finding.scanner_module == ScannerModule.SCHEMA_VALID
            assert finding.confidence >= 0.99
