"""SchemaValid scanner module.

Validates AI artifacts against expected schemas including:
- YAML/JSON syntax validation
- OpenAPI spec structure validation
- YAML frontmatter structure checking in markdown files
- MCP server configuration schema validation
- Plugin manifest (package.json) schema validation
- JSON Schema $schema reference validation

Detects risk IDs: I-Q1, ST-Q1, MCP-Q1, API-Q1, PL-Q1
"""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from ai_artifact_risk_validator.models import (
    ArtifactType,
    FindingLocation,
    GateAction,
    Priority,
    RiskCategory,
    ScanFinding,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.scanners.base import BaseScanner

# Frontmatter regex: matches YAML between leading --- delimiters
_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)


class SchemaValidScanner(BaseScanner):
    """Scanner that validates artifact schema conformance.

    Performs deterministic schema validation checks on AI artifacts including
    YAML/JSON syntax, OpenAPI structure, frontmatter fields, MCP config,
    and plugin manifests.
    """

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.SCHEMA_VALID

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.INSTRUCTION,
            ArtifactType.PLUGIN,
            ArtifactType.API_SCHEMA,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["I-Q1", "ST-Q1", "MCP-Q1", "API-Q1", "PL-Q1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for schema validation issues.

        Routes to the appropriate validation method based on artifact type.
        """
        findings: list[ScanFinding] = []

        if artifact_type == ArtifactType.INSTRUCTION:
            findings.extend(self._validate_instruction(artifact_content, artifact_path))
        elif artifact_type == ArtifactType.STEERING:
            findings.extend(self._validate_steering(artifact_content, artifact_path))
        elif artifact_type == ArtifactType.MCP:
            findings.extend(self._validate_mcp(artifact_content, artifact_path))
        elif artifact_type == ArtifactType.API_SCHEMA:
            findings.extend(self._validate_api_schema(artifact_content, artifact_path))
        elif artifact_type == ArtifactType.PLUGIN:
            findings.extend(self._validate_plugin(artifact_content, artifact_path))

        return findings

    # ------------------------------------------------------------------
    # Instruction validation (I-Q1)
    # ------------------------------------------------------------------

    def _validate_instruction(self, content: str, path: str) -> list[ScanFinding]:
        """Validate instruction file frontmatter schema."""
        findings: list[ScanFinding] = []

        # Instruction files (.md) should have YAML frontmatter with applyTo
        if not path.lower().endswith(".md"):
            return findings

        match = _FRONTMATTER_RE.search(content)
        if match is None:
            # No frontmatter at all — schema issue
            findings.append(
                self._make_finding(
                    risk_id="I-Q1",
                    artifact_type=ArtifactType.INSTRUCTION,
                    artifact_path=path,
                    title="Invalid Instruction Schema",
                    description="Instruction file is missing YAML frontmatter.",
                    evidence="No YAML frontmatter block (---) found at start of file.",
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Add YAML frontmatter with required fields (e.g., applyTo).",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )
            return findings

        # Try parsing the frontmatter YAML
        raw_frontmatter = match.group(1)
        try:
            frontmatter = yaml.safe_load(raw_frontmatter)
        except yaml.YAMLError as exc:
            findings.append(
                self._make_finding(
                    risk_id="I-Q1",
                    artifact_type=ArtifactType.INSTRUCTION,
                    artifact_path=path,
                    title="Invalid Instruction Schema",
                    description=f"Instruction frontmatter contains invalid YAML: {exc}",
                    evidence=raw_frontmatter[:200],
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Fix YAML syntax errors in frontmatter.",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )
            return findings

        # Validate required fields
        if not isinstance(frontmatter, dict):
            findings.append(
                self._make_finding(
                    risk_id="I-Q1",
                    artifact_type=ArtifactType.INSTRUCTION,
                    artifact_path=path,
                    title="Invalid Instruction Schema",
                    description="Frontmatter must be a YAML mapping, got a scalar or list.",
                    evidence=raw_frontmatter[:200],
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Ensure frontmatter is a YAML mapping with key-value pairs.",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )
            return findings

        # Check for applyTo field (expected in instruction files)
        if "applyTo" not in frontmatter:
            findings.append(
                self._make_finding(
                    risk_id="I-Q1",
                    artifact_type=ArtifactType.INSTRUCTION,
                    artifact_path=path,
                    title="Invalid Instruction Schema",
                    description="Instruction frontmatter is missing required 'applyTo' field.",
                    evidence=f"Frontmatter keys: {list(frontmatter.keys())}",
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Add an 'applyTo' field specifying which files the instruction applies to.",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Steering validation (ST-Q1)
    # ------------------------------------------------------------------

    def _validate_steering(self, content: str, path: str) -> list[ScanFinding]:
        """Validate steering file frontmatter schema."""
        findings: list[ScanFinding] = []

        if not path.lower().endswith(".md"):
            return findings

        match = _FRONTMATTER_RE.search(content)
        if match is None:
            findings.append(
                self._make_finding(
                    risk_id="ST-Q1",
                    artifact_type=ArtifactType.STEERING,
                    artifact_path=path,
                    title="Invalid Steering Schema",
                    description="Steering file is missing YAML frontmatter.",
                    evidence="No YAML frontmatter block (---) found at start of file.",
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Add YAML frontmatter with required fields (e.g., inclusion).",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )
            return findings

        raw_frontmatter = match.group(1)
        try:
            frontmatter = yaml.safe_load(raw_frontmatter)
        except yaml.YAMLError as exc:
            findings.append(
                self._make_finding(
                    risk_id="ST-Q1",
                    artifact_type=ArtifactType.STEERING,
                    artifact_path=path,
                    title="Invalid Steering Schema",
                    description=f"Steering frontmatter contains invalid YAML: {exc}",
                    evidence=raw_frontmatter[:200],
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Fix YAML syntax errors in frontmatter.",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )
            return findings

        if not isinstance(frontmatter, dict):
            findings.append(
                self._make_finding(
                    risk_id="ST-Q1",
                    artifact_type=ArtifactType.STEERING,
                    artifact_path=path,
                    title="Invalid Steering Schema",
                    description="Frontmatter must be a YAML mapping.",
                    evidence=raw_frontmatter[:200],
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Ensure frontmatter is a YAML mapping with key-value pairs.",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )
            return findings

        # Steering files require 'inclusion' field
        if "inclusion" not in frontmatter:
            findings.append(
                self._make_finding(
                    risk_id="ST-Q1",
                    artifact_type=ArtifactType.STEERING,
                    artifact_path=path,
                    title="Invalid Steering Schema",
                    description="Steering frontmatter is missing required 'inclusion' field.",
                    evidence=f"Frontmatter keys: {list(frontmatter.keys())}",
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation="Add an 'inclusion' field (e.g., 'auto', 'manual') to steering frontmatter.",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )

        # Validate inclusion value if present
        valid_inclusion_values = {"auto", "manual", "always"}
        inclusion_val = frontmatter.get("inclusion")
        if inclusion_val is not None and str(inclusion_val).lower() not in valid_inclusion_values:
            findings.append(
                self._make_finding(
                    risk_id="ST-Q1",
                    artifact_type=ArtifactType.STEERING,
                    artifact_path=path,
                    title="Invalid Steering Schema",
                    description=f"Invalid 'inclusion' value: '{inclusion_val}'. Expected one of: {sorted(valid_inclusion_values)}.",
                    evidence=f"inclusion: {inclusion_val}",
                    location=FindingLocation(line=1, section="frontmatter"),
                    remediation=f"Use a valid inclusion value: {sorted(valid_inclusion_values)}.",
                    severity_score=4,
                    severity_label=SeverityLabel.LOW,
                    priority=Priority.P3,
                    gate_action=GateAction.INFO,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # MCP server config validation (MCP-Q1)
    # ------------------------------------------------------------------

    def _validate_mcp(self, content: str, path: str) -> list[ScanFinding]:
        """Validate MCP server configuration schema."""
        findings: list[ScanFinding] = []
        lower_path = path.lower()

        # MCP configs are typically JSON files (mcp.json)
        if lower_path.endswith(".json"):
            findings.extend(self._validate_mcp_json(content, path))
        elif lower_path.endswith((".yaml", ".yml")):
            findings.extend(self._validate_mcp_yaml(content, path))

        return findings

    def _validate_mcp_json(self, content: str, path: str) -> list[ScanFinding]:
        """Validate MCP JSON configuration."""
        findings: list[ScanFinding] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            findings.append(
                self._make_finding(
                    risk_id="MCP-Q1",
                    artifact_type=ArtifactType.MCP,
                    artifact_path=path,
                    title="Invalid MCP Schema Definition",
                    description=f"MCP configuration contains invalid JSON: {exc}",
                    evidence=content[:200],
                    location=FindingLocation(line=exc.lineno, section="root"),
                    remediation="Fix JSON syntax errors in MCP configuration.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )
            return findings

        if not isinstance(data, dict):
            findings.append(
                self._make_finding(
                    risk_id="MCP-Q1",
                    artifact_type=ArtifactType.MCP,
                    artifact_path=path,
                    title="Invalid MCP Schema Definition",
                    description="MCP configuration root must be a JSON object.",
                    evidence=f"Root type: {type(data).__name__}",
                    location=FindingLocation(line=1, section="root"),
                    remediation="Ensure the MCP configuration is a JSON object at the root level.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )
            return findings

        # Check for required MCP fields: tools or transport
        has_tools = "tools" in data or "mcpServers" in data
        has_transport = "transport" in data

        if not has_tools and not has_transport:
            findings.append(
                self._make_finding(
                    risk_id="MCP-Q1",
                    artifact_type=ArtifactType.MCP,
                    artifact_path=path,
                    title="Invalid MCP Schema Definition",
                    description="MCP configuration is missing required fields ('tools'/'mcpServers' or 'transport').",
                    evidence=f"Top-level keys: {list(data.keys())}",
                    location=FindingLocation(line=1, section="root"),
                    remediation="Add required MCP fields: 'tools' or 'mcpServers' for tool definitions, 'transport' for connection config.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        # Validate transport field if present
        if has_transport:
            transport = data.get("transport")
            valid_transports = {"stdio", "sse", "http", "streamable-http"}
            if isinstance(transport, str) and transport.lower() not in valid_transports:
                findings.append(
                    self._make_finding(
                        risk_id="MCP-Q1",
                        artifact_type=ArtifactType.MCP,
                        artifact_path=path,
                        title="Invalid MCP Schema Definition",
                        description=f"Invalid transport type: '{transport}'. Expected one of: {sorted(valid_transports)}.",
                        evidence=f"transport: {transport}",
                        location=FindingLocation(line=1, section="transport"),
                        remediation=f"Use a valid transport type: {sorted(valid_transports)}.",
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )

        # Validate tools structure if present
        tools = data.get("tools")
        if tools is not None and not isinstance(tools, (list, dict)):
            findings.append(
                self._make_finding(
                    risk_id="MCP-Q1",
                    artifact_type=ArtifactType.MCP,
                    artifact_path=path,
                    title="Invalid MCP Schema Definition",
                    description="'tools' field must be an array or object.",
                    evidence=f"tools type: {type(tools).__name__}",
                    location=FindingLocation(line=1, section="tools"),
                    remediation="Define 'tools' as an array of tool definitions or a mapping.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        return findings

    def _validate_mcp_yaml(self, content: str, path: str) -> list[ScanFinding]:
        """Validate MCP YAML configuration."""
        findings: list[ScanFinding] = []

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            findings.append(
                self._make_finding(
                    risk_id="MCP-Q1",
                    artifact_type=ArtifactType.MCP,
                    artifact_path=path,
                    title="Invalid MCP Schema Definition",
                    description=f"MCP configuration contains invalid YAML: {exc}",
                    evidence=content[:200],
                    location=FindingLocation(line=1, section="root"),
                    remediation="Fix YAML syntax errors in MCP configuration.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )
            return findings

        if not isinstance(data, dict):
            findings.append(
                self._make_finding(
                    risk_id="MCP-Q1",
                    artifact_type=ArtifactType.MCP,
                    artifact_path=path,
                    title="Invalid MCP Schema Definition",
                    description="MCP configuration root must be a YAML mapping.",
                    evidence=f"Root type: {type(data).__name__}"
                    if data is not None
                    else "Empty document",
                    location=FindingLocation(line=1, section="root"),
                    remediation="Ensure the MCP configuration is a YAML mapping at the root level.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # API / OpenAPI schema validation (API-Q1)
    # ------------------------------------------------------------------

    def _validate_api_schema(self, content: str, path: str) -> list[ScanFinding]:
        """Validate API schema (OpenAPI or JSON Schema) structure."""
        findings: list[ScanFinding] = []
        lower_path = path.lower()

        # Determine format and parse
        data: Any = None
        if lower_path.endswith(".json"):
            try:
                data = json.loads(content)
            except json.JSONDecodeError as exc:
                findings.append(
                    self._make_finding(
                        risk_id="API-Q1",
                        artifact_type=ArtifactType.API_SCHEMA,
                        artifact_path=path,
                        title="Invalid API Schema Structure",
                        description=f"API schema contains invalid JSON: {exc}",
                        evidence=content[:200],
                        location=FindingLocation(line=exc.lineno, section="root"),
                        remediation="Fix JSON syntax errors in the API schema file.",
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )
                return findings
        elif lower_path.endswith((".yaml", ".yml")):
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as exc:
                findings.append(
                    self._make_finding(
                        risk_id="API-Q1",
                        artifact_type=ArtifactType.API_SCHEMA,
                        artifact_path=path,
                        title="Invalid API Schema Structure",
                        description=f"API schema contains invalid YAML: {exc}",
                        evidence=content[:200],
                        location=FindingLocation(line=1, section="root"),
                        remediation="Fix YAML syntax errors in the API schema file.",
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )
                return findings
        else:
            # Try JSON first, then YAML
            try:
                data = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                try:
                    data = yaml.safe_load(content)
                except yaml.YAMLError:
                    findings.append(
                        self._make_finding(
                            risk_id="API-Q1",
                            artifact_type=ArtifactType.API_SCHEMA,
                            artifact_path=path,
                            title="Invalid API Schema Structure",
                            description="API schema file could not be parsed as JSON or YAML.",
                            evidence=content[:200],
                            location=FindingLocation(line=1, section="root"),
                            remediation="Ensure the API schema file contains valid JSON or YAML.",
                            severity_score=5,
                            severity_label=SeverityLabel.MEDIUM,
                            priority=Priority.P2,
                            gate_action=GateAction.WARN,
                        )
                    )
                    return findings

        if not isinstance(data, dict):
            findings.append(
                self._make_finding(
                    risk_id="API-Q1",
                    artifact_type=ArtifactType.API_SCHEMA,
                    artifact_path=path,
                    title="Invalid API Schema Structure",
                    description="API schema root must be an object/mapping.",
                    evidence=f"Root type: {type(data).__name__}"
                    if data is not None
                    else "Empty document",
                    location=FindingLocation(line=1, section="root"),
                    remediation="Ensure the API schema is a JSON object or YAML mapping at root.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )
            return findings

        # Check for OpenAPI spec markers
        is_openapi = "openapi" in data or "swagger" in data
        is_json_schema = "$schema" in data

        if is_openapi:
            findings.extend(self._validate_openapi_structure(data, path))
        elif is_json_schema:
            findings.extend(self._validate_json_schema_ref(data, path))
        else:
            # Neither OpenAPI nor JSON Schema identifiers found
            findings.append(
                self._make_finding(
                    risk_id="API-Q1",
                    artifact_type=ArtifactType.API_SCHEMA,
                    artifact_path=path,
                    title="Invalid API Schema Structure",
                    description="API schema is missing identifying marker ('openapi'/'swagger' or '$schema').",
                    evidence=f"Top-level keys: {list(data.keys())[:10]}",
                    location=FindingLocation(line=1, section="root"),
                    remediation="Add 'openapi' version field for OpenAPI specs or '$schema' for JSON Schema.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        return findings

    def _validate_openapi_structure(self, data: dict[str, Any], path: str) -> list[ScanFinding]:
        """Validate basic OpenAPI spec structure."""
        findings: list[ScanFinding] = []

        # OpenAPI 3.x requires: openapi, info, paths (or webhooks in 3.1)
        # Swagger 2.x requires: swagger, info, paths
        openapi_version = data.get("openapi") or data.get("swagger")

        if openapi_version is not None:
            # Validate version format
            version_str = str(openapi_version)
            if not re.match(r"^\d+\.\d+(\.\d+)?$", version_str):
                findings.append(
                    self._make_finding(
                        risk_id="API-Q1",
                        artifact_type=ArtifactType.API_SCHEMA,
                        artifact_path=path,
                        title="Invalid API Schema Structure",
                        description=f"Invalid OpenAPI version format: '{openapi_version}'.",
                        evidence=f"openapi: {openapi_version}",
                        location=FindingLocation(line=1, section="openapi"),
                        remediation="Use a valid semver version string (e.g., '3.0.3', '3.1.0').",
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )

        # Check for required 'info' object
        if "info" not in data:
            findings.append(
                self._make_finding(
                    risk_id="API-Q1",
                    artifact_type=ArtifactType.API_SCHEMA,
                    artifact_path=path,
                    title="Invalid API Schema Structure",
                    description="OpenAPI spec is missing required 'info' object.",
                    evidence=f"Top-level keys: {list(data.keys())[:10]}",
                    location=FindingLocation(line=1, section="info"),
                    remediation="Add an 'info' object with at minimum 'title' and 'version' fields.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )
        elif isinstance(data.get("info"), dict):
            info = data["info"]
            if "title" not in info or "version" not in info:
                missing = [f for f in ("title", "version") if f not in info]
                findings.append(
                    self._make_finding(
                        risk_id="API-Q1",
                        artifact_type=ArtifactType.API_SCHEMA,
                        artifact_path=path,
                        title="Invalid API Schema Structure",
                        description=f"OpenAPI 'info' object is missing required fields: {missing}.",
                        evidence=f"info keys: {list(info.keys())}",
                        location=FindingLocation(line=1, section="info"),
                        remediation=f"Add missing fields to 'info': {missing}.",
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )

        # Check for paths or webhooks (3.1+)
        if "paths" not in data and "webhooks" not in data:
            findings.append(
                self._make_finding(
                    risk_id="API-Q1",
                    artifact_type=ArtifactType.API_SCHEMA,
                    artifact_path=path,
                    title="Invalid API Schema Structure",
                    description="OpenAPI spec is missing 'paths' (or 'webhooks') object.",
                    evidence=f"Top-level keys: {list(data.keys())[:10]}",
                    location=FindingLocation(line=1, section="paths"),
                    remediation="Add a 'paths' object defining the API endpoints.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        return findings

    def _validate_json_schema_ref(self, data: dict[str, Any], path: str) -> list[ScanFinding]:
        """Validate JSON Schema $schema reference."""
        findings: list[ScanFinding] = []

        schema_ref = data.get("$schema", "")
        if not isinstance(schema_ref, str) or not schema_ref.strip():
            findings.append(
                self._make_finding(
                    risk_id="API-Q1",
                    artifact_type=ArtifactType.API_SCHEMA,
                    artifact_path=path,
                    title="Invalid API Schema Structure",
                    description="JSON Schema '$schema' field is empty or not a string.",
                    evidence=f"$schema: {schema_ref!r}",
                    location=FindingLocation(line=1, section="$schema"),
                    remediation="Set '$schema' to a valid JSON Schema draft URI (e.g., 'https://json-schema.org/draft/2020-12/schema').",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Plugin manifest validation (PL-Q1)
    # ------------------------------------------------------------------

    def _validate_plugin(self, content: str, path: str) -> list[ScanFinding]:
        """Validate plugin manifest (package.json) schema."""
        findings: list[ScanFinding] = []
        lower_path = path.lower()

        if not lower_path.endswith(".json"):
            return findings

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            findings.append(
                self._make_finding(
                    risk_id="PL-Q1",
                    artifact_type=ArtifactType.PLUGIN,
                    artifact_path=path,
                    title="Invalid Plugin Manifest Schema",
                    description=f"Plugin manifest contains invalid JSON: {exc}",
                    evidence=content[:200],
                    location=FindingLocation(line=exc.lineno, section="root"),
                    remediation="Fix JSON syntax errors in the plugin manifest.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )
            return findings

        if not isinstance(data, dict):
            findings.append(
                self._make_finding(
                    risk_id="PL-Q1",
                    artifact_type=ArtifactType.PLUGIN,
                    artifact_path=path,
                    title="Invalid Plugin Manifest Schema",
                    description="Plugin manifest root must be a JSON object.",
                    evidence=f"Root type: {type(data).__name__}",
                    location=FindingLocation(line=1, section="root"),
                    remediation="Ensure the plugin manifest is a JSON object.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )
            return findings

        # Required fields for a plugin manifest (package.json)
        required_fields = ["name", "version"]
        missing_required = [f for f in required_fields if f not in data]

        if missing_required:
            findings.append(
                self._make_finding(
                    risk_id="PL-Q1",
                    artifact_type=ArtifactType.PLUGIN,
                    artifact_path=path,
                    title="Invalid Plugin Manifest Schema",
                    description=f"Plugin manifest is missing required fields: {missing_required}.",
                    evidence=f"Top-level keys: {list(data.keys())[:10]}",
                    location=FindingLocation(line=1, section="root"),
                    remediation=f"Add missing required fields to the manifest: {missing_required}.",
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        # Check for plugin-specific fields (contributes, activationEvents, engines)
        # If it claims to be a plugin but is missing contributes
        if "main" in data or "publisher" in data or "engines" in data:
            if "contributes" not in data and "activationEvents" not in data:
                findings.append(
                    self._make_finding(
                        risk_id="PL-Q1",
                        artifact_type=ArtifactType.PLUGIN,
                        artifact_path=path,
                        title="Invalid Plugin Manifest Schema",
                        description="Plugin manifest is missing 'contributes' or 'activationEvents' fields.",
                        evidence=f"Top-level keys: {list(data.keys())[:10]}",
                        location=FindingLocation(line=1, section="contributes"),
                        remediation="Add 'contributes' defining the plugin's extension points or 'activationEvents'.",
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        *,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        title: str,
        description: str,
        evidence: str,
        location: FindingLocation,
        remediation: str,
        severity_score: int,
        severity_label: SeverityLabel,
        priority: Priority,
        gate_action: GateAction,
    ) -> ScanFinding:
        """Create a ScanFinding with schema validation confidence (0.99-1.0)."""
        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=severity_score,
            severity_label=severity_label,
            priority=priority,
            gate_action=gate_action,
            category=RiskCategory.QUALITY,
            title=title,
            description=description,
            location=location,
            evidence=evidence,
            confidence=1.0,  # Schema validation is deterministic
            scanner_module=ScannerModule.SCHEMA_VALID,
            remediation=remediation,
        )
