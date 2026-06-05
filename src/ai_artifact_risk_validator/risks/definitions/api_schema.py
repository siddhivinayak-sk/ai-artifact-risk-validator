"""Risk definitions for API Schema artifacts (API-S1 through API-Q1).

Contains 3 risks covering security and quality categories
for OpenAPI schemas, JSON Schema definitions, and tool schema files.
"""

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.risk import RiskDefinition

RISKS: list[RiskDefinition] = [
    # ===== Security Risks (API-S1 to API-S2) =====
    RiskDefinition(
        id="API-S1",
        title="Injection via API Schema Examples",
        artifact_types=[ArtifactType.API_SCHEMA],
        category=RiskCategory.SECURITY,
        severity_score=7,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        description="API schema examples contain patterns that could be used for injection when loaded into AI context.",
        examples=["OpenAPI example values containing injection payloads", "Schema default values with override instructions"],
        mitigation=["Sanitize schema examples", "Validate example values", "Use safe placeholder data in schemas"],
        detection_mechanisms=["Injection pattern detection in schema examples", "Default value analysis"],
        scanner_modules=[ScannerModule.INJECTION_DET],
        owasp_refs=["LLM01:2025 Prompt Injection"],
        cwe_refs=["CWE-74"],
    ),
    RiskDefinition(
        id="API-S2",
        title="Overly Permissive API Schema",
        artifact_types=[ArtifactType.API_SCHEMA],
        category=RiskCategory.SECURITY,
        severity_score=6,
        severity_label=SeverityLabel.MEDIUM,
        priority=Priority.P2,
        gate_action=GateAction.WARN,
        description="API schema defines overly permissive input types that allow dangerous payloads.",
        examples=["'additionalProperties: true' on sensitive endpoints", "No input validation constraints defined"],
        mitigation=["Restrict input types", "Add validation constraints", "Disable additional properties on sensitive schemas"],
        detection_mechanisms=["Schema permissiveness analysis", "Input constraint validation"],
        scanner_modules=[ScannerModule.PERM_AUDIT],
        owasp_refs=["LLM06:2025 Excessive Agency"],
        cwe_refs=["CWE-20"],
    ),
    # ===== Quality Risks (API-Q1) =====
    RiskDefinition(
        id="API-Q1",
        title="Invalid API Schema Structure",
        artifact_types=[ArtifactType.API_SCHEMA],
        category=RiskCategory.QUALITY,
        severity_score=5,
        severity_label=SeverityLabel.MEDIUM,
        priority=Priority.P2,
        gate_action=GateAction.WARN,
        description="API schema does not conform to the expected specification (OpenAPI, JSON Schema).",
        examples=["Invalid OpenAPI 3.0 structure", "Missing required $schema reference"],
        mitigation=["Validate schema against specification", "Fix structural violations", "Use schema validation tools"],
        detection_mechanisms=["OpenAPI spec validation", "JSON Schema meta-schema validation"],
        scanner_modules=[ScannerModule.SCHEMA_VALID],
        owasp_refs=[],
        cwe_refs=[],
    ),
]
