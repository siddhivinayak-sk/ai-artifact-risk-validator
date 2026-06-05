"""Risk definition model for the AI Artifact Risk Validator.

Defines the RiskDefinition Pydantic model representing a single risk
in the taxonomy catalog (190 total risks: 163 artifact-specific + 27 cross-cutting).
"""

from pydantic import BaseModel, Field

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)


class RiskDefinition(BaseModel):
    """Schema for a risk definition in the taxonomy.

    Each risk definition captures the full metadata needed by the Risk Registry
    to catalog, query, and report on individual risks detected by scanner modules.
    """

    id: str = Field(..., description="Unique risk ID, e.g. P-S1, MCP-S3")
    title: str
    artifact_types: list[ArtifactType]
    category: RiskCategory
    severity_score: int = Field(..., ge=1, le=10)
    severity_label: SeverityLabel
    priority: Priority
    gate_action: GateAction
    description: str
    examples: list[str] = Field(..., min_length=1)
    mitigation: list[str] = Field(..., min_length=1)
    detection_mechanisms: list[str] = Field(..., min_length=1)
    scanner_modules: list[ScannerModule] = Field(..., min_length=1)
    owasp_refs: list[str] = Field(default_factory=list)
    cwe_refs: list[str] = Field(default_factory=list)
