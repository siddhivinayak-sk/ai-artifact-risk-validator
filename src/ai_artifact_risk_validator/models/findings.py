"""Finding models for the AI Artifact Risk Validator.

Defines FindingLocation and ScanFinding Pydantic models used to represent
individual risk detections produced by scanner modules.
"""

from datetime import datetime

from pydantic import BaseModel, Field

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)


class FindingLocation(BaseModel):
    """Specifies where in a file a finding was detected."""

    line: int | None = None
    end_line: int | None = None
    section: str | None = None
    offset: int | None = None


class ScanFinding(BaseModel):
    """A single detected risk instance produced by a scanner.

    Each finding represents one risk detected in an artifact, with full
    metadata including severity, confidence, location, and remediation guidance.
    """

    id: str = Field(
        ..., pattern=r"^[A-Z]+-[A-Z]?[0-9]+$", description="Risk ID (e.g. P-S1, MCP-S3)"
    )
    artifact_type: ArtifactType
    artifact_path: str
    severity_score: int = Field(..., ge=1, le=10)
    severity_label: SeverityLabel
    priority: Priority
    gate_action: GateAction
    category: RiskCategory
    title: str
    description: str
    location: FindingLocation
    evidence: str = Field(..., description="Text/pattern that triggered the finding")
    confidence: float = Field(..., ge=0.0, le=1.0)
    scanner_module: ScannerModule
    remediation: str
    references: list[str] = Field(default_factory=list)
    false_positive: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)
