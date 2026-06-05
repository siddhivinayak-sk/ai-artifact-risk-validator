"""Report models for the AI Artifact Risk Validator.

Defines ScanSummary and ScanReport Pydantic models used to represent
the complete output of a validation run.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from ai_artifact_risk_validator.models.enums import ArtifactType, GateAction
from ai_artifact_risk_validator.models.findings import ScanFinding


class ScanSummary(BaseModel):
    """Aggregated metrics for a scan report.

    Contains counts by severity and category, the overall gate decision,
    and breakdown of findings by gate action type.
    """

    total_findings: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    gate_decision: GateAction
    blocking_findings: int
    warning_findings: int
    info_findings: int


class ScanReport(BaseModel):
    """Complete scan report for a validation run.

    Contains all findings, summary metrics, and metadata about the scan
    including the scanned path, timestamp, and any errors encountered.
    """

    scan_id: str
    artifact_path: str
    artifact_type: Optional[ArtifactType] = None  # None for directory scans
    scan_timestamp: datetime
    scanner_version: str
    findings: list[ScanFinding]
    summary: ScanSummary
    errors: list[str] = Field(default_factory=list)
