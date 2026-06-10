"""Pydantic v2 models for SARIF v2.1.0 document structure.

These internal models provide type-safe construction and serialization of SARIF
documents. All models use Field(alias=...) for camelCase SARIF keys and
ConfigDict(populate_by_name=True) to allow population by Python field name.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SarifMessage(BaseModel):
    """SARIF message object containing a text string."""

    model_config = ConfigDict(populate_by_name=True)

    text: str


class SarifArtifactLocation(BaseModel):
    """SARIF artifact location referencing a file URI."""

    model_config = ConfigDict(populate_by_name=True)

    uri: str


class SarifRegion(BaseModel):
    """SARIF region specifying line numbers within a file."""

    model_config = ConfigDict(populate_by_name=True)

    start_line: int = Field(alias="startLine")
    end_line: int | None = Field(default=None, alias="endLine")


class SarifPhysicalLocation(BaseModel):
    """SARIF physical location combining artifact location and region."""

    model_config = ConfigDict(populate_by_name=True)

    artifact_location: SarifArtifactLocation = Field(alias="artifactLocation")
    region: SarifRegion | None = None


class SarifSuppression(BaseModel):
    """SARIF suppression indicating a finding is suppressed (false positive)."""

    model_config = ConfigDict(populate_by_name=True)

    kind: str
    justification: str


class SarifResultProperties(BaseModel):
    """Properties bag attached to each SARIF result with enrichment data."""

    model_config = ConfigDict(populate_by_name=True)

    severity_score: int
    confidence: float
    category: str
    scanner_module: str
    evidence: str


class SarifResult(BaseModel):
    """SARIF result representing a single finding."""

    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(alias="ruleId")
    rule_index: int = Field(alias="ruleIndex")
    level: str
    message: SarifMessage
    locations: list[SarifPhysicalLocation]
    properties: SarifResultProperties
    suppressions: list[SarifSuppression] | None = None


class SarifDefaultConfiguration(BaseModel):
    """SARIF default configuration for a reporting descriptor."""

    model_config = ConfigDict(populate_by_name=True)

    level: str


class SarifHelp(BaseModel):
    """SARIF help object containing remediation text."""

    model_config = ConfigDict(populate_by_name=True)

    text: str


class SarifReportingDescriptor(BaseModel):
    """SARIF reporting descriptor (rule) with metadata."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    short_description: SarifMessage = Field(alias="shortDescription")
    full_description: SarifMessage = Field(alias="fullDescription")
    default_configuration: SarifDefaultConfiguration = Field(alias="defaultConfiguration")
    help: SarifHelp | None = None


class SarifToolDriver(BaseModel):
    """SARIF tool driver containing name, version, and rules."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    version: str
    information_uri: str = Field(alias="informationUri")
    rules: list[SarifReportingDescriptor]


class SarifTool(BaseModel):
    """SARIF tool object wrapping the driver."""

    model_config = ConfigDict(populate_by_name=True)

    driver: SarifToolDriver


class SarifInvocation(BaseModel):
    """SARIF invocation metadata for a scan execution."""

    model_config = ConfigDict(populate_by_name=True)

    execution_successful: bool = Field(alias="executionSuccessful")
    command_line: str = Field(alias="commandLine")
    start_time_utc: str = Field(alias="startTimeUtc")


class SarifAutomationDetails(BaseModel):
    """SARIF automation details identifying the run."""

    model_config = ConfigDict(populate_by_name=True)

    id: str


class SarifRun(BaseModel):
    """SARIF run containing tool, invocations, results, and automation details."""

    model_config = ConfigDict(populate_by_name=True)

    tool: SarifTool
    invocations: list[SarifInvocation]
    results: list[SarifResult]
    automation_details: SarifAutomationDetails = Field(alias="automationDetails")


class SarifDocument(BaseModel):
    """Top-level SARIF v2.1.0 document."""

    model_config = ConfigDict(populate_by_name=True)

    schema_uri: str = Field(alias="$schema")
    version: str
    runs: list[SarifRun]
