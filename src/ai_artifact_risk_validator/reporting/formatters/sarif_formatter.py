"""SARIF v2.1.0 output formatter for scan reports.

Converts a ScanReport into a SARIF v2.1.0 compliant JSON string suitable for
ingestion by GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer, and
other SARIF-consuming tools.
"""

from __future__ import annotations

import json
from typing import Any

import ai_artifact_risk_validator
from ai_artifact_risk_validator.models.enums import GateAction
from ai_artifact_risk_validator.models.findings import ScanFinding
from ai_artifact_risk_validator.models.report import ScanReport
from ai_artifact_risk_validator.reporting.formatters.sarif_models import (
    SarifArtifactLocation,
    SarifAutomationDetails,
    SarifDefaultConfiguration,
    SarifDocument,
    SarifHelp,
    SarifInvocation,
    SarifMessage,
    SarifPhysicalLocation,
    SarifRegion,
    SarifReportingDescriptor,
    SarifResult,
    SarifResultProperties,
    SarifRun,
    SarifSuppression,
    SarifTool,
    SarifToolDriver,
)

_SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "ai-artifact-risk-validator"
_TOOL_INFO_URI = "https://github.com/example/ai-artifact-risk-validator"

_GATE_ACTION_TO_LEVEL: dict[GateAction, str] = {
    GateAction.BLOCK: "error",
    GateAction.WARN: "warning",
    GateAction.INFO: "note",
}


def _normalize_path(path: str) -> str:
    """Normalize a file path by replacing backslashes with forward slashes."""
    return path.replace("\\", "/")


def _format_timestamp_utc(report: ScanReport) -> str:
    """Format scan_timestamp as ISO 8601 UTC string: YYYY-MM-DDTHH:MM:SSZ."""
    ts = report.scan_timestamp
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_rules(
    findings: list[ScanFinding],
) -> tuple[list[SarifReportingDescriptor], dict[str, int]]:
    """Build rule descriptors from distinct finding IDs, ordered by first appearance.

    Returns:
        A tuple of (rules list, mapping of rule_id -> zero-based index).
    """
    rule_index_map: dict[str, int] = {}
    rules: list[SarifReportingDescriptor] = []

    for finding in findings:
        if finding.id in rule_index_map:
            continue

        rule_index_map[finding.id] = len(rules)

        help_field: SarifHelp | None = None
        if finding.remediation.strip():
            help_field = SarifHelp(text=finding.remediation)

        descriptor = SarifReportingDescriptor(
            id=finding.id,
            shortDescription=SarifMessage(text=finding.title),
            fullDescription=SarifMessage(text=finding.description),
            defaultConfiguration=SarifDefaultConfiguration(
                level=_GATE_ACTION_TO_LEVEL[finding.gate_action]
            ),
            help=help_field,
        )
        rules.append(descriptor)

    return rules, rule_index_map


def _build_physical_location(finding: ScanFinding) -> SarifPhysicalLocation:
    """Convert a ScanFinding's location to a SARIF physical location."""
    normalized_path = _normalize_path(finding.artifact_path)
    artifact_location = SarifArtifactLocation(uri=normalized_path)

    region: SarifRegion | None = None
    if finding.location.line is not None:
        region = SarifRegion(
            startLine=finding.location.line,
            endLine=finding.location.end_line,
        )

    return SarifPhysicalLocation(
        artifactLocation=artifact_location,
        region=region,
    )


def _build_suppressions(finding: ScanFinding) -> list[SarifSuppression] | None:
    """Build suppressions array if finding is marked as false positive."""
    if finding.false_positive:
        return [
            SarifSuppression(
                kind="inSource",
                justification="Marked as false positive by validator",
            )
        ]
    return None


def _build_result(finding: ScanFinding, rule_index_map: dict[str, int]) -> SarifResult:
    """Map a ScanFinding to a SarifResult instance."""
    physical_location = _build_physical_location(finding)

    properties = SarifResultProperties(
        severity_score=finding.severity_score,
        confidence=finding.confidence,
        category=finding.category.value,
        scanner_module=finding.scanner_module.value,
        evidence=finding.evidence,
    )

    return SarifResult(
        ruleId=finding.id,
        ruleIndex=rule_index_map[finding.id],
        level=_GATE_ACTION_TO_LEVEL[finding.gate_action],
        message=SarifMessage(text=finding.description),
        locations=[physical_location],
        properties=properties,
        suppressions=_build_suppressions(finding),
    )


def _build_invocation(report: ScanReport) -> SarifInvocation:
    """Build SARIF invocation metadata from the scan report."""
    normalized_path = _normalize_path(report.artifact_path)
    return SarifInvocation(
        executionSuccessful=len(report.errors) == 0,
        commandLine=f"ai-artifact-validator verify {normalized_path}",
        startTimeUtc=_format_timestamp_utc(report),
    )


def format_sarif(report: ScanReport) -> str:
    """Format a ScanReport as a SARIF v2.1.0 JSON document.

    Args:
        report: The ScanReport to format.

    Returns:
        A SARIF v2.1.0 compliant JSON string with sorted keys and 2-space indent.

    Raises:
        ValueError: If the report contains data that cannot be serialized to
            valid SARIF.
    """
    try:
        rules, rule_index_map = _build_rules(report.findings)

        results = [_build_result(finding, rule_index_map) for finding in report.findings]

        invocation = _build_invocation(report)

        tool_driver = SarifToolDriver(
            name=_TOOL_NAME,
            version=ai_artifact_risk_validator.__version__,
            informationUri=_TOOL_INFO_URI,
            rules=rules,
        )

        run = SarifRun(
            tool=SarifTool(driver=tool_driver),
            invocations=[invocation],
            results=results,
            automationDetails=SarifAutomationDetails(id=report.scan_id),
        )

        document = SarifDocument(
            **{"$schema": _SARIF_SCHEMA_URL},
            version=_SARIF_VERSION,
            runs=[run],
        )

        data: dict[str, Any] = document.model_dump(by_alias=True, exclude_none=True)
        return json.dumps(data, sort_keys=True, indent=2)

    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"Failed to serialize ScanReport to SARIF: {exc}") from exc
