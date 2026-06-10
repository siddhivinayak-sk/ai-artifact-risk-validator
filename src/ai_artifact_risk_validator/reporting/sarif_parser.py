"""SARIF v2.1.0 deserialization into ScanReport objects.

Parses SARIF JSON documents back into ScanReport Pydantic models,
restoring findings, metadata, and summary from the SARIF structure.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.models.report import ScanReport, ScanSummary

# Reverse mapping from SARIF level to GateAction
_LEVEL_TO_GATE: dict[str, GateAction] = {
    "error": GateAction.BLOCK,
    "warning": GateAction.WARN,
    "note": GateAction.INFO,
}

# GateAction to Priority mapping
_GATE_TO_PRIORITY: dict[GateAction, Priority] = {
    GateAction.BLOCK: Priority.P0,
    GateAction.WARN: Priority.P2,
    GateAction.INFO: Priority.P4,
}


def _severity_label_from_score(score: int) -> SeverityLabel:
    """Determine severity label from a numeric score (1-10)."""
    if score >= 9:
        return SeverityLabel.CRITICAL
    if score >= 7:
        return SeverityLabel.HIGH
    if score >= 5:
        return SeverityLabel.MEDIUM
    if score >= 3:
        return SeverityLabel.LOW
    return SeverityLabel.INFORMATIONAL


class SarifParser:
    """Parses SARIF v2.1.0 JSON documents back into ScanReport objects.

    Validates SARIF document structure, extracts scan metadata, maps
    SARIF results back to ScanFinding objects, and recomputes the
    ScanSummary gate decision.
    """

    def parse(self, json_str: str) -> ScanReport:
        """Parse a SARIF JSON string into a ScanReport.

        Args:
            json_str: A SARIF v2.1.0 JSON string.

        Returns:
            A reconstructed ScanReport object.

        Raises:
            ValueError: If the JSON is malformed, missing required SARIF
                structure, or missing required properties bag keys on results.
        """
        data = self._parse_json(json_str)
        self._validate_structure(data)

        run = data["runs"][0]
        driver = run["tool"]["driver"]

        # Build rule lookup by ruleId
        rules: list[dict[str, Any]] = driver.get("rules", [])
        rule_map: dict[str, dict[str, Any]] = {r["id"]: r for r in rules}

        # Extract metadata
        scan_id = self._extract_scan_id(run)
        scan_timestamp = self._extract_timestamp(run)
        artifact_path = self._extract_artifact_path(run)
        scanner_version = driver.get("version", "")

        # Map results to findings
        findings = self._map_results(
            run.get("results", []),
            rule_map,
            artifact_path,
            scan_timestamp,
        )

        # Recompute summary
        summary = self._compute_summary(findings)

        return ScanReport(
            scan_id=scan_id,
            artifact_path=artifact_path,
            artifact_type=None,
            scan_timestamp=scan_timestamp,
            scanner_version=scanner_version,
            findings=findings,
            summary=summary,
            errors=[],
        )

    def _parse_json(self, json_str: str) -> dict[str, Any]:
        """Parse a JSON string, raising ValueError on failure."""
        try:
            data: dict[str, Any] = json.loads(json_str)
        except (json.JSONDecodeError, TypeError) as e:
            raise ValueError(f"Invalid JSON: {e}") from e
        return data

    def _validate_structure(self, data: dict[str, Any]) -> None:
        """Validate required SARIF document structure."""
        if "version" not in data:
            raise ValueError("Missing required SARIF field: version")
        if "runs" not in data:
            raise ValueError("Missing required SARIF field: runs")
        runs = data["runs"]
        if not isinstance(runs, list) or len(runs) == 0:
            raise ValueError("SARIF document has empty runs array")
        run = runs[0]
        tool = run.get("tool")
        if not tool or "driver" not in tool:
            raise ValueError("Missing required SARIF field: tool.driver")

    def _extract_scan_id(self, run: dict[str, Any]) -> str:
        """Extract scan_id from automationDetails.id."""
        automation = run.get("automationDetails", {})
        return str(automation.get("id", ""))

    def _extract_timestamp(self, run: dict[str, Any]) -> datetime:
        """Extract scan_timestamp from invocation startTimeUtc."""
        invocations = run.get("invocations", [])
        if invocations:
            time_str = invocations[0].get("startTimeUtc", "")
            if time_str:
                # Parse ISO 8601 UTC string
                clean = time_str.replace("Z", "+00:00")
                return datetime.fromisoformat(clean)
        return datetime.now(tz=timezone.utc)

    def _extract_artifact_path(self, run: dict[str, Any]) -> str:
        """Extract artifact_path from invocation commandLine or first result."""
        invocations = run.get("invocations", [])
        if invocations:
            cmd_line: str = invocations[0].get("commandLine", "")
            if "verify " in cmd_line:
                return cmd_line.split("verify ", 1)[1]

        # Fallback to first result location URI
        results = run.get("results", [])
        if results:
            locations = results[0].get("locations", [])
            if locations:
                artifact_loc = locations[0].get("artifactLocation", {})
                uri: str = artifact_loc.get("uri", "")
                return uri

        return ""

    def _map_results(
        self,
        results: list[dict[str, Any]],
        rule_map: dict[str, dict[str, Any]],
        default_artifact_path: str,
        scan_timestamp: datetime,
    ) -> list[ScanFinding]:
        """Map SARIF results back to ScanFinding objects."""
        findings: list[ScanFinding] = []
        for result in results:
            finding = self._map_single_result(
                result, rule_map, default_artifact_path, scan_timestamp
            )
            findings.append(finding)
        return findings

    def _map_single_result(
        self,
        result: dict[str, Any],
        rule_map: dict[str, dict[str, Any]],
        default_artifact_path: str,
        scan_timestamp: datetime,
    ) -> ScanFinding:
        """Map a single SARIF result to a ScanFinding."""
        rule_id = result.get("ruleId", "")
        description = result.get("message", {}).get("text", "")
        level = result.get("level", "note")
        gate_action = _LEVEL_TO_GATE.get(level, GateAction.INFO)

        # Extract location
        location, artifact_path = self._extract_location(result, default_artifact_path)

        # Extract properties bag with validation
        properties = result.get("properties", {})
        self._validate_properties(rule_id, properties)

        severity_score: int = properties["severity_score"]
        confidence: float = properties["confidence"]
        category_str: str = properties["category"]
        scanner_module_str: str = properties["scanner_module"]
        evidence: str = properties["evidence"]

        # Look up rule descriptor for title and remediation
        title = ""
        remediation = ""
        rule = rule_map.get(rule_id)
        if rule:
            short_desc = rule.get("shortDescription", {})
            title = short_desc.get("text", "")
            help_obj = rule.get("help")
            if help_obj:
                remediation = help_obj.get("text", "")

        # Determine derived fields
        severity_label = _severity_label_from_score(severity_score)
        priority = _GATE_TO_PRIORITY[gate_action]

        # Determine false_positive from suppressions
        false_positive = bool(result.get("suppressions"))

        return ScanFinding(
            id=rule_id,
            artifact_type=ArtifactType.PROMPT,
            artifact_path=artifact_path,
            severity_score=severity_score,
            severity_label=severity_label,
            priority=priority,
            gate_action=gate_action,
            category=RiskCategory(category_str),
            title=title,
            description=description,
            location=location,
            evidence=evidence,
            confidence=confidence,
            scanner_module=ScannerModule(scanner_module_str),
            remediation=remediation,
            references=[],
            false_positive=false_positive,
            timestamp=scan_timestamp,
        )

    def _extract_location(
        self,
        result: dict[str, Any],
        default_artifact_path: str,
    ) -> tuple[FindingLocation, str]:
        """Extract FindingLocation and artifact_path from a SARIF result."""
        locations = result.get("locations", [])
        if not locations:
            return FindingLocation(), default_artifact_path

        phys_loc = locations[0]
        artifact_loc = phys_loc.get("artifactLocation", {})
        artifact_path = artifact_loc.get("uri", default_artifact_path)

        region = phys_loc.get("region")
        if region:
            line = region.get("startLine")
            end_line = region.get("endLine")
            return FindingLocation(line=line, end_line=end_line), artifact_path

        return FindingLocation(), artifact_path

    def _validate_properties(self, rule_id: str, properties: dict[str, Any]) -> None:
        """Validate that required properties bag keys are present."""
        required_keys = [
            "severity_score",
            "confidence",
            "category",
            "scanner_module",
            "evidence",
        ]
        for key in required_keys:
            if key not in properties:
                raise ValueError(f"Result '{rule_id}' missing required properties key: '{key}'")

    def _compute_summary(self, findings: list[ScanFinding]) -> ScanSummary:
        """Recompute ScanSummary from findings using gate logic."""
        total = len(findings)
        blocking = sum(
            1 for f in findings if f.gate_action == GateAction.BLOCK and not f.false_positive
        )
        warning = sum(
            1 for f in findings if f.gate_action == GateAction.WARN and not f.false_positive
        )
        info = sum(1 for f in findings if f.gate_action == GateAction.INFO and not f.false_positive)

        # Gate decision: BLOCK > WARN > INFO
        if blocking > 0:
            gate_decision = GateAction.BLOCK
        elif warning > 0:
            gate_decision = GateAction.WARN
        else:
            gate_decision = GateAction.INFO

        # Aggregate by severity
        by_severity: dict[str, int] = {}
        for f in findings:
            label = f.severity_label.value
            by_severity[label] = by_severity.get(label, 0) + 1

        # Aggregate by category
        by_category: dict[str, int] = {}
        for f in findings:
            cat = f.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        return ScanSummary(
            total_findings=total,
            by_severity=by_severity,
            by_category=by_category,
            gate_decision=gate_decision,
            blocking_findings=blocking,
            warning_findings=warning,
            info_findings=info,
        )
