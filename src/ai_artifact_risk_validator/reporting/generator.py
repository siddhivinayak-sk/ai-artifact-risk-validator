"""Report generator for the AI Artifact Risk Validator.

Assembles ScanReport objects from scan findings and context metadata,
computing summary statistics and gate decisions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from ai_artifact_risk_validator import __version__
from ai_artifact_risk_validator.models.enums import ArtifactType, GateAction
from ai_artifact_risk_validator.models.findings import ScanFinding
from ai_artifact_risk_validator.models.report import ScanReport, ScanSummary
from ai_artifact_risk_validator.pipeline.gate import assign_gate_action, compute_overall_gate
from ai_artifact_risk_validator.pipeline.scorer import compute_risk_score, severity_band


class ReportGenerator:
    """Generates scan reports from findings and scan context.

    Assembles a complete ScanReport with computed summary statistics,
    gate decisions, and metadata.
    """

    def generate(
        self,
        findings: list[ScanFinding],
        artifact_path: str,
        artifact_type: ArtifactType | None = None,
        errors: list[str] | None = None,
        has_executable_scripts: bool = False,
        gate_overrides: dict[str, GateAction] | None = None,
    ) -> ScanReport:
        """Generate a complete ScanReport from findings and context.

        Args:
            findings: List of scan findings produced by scanners.
            artifact_path: The path that was scanned.
            artifact_type: Optional artifact type (None for directory scans).
            errors: Optional list of error/diagnostic messages.
            has_executable_scripts: Whether the artifact includes executable files
                (triggers the 1.3x risk multiplier in aggregate score calculation).
            gate_overrides: Optional dict mapping risk IDs to overridden GateAction values.

        Returns:
            A fully assembled ScanReport with computed summary and risk score.
        """
        # Apply gate_overrides to each finding's gate_action field so the
        # serialized report reflects the effective gate decision.
        effective_findings = self._apply_gate_overrides(findings, gate_overrides)

        summary = self._compute_summary(effective_findings, gate_overrides)
        risk_score = compute_risk_score(effective_findings, has_executable_scripts)
        risk_sev, risk_rec = severity_band(risk_score)

        return ScanReport(
            scan_id=str(uuid4()),
            artifact_path=artifact_path,
            artifact_type=artifact_type,
            scan_timestamp=datetime.now(timezone.utc),
            scanner_version=__version__,
            findings=effective_findings,
            summary=summary,
            errors=errors or [],
            risk_score=risk_score,
            risk_severity=risk_sev,
            risk_recommendation=risk_rec,
            has_executable_scripts=has_executable_scripts,
        )

    def _apply_gate_overrides(
        self,
        findings: list[ScanFinding],
        gate_overrides: dict[str, GateAction] | None = None,
    ) -> list[ScanFinding]:
        """Apply gate_overrides to each finding's gate_action field.

        This ensures the serialized report JSON reflects the effective gate
        decision for each finding (including overrides), not just the scanner's
        default severity-based assignment.

        Args:
            findings: List of scan findings.
            gate_overrides: Optional dict mapping risk IDs to overridden GateAction values.

        Returns:
            List of findings with gate_action updated per overrides.
        """
        if not gate_overrides:
            return findings

        result: list[ScanFinding] = []
        for finding in findings:
            if finding.id in gate_overrides:
                effective_gate = assign_gate_action(finding, gate_overrides)
                result.append(finding.model_copy(update={"gate_action": effective_gate}))
            else:
                result.append(finding)
        return result

    def _compute_summary(
        self, findings: list[ScanFinding], gate_overrides: dict[str, GateAction] | None = None
    ) -> ScanSummary:
        """Compute the ScanSummary from a list of findings.

        - total_findings: count of ALL findings (including false positives)
        - by_severity: count per severity_label (ALL findings)
        - by_category: count per category (ALL findings)
        - blocking_findings: count with effective gate BLOCK (excludes false_positive)
        - warning_findings: count with effective gate WARN (excludes false_positive)
        - info_findings: count with effective gate INFO (excludes false_positive)
        - gate_decision: most severe non-false-positive gate

        Args:
            findings: List of scan findings to summarize.
            gate_overrides: Optional dict mapping risk IDs to overridden GateAction values.

        Returns:
            Computed ScanSummary.
        """
        total_findings = len(findings)

        # Count by severity label (ALL findings)
        by_severity: dict[str, int] = {}
        for finding in findings:
            label = finding.severity_label.value
            by_severity[label] = by_severity.get(label, 0) + 1

        # Count by category (ALL findings)
        by_category: dict[str, int] = {}
        for finding in findings:
            category = finding.category.value
            by_category[category] = by_category.get(category, 0) + 1

        # Gate action counts (EXCLUDE false positives)
        blocking_findings = 0
        warning_findings = 0
        info_findings = 0

        for finding in findings:
            if finding.false_positive:
                continue

            effective_gate = assign_gate_action(finding, gate_overrides)

            if effective_gate == GateAction.BLOCK:
                blocking_findings += 1
            elif effective_gate == GateAction.WARN:
                warning_findings += 1
            else:
                info_findings += 1

        # Overall gate decision (excludes false positives)
        gate_decision = compute_overall_gate(findings, gate_overrides)

        return ScanSummary(
            total_findings=total_findings,
            by_severity=by_severity,
            by_category=by_category,
            gate_decision=gate_decision,
            blocking_findings=blocking_findings,
            warning_findings=warning_findings,
            info_findings=info_findings,
        )
