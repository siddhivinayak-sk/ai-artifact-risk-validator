"""Gate decision engine for the AI Artifact Risk Validator.

Computes per-finding gate actions and overall gate decisions based on
severity scores, confidence levels, and configuration overrides.
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.enums import GateAction
from ai_artifact_risk_validator.models.findings import ScanFinding


def _severity_to_gate(severity_score: int) -> GateAction:
    """Map a severity score (1-10) to a default gate action.

    Mapping:
        S9-S10 → BLOCK
        S7-S8  → BLOCK
        S5-S6  → WARN
        S3-S4  → INFO
        S1-S2  → INFO
    """
    if severity_score >= 7:
        return GateAction.BLOCK
    elif severity_score >= 5:
        return GateAction.WARN
    else:
        return GateAction.INFO


def assign_gate_action(
    finding: ScanFinding,
    gate_overrides: dict[str, GateAction] | None = None,
) -> GateAction:
    """Assign an effective gate action for a single finding.

    The logic applies in order:
    1. Start with severity-based mapping
    2. Apply gate override if the risk ID exists in gate_overrides
    3. Apply low-confidence downgrade: if confidence < 0.60, effective gate is INFO

    Args:
        finding: The scan finding to evaluate.
        gate_overrides: Optional dict mapping risk IDs to overridden GateAction values.

    Returns:
        The effective GateAction for this finding.
    """
    # Step 1: Severity-based default
    gate = _severity_to_gate(finding.severity_score)

    # Step 2: Apply override if configured
    if gate_overrides and finding.id in gate_overrides:
        gate = gate_overrides[finding.id]

    # Step 3: Low-confidence downgrade (skip if semantic_score corroborates)
    if finding.confidence < 0.60:
        semantic = getattr(finding, "semantic_score", None)
        if semantic is not None and semantic >= 0.70:
            pass  # Semantic corroboration — keep original gate
        else:
            gate = GateAction.INFO

    return gate


def compute_overall_gate(
    findings: list[ScanFinding],
    gate_overrides: dict[str, GateAction] | None = None,
) -> GateAction:
    """Compute the overall gate decision across all non-false-positive findings.

    Returns the most severe gate action: BLOCK > WARN > INFO.
    If no findings or all are false_positive, returns INFO.

    Args:
        findings: List of scan findings to evaluate.
        gate_overrides: Optional dict mapping risk IDs to overridden GateAction values.

    Returns:
        The overall GateAction (most severe across all active findings).
    """
    if not findings:
        return GateAction.INFO

    # Gate action severity ordering for comparison
    _gate_severity = {
        GateAction.INFO: 0,
        GateAction.WARN: 1,
        GateAction.BLOCK: 2,
    }

    most_severe = GateAction.INFO

    for finding in findings:
        # Skip false positives
        if finding.false_positive:
            continue

        effective_gate = assign_gate_action(finding, gate_overrides)

        if _gate_severity[effective_gate] > _gate_severity[most_severe]:
            most_severe = effective_gate

        # Early exit: can't get more severe than BLOCK
        if most_severe == GateAction.BLOCK:
            break

    return most_severe


def should_suppress(finding: ScanFinding, log_level: str = "INFO") -> bool:
    """Determine whether a finding should be suppressed from the report.

    Findings with confidence < 0.40 are suppressed unless the log level is DEBUG.

    Args:
        finding: The scan finding to evaluate.
        log_level: The current logging level (e.g., "DEBUG", "INFO", "WARNING").

    Returns:
        True if the finding should be suppressed, False otherwise.
    """
    if finding.confidence < 0.40:
        return log_level.upper() != "DEBUG"
    return False
