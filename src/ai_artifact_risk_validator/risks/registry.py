"""Risk Registry for the AI Artifact Risk Validator.

Provides the RiskRegistry class that catalogs all 190 risk definitions
and supports querying by risk ID, artifact type, category, severity,
priority, and scanner module.
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.risk import RiskDefinition
from ai_artifact_risk_validator.risks.definitions import load_all_risks


class RiskRegistry:
    """Catalog of all risk definitions with query capabilities.

    The registry stores RiskDefinition objects keyed by risk ID and provides
    methods for lookup, filtered querying, and custom risk addition.

    On initialization, all built-in risk definitions are loaded automatically
    from the risks/definitions/ modules.
    """

    def __init__(self) -> None:
        """Initialize the registry and load all built-in risk definitions."""
        self._risks: dict[str, RiskDefinition] = {}
        self._load_builtin_risks()

    def _load_builtin_risks(self) -> None:
        """Load all built-in risk definitions from definition modules."""
        for risk in load_all_risks():
            self._risks[risk.id] = risk

    def get(self, risk_id: str) -> RiskDefinition | None:
        """Retrieve a single risk definition by its ID.

        Args:
            risk_id: The unique risk identifier (e.g. "P-S1", "MCP-S3").

        Returns:
            The RiskDefinition if found, or None.
        """
        return self._risks.get(risk_id)

    def query(
        self,
        artifact_type: ArtifactType | None = None,
        category: RiskCategory | None = None,
        severity: SeverityLabel | None = None,
        priority: Priority | None = None,
        scanner_module: ScannerModule | None = None,
    ) -> list[RiskDefinition]:
        """Query risks with optional filters (all filters are ANDed).

        Args:
            artifact_type: Filter by artifact type applicability.
            category: Filter by risk category.
            severity: Filter by severity label.
            priority: Filter by priority level.
            scanner_module: Filter by responsible scanner module.

        Returns:
            List of RiskDefinition objects matching all specified filters.
        """
        results: list[RiskDefinition] = []

        for risk in self._risks.values():
            if artifact_type is not None and artifact_type not in risk.artifact_types:
                continue
            if category is not None and risk.category != category:
                continue
            if severity is not None and risk.severity_label != severity:
                continue
            if priority is not None and risk.priority != priority:
                continue
            if scanner_module is not None and scanner_module not in risk.scanner_modules:
                continue
            results.append(risk)

        return results

    def add_custom(self, risk: RiskDefinition) -> None:
        """Add a custom risk definition to the registry.

        If a risk with the same ID already exists, it will be overwritten.

        Args:
            risk: The RiskDefinition to add.
        """
        self._risks[risk.id] = risk

    @property
    def total_count(self) -> int:
        """Return the total number of registered risk definitions."""
        return len(self._risks)

    # Severity-to-gate-action mapping as specified in requirements 11.4
    SEVERITY_GATE_MAP: dict[tuple[int, int], GateAction] = {
        (9, 10): GateAction.BLOCK,
        (7, 8): GateAction.BLOCK,
        (5, 6): GateAction.WARN,
        (3, 4): GateAction.INFO,
        (1, 2): GateAction.INFO,
    }

    @staticmethod
    def severity_to_gate_action(severity_score: int) -> GateAction:
        """Map a severity score to the default gate action.

        Mapping:
            S9-S10 -> BLOCK
            S7-S8  -> BLOCK (overridable)
            S5-S6  -> WARN
            S3-S4  -> INFO
            S1-S2  -> INFO

        Args:
            severity_score: Integer severity score (1-10).

        Returns:
            The corresponding GateAction.
        """
        if severity_score >= 9:
            return GateAction.BLOCK
        if severity_score >= 7:
            return GateAction.BLOCK
        if severity_score >= 5:
            return GateAction.WARN
        return GateAction.INFO
