"""JSON serialization for ScanReport objects.

Converts ScanReport Pydantic models to JSON strings with proper
datetime→ISO 8601 handling using Pydantic v2's built-in serialization.
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.report import ScanReport


class ReportSerializer:
    """Serializes ScanReport objects to JSON strings.

    Uses Pydantic v2's model_dump_json() for proper datetime serialization
    to ISO 8601 format, with pretty-printed output (indent=2).
    """

    def serialize(self, report: ScanReport) -> str:
        """Convert a ScanReport to a JSON string.

        Datetime values are rendered as ISO 8601 strings.
        Output is pretty-printed with 2-space indentation.

        Args:
            report: The ScanReport to serialize.

        Returns:
            A valid JSON string representation of the report.
        """
        return report.model_dump_json(indent=2)
