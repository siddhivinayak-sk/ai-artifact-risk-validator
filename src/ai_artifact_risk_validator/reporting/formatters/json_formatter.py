"""JSON output formatter for scan reports.

Formats a ScanReport as a pretty-printed JSON string using
Pydantic v2's built-in serialization with ISO 8601 datetime handling.
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.report import ScanReport


def format_json(report: ScanReport) -> str:
    """Format a ScanReport as pretty-printed JSON.

    Uses Pydantic v2's model_dump_json() for proper serialization,
    including datetime values rendered as ISO 8601 strings.

    Args:
        report: The ScanReport to format.

    Returns:
        A JSON string with 2-space indentation.
    """
    return report.model_dump_json(indent=2)
