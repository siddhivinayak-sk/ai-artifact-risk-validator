"""JSON deserialization for ScanReport objects.

Parses JSON strings back into ScanReport Pydantic models with
validation error reporting for malformed input.
"""

from __future__ import annotations

from pydantic import ValidationError

from ai_artifact_risk_validator.models.report import ScanReport


class ReportParser:
    """Parses JSON strings into ScanReport objects.

    Uses Pydantic v2's model_validate_json() for deserialization with
    full model validation. Raises descriptive ValueErrors for malformed
    JSON or missing/invalid fields.
    """

    def parse(self, json_str: str) -> ScanReport:
        """Parse a JSON string into a ScanReport object.

        Validates the JSON against the ScanReport model schema.
        On malformed JSON or missing/invalid fields, raises a
        descriptive ValueError with field-level error details.

        Args:
            json_str: A JSON string to parse.

        Returns:
            A validated ScanReport object.

        Raises:
            ValueError: If the JSON is malformed or fails validation,
                with a descriptive message indicating which fields
                are invalid or missing.
        """
        try:
            return ScanReport.model_validate_json(json_str)
        except ValidationError as e:
            error_details = []
            for error in e.errors():
                location = " -> ".join(str(loc) for loc in error["loc"])
                msg = error["msg"]
                error_details.append(f"  {location}: {msg}")

            field_errors = "\n".join(error_details)
            raise ValueError(
                f"Invalid ScanReport JSON: {e.error_count()} validation error(s)\n{field_errors}"
            ) from e
        except Exception as e:
            raise ValueError(f"Malformed JSON: {e}") from e
