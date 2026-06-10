"""Unit tests for SARIF parser error handling.

Tests that the SarifParser raises ValueError with appropriate messages
for invalid JSON, missing SARIF structure, and missing properties keys.
"""

from __future__ import annotations

import json

import pytest

from ai_artifact_risk_validator.reporting.sarif_parser import SarifParser


@pytest.fixture
def parser() -> SarifParser:
    """Create a SarifParser instance for testing."""
    return SarifParser()


def _minimal_sarif_with_result(
    *,
    properties: dict[str, object] | None = None,
    rule_id: str = "P-S1",
) -> str:
    """Build a minimal valid SARIF document with one result.

    If properties is None, includes all required keys.
    Otherwise uses the provided dict as the properties bag.
    """
    if properties is None:
        properties = {
            "severity_score": 7,
            "confidence": 0.9,
            "category": "Security",
            "scanner_module": "SecretScan",
            "evidence": "hardcoded secret",
        }

    doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ai-artifact-risk-validator",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/example/repo",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": "Test Rule"},
                                "fullDescription": {"text": "A test rule description"},
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": "ai-artifact-validator verify src/test.py",
                        "startTimeUtc": "2025-06-05T12:00:00Z",
                    }
                ],
                "results": [
                    {
                        "ruleId": rule_id,
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {"text": "A test finding"},
                        "locations": [
                            {
                                "artifactLocation": {"uri": "src/test.py"},
                                "region": {"startLine": 10},
                            }
                        ],
                        "properties": properties,
                    }
                ],
                "automationDetails": {"id": "test-scan-001"},
            }
        ],
    }
    return json.dumps(doc)


class TestSarifParserErrorHandling:
    """Tests for SarifParser error handling on invalid inputs."""

    def test_invalid_json_raises_valueerror(self, parser: SarifParser) -> None:
        """Invalid JSON string raises ValueError with parse failure message."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            parser.parse("this is not valid json {{{")

    def test_missing_version_field_raises_valueerror(self, parser: SarifParser) -> None:
        """Valid JSON missing 'version' raises ValueError."""
        doc = json.dumps(
            {
                "$schema": "https://example.com/schema.json",
                "runs": [{"tool": {"driver": {"name": "test"}}}],
            }
        )
        with pytest.raises(ValueError, match="Missing required SARIF field: version"):
            parser.parse(doc)

    def test_missing_runs_array_raises_valueerror(self, parser: SarifParser) -> None:
        """Valid JSON missing 'runs' raises ValueError."""
        doc = json.dumps(
            {
                "$schema": "https://example.com/schema.json",
                "version": "2.1.0",
            }
        )
        with pytest.raises(ValueError, match="Missing required SARIF field: runs"):
            parser.parse(doc)

    def test_missing_tool_driver_raises_valueerror(self, parser: SarifParser) -> None:
        """Valid JSON with runs but missing 'tool.driver' raises ValueError."""
        doc = json.dumps(
            {
                "$schema": "https://example.com/schema.json",
                "version": "2.1.0",
                "runs": [{"tool": {}, "results": []}],
            }
        )
        with pytest.raises(ValueError, match="Missing required SARIF field: tool.driver"):
            parser.parse(doc)

    def test_result_missing_properties_key_raises_valueerror_with_rule_id(
        self, parser: SarifParser
    ) -> None:
        """Result missing a required properties key raises ValueError with ruleId."""
        # Remove 'evidence' from properties
        incomplete_properties = {
            "severity_score": 7,
            "confidence": 0.9,
            "category": "Security",
            "scanner_module": "SecretScan",
            # "evidence" is missing
        }
        sarif_str = _minimal_sarif_with_result(properties=incomplete_properties, rule_id="MCP-S3")
        with pytest.raises(
            ValueError, match=r"Result 'MCP-S3' missing required properties key: 'evidence'"
        ):
            parser.parse(sarif_str)

    def test_result_missing_severity_score_raises_valueerror(self, parser: SarifParser) -> None:
        """Result missing 'severity_score' raises ValueError identifying the key."""
        incomplete_properties = {
            # "severity_score" is missing
            "confidence": 0.85,
            "category": "Performance",
            "scanner_module": "TokenAnalyzer",
            "evidence": "long token chain",
        }
        sarif_str = _minimal_sarif_with_result(properties=incomplete_properties, rule_id="P-S1")
        with pytest.raises(
            ValueError,
            match=r"Result 'P-S1' missing required properties key: 'severity_score'",
        ):
            parser.parse(sarif_str)

    def test_result_missing_confidence_raises_valueerror(self, parser: SarifParser) -> None:
        """Result missing 'confidence' raises ValueError identifying the key."""
        incomplete_properties = {
            "severity_score": 5,
            # "confidence" is missing
            "category": "Quality",
            "scanner_module": "QualityLint",
            "evidence": "lint warning",
        }
        sarif_str = _minimal_sarif_with_result(properties=incomplete_properties, rule_id="Q-L1")
        with pytest.raises(
            ValueError,
            match=r"Result 'Q-L1' missing required properties key: 'confidence'",
        ):
            parser.parse(sarif_str)

    def test_empty_runs_array_raises_valueerror(self, parser: SarifParser) -> None:
        """Valid JSON with empty 'runs' array raises ValueError."""
        doc = json.dumps(
            {
                "$schema": "https://example.com/schema.json",
                "version": "2.1.0",
                "runs": [],
            }
        )
        with pytest.raises(ValueError, match="SARIF document has empty runs array"):
            parser.parse(doc)
