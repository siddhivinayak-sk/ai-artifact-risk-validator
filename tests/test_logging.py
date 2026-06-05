"""Tests for the structured logging configuration module.

Tests cover:
- structlog configuration with JSON output (Requirement 17.1)
- Log level classification and filtering (Requirements 17.2, 17.3)
- Contextual field binding (Requirement 17.4)
- Configurable log level suppression (Requirement 5.2)
"""

from __future__ import annotations

import json
import logging
from io import StringIO

import pytest
import structlog

from ai_artifact_risk_validator._internal.logging import (
    bind_scan_context,
    clear_scan_context,
    configure_logging,
    get_logger,
)


@pytest.fixture(autouse=True)
def _reset_logging():
    """Reset logging state before and after each test."""
    # Clear any bound context vars
    clear_scan_context()
    yield
    clear_scan_context()
    # Reset the package logger
    package_logger = logging.getLogger("ai_artifact_risk_validator")
    package_logger.handlers.clear()
    package_logger.setLevel(logging.WARNING)


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def test_configures_package_logger_with_specified_level(self):
        """Verify the package logger is set to the requested level."""
        configure_logging(log_level="DEBUG")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert package_logger.level == logging.DEBUG

    def test_configures_package_logger_info_level(self):
        """Verify INFO level configuration."""
        configure_logging(log_level="INFO")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert package_logger.level == logging.INFO

    def test_configures_package_logger_warning_level(self):
        """Verify WARNING level configuration."""
        configure_logging(log_level="WARNING")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert package_logger.level == logging.WARNING

    def test_configures_package_logger_error_level(self):
        """Verify ERROR level configuration."""
        configure_logging(log_level="ERROR")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert package_logger.level == logging.ERROR

    def test_configures_package_logger_critical_level(self):
        """Verify CRITICAL level configuration."""
        configure_logging(log_level="CRITICAL")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert package_logger.level == logging.CRITICAL

    def test_handler_uses_json_formatter_by_default(self):
        """Verify the handler has a ProcessorFormatter with JSON rendering."""
        configure_logging(log_level="INFO")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert len(package_logger.handlers) == 1
        handler = package_logger.handlers[0]
        assert isinstance(handler.formatter, structlog.stdlib.ProcessorFormatter)

    def test_prevents_propagation_to_root_logger(self):
        """Verify propagation is disabled to avoid duplicate messages."""
        configure_logging(log_level="INFO")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert package_logger.propagate is False

    def test_reconfiguration_clears_old_handlers(self):
        """Verify re-calling configure_logging doesn't duplicate handlers."""
        configure_logging(log_level="INFO")
        configure_logging(log_level="DEBUG")
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert len(package_logger.handlers) == 1

    def test_default_log_level_is_info(self):
        """Verify default log level when no argument is provided."""
        configure_logging()
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        assert package_logger.level == logging.INFO


class TestJsonOutput:
    """Tests for JSON-formatted log output (Requirement 17.1)."""

    def test_log_output_is_valid_json(self):
        """Verify log entries are valid JSON when json_output=True."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        # Replace the handler's stream with our capture buffer
        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("test message")

        output = stream.getvalue().strip()
        assert output, "Expected log output but got empty string"
        parsed = json.loads(output)
        assert parsed["event"] == "test message"

    def test_log_output_includes_log_level(self):
        """Verify JSON log output contains the level field."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.warning("a warning")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["level"] == "warning"

    def test_log_output_includes_timestamp(self):
        """Verify JSON log output contains an ISO-formatted timestamp."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("timestamped")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert "timestamp" in parsed

    def test_log_output_includes_logger_name(self):
        """Verify JSON log output contains the logger name."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test_module")
        logger.info("named logger")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["logger"] == "ai_artifact_risk_validator.test_module"


class TestLogLevelFiltering:
    """Tests for log level suppression (Requirements 17.3, 5.2)."""

    def test_suppresses_debug_when_level_is_info(self):
        """Verify DEBUG messages are suppressed when log level is INFO."""
        stream = StringIO()
        configure_logging(log_level="INFO", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.debug("should not appear")

        output = stream.getvalue().strip()
        assert output == ""

    def test_emits_info_when_level_is_info(self):
        """Verify INFO messages are emitted when log level is INFO."""
        stream = StringIO()
        configure_logging(log_level="INFO", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("should appear")

        output = stream.getvalue().strip()
        assert output != ""
        parsed = json.loads(output)
        assert parsed["event"] == "should appear"

    def test_suppresses_info_when_level_is_warning(self):
        """Verify INFO messages are suppressed when log level is WARNING."""
        stream = StringIO()
        configure_logging(log_level="WARNING", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("should not appear")

        output = stream.getvalue().strip()
        assert output == ""

    def test_emits_warning_when_level_is_warning(self):
        """Verify WARNING messages are emitted when log level is WARNING."""
        stream = StringIO()
        configure_logging(log_level="WARNING", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.warning("a warning")

        output = stream.getvalue().strip()
        assert output != ""
        parsed = json.loads(output)
        assert parsed["event"] == "a warning"

    def test_suppresses_warning_when_level_is_error(self):
        """Verify WARNING messages are suppressed when log level is ERROR."""
        stream = StringIO()
        configure_logging(log_level="ERROR", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.warning("should not appear")

        output = stream.getvalue().strip()
        assert output == ""

    def test_emits_error_when_level_is_error(self):
        """Verify ERROR messages are emitted when log level is ERROR."""
        stream = StringIO()
        configure_logging(log_level="ERROR", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.error("an error")

        output = stream.getvalue().strip()
        assert output != ""
        parsed = json.loads(output)
        assert parsed["event"] == "an error"

    def test_emits_debug_when_level_is_debug(self):
        """Verify DEBUG messages are emitted when log level is DEBUG."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.debug("debug message")

        output = stream.getvalue().strip()
        assert output != ""
        parsed = json.loads(output)
        assert parsed["event"] == "debug message"

    def test_only_critical_emitted_at_critical_level(self):
        """Verify only CRITICAL messages pass when log level is CRITICAL."""
        stream = StringIO()
        configure_logging(log_level="CRITICAL", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.error("should not appear")
        logger.critical("critical issue")

        output = stream.getvalue().strip()
        lines = [line for line in output.split("\n") if line.strip()]
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["event"] == "critical issue"
        assert parsed["level"] == "critical"


class TestContextualFields:
    """Tests for contextual field binding (Requirement 17.4)."""

    def test_bind_scan_context_includes_scan_id(self):
        """Verify scan_id appears in log output after binding."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        bind_scan_context(scan_id="test-scan-001")
        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("scan started")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["scan_id"] == "test-scan-001"

    def test_bind_scan_context_includes_artifact_path(self):
        """Verify artifact_path appears in log output after binding."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        bind_scan_context(artifact_path="/path/to/artifact.md")
        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("processing file")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["artifact_path"] == "/path/to/artifact.md"

    def test_bind_scan_context_includes_artifact_type(self):
        """Verify artifact_type appears in log output after binding."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        bind_scan_context(artifact_type="prompt")
        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("classified")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["artifact_type"] == "prompt"

    def test_bind_scan_context_includes_scanner_module(self):
        """Verify scanner_module appears in log output after binding."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        bind_scan_context(scanner_module="SecretScan")
        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("scanning")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["scanner_module"] == "SecretScan"

    def test_bind_scan_context_multiple_fields(self):
        """Verify multiple context fields are included simultaneously."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        bind_scan_context(
            scan_id="scan-xyz",
            artifact_path="/my/file.md",
            artifact_type="agent",
            scanner_module="InjectionDet",
        )
        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("full context")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["scan_id"] == "scan-xyz"
        assert parsed["artifact_path"] == "/my/file.md"
        assert parsed["artifact_type"] == "agent"
        assert parsed["scanner_module"] == "InjectionDet"

    def test_clear_scan_context_removes_fields(self):
        """Verify clear_scan_context removes previously bound fields."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        bind_scan_context(scan_id="scan-abc")
        clear_scan_context()

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("after clear")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert "scan_id" not in parsed

    def test_get_logger_with_initial_context(self):
        """Verify get_logger binds initial context fields."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger(
            "ai_artifact_risk_validator.test",
            scanner_module="QualityLint",
            artifact_path="/test/artifact.md",
        )
        logger.info("with initial context")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["scanner_module"] == "QualityLint"
        assert parsed["artifact_path"] == "/test/artifact.md"

    def test_inline_context_in_log_call(self):
        """Verify ad-hoc context fields passed in a log call appear in output."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("inline context", artifact_path="/inline/path.yaml", scan_id="inline-scan")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["artifact_path"] == "/inline/path.yaml"
        assert parsed["scan_id"] == "inline-scan"


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_bound_logger(self):
        """Verify get_logger returns a structlog BoundLogger."""
        configure_logging(log_level="INFO")
        logger = get_logger("ai_artifact_risk_validator.test")
        # BoundLogger has info, debug, warning, error, critical methods
        assert hasattr(logger, "info")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")
        assert hasattr(logger, "critical")

    def test_logger_without_name(self):
        """Verify get_logger works without a name argument."""
        configure_logging(log_level="INFO")
        logger = get_logger()
        assert hasattr(logger, "info")

    def test_logger_bind_adds_context(self):
        """Verify logger.bind() adds fields to subsequent log entries."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=True)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        bound_logger = logger.bind(custom_field="custom_value")
        bound_logger.info("bound message")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["custom_field"] == "custom_value"


class TestConsoleOutput:
    """Tests for console (non-JSON) output mode."""

    def test_console_renderer_produces_non_json_output(self):
        """Verify json_output=False uses a non-JSON format."""
        stream = StringIO()
        configure_logging(log_level="DEBUG", json_output=False)

        package_logger = logging.getLogger("ai_artifact_risk_validator")
        package_logger.handlers[0].stream = stream

        logger = get_logger("ai_artifact_risk_validator.test")
        logger.info("console message")

        output = stream.getvalue().strip()
        assert output != ""
        # Console output should NOT be valid JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(output)
