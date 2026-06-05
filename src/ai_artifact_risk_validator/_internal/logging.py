"""Structured logging configuration using structlog.

Configures structlog with JSON-formatted output and contextual fields
for tracing scan operations throughout the package. The logging is
initialized when a Validator instance is created.

Key features:
- JSON-formatted structured log output
- Configurable log levels (DEBUG/INFO/WARNING/ERROR/CRITICAL)
- Contextual fields: scanner_module, artifact_path, artifact_type, scan_id
- Integration with Python's standard logging for compatibility
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def configure_logging(
    log_level: str = "INFO",
    *,
    json_output: bool = True,
) -> None:
    """Configure structlog for the ai_artifact_risk_validator package.

    Sets up structlog with JSON rendering, timestamp injection, log level
    filtering, and standard library logging integration. This should be
    called once when the Validator is instantiated.

    Args:
        log_level: Minimum log level to emit. One of DEBUG, INFO, WARNING,
            ERROR, CRITICAL. Defaults to INFO.
        json_output: If True, render logs as JSON. If False, use console
            renderer for development. Defaults to True.
    """
    # Map string level to numeric for stdlib logging
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure the standard library logger for the package
    # This ensures structlog-wrapped loggers respect the level threshold
    package_logger = logging.getLogger("ai_artifact_risk_validator")
    package_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicate output on re-configuration
    package_logger.handlers.clear()

    # Choose the renderer based on configuration
    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    # Shared processors applied to all log entries
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    # Configure structlog to use stdlib integration
    # The processor chain here runs before handing off to the stdlib logger.
    # filter_by_level ensures messages below the configured level are dropped.
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    # Create a ProcessorFormatter that renders the final output
    # This formatter handles structlog events that have been wrapped
    # as well as foreign (plain stdlib) log records.
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    # Add a stream handler with the ProcessorFormatter for output
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)
    handler.setFormatter(formatter)
    package_logger.addHandler(handler)

    # Prevent propagation to root logger to avoid duplicate messages
    package_logger.propagate = False


def get_logger(name: str | None = None, **initial_context: Any) -> structlog.stdlib.BoundLogger:
    """Get a structlog logger with optional initial context.

    This is the primary way modules in this package should obtain a logger.
    The returned logger supports binding additional context fields for
    scan traceability.

    Args:
        name: Logger name, typically __name__ of the calling module.
        **initial_context: Initial context fields to bind to the logger.
            Common fields: scanner_module, artifact_path, artifact_type, scan_id.

    Returns:
        A bound structlog logger instance.

    Example:
        >>> logger = get_logger(__name__, scan_id="abc-123")
        >>> logger.info("scan started", artifact_path="/path/to/file")
    """
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    if initial_context:
        logger = logger.bind(**initial_context)
    return logger  # type: ignore[return-value]


def bind_scan_context(
    *,
    scan_id: str | None = None,
    artifact_path: str | None = None,
    artifact_type: str | None = None,
    scanner_module: str | None = None,
) -> None:
    """Bind scan context fields to the current context (thread-local).

    Uses structlog's contextvars to attach contextual fields that will
    be included in all subsequent log entries within the same context.
    This is useful for setting scan-wide context at the start of a
    verify() call.

    Args:
        scan_id: Unique identifier for the current scan operation.
        artifact_path: Path of the artifact being scanned.
        artifact_type: Classified type of the artifact.
        scanner_module: Name of the scanner module currently executing.
    """
    context: dict[str, str] = {}
    if scan_id is not None:
        context["scan_id"] = scan_id
    if artifact_path is not None:
        context["artifact_path"] = artifact_path
    if artifact_type is not None:
        context["artifact_type"] = artifact_type
    if scanner_module is not None:
        context["scanner_module"] = scanner_module

    if context:
        structlog.contextvars.bind_contextvars(**context)


def clear_scan_context() -> None:
    """Clear all bound scan context fields.

    Should be called at the end of a scan operation to prevent
    context leaking between scans.
    """
    structlog.contextvars.clear_contextvars()
