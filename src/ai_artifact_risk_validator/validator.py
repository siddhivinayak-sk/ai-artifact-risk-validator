"""Core Validator class - main entry point for AI artifact risk validation.

Orchestrates the full scan pipeline:
    discovery → classification → scanning → aggregation → gate decision → reporting

Implements graceful degradation by catching all exceptions and returning
a ScanReport with error status rather than propagating exceptions to callers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ai_artifact_risk_validator._internal.logging import (
    bind_scan_context,
    clear_scan_context,
    configure_logging,
    get_logger,
)
from ai_artifact_risk_validator.classifiers import ArtifactClassifier
from ai_artifact_risk_validator.config.manager import ConfigManager
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import GateAction
from ai_artifact_risk_validator.models.report import ScanReport, ScanSummary
from ai_artifact_risk_validator.pipeline.aggregator import Aggregator
from ai_artifact_risk_validator.pipeline.discovery import FileDiscovery
from ai_artifact_risk_validator.pipeline.executor import PipelineExecutor
from ai_artifact_risk_validator.pipeline.gate import should_suppress
from ai_artifact_risk_validator.reporting.generator import ReportGenerator
from ai_artifact_risk_validator.scanners.registry import ScannerRegistry

logger = get_logger(__name__)


class Validator:
    """Main entry point for AI artifact risk validation.

    Wires together ConfigManager, FileDiscovery, ArtifactClassifier,
    ScannerRegistry, PipelineExecutor, Aggregator, GateDecisionEngine,
    and ReportGenerator to orchestrate the full scan pipeline.

    Usage:
        from ai_artifact_risk_validator import Validator

        validator = Validator()
        report = validator.verify("path/to/artifacts")
    """

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        """Initialize the Validator with optional configuration.

        Args:
            config: Optional ValidatorConfig. Defaults are used if None.
        """
        self._config = config or ValidatorConfig()

        # Initialize structured logging with the configured log level
        configure_logging(log_level=self._config.log_level)

        self._config_manager = ConfigManager()
        self._file_discovery = FileDiscovery(config=self._config)
        self._classifier = ArtifactClassifier(
            custom_patterns=self._config.custom_artifact_patterns or None
        )
        self._scanner_registry = ScannerRegistry(config=self._config)
        self._pipeline_executor = PipelineExecutor(config=self._config)
        self._aggregator = Aggregator()
        self._report_generator = ReportGenerator()

        # Discover scanners from entry points and plugin directories
        self._scanner_registry.discover_entry_points()
        for plugin_dir in self._config.custom_plugin_dirs:
            self._scanner_registry.discover_plugin_dir(Path(plugin_dir))

    def verify(self, path: str | Path) -> ScanReport:
        """Scan the given path for AI artifact risks.

        Orchestrates the full pipeline:
        1. Resolve and validate the path
        2. Discover files (recursive for directories, single for files)
        3. Execute scanners in parallel (classification + scanning)
        4. Aggregate and deduplicate findings
        5. Apply suppression rules and confidence filtering
        6. Generate report with gate decision

        Args:
            path: Directory or file path to scan.

        Returns:
            ScanReport containing all findings and summary.
            Never raises exceptions to calling code.
        """
        try:
            return self._do_verify(path)
        except Exception as exc:
            # Graceful degradation: catch ALL exceptions and return error report
            logger.error(
                "Unexpected error during verify",
                error=str(exc),
                exc_info=True,
            )
            return self._error_report(
                artifact_path=str(path),
                error_message=f"Unexpected error during scan: {exc}",
            )

    def _do_verify(self, path: str | Path) -> ScanReport:
        """Internal verify implementation that may raise exceptions.

        Exceptions are caught by the public verify() method for graceful degradation.
        """
        resolved_path = Path(path) if isinstance(path, str) else path

        # Generate scan_id early so it can be bound to logging context
        scan_id = str(uuid4())

        # Bind scan-level context for all log entries during this scan
        bind_scan_context(scan_id=scan_id, artifact_path=str(path))

        try:
            return self._execute_scan(resolved_path, path, scan_id)
        finally:
            # Always clear context to prevent leaking between scans
            clear_scan_context()

    def _execute_scan(
        self, resolved_path: Path, original_path: str | Path, scan_id: str
    ) -> ScanReport:
        """Execute the scan pipeline after context is bound.

        Args:
            resolved_path: The resolved Path object.
            original_path: The original path argument passed to verify().
            scan_id: The unique scan identifier.

        Returns:
            ScanReport with findings and summary.
        """
        # Handle non-existent paths
        if not resolved_path.exists():
            logger.warning("Path does not exist", path=str(resolved_path))
            return self._error_report(
                artifact_path=str(original_path),
                error_message=f"Path does not exist: {resolved_path}",
                scan_id=scan_id,
            )

        # Step 1: Discover files
        files = self._file_discovery.discover(resolved_path)
        logger.info(
            "File discovery complete",
            file_count=len(files),
            scan_path=str(resolved_path),
        )

        # Step 2 & 3: Execute pipeline (classify + scan in parallel)
        raw_findings = self._pipeline_executor.execute(
            files=files,
            classifier=self._classifier,
            scanner_registry=self._scanner_registry,
        )

        # Step 4: Aggregate and deduplicate
        aggregated_findings = self._aggregator.aggregate(
            findings=raw_findings,
            suppression_rules=self._config.suppression_rules or None,
        )

        # Step 5: Apply confidence-based suppression
        filtered_findings = [
            finding
            for finding in aggregated_findings
            if not should_suppress(finding, self._config.log_level)
        ]

        # Step 6: Determine artifact_type for single-file scans
        artifact_type = None
        if resolved_path.is_file() and filtered_findings:
            # Use the artifact type from the first finding if available
            artifact_type = filtered_findings[0].artifact_type

        # Step 7: Generate report
        report = self._report_generator.generate(
            findings=filtered_findings,
            artifact_path=str(original_path),
            artifact_type=artifact_type,
        )

        logger.info(
            "Scan complete",
            total_findings=report.summary.total_findings,
            gate_decision=report.summary.gate_decision.value,
        )

        return report

    @property
    def version(self) -> str:
        """Return the validator package version."""
        from ai_artifact_risk_validator import __version__

        return __version__

    def _error_report(
        self, artifact_path: str, error_message: str, scan_id: str | None = None
    ) -> ScanReport:
        """Create a ScanReport representing an error state.

        Used when the scan cannot proceed due to path issues or unexpected errors.

        Args:
            artifact_path: The path that was attempted to be scanned.
            error_message: A human-readable description of the error.
            scan_id: Optional scan ID. A new UUID is generated if not provided.

        Returns:
            A ScanReport with zero findings, INFO gate decision, and the error
            message in the errors list.
        """
        from ai_artifact_risk_validator import __version__

        return ScanReport(
            scan_id=scan_id or str(uuid4()),
            artifact_path=artifact_path,
            artifact_type=None,
            scan_timestamp=datetime.now(timezone.utc),
            scanner_version=__version__,
            findings=[],
            summary=ScanSummary(
                total_findings=0,
                by_severity={},
                by_category={},
                gate_decision=GateAction.INFO,
                blocking_findings=0,
                warning_findings=0,
                info_findings=0,
            ),
            errors=[error_message],
        )
