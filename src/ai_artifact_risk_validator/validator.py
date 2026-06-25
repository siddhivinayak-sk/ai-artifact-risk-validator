"""Core Validator class - main entry point for AI artifact risk validation.

Orchestrates the full scan pipeline:
    discovery → classification → scanning → aggregation → gate decision → reporting

Implements a two-pass classification strategy:
    Pass 1: classify and scan non-script files
    Pass 2: classify script files using context from pass 1 (reference resolution,
             MCP project detection, sibling classification)

Implements graceful degradation by catching all exceptions and returning
a ScanReport with error status rather than propagating exceptions to callers.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ai_artifact_risk_validator._internal.logging import (
    bind_scan_context,
    clear_scan_context,
    configure_logging,
    get_logger,
)
from ai_artifact_risk_validator.classifiers import ArtifactClassifier, ClassificationResult
from ai_artifact_risk_validator.classifiers.mcp_detector import MCPProjectDetector
from ai_artifact_risk_validator.classifiers.reference_resolver import ReferenceResolver
from ai_artifact_risk_validator.classifiers.script_context import (
    ScriptClassificationContext,
)
from ai_artifact_risk_validator.config.manager import ConfigManager
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import ArtifactType, GateAction
from ai_artifact_risk_validator.models.findings import ScanFinding
from ai_artifact_risk_validator.models.report import ScanReport, ScanSummary
from ai_artifact_risk_validator.pipeline.aggregator import Aggregator
from ai_artifact_risk_validator.pipeline.discovery import FileDiscovery
from ai_artifact_risk_validator.pipeline.executor import PipelineExecutor
from ai_artifact_risk_validator.pipeline.gate import should_suppress
from ai_artifact_risk_validator.pipeline.scorer import detect_executable_scripts
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

        # Wire the global semantic enabled state BEFORE creating classifiers
        # or scanner registry so that all consumers see the correct value.
        from ai_artifact_risk_validator.semantic.embeddings import get_shared_engine

        get_shared_engine().set_enabled(self._config.semantic.enabled)

        self._config_manager = ConfigManager()
        self._file_discovery = FileDiscovery(config=self._config)
        self._classifier = ArtifactClassifier(
            custom_patterns=self._config.custom_artifact_patterns or None,
            semantic_enabled=self._config.semantic.enabled,
        )
        self._scanner_registry = ScannerRegistry(config=self._config)
        self._pipeline_executor = PipelineExecutor(config=self._config)
        self._aggregator = Aggregator()
        self._report_generator = ReportGenerator()

        # Discover scanners from entry points and plugin directories
        self._scanner_registry.discover_entry_points()
        for plugin_dir in self._config.custom_plugin_dirs:
            self._scanner_registry.discover_plugin_dir(Path(plugin_dir))

        # Configure DynamicScanner with allow_dynamic_scan and interactive settings
        self._configure_dynamic_scanner()

        # Configure CodeAuditScanner with additional shell executables
        self._configure_code_audit_scanner()

        # Configure ProvenanceChkScanner with first-party path patterns
        self._configure_provenance_chk_scanner()

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

        Implements two-pass orchestration:
            Pass 1: classify and scan non-script files (existing behavior)
            Pass 2: classify script files using context from pass 1
                    (reference resolution, MCP project detection, sibling
                    classification), then scan classified scripts

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

        # Step 2: Partition files into script and non-script
        script_files, non_script_files = self._partition_files(files)

        # Step 3: Execute Pass 1 — classify and scan non-script files
        pass1_findings = self._pipeline_executor.execute(
            files=non_script_files,
            classifier=self._classifier,
            scanner_registry=self._scanner_registry,
        )

        # Step 4: Execute Pass 2 — classify and scan script files (if enabled)
        pass2_findings = self._execute_script_pass(
            script_files=script_files,
            all_files=files,
            resolved_path=resolved_path,
        )

        # Step 5: Combine findings from both passes
        raw_findings = pass1_findings + pass2_findings

        # Step 6: Aggregate and deduplicate
        aggregated_findings = self._aggregator.aggregate(
            findings=raw_findings,
            suppression_rules=self._config.suppression_rules or None,
        )

        # Step 7: Apply confidence-based suppression
        filtered_findings = [
            finding
            for finding in aggregated_findings
            if not should_suppress(finding, self._config.log_level)
        ]

        # Step 8: Determine artifact_type for single-file scans
        artifact_type = None
        if resolved_path.is_file() and filtered_findings:
            # Use the artifact type from the first finding if available
            artifact_type = filtered_findings[0].artifact_type

        # Step 9: Generate report
        report = self._report_generator.generate(
            findings=filtered_findings,
            artifact_path=str(original_path),
            artifact_type=artifact_type,
            has_executable_scripts=detect_executable_scripts([str(f) for f in files]),
        )

        logger.info(
            "Scan complete",
            total_findings=report.summary.total_findings,
            gate_decision=report.summary.gate_decision.value,
        )

        return report

    def _partition_files(self, files: list[Path]) -> tuple[list[Path], list[Path]]:
        """Partition discovered files into script and non-script files.

        Uses the configured ``script_extensions`` list to determine which
        files are script files. Only partitions when script scanning is
        enabled; otherwise all files are treated as non-script.

        Args:
            files: All discovered files.

        Returns:
            Tuple of (script_files, non_script_files).
        """
        if not self._config.script_scanning_enabled:
            return [], files

        extensions = {ext.lower() for ext in self._config.script_extensions}
        script_files: list[Path] = []
        non_script_files: list[Path] = []

        for f in files:
            if f.suffix.lower() in extensions:
                script_files.append(f)
            else:
                non_script_files.append(f)

        return script_files, non_script_files

    def _execute_script_pass(
        self,
        script_files: list[Path],
        all_files: list[Path],
        resolved_path: Path,
    ) -> list[ScanFinding]:
        """Execute pass 2: classify and scan script files.

        When script scanning is disabled or no script files exist, returns
        an empty list immediately. When script_extensions is empty, logs a
        WARNING and skips script scanning.

        Args:
            script_files: Script files discovered during partitioning.
            all_files: All discovered files (for reference resolution).
            resolved_path: The root scan path.

        Returns:
            List of ScanFinding from scanning classified script files.
        """
        # Skip entirely when script scanning is disabled
        if not self._config.script_scanning_enabled:
            logger.debug("Script scanning disabled, skipping script pass")
            return []

        # Skip when no script extensions configured
        if not self._config.script_extensions:
            logger.warning("No script extensions configured, skipping script scanning")
            return []

        # Skip when no script files were found
        if not script_files:
            return []

        # Req 9.6: Log candidate script count and extensions at DEBUG level
        extensions_list = sorted(set(f.suffix.lower() for f in script_files if f.suffix))
        logger.debug(
            "Script scanning started",
            candidate_script_count=len(script_files),
            extensions=extensions_list,
        )

        # Build ScriptClassificationContext from pass 1 results
        context = self._build_script_context(
            script_files=script_files,
            all_files=all_files,
            resolved_path=resolved_path,
        )

        # Classify script files using multi-layered signals
        classified_scripts: list[tuple[Path, ClassificationResult]] = []
        for script_path in script_files:
            content = self._read_file_content(script_path)
            result = self._classifier.classify_script(script_path, context, content)
            if result is not None:
                classified_scripts.append((script_path, result))
                # Req 9.2: Log classification at INFO level
                reason = self._determine_classification_reason(script_path, context, result)
                logger.info(
                    "Script classified as AI-related",
                    file_path=str(script_path.resolve()),
                    artifact_type=result.artifact_type.value,
                    reason=reason,
                )
            else:
                # Req 9.1: Log skip at DEBUG level
                logger.debug(
                    "Script skipped, not AI-related",
                    file_path=str(script_path.resolve()),
                    reason="no AI reference found",
                )

        if not classified_scripts:
            return []

        # Scan classified scripts through the pipeline executor
        # Create a temporary executor to scan only the classified scripts
        # We use a custom process that respects pre-existing classifications
        pass2_findings = self._scan_classified_scripts(classified_scripts)

        return pass2_findings

    @staticmethod
    def _determine_classification_reason(
        script_path: Path,
        context: ScriptClassificationContext,
        result: ClassificationResult,
    ) -> str:
        """Determine a human-readable classification reason for a script.

        Maps classification signals and context back to a single-sentence
        reason string as required by Req 9.2.

        Args:
            script_path: The script file that was classified.
            context: The ScriptClassificationContext used for classification.
            result: The ClassificationResult produced by classify_script.

        Returns:
            One of: "referenced by AI artifact", "located in Known_AI_Directory",
            "MCP project detected", "sibling to AI artifact".
        """
        from ai_artifact_risk_validator.classifiers.script_patterns import (
            KNOWN_AI_DIRECTORIES,
            TYPE_INDICATING_DIRS,
            TYPE_INDICATING_PATTERNS,
        )

        resolved_path = script_path.resolve()

        # Check if referenced by AI artifact
        if resolved_path in context.referenced_scripts:
            return "referenced by AI artifact"

        # Check if in a Known AI Directory
        normalized = script_path.as_posix()
        parts_lower = [p.lower() for p in Path(normalized).parts]
        for dir_key in KNOWN_AI_DIRECTORIES:
            dir_segments = dir_key.lower().split("/")
            dir_len = len(dir_segments)
            for i in range(len(parts_lower) - dir_len + 1):
                if parts_lower[i : i + dir_len] == dir_segments:
                    return "located in Known_AI_Directory"

        # Check if in a Type-Indicating Directory (also path-based, reported
        # as "located in Known_AI_Directory" since Req 9.2 defines only 4
        # possible reason strings)
        dir_parts = list(script_path.parts)[:-1]
        for segment in dir_parts:
            segment_lower = segment.lower()
            if segment_lower in TYPE_INDICATING_DIRS:
                return "located in Known_AI_Directory"
            for pattern in TYPE_INDICATING_PATTERNS:
                if re.search(pattern, segment_lower):
                    return "located in Known_AI_Directory"

        # Check if in MCP project directory
        file_dir = resolved_path.parent
        for mcp_dir in context.mcp_project_dirs:
            try:
                file_dir.relative_to(mcp_dir)
                return "MCP project detected"
            except ValueError:
                continue

        # Use the result signals to distinguish directory_context (sibling)
        if "directory_context" in result.signals:
            return "sibling to AI artifact"

        # Default fallback
        return "sibling to AI artifact"

    def _build_script_context(
        self,
        script_files: list[Path],
        all_files: list[Path],
        resolved_path: Path,
    ) -> ScriptClassificationContext:
        """Build ScriptClassificationContext from pass 1 classification results.

        Gathers directory_artifacts from the pipeline executor's tracked
        classifications, runs MCPProjectDetector on all discovered files,
        and runs ReferenceResolver on classified non-script artifacts.

        Args:
            script_files: Script files to be classified in pass 2.
            all_files: All discovered files.
            resolved_path: The root scan path.

        Returns:
            A populated ScriptClassificationContext.
        """
        # Build directory_artifacts from pass 1 classified files
        directory_artifacts: dict[Path, list[tuple[ArtifactType, float]]] = {}
        for file_path, classification in self._pipeline_executor._file_classifications.items():
            file_dir = file_path.resolve().parent
            if file_dir not in directory_artifacts:
                directory_artifacts[file_dir] = []
            directory_artifacts[file_dir].append(
                (classification.artifact_type, classification.confidence)
            )

        # Detect MCP server project directories
        mcp_detector = MCPProjectDetector()
        mcp_project_dirs = mcp_detector.detect(all_files)

        # Resolve script references from classified artifacts
        reference_resolver = ReferenceResolver(
            config=self._config,
            scan_root=resolved_path,
            discovered_files=all_files,
        )
        referenced_scripts = reference_resolver.resolve(
            self._pipeline_executor._file_classifications
        )

        return ScriptClassificationContext(
            directory_artifacts=directory_artifacts,
            referenced_scripts=referenced_scripts,
            mcp_project_dirs=mcp_project_dirs,
        )

    def _scan_classified_scripts(
        self,
        classified_scripts: list[tuple[Path, ClassificationResult]],
    ) -> list[ScanFinding]:
        """Scan pre-classified script files using the scanner registry.

        For each classified script, reads content and runs applicable scanners.
        This bypasses the normal classification step in the pipeline executor
        since scripts have already been classified via classify_script().

        Args:
            classified_scripts: List of (path, classification) tuples.

        Returns:
            List of ScanFinding from all scanned script files.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        all_findings: list[ScanFinding] = []

        with ThreadPoolExecutor(max_workers=self._config.parallel_files) as executor:
            future_to_script = {
                executor.submit(self._scan_single_script, script_path, classification): script_path
                for script_path, classification in classified_scripts
            }

            for future in as_completed(future_to_script):
                script_path = future_to_script[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as exc:
                    logger.error(
                        "Unexpected error scanning script file",
                        artifact_path=str(script_path),
                        error=str(exc),
                    )

        return all_findings

    def _scan_single_script(
        self,
        script_path: Path,
        classification: ClassificationResult,
    ) -> list[ScanFinding]:
        """Scan a single pre-classified script file.

        Reads the file content and runs all applicable scanners for the
        classified artifact type.

        Args:
            script_path: Path to the script file.
            classification: The classification result from classify_script().

        Returns:
            List of ScanFinding from all applicable scanners.
        """
        content = self._read_file_content(script_path)
        if content is None:
            return []

        artifact_type = classification.artifact_type
        scanners = self._scanner_registry.get_scanners_for_artifact(artifact_type)
        if not scanners:
            return []

        return self._pipeline_executor._run_scanners(scanners, content, artifact_type, script_path)

    @staticmethod
    def _read_file_content(file_path: Path) -> str | None:
        """Read file content with UTF-8 fallback to latin-1.

        Args:
            file_path: Path to the file to read.

        Returns:
            File content as string, or None if reading fails.
        """
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                return file_path.read_text(encoding="latin-1")
            except (OSError, PermissionError) as exc:
                logger.warning(
                    "Failed to read file (latin-1 fallback)",
                    artifact_path=str(file_path),
                    error=str(exc),
                )
                return None
        except (OSError, PermissionError) as exc:
            logger.warning(
                "Failed to read file",
                artifact_path=str(file_path),
                error=str(exc),
            )
            return None

    @property
    def version(self) -> str:
        """Return the validator package version."""
        from ai_artifact_risk_validator import __version__

        return __version__

    def _configure_dynamic_scanner(self) -> None:
        """Configure DynamicScanner with allow_dynamic_scan from ValidatorConfig.

        Detects interactive mode based on whether stdin is a TTY.
        Passes the CLI flag value and interactive mode through DynamicScanConfig.
        """
        import sys

        from ai_artifact_risk_validator.models.enums import ScannerModule
        from ai_artifact_risk_validator.models.mcp_models import DynamicScanConfig
        from ai_artifact_risk_validator.scanners.dynamic.scanner import DynamicScanner

        scanner = self._scanner_registry.get_scanner_by_name(ScannerModule.DYNAMIC_SCAN)
        if scanner is not None and isinstance(scanner, DynamicScanner):
            interactive = sys.stdin.isatty()
            scanner._config = DynamicScanConfig(
                allow_dynamic_scan=self._config.allow_dynamic_scan,
                interactive=interactive,
                connection_timeout=self._config.dynamic_connection_timeout,
                per_server_timeout=self._config.dynamic_server_timeout,
            )

    def _configure_code_audit_scanner(self) -> None:
        """Configure CodeAuditScanner with additional shell executables from config.

        Merges any user-specified shell executable names with the built-in defaults
        so that Command_Pattern detection recognizes custom executables.
        """
        from ai_artifact_risk_validator.models.enums import ScannerModule
        from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

        scanner = self._scanner_registry.get_scanner_by_name(ScannerModule.CODE_AUDIT)
        if scanner is not None and isinstance(scanner, CodeAuditScanner):
            scanner.configure(self._config.additional_shell_executables)

    def _configure_provenance_chk_scanner(self) -> None:
        """Configure ProvenanceChkScanner with first-party path patterns from config.

        Passes the user-specified first-party path glob patterns to the scanner
        so it can skip provenance/integrity checks for matching file paths.
        """
        from ai_artifact_risk_validator.models.enums import ScannerModule
        from ai_artifact_risk_validator.scanners.provenance_chk import ProvenanceChkScanner

        scanner = self._scanner_registry.get_scanner_by_name(ScannerModule.PROVENANCE_CHK)
        if scanner is not None and isinstance(scanner, ProvenanceChkScanner):
            scanner.set_first_party_patterns(self._config.first_party_path_patterns)

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
