"""Parallel scanner execution engine for the validation pipeline.

Implements two levels of parallelism:
1. File-level: multiple files processed concurrently
2. Scanner-level: multiple scanners run concurrently within each file

Each scanner invocation has a 30-second timeout. Scanner exceptions and file
read errors are handled gracefully with logging, ensuring the pipeline always
completes without propagating exceptions.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.classifiers import ArtifactClassifier
from ai_artifact_risk_validator.models import ScanFinding, ValidatorConfig
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.scanners.registry import ScannerRegistry

logger = get_logger(__name__)

# Default timeout in seconds for each scanner invocation
_SCANNER_TIMEOUT_SECONDS: float = 30.0


class PipelineExecutor:
    """Executes scanners in parallel across files and within each file.

    Uses ThreadPoolExecutor for file-level parallelism and a nested
    ThreadPoolExecutor for scanner-level parallelism per file. Each
    scanner invocation is subject to a 30-second timeout.

    Args:
        config: Optional ValidatorConfig providing parallel_files and
            parallel_scanners settings. Defaults are used if None.
    """

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        self._config = config or ValidatorConfig()
        self._parallel_files: int = self._config.parallel_files
        self._parallel_scanners: int = self._config.parallel_scanners

    def execute(
        self,
        files: list[Path],
        classifier: ArtifactClassifier,
        scanner_registry: ScannerRegistry,
    ) -> list[ScanFinding]:
        """Execute the scanning pipeline across all files.

        For each file:
        1. Read the file content
        2. Classify the artifact type
        3. Get applicable scanners
        4. Run all scanners in parallel with timeout

        Args:
            files: List of file paths to scan.
            classifier: ArtifactClassifier for determining artifact types.
            scanner_registry: ScannerRegistry providing applicable scanners.

        Returns:
            Flat list of all ScanFinding objects collected across all files.
        """
        if not files:
            return []

        all_findings: list[ScanFinding] = []

        with ThreadPoolExecutor(max_workers=self._parallel_files) as file_executor:
            future_to_file = {
                file_executor.submit(
                    self._process_file, file_path, classifier, scanner_registry
                ): file_path
                for file_path in files
            }

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as exc:
                    logger.error(
                        "Unexpected error processing file",
                        artifact_path=str(file_path),
                        error=str(exc),
                    )

        return all_findings

    def _process_file(
        self,
        file_path: Path,
        classifier: ArtifactClassifier,
        scanner_registry: ScannerRegistry,
    ) -> list[ScanFinding]:
        """Process a single file: read, classify, and scan.

        Args:
            file_path: Path to the file to process.
            classifier: ArtifactClassifier for determining the artifact type.
            scanner_registry: ScannerRegistry for getting applicable scanners.

        Returns:
            List of ScanFinding objects from all scanners for this file.
        """
        # Step 1: Read file content
        content = self._read_file(file_path)
        if content is None:
            return []

        # Step 2: Classify the artifact
        classification = classifier.classify(file_path, content)
        if classification is None:
            logger.info(
                "Could not classify artifact type for file",
                artifact_path=str(file_path),
            )
            return []

        artifact_type = classification.artifact_type

        # Step 3: Get applicable scanners
        scanners = scanner_registry.get_scanners_for_artifact(artifact_type)
        if not scanners:
            logger.debug(
                "No applicable scanners for file",
                artifact_path=str(file_path),
                artifact_type=artifact_type.value,
            )
            return []

        # Step 4: Run all scanners in parallel
        return self._run_scanners(scanners, content, artifact_type, file_path)

    def _run_scanners(
        self,
        scanners: list[BaseScanner],
        content: str,
        artifact_type: "ArtifactType",
        file_path: Path,
    ) -> list[ScanFinding]:
        """Run all applicable scanners in parallel for a single file.

        Each scanner invocation has a 30-second timeout. If a scanner times
        out or raises an exception, it is logged and processing continues
        with the remaining scanners.

        Args:
            scanners: List of scanner instances to run.
            content: The file content to scan.
            artifact_type: The classified artifact type.
            file_path: The path of the file being scanned.

        Returns:
            Combined list of findings from all scanners.
        """
        from ai_artifact_risk_validator.models.enums import ArtifactType

        findings: list[ScanFinding] = []
        artifact_path_str = str(file_path)

        with ThreadPoolExecutor(max_workers=self._parallel_scanners) as scanner_executor:
            future_to_scanner = {
                scanner_executor.submit(
                    self._invoke_scanner,
                    scanner,
                    content,
                    artifact_type,
                    artifact_path_str,
                ): scanner
                for scanner in scanners
            }

            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                scanner_name = scanner.name.value
                try:
                    result = future.result(timeout=_SCANNER_TIMEOUT_SECONDS)
                    findings.extend(result)
                except TimeoutError:
                    logger.error(
                        "Scanner timed out",
                        scanner_module=scanner_name,
                        timeout_seconds=_SCANNER_TIMEOUT_SECONDS,
                        artifact_path=artifact_path_str,
                    )
                except Exception as exc:
                    logger.error(
                        "Scanner raised an exception",
                        scanner_module=scanner_name,
                        artifact_path=artifact_path_str,
                        error=str(exc),
                    )

        return findings

    @staticmethod
    def _invoke_scanner(
        scanner: BaseScanner,
        content: str,
        artifact_type: "ArtifactType",
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Invoke a single scanner's scan method.

        This is the unit of work submitted to the scanner-level thread pool.

        Args:
            scanner: The scanner instance to invoke.
            content: Artifact content to scan.
            artifact_type: The classified artifact type.
            artifact_path: The file path string.

        Returns:
            List of ScanFinding objects from this scanner.
        """
        return scanner.scan(content, artifact_type, artifact_path)

    @staticmethod
    def _read_file(file_path: Path) -> str | None:
        """Read file content with graceful error handling.

        Tries UTF-8 encoding first, then falls back to latin-1.
        Logs a warning and returns None on any failure.

        Args:
            file_path: Path to the file to read.

        Returns:
            File content as a string, or None if reading fails.
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
