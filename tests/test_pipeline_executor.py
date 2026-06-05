"""Unit tests for PipelineExecutor."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from ai_artifact_risk_validator.classifiers import ArtifactClassifier
from ai_artifact_risk_validator.models import (
    ArtifactType,
    FindingLocation,
    GateAction,
    Priority,
    RiskCategory,
    ScanFinding,
    ScannerModule,
    SeverityLabel,
    ValidatorConfig,
)
from ai_artifact_risk_validator.pipeline.executor import PipelineExecutor
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.scanners.registry import ScannerRegistry


# --- Fake scanner implementations for testing ---


class FakePromptScanner(BaseScanner):
    """A fake scanner that produces findings for prompt artifacts."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.QUALITY_LINT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-Q1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        return [
            ScanFinding(
                id="P-Q1",
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                severity_score=5,
                severity_label=SeverityLabel.MEDIUM,
                priority=Priority.P2,
                gate_action=GateAction.WARN,
                category=RiskCategory.QUALITY,
                title="Quality issue detected",
                description="Test quality finding",
                location=FindingLocation(line=1),
                evidence="test evidence",
                confidence=0.85,
                scanner_module=ScannerModule.QUALITY_LINT,
                remediation="Fix the issue",
            )
        ]


class FakeSecretScanner(BaseScanner):
    """A fake scanner that produces findings for secret detection."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.SECRET_SCAN

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT, ArtifactType.SKILL]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-S3"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        if "SECRET" in artifact_content:
            return [
                ScanFinding(
                    id="P-S3",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    severity_score=9,
                    severity_label=SeverityLabel.CRITICAL,
                    priority=Priority.P0,
                    gate_action=GateAction.BLOCK,
                    category=RiskCategory.SECURITY,
                    title="Secret detected",
                    description="Hardcoded secret found",
                    location=FindingLocation(line=1),
                    evidence="SECRET",
                    confidence=0.95,
                    scanner_module=ScannerModule.SECRET_SCAN,
                    remediation="Remove the secret",
                )
            ]
        return []


class FailingScanner(BaseScanner):
    """A scanner that always raises an exception."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.INJECTION_DET

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-S1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        raise RuntimeError("Scanner crashed!")


class SlowScanner(BaseScanner):
    """A scanner that takes too long (simulates timeout)."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.BIAS_DETECTOR

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["ETH-1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        # Sleep for longer than the timeout
        time.sleep(60)
        return []


class EmptyScanner(BaseScanner):
    """A scanner that returns no findings."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.PERM_AUDIT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT, ArtifactType.SKILL]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["SK-S1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        return []


# --- Helper functions ---


def _create_prompt_file(directory: Path, name: str = "test.prompt.md", content: str = "## System Prompt\nYou are a helpful assistant.\n") -> Path:
    """Create a prompt file that will be classified as ArtifactType.PROMPT."""
    file_path = directory / name
    file_path.write_text(content, encoding="utf-8")
    return file_path


def _make_registry(*scanner_classes: type[BaseScanner]) -> ScannerRegistry:
    """Create a ScannerRegistry with given scanners registered."""
    registry = ScannerRegistry()
    for cls in scanner_classes:
        registry.register(cls)
    return registry


# --- Tests ---


class TestPipelineExecutorBasic:
    """Tests for basic PipelineExecutor functionality."""

    def test_empty_file_list_returns_empty(self):
        executor = PipelineExecutor()
        classifier = ArtifactClassifier()
        registry = _make_registry(FakePromptScanner)

        findings = executor.execute([], classifier, registry)
        assert findings == []

    def test_single_file_single_scanner(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            file_path = _create_prompt_file(tmpdir_path)

            executor = PipelineExecutor()
            classifier = ArtifactClassifier()
            registry = _make_registry(FakePromptScanner)

            findings = executor.execute([file_path], classifier, registry)
            assert len(findings) == 1
            assert findings[0].id == "P-Q1"
            assert findings[0].artifact_path == str(file_path)

    def test_single_file_multiple_scanners(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            content = "## System Prompt\nHere is a SECRET key.\n"
            file_path = _create_prompt_file(tmpdir_path, content=content)

            executor = PipelineExecutor()
            classifier = ArtifactClassifier()
            registry = _make_registry(FakePromptScanner, FakeSecretScanner)

            findings = executor.execute([file_path], classifier, registry)
            # FakePromptScanner always produces 1 finding, FakeSecretScanner produces 1 with SECRET
            assert len(findings) == 2
            finding_ids = {f.id for f in findings}
            assert "P-Q1" in finding_ids
            assert "P-S3" in finding_ids

    def test_multiple_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            file1 = _create_prompt_file(tmpdir_path, "file1.prompt.md")
            file2 = _create_prompt_file(tmpdir_path, "file2.prompt.md")

            executor = PipelineExecutor()
            classifier = ArtifactClassifier()
            registry = _make_registry(FakePromptScanner)

            findings = executor.execute([file1, file2], classifier, registry)
            assert len(findings) == 2


class TestPipelineExecutorErrorHandling:
    """Tests for graceful error handling in PipelineExecutor."""

    def test_unreadable_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            # Create a path to a non-existent file
            fake_file = tmpdir_path / "nonexistent.prompt.md"

            executor = PipelineExecutor()
            classifier = ArtifactClassifier()
            registry = _make_registry(FakePromptScanner)

            findings = executor.execute([fake_file], classifier, registry)
            assert findings == []

    def test_unclassifiable_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            # A file that won't be classified as any artifact type
            file_path = tmpdir_path / "random.txt"
            file_path.write_text("just plain text with no markers")

            executor = PipelineExecutor()
            classifier = ArtifactClassifier()
            registry = _make_registry(FakePromptScanner)

            findings = executor.execute([file_path], classifier, registry)
            assert findings == []

    def test_scanner_exception_does_not_stop_other_scanners(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            file_path = _create_prompt_file(tmpdir_path)

            executor = PipelineExecutor()
            classifier = ArtifactClassifier()
            # FailingScanner raises, but FakePromptScanner should still produce findings
            registry = _make_registry(FakePromptScanner, FailingScanner)

            findings = executor.execute([file_path], classifier, registry)
            # The FakePromptScanner should still produce its finding
            assert len(findings) == 1
            assert findings[0].id == "P-Q1"

    def test_no_applicable_scanners_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            file_path = _create_prompt_file(tmpdir_path)

            executor = PipelineExecutor()
            classifier = ArtifactClassifier()
            # EmptyScanner applies to PROMPT but returns no findings
            registry = _make_registry(EmptyScanner)

            findings = executor.execute([file_path], classifier, registry)
            assert findings == []


class TestPipelineExecutorParallelism:
    """Tests for parallel execution configuration."""

    def test_custom_parallel_config(self):
        config = ValidatorConfig(parallel_files=2, parallel_scanners=2)
        executor = PipelineExecutor(config=config)
        assert executor._parallel_files == 2
        assert executor._parallel_scanners == 2

    def test_default_config_uses_defaults(self):
        executor = PipelineExecutor()
        assert executor._parallel_files == 4
        assert executor._parallel_scanners == 4

    def test_parallel_files_execution(self):
        """Verify that multiple files are processed and produce findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            files = []
            for i in range(5):
                f = _create_prompt_file(tmpdir_path, f"file{i}.prompt.md")
                files.append(f)

            config = ValidatorConfig(parallel_files=3, parallel_scanners=2)
            executor = PipelineExecutor(config=config)
            classifier = ArtifactClassifier()
            registry = _make_registry(FakePromptScanner)

            findings = executor.execute(files, classifier, registry)
            # Each file should produce 1 finding from FakePromptScanner
            assert len(findings) == 5


class TestPipelineExecutorTimeout:
    """Tests for scanner timeout handling."""

    def test_slow_scanner_times_out_gracefully(self):
        """Test that a scanner exceeding the timeout is handled gracefully.

        Note: This test uses a patched timeout to avoid waiting 30 seconds.
        """
        import ai_artifact_risk_validator.pipeline.executor as executor_module

        original_timeout = executor_module._SCANNER_TIMEOUT_SECONDS

        try:
            # Set a very short timeout for testing
            executor_module._SCANNER_TIMEOUT_SECONDS = 0.1

            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir_path = Path(tmpdir)
                file_path = _create_prompt_file(tmpdir_path)

                executor = PipelineExecutor()
                classifier = ArtifactClassifier()
                # SlowScanner sleeps for 60s, will timeout
                # FakePromptScanner should still produce its finding
                registry = _make_registry(FakePromptScanner, SlowScanner)

                findings = executor.execute([file_path], classifier, registry)
                # FakePromptScanner finding should still be collected
                assert len(findings) == 1
                assert findings[0].id == "P-Q1"
        finally:
            executor_module._SCANNER_TIMEOUT_SECONDS = original_timeout
