"""Unit tests for ScannerRegistry."""

import tempfile
from pathlib import Path

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScanFinding,
    ScannerModule,
    ValidatorConfig,
)
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.scanners.registry import ScannerRegistry

# --- Test scanner implementations ---


class FakeSecretScanner(BaseScanner):
    """A fake scanner for testing."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.SECRET_SCAN

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT, ArtifactType.SKILL, ArtifactType.AGENT]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-S3", "P-S4"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        return []


class FakeQualityScanner(BaseScanner):
    """A fake quality scanner for testing."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.QUALITY_LINT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT, ArtifactType.SOP]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-Q1", "SOP-Q1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        return []


class UnavailableScanner(BaseScanner):
    """A scanner that is not available (missing deps)."""

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
        return []

    def is_available(self) -> bool:
        return False


# --- Tests ---


class TestScannerRegistration:
    """Tests for scanner registration."""

    def test_register_valid_scanner(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)
        assert ScannerModule.SECRET_SCAN in registry.registered_scanners

    def test_register_multiple_scanners(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)
        registry.register(FakeQualityScanner)
        assert len(registry.registered_scanners) == 2
        assert ScannerModule.SECRET_SCAN in registry.registered_scanners
        assert ScannerModule.QUALITY_LINT in registry.registered_scanners

    def test_register_non_basescanner_raises_typeerror(self):
        registry = ScannerRegistry()
        with pytest.raises(TypeError, match="Expected a subclass of BaseScanner"):
            registry.register(str)  # type: ignore[arg-type]

    def test_register_instance_raises_typeerror(self):
        registry = ScannerRegistry()
        instance = FakeSecretScanner()
        with pytest.raises(TypeError, match="Expected a subclass of BaseScanner"):
            registry.register(instance)  # type: ignore[arg-type]


class TestGetScannersForArtifact:
    """Tests for getting scanners by artifact type."""

    def test_returns_applicable_scanners(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)
        registry.register(FakeQualityScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        assert len(scanners) == 2

    def test_filters_by_artifact_type(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)
        registry.register(FakeQualityScanner)

        # AGENT is only in FakeSecretScanner's applicable types
        scanners = registry.get_scanners_for_artifact(ArtifactType.AGENT)
        assert len(scanners) == 1
        assert scanners[0].name == ScannerModule.SECRET_SCAN

    def test_returns_empty_for_no_match(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)

        # MCP not in FakeSecretScanner's applicable types
        scanners = registry.get_scanners_for_artifact(ArtifactType.MCP)
        assert scanners == []

    def test_excludes_unavailable_scanners(self):
        registry = ScannerRegistry()
        registry.register(UnavailableScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        assert scanners == []

    def test_lazy_instantiation(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)

        # The instance should exist after registration (created in register())
        assert ScannerModule.SECRET_SCAN in registry._scanner_instances

        # Getting scanners should return the same instance
        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        assert len(scanners) == 1
        assert scanners[0] is registry._scanner_instances[ScannerModule.SECRET_SCAN]


class TestEnabledDisabledConfig:
    """Tests for enabled/disabled scanner configuration."""

    def test_disabled_scanners_excluded(self):
        config = ValidatorConfig(disabled_scanners=[ScannerModule.SECRET_SCAN])
        registry = ScannerRegistry(config=config)
        registry.register(FakeSecretScanner)
        registry.register(FakeQualityScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        assert len(scanners) == 1
        assert scanners[0].name == ScannerModule.QUALITY_LINT

    def test_enabled_scanners_whitelist(self):
        config = ValidatorConfig(enabled_scanners=[ScannerModule.SECRET_SCAN])
        registry = ScannerRegistry(config=config)
        registry.register(FakeSecretScanner)
        registry.register(FakeQualityScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        assert len(scanners) == 1
        assert scanners[0].name == ScannerModule.SECRET_SCAN

    def test_disabled_takes_priority_over_enabled(self):
        config = ValidatorConfig(
            enabled_scanners=[ScannerModule.SECRET_SCAN, ScannerModule.QUALITY_LINT],
            disabled_scanners=[ScannerModule.SECRET_SCAN],
        )
        registry = ScannerRegistry(config=config)
        registry.register(FakeSecretScanner)
        registry.register(FakeQualityScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        assert len(scanners) == 1
        assert scanners[0].name == ScannerModule.QUALITY_LINT

    def test_no_config_enables_all(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)
        registry.register(FakeQualityScanner)

        scanners = registry.get_scanners_for_artifact(ArtifactType.PROMPT)
        assert len(scanners) == 2


class TestGetScannerByName:
    """Tests for getting a scanner by name."""

    def test_returns_registered_scanner(self):
        registry = ScannerRegistry()
        registry.register(FakeSecretScanner)

        scanner = registry.get_scanner_by_name(ScannerModule.SECRET_SCAN)
        assert scanner is not None
        assert scanner.name == ScannerModule.SECRET_SCAN

    def test_returns_none_for_unregistered(self):
        registry = ScannerRegistry()
        scanner = registry.get_scanner_by_name(ScannerModule.SECRET_SCAN)
        assert scanner is None


class TestPluginDirectoryDiscovery:
    """Tests for plugin directory discovery."""

    def test_loads_scanner_from_plugin_file(self):
        plugin_code = """
from ai_artifact_risk_validator.models import ArtifactType, ScanFinding, ScannerModule
from ai_artifact_risk_validator.scanners.base import BaseScanner


class MyPluginScanner(BaseScanner):
    @property
    def name(self) -> ScannerModule:
        return ScannerModule.CODE_AUDIT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PLUGIN]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["PL-S1"]

    def scan(self, artifact_content, artifact_type, artifact_path):
        return []
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "my_scanner.py"
            plugin_file.write_text(plugin_code)

            registry = ScannerRegistry()
            registry.discover_plugin_dir(Path(tmpdir))

            assert ScannerModule.CODE_AUDIT in registry.registered_scanners

    def test_skips_underscore_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file starting with underscore
            plugin_file = Path(tmpdir) / "_private.py"
            plugin_file.write_text("# should be skipped")

            registry = ScannerRegistry()
            registry.discover_plugin_dir(Path(tmpdir))
            assert registry.registered_scanners == []

    def test_handles_nonexistent_directory(self):
        registry = ScannerRegistry()
        registry.discover_plugin_dir(Path("/nonexistent/path"))
        assert registry.registered_scanners == []

    def test_handles_invalid_plugin_file_gracefully(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "bad_plugin.py"
            plugin_file.write_text("raise RuntimeError('import failed')")

            registry = ScannerRegistry()
            # Should not raise, just log a warning
            registry.discover_plugin_dir(Path(tmpdir))
            assert registry.registered_scanners == []


class TestEntryPointDiscovery:
    """Tests for entry point discovery."""

    def test_discover_entry_points_no_error_when_none_exist(self):
        """Entry point discovery should not raise even when no plugins are installed."""
        registry = ScannerRegistry()
        registry.discover_entry_points()
        # No scanners from entry points expected in test environment
        # Just verify it doesn't crash
