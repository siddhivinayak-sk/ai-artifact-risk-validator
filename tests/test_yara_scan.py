"""Tests for the YaraScan scanner.

Note: Test content strings that would match YARA malware rules are constructed
programmatically at runtime to avoid triggering host antivirus scanners on
static test file analysis.
"""

from __future__ import annotations

import pytest

from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.yara_scan import YaraScanScanner


@pytest.fixture
def scanner() -> YaraScanScanner:
    return YaraScanScanner()


class TestScannerMetadata:
    def test_name(self, scanner: YaraScanScanner) -> None:
        assert scanner.name == ScannerModule.YARA_SCAN

    def test_applicable_types(self, scanner: YaraScanScanner) -> None:
        types = scanner.applicable_artifact_types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.MCP in types
        assert len(types) == len(list(ArtifactType))

    def test_detected_risk_ids(self, scanner: YaraScanScanner) -> None:
        ids = scanner.detected_risk_ids
        assert "Y-S1" in ids
        assert "Y-S2" in ids
        assert "Y-S3" in ids
        assert "Y-S4" in ids


class TestAvailability:
    def test_is_available_returns_bool(self, scanner: YaraScanScanner) -> None:
        result = scanner.is_available()
        assert isinstance(result, bool)

    def test_scan_returns_empty_when_unavailable(
        self, scanner: YaraScanScanner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("ai_artifact_risk_validator.scanners.yara_scan._compiled_rules", None)
        monkeypatch.setattr("ai_artifact_risk_validator.scanners.yara_scan._rules_loaded", True)
        findings = scanner.scan("some content", ArtifactType.SKILL, "test.py")
        assert findings == []

    def test_scan_empty_content(self, scanner: YaraScanScanner) -> None:
        # Empty content should not raise and should return a list
        findings = scanner.scan("", ArtifactType.SKILL, "empty.py")
        assert isinstance(findings, list)

    def test_scan_clean_code_returns_list(self, scanner: YaraScanScanner) -> None:
        content = "def greet(name: str) -> str:\n    return f'Hello {name}'\n"
        findings = scanner.scan(content, ArtifactType.SKILL, "safe.py")
        assert isinstance(findings, list)


class TestWithYaraAvailable:
    """Tests that only run when yara-python is installed."""

    @pytest.fixture(autouse=True)
    def skip_if_no_yara(self, scanner: YaraScanScanner) -> None:  # type: ignore[return]
        if not scanner.is_available():
            pytest.skip("yara-python not installed")

    def test_clean_code_no_findings(self, scanner: YaraScanScanner) -> None:
        content = "def hello(name: str) -> str:\n    return f'Hello, {name}!'\n"
        findings = scanner.scan(content, ArtifactType.SKILL, "hello.py")
        assert findings == []

    def test_cryptominer_stratum_pattern(self, scanner: YaraScanScanner) -> None:
        # Construct the test string at runtime to avoid static AV flagging
        proto = "stratum" + "+" + "tcp" + "://"
        pool = "pool.mine" + "xmr.com" + ":443"
        content = f"connect_to('{proto}{pool}')\n"
        findings = scanner.scan(content, ArtifactType.SKILL, "test.py")
        assert any(f.id == "Y-S3" for f in findings)

    def test_findings_have_valid_structure(self, scanner: YaraScanScanner) -> None:
        # Use a known-safe YARA trigger for cryptominer (no exec/eval involved)
        proto = "stratum" + "+ssl" + "://"
        pool = "nanopool" + ".org"
        content = f"pool = '{proto}{pool}'\n"
        findings = scanner.scan(content, ArtifactType.SKILL, "test.py")
        for f in findings:
            assert f.id.startswith("Y-")
            assert 0.0 <= f.confidence <= 1.0
            assert f.scanner_module == ScannerModule.YARA_SCAN
