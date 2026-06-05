"""Unit tests for the DepScan scanner module."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.dep_scan import (
    DepScanScanner,
    _is_typosquat_candidate,
    _levenshtein_distance,
    _parse_package_json,
    _parse_pyproject_toml,
    _parse_requirements_txt,
)


@pytest.fixture
def scanner() -> DepScanScanner:
    """Create a DepScanScanner instance for testing."""
    return DepScanScanner()


class TestScannerMetadata:
    """Tests for scanner properties and metadata."""

    def test_name(self, scanner: DepScanScanner) -> None:
        assert scanner.name == ScannerModule.DEP_SCAN

    def test_applicable_artifact_types(self, scanner: DepScanScanner) -> None:
        types = scanner.applicable_artifact_types
        assert ArtifactType.SKILL in types
        assert ArtifactType.MCP in types
        assert ArtifactType.HOOK in types
        assert ArtifactType.PLUGIN in types
        assert len(types) == 4

    def test_detected_risk_ids(self, scanner: DepScanScanner) -> None:
        risk_ids = scanner.detected_risk_ids
        expected = ["MCP-S4", "MCP-S11", "MCP-S12", "PL-S3", "PL-S8", "SK-S7"]
        assert set(risk_ids) == set(expected)

    def test_is_available_always_true(self, scanner: DepScanScanner) -> None:
        assert scanner.is_available() is True


class TestLevenshteinDistance:
    """Tests for edit distance calculation."""

    def test_identical_strings(self) -> None:
        assert _levenshtein_distance("hello", "hello") == 0

    def test_single_substitution(self) -> None:
        assert _levenshtein_distance("cat", "bat") == 1

    def test_single_insertion(self) -> None:
        assert _levenshtein_distance("cat", "cats") == 1

    def test_single_deletion(self) -> None:
        assert _levenshtein_distance("cats", "cat") == 1

    def test_empty_strings(self) -> None:
        assert _levenshtein_distance("", "") == 0

    def test_one_empty(self) -> None:
        assert _levenshtein_distance("abc", "") == 3


class TestTyposquatDetection:
    """Tests for typosquatting candidate detection."""

    def test_exact_match_not_flagged(self) -> None:
        assert _is_typosquat_candidate("requests") is None

    def test_typosquat_detected(self) -> None:
        result = _is_typosquat_candidate("requets")
        assert result == "requests"

    def test_typosquat_lodash(self) -> None:
        result = _is_typosquat_candidate("lodahs")
        assert result == "lodash"

    def test_unrelated_name_not_flagged(self) -> None:
        assert _is_typosquat_candidate("mycompanylib") is None

    def test_short_name_not_flagged(self) -> None:
        # Very short names shouldn't trigger false positives from popular short names
        assert _is_typosquat_candidate("ab") is None


class TestRequirementsTxtParsing:
    """Tests for requirements.txt parsing."""

    def test_pinned_dependency(self) -> None:
        content = "requests==2.28.1"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "requests"
        assert deps[0]["version"] == "2.28.1"
        assert deps[0]["operator"] == "=="
        assert deps[0]["pinned"] is True

    def test_unpinned_dependency(self) -> None:
        content = "requests"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "requests"
        assert deps[0]["version"] is None
        assert deps[0]["pinned"] is False

    def test_minimum_version(self) -> None:
        content = "flask>=2.0.0"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["operator"] == ">="
        assert deps[0]["pinned"] is False

    def test_comments_ignored(self) -> None:
        content = "# This is a comment\nrequests==2.28.1"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1

    def test_blank_lines_ignored(self) -> None:
        content = "requests==2.28.1\n\nflask==2.0.0"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 2

    def test_options_ignored(self) -> None:
        content = "--index-url https://pypi.org/simple\nrequests==2.28.1"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1

    def test_environment_markers(self) -> None:
        content = 'pywin32==305; sys_platform == "win32"'
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "pywin32"

    def test_multiple_dependencies(self) -> None:
        content = "requests==2.28.1\nflask>=2.0.0\nnumpy\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 3


class TestPackageJsonParsing:
    """Tests for package.json parsing."""

    def test_pinned_dependency(self) -> None:
        content = '{"dependencies": {"express": "4.18.2"}}'
        deps = _parse_package_json(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "express"
        assert deps[0]["version"] == "4.18.2"
        assert deps[0]["pinned"] is True

    def test_range_dependency(self) -> None:
        content = '{"dependencies": {"lodash": "^4.17.21"}}'
        deps = _parse_package_json(content)
        assert len(deps) == 1
        assert deps[0]["pinned"] is False

    def test_wildcard_dependency(self) -> None:
        content = '{"dependencies": {"lodash": "*"}}'
        deps = _parse_package_json(content)
        assert len(deps) == 1
        assert deps[0]["wildcard"] is True

    def test_latest_dependency(self) -> None:
        content = '{"dependencies": {"lodash": "latest"}}'
        deps = _parse_package_json(content)
        assert len(deps) == 1
        assert deps[0]["wildcard"] is True

    def test_dev_dependencies(self) -> None:
        content = '{"devDependencies": {"jest": "29.0.0"}}'
        deps = _parse_package_json(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "jest"

    def test_multiple_sections(self) -> None:
        content = '{"dependencies": {"express": "4.18.2"}, "devDependencies": {"jest": "29.0.0"}}'
        deps = _parse_package_json(content)
        assert len(deps) == 2

    def test_invalid_json_returns_empty(self) -> None:
        content = "not valid json {"
        deps = _parse_package_json(content)
        assert deps == []


class TestPyprojectTomlParsing:
    """Tests for pyproject.toml parsing."""

    def test_pinned_dependency(self) -> None:
        content = '[project]\ndependencies = [\n  "requests==2.28.1"\n]'
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "requests"
        assert deps[0]["pinned"] is True

    def test_range_dependency(self) -> None:
        content = '[project]\ndependencies = [\n  "flask>=2.0.0"\n]'
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 1
        assert deps[0]["operator"] == ">="
        assert deps[0]["pinned"] is False

    def test_multiple_dependencies(self) -> None:
        content = '[project]\ndependencies = [\n  "requests==2.28.1",\n  "flask>=2.0.0"\n]'
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 2


class TestKnownVulnerabilities:
    """Tests for known vulnerability detection."""

    def test_detects_vulnerable_python_package(self, scanner: DepScanScanner) -> None:
        content = "pyyaml==5.3\nrequests==2.28.1"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        vuln_findings = [
            f
            for f in findings
            if "vulnerability" in f.description.lower() or "CVE" in f.description
        ]
        assert len(vuln_findings) >= 1
        assert any("pyyaml" in f.evidence.lower() for f in vuln_findings)

    def test_detects_vulnerable_node_package(self, scanner: DepScanScanner) -> None:
        content = '{"dependencies": {"lodash": "4.17.20"}}'
        findings = scanner.scan(content, ArtifactType.MCP, "package.json")
        vuln_findings = [
            f
            for f in findings
            if "vulnerability" in f.description.lower() or "CVE" in f.description
        ]
        assert len(vuln_findings) >= 1

    def test_mcp_uses_MCP_S4(self, scanner: DepScanScanner) -> None:
        content = "pyyaml==5.3"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        vuln_findings = [f for f in findings if "CVE" in f.description]
        assert any(f.id == "MCP-S4" for f in vuln_findings)

    def test_plugin_uses_PL_S3(self, scanner: DepScanScanner) -> None:
        content = '{"dependencies": {"lodash": "4.17.20"}}'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        vuln_findings = [f for f in findings if "CVE" in f.description]
        assert any(f.id == "PL-S3" for f in vuln_findings)

    def test_skill_uses_SK_S7(self, scanner: DepScanScanner) -> None:
        content = "pyyaml==5.3"
        findings = scanner.scan(content, ArtifactType.SKILL, "requirements.txt")
        vuln_findings = [f for f in findings if "CVE" in f.description]
        assert any(f.id == "SK-S7" for f in vuln_findings)

    def test_vulnerability_confidence_high(self, scanner: DepScanScanner) -> None:
        content = "pyyaml==5.3"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        vuln_findings = [f for f in findings if "CVE" in f.description]
        assert all(f.confidence >= 0.85 for f in vuln_findings)


class TestUnpinnedDependencies:
    """Tests for unpinned dependency detection."""

    def test_detects_no_version(self, scanner: DepScanScanner) -> None:
        content = "requests\nflask"
        findings = scanner.scan(content, ArtifactType.SKILL, "requirements.txt")
        unpinned = [
            f for f in findings if "unpinned" in f.description.lower() or "No version" in f.evidence
        ]
        assert len(unpinned) >= 2

    def test_detects_wildcard_version(self, scanner: DepScanScanner) -> None:
        content = '{"dependencies": {"lodash": "*"}}'
        findings = scanner.scan(content, ArtifactType.MCP, "package.json")
        unpinned = [
            f
            for f in findings
            if "unpinned" in f.description.lower()
            or "wildcard" in f.description.lower()
            or "Wildcard" in f.evidence
            or "Unrestricted" in f.evidence
        ]
        assert len(unpinned) >= 1

    def test_detects_latest_version(self, scanner: DepScanScanner) -> None:
        content = '{"dependencies": {"express": "latest"}}'
        findings = scanner.scan(content, ArtifactType.MCP, "package.json")
        unpinned = [
            f
            for f in findings
            if "unpinned" in f.description.lower() or "Unrestricted" in f.evidence
        ]
        assert len(unpinned) >= 1

    def test_unpinned_confidence_070(self, scanner: DepScanScanner) -> None:
        content = "requests"
        findings = scanner.scan(content, ArtifactType.SKILL, "requirements.txt")
        unpinned = [f for f in findings if "No version" in f.evidence]
        assert all(f.confidence == 0.70 for f in unpinned)

    def test_pinned_not_flagged_unpinned(self, scanner: DepScanScanner) -> None:
        # A properly pinned, non-vulnerable package shouldn't trigger unpinned finding
        content = "click==8.1.7"
        findings = scanner.scan(content, ArtifactType.SKILL, "requirements.txt")
        unpinned = [
            f for f in findings if "unpinned" in f.description.lower() or "No version" in f.evidence
        ]
        assert len(unpinned) == 0


class TestTyposquattingDetection:
    """Tests for typosquatting detection in manifests."""

    def test_detects_typosquat_python(self, scanner: DepScanScanner) -> None:
        content = "requets==2.28.1"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        typo_findings = [
            f
            for f in findings
            if "typosquat" in f.description.lower() or "similar to" in f.evidence.lower()
        ]
        assert len(typo_findings) >= 1

    def test_detects_typosquat_node(self, scanner: DepScanScanner) -> None:
        content = '{"dependencies": {"lodahs": "^4.17.21"}}'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        typo_findings = [f for f in findings if "similar to" in f.evidence.lower()]
        assert len(typo_findings) >= 1

    def test_mcp_typosquat_uses_MCP_S12(self, scanner: DepScanScanner) -> None:
        content = "requets==2.28.1"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        typo_findings = [f for f in findings if "similar to" in f.evidence.lower()]
        assert any(f.id == "MCP-S12" for f in typo_findings)

    def test_plugin_typosquat_uses_PL_S8(self, scanner: DepScanScanner) -> None:
        content = '{"dependencies": {"lodahs": "^4.17.21"}}'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        typo_findings = [f for f in findings if "similar to" in f.evidence.lower()]
        assert any(f.id == "PL-S8" for f in typo_findings)


class TestExcessiveDependencies:
    """Tests for excessive dependency count detection."""

    def test_normal_count_no_finding(self, scanner: DepScanScanner) -> None:
        # 5 dependencies should be fine
        content = "\n".join(f"package{i}==1.0.0" for i in range(5))
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        excessive = [
            f
            for f in findings
            if "excessive" in f.description.lower() or "dependencies declared" in f.evidence.lower()
        ]
        assert len(excessive) == 0

    def test_excessive_count_flagged(self, scanner: DepScanScanner) -> None:
        # 51 dependencies exceeds threshold
        content = "\n".join(f"package{i}==1.0.0" for i in range(51))
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        excessive = [
            f
            for f in findings
            if "excessive" in f.description.lower() or "dependencies declared" in f.evidence.lower()
        ]
        assert len(excessive) >= 1


class TestUntrustedSources:
    """Tests for untrusted source detection."""

    def test_detects_git_url(self, scanner: DepScanScanner) -> None:
        content = "git+https://github.com/user/repo.git#egg=package"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        source_findings = [
            f
            for f in findings
            if "non-standard" in f.description.lower() or "Git URL" in f.description
        ]
        assert len(source_findings) >= 1

    def test_detects_direct_url(self, scanner: DepScanScanner) -> None:
        content = "https://evil.com/malicious-package-1.0.tar.gz"
        findings = scanner.scan(content, ArtifactType.SKILL, "requirements.txt")
        source_findings = [
            f for f in findings if "non-standard" in f.description.lower() or "URL" in f.description
        ]
        assert len(source_findings) >= 1


class TestManifestTypeDetection:
    """Tests for manifest type detection."""

    def test_non_manifest_returns_empty(self, scanner: DepScanScanner) -> None:
        content = "This is just a regular markdown file with no dependencies."
        findings = scanner.scan(content, ArtifactType.MCP, "readme.md")
        assert findings == []

    def test_detects_requirements_txt_by_path(self, scanner: DepScanScanner) -> None:
        content = "requests==2.28.1"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        # Should parse and detect (no vulns for requests 2.28.1, but it's a valid scan)
        assert isinstance(findings, list)

    def test_detects_package_json_by_path(self, scanner: DepScanScanner) -> None:
        content = '{"dependencies": {"express": "4.18.2"}}'
        findings = scanner.scan(content, ArtifactType.PLUGIN, "package.json")
        assert isinstance(findings, list)

    def test_detects_pyproject_toml_by_path(self, scanner: DepScanScanner) -> None:
        content = '[project]\ndependencies = [\n  "click==8.1.7"\n]'
        findings = scanner.scan(content, ArtifactType.SKILL, "pyproject.toml")
        assert isinstance(findings, list)


class TestConfidenceBands:
    """Tests for confidence band assignment per design spec."""

    def test_known_cve_high_confidence(self, scanner: DepScanScanner) -> None:
        content = "pyyaml==5.3"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        vuln_findings = [f for f in findings if "CVE" in f.description]
        # Known CVE match should be 0.95-1.0
        assert all(0.95 <= f.confidence <= 1.0 for f in vuln_findings)

    def test_unpinned_moderate_confidence(self, scanner: DepScanScanner) -> None:
        content = "requests"
        findings = scanner.scan(content, ArtifactType.SKILL, "requirements.txt")
        unpinned = [f for f in findings if "No version" in f.evidence]
        # Unpinned = 0.70
        assert all(f.confidence == 0.70 for f in unpinned)

    def test_typosquat_high_confidence(self, scanner: DepScanScanner) -> None:
        content = "requets==2.28.1"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        typo_findings = [f for f in findings if "similar to" in f.evidence.lower()]
        # Typosquatting detection should be 0.80-0.94
        assert all(0.80 <= f.confidence <= 0.94 for f in typo_findings)


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_content_returns_no_findings(self, scanner: DepScanScanner) -> None:
        findings = scanner.scan("", ArtifactType.MCP, "requirements.txt")
        assert findings == []

    def test_comments_only_returns_no_findings(self, scanner: DepScanScanner) -> None:
        content = "# This is a comment\n# Another comment"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        assert findings == []

    def test_scanner_module_set_correctly(self, scanner: DepScanScanner) -> None:
        content = "pyyaml==5.3"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        assert all(f.scanner_module == ScannerModule.DEP_SCAN for f in findings)

    def test_finding_has_location(self, scanner: DepScanScanner) -> None:
        content = "safe-package==1.0.0\npyyaml==5.3"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        vuln_findings = [f for f in findings if "CVE" in f.description]
        if vuln_findings:
            assert vuln_findings[0].location.line == 2

    def test_clean_manifest_minimal_findings(self, scanner: DepScanScanner) -> None:
        content = "click==8.1.7\nrich==13.7.0\nstructlog==23.2.0"
        findings = scanner.scan(content, ArtifactType.MCP, "requirements.txt")
        # No known vulns, properly pinned, not typosquats
        vuln_findings = [f for f in findings if "CVE" in f.description]
        assert len(vuln_findings) == 0
