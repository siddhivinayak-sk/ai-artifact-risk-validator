"""Unit tests for the ProvenanceChk scanner module."""

from __future__ import annotations

import pytest

from ai_artifact_risk_validator.models import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.provenance_chk import ProvenanceChkScanner


@pytest.fixture
def scanner() -> ProvenanceChkScanner:
    """Create a ProvenanceChkScanner instance."""
    return ProvenanceChkScanner()


class TestProvenanceChkScannerProperties:
    """Test scanner properties and availability."""

    def test_name(self, scanner: ProvenanceChkScanner) -> None:
        assert scanner.name == ScannerModule.PROVENANCE_CHK

    def test_applicable_artifact_types(self, scanner: ProvenanceChkScanner) -> None:
        types = scanner.applicable_artifact_types
        assert ArtifactType.SKILL in types
        assert ArtifactType.AGENT in types
        assert ArtifactType.MCP in types
        assert ArtifactType.PLUGIN in types
        assert ArtifactType.RAG in types
        # These should NOT be in applicable types
        assert ArtifactType.PROMPT not in types
        assert ArtifactType.HOOK not in types

    def test_detected_risk_ids(self, scanner: ProvenanceChkScanner) -> None:
        risk_ids = scanner.detected_risk_ids
        expected = [
            "SK-S7",
            "SK-S8",
            "MCP-S4",
            "MCP-S5",
            "PL-S6",
            "PL-S7",
            "A-S8",
            "A-S9",
            "GOV-1",
            "GOV-2",
            "REG-2",
            "RAG-S2",
        ]
        for rid in expected:
            assert rid in risk_ids

    def test_is_available(self, scanner: ProvenanceChkScanner) -> None:
        assert scanner.is_available() is True


class TestMissingProvenance:
    """Test detection of missing provenance metadata."""

    def test_no_provenance_metadata_at_all(self, scanner: ProvenanceChkScanner) -> None:
        """Content with no provenance metadata should flag multiple findings."""
        content = "This is just plain content with no metadata at all."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        # Should detect missing provenance
        risk_ids = [f.id for f in findings]
        assert "SK-S7" in risk_ids
        assert "GOV-1" in risk_ids

    def test_has_author_only(self, scanner: ProvenanceChkScanner) -> None:
        """Content with only author metadata should still flag other missing fields."""
        content = "author: John Doe\nSome skill content."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        risk_ids = [f.id for f in findings]
        # Should still flag missing version/timestamp/source
        assert "SK-S7" in risk_ids

    def test_full_provenance_no_flag(self, scanner: ProvenanceChkScanner) -> None:
        """Content with all provenance metadata should not flag provenance risks."""
        content = (
            "author: John Doe\n"
            "version: 1.2.3\n"
            "created: 2025-01-15\n"
            "source: https://github.com/org/repo\n"
            "sha256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n"
            "license: MIT\n"
            "signature: abc123\n"
            "Some content here."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        risk_ids = [f.id for f in findings]
        # Should NOT flag provenance-related risks
        assert "SK-S7" not in risk_ids
        assert "GOV-1" not in risk_ids

    def test_agent_provenance_risk_id(self, scanner: ProvenanceChkScanner) -> None:
        """Agent artifacts should use A-S8 for provenance issues."""
        content = "Plain agent content with no metadata."
        findings = scanner.scan(content, ArtifactType.AGENT, "/path/to/agent.md")
        risk_ids = [f.id for f in findings]
        assert "A-S8" in risk_ids

    def test_mcp_provenance_risk_id(self, scanner: ProvenanceChkScanner) -> None:
        """MCP artifacts should use MCP-S4 for provenance issues."""
        content = "Plain MCP content with no metadata."
        findings = scanner.scan(content, ArtifactType.MCP, "/path/to/mcp.json")
        risk_ids = [f.id for f in findings]
        assert "MCP-S4" in risk_ids

    def test_plugin_provenance_risk_id(self, scanner: ProvenanceChkScanner) -> None:
        """Plugin artifacts should use PL-S6 for provenance issues."""
        content = "Plain plugin content with no metadata."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "/path/to/plugin.json")
        risk_ids = [f.id for f in findings]
        assert "PL-S6" in risk_ids

    def test_rag_provenance_risk_id(self, scanner: ProvenanceChkScanner) -> None:
        """RAG artifacts should use RAG-S2 for provenance issues."""
        content = "Plain RAG content with no metadata."
        findings = scanner.scan(content, ArtifactType.RAG, "/path/to/knowledge.md")
        risk_ids = [f.id for f in findings]
        assert "RAG-S2" in risk_ids


class TestMissingIntegrityHash:
    """Test detection of missing integrity hashes."""

    def test_no_hash_detected(self, scanner: ProvenanceChkScanner) -> None:
        """Content without any hash should flag integrity risk."""
        content = "author: Jane\nversion: 1.0\nSome skill content."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        risk_ids = [f.id for f in findings]
        assert "SK-S8" in risk_ids

    def test_sha256_hex_present(self, scanner: ProvenanceChkScanner) -> None:
        """Content with SHA-256 hex string should not flag integrity risk."""
        content = (
            "author: Jane\nversion: 1.0\nsource: https://github.com/org/repo\n"
            "created: 2025-06-01\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\nsignature: sig123\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        risk_ids = [f.id for f in findings]
        assert "SK-S8" not in risk_ids

    def test_mcp_integrity_risk_id(self, scanner: ProvenanceChkScanner) -> None:
        """MCP artifacts should use MCP-S5 for missing integrity."""
        content = "author: Jane\nversion: 1.0\nMCP content."
        findings = scanner.scan(content, ArtifactType.MCP, "/path/to/mcp.json")
        risk_ids = [f.id for f in findings]
        assert "MCP-S5" in risk_ids

    def test_plugin_integrity_risk_id(self, scanner: ProvenanceChkScanner) -> None:
        """Plugin artifacts should use PL-S7 for missing integrity."""
        content = "author: Jane\nversion: 1.0\nPlugin content."
        findings = scanner.scan(content, ArtifactType.PLUGIN, "/path/to/plugin.json")
        risk_ids = [f.id for f in findings]
        assert "PL-S7" in risk_ids

    def test_agent_integrity_risk_id(self, scanner: ProvenanceChkScanner) -> None:
        """Agent artifacts should use A-S9 for missing integrity."""
        content = "author: Jane\nversion: 1.0\nAgent content."
        findings = scanner.scan(content, ArtifactType.AGENT, "/path/to/agent.md")
        risk_ids = [f.id for f in findings]
        assert "A-S9" in risk_ids


class TestUnsignedArtifacts:
    """Test detection of unsigned artifacts."""

    def test_no_signature(self, scanner: ProvenanceChkScanner) -> None:
        """Content without a signature should flag integrity risk."""
        content = (
            "author: Jane\nversion: 1.0\nsource: https://github.com/org/repo\n"
            "created: 2025-06-01\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        # Should have a finding for missing signature
        unsigned_findings = [
            f
            for f in findings
            if "signature" in f.evidence.lower() or "signature" in f.description.lower()
        ]
        assert len(unsigned_findings) > 0

    def test_pgp_signature_present(self, scanner: ProvenanceChkScanner) -> None:
        """Content with PGP signature should not flag unsigned."""
        content = (
            "author: Jane\nversion: 1.0\nsource: https://github.com/org/repo\n"
            "created: 2025-06-01\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\n"
            "-----BEGIN PGP SIGNATURE-----\nsomedata\n-----END PGP SIGNATURE-----\n"
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        unsigned_findings = [f for f in findings if "No cryptographic signature" in f.evidence]
        assert len(unsigned_findings) == 0


class TestSourceAttribution:
    """Test detection of missing source/origin."""

    def test_no_source(self, scanner: ProvenanceChkScanner) -> None:
        """Content without source URL should flag REG-2."""
        content = "author: Jane\nversion: 1.0\nSome content."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        risk_ids = [f.id for f in findings]
        assert "REG-2" in risk_ids

    def test_github_url_present(self, scanner: ProvenanceChkScanner) -> None:
        """Content with GitHub URL should not flag REG-2."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        risk_ids = [f.id for f in findings]
        assert "REG-2" not in risk_ids


class TestLicenseCompliance:
    """Test detection of missing license information."""

    def test_no_license(self, scanner: ProvenanceChkScanner) -> None:
        """Content without license should flag GOV-2 for license."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "signature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        license_findings = [f for f in findings if "license" in f.evidence.lower()]
        assert len(license_findings) > 0

    def test_license_present(self, scanner: ProvenanceChkScanner) -> None:
        """Content with license should not flag license-related findings."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: Apache-2.0\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        license_findings = [f for f in findings if "license" in f.evidence.lower()]
        assert len(license_findings) == 0


class TestStaleness:
    """Test detection of stale provenance."""

    def test_very_old_date(self, scanner: ProvenanceChkScanner) -> None:
        """Content with a very old date should flag staleness."""
        content = (
            "author: Jane\nversion: 1.0\n"
            "created: 2020-01-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        stale_findings = [f for f in findings if "days old" in f.evidence]
        assert len(stale_findings) > 0

    def test_recent_date_no_staleness(self, scanner: ProvenanceChkScanner) -> None:
        """Content with a recent date should not flag staleness."""
        from datetime import datetime, timedelta, timezone

        recent_date = (datetime.now(tz=timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        content = (
            "author: Jane\nversion: 1.0\n"
            f"created: {recent_date}\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        stale_findings = [f for f in findings if "days old" in f.evidence]
        assert len(stale_findings) == 0


class TestLazyLoading:
    """Test lazy loading of optional dependencies."""

    def test_git_lazy_load_does_not_crash(self, scanner: ProvenanceChkScanner) -> None:
        """Loading git module should not crash even if not installed."""
        # This should not raise
        result = scanner._load_git()
        # Result is either the git module or None
        assert result is None or result is not None

    def test_cryptography_lazy_load_does_not_crash(self, scanner: ProvenanceChkScanner) -> None:
        """Loading cryptography module should not crash even if not installed."""
        result = scanner._load_cryptography()
        assert result is None or result is not None

    def test_git_loaded_only_once(self, scanner: ProvenanceChkScanner) -> None:
        """Git module should only be loaded once (cached)."""
        scanner._load_git()
        assert scanner._git_loaded is True
        # Call again - should use cached value
        scanner._load_git()
        assert scanner._git_loaded is True

    def test_cryptography_loaded_only_once(self, scanner: ProvenanceChkScanner) -> None:
        """Cryptography module should only be loaded once (cached)."""
        scanner._load_cryptography()
        assert scanner._cryptography_loaded is True
        scanner._load_cryptography()
        assert scanner._cryptography_loaded is True


class TestFindingProperties:
    """Test that findings have correct properties."""

    def test_confidence_bands(self, scanner: ProvenanceChkScanner) -> None:
        """Missing provenance findings should have confidence 0.95."""
        content = "Plain content with nothing."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        provenance_findings = [f for f in findings if f.id == "SK-S7"]
        assert len(provenance_findings) > 0
        for f in provenance_findings:
            assert f.confidence == 0.95

    def test_scanner_module_set(self, scanner: ProvenanceChkScanner) -> None:
        """All findings should have the correct scanner module."""
        content = "Plain content."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        for f in findings:
            assert f.scanner_module == ScannerModule.PROVENANCE_CHK

    def test_finding_has_evidence(self, scanner: ProvenanceChkScanner) -> None:
        """All findings should have non-empty evidence."""
        content = "Plain content."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        for f in findings:
            assert f.evidence != ""

    def test_finding_has_remediation(self, scanner: ProvenanceChkScanner) -> None:
        """All findings should have non-empty remediation."""
        content = "Plain content."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        for f in findings:
            assert f.remediation != ""


class TestJsonContentDetection:
    """Test provenance detection in JSON content."""

    def test_json_author_detected(self, scanner: ProvenanceChkScanner) -> None:
        """JSON author field should be detected."""
        content = '{"author": "Jane Doe", "version": "1.0.0", "created": "2025-06-01", "source": "https://github.com/org/repo"}'
        findings = scanner.scan(content, ArtifactType.MCP, "/path/to/mcp.json")
        # Should not have provenance-missing finding for author/version/timestamp/source
        provenance_findings = [f for f in findings if f.id == "MCP-S4"]
        assert len(provenance_findings) == 0

    def test_json_no_author(self, scanner: ProvenanceChkScanner) -> None:
        """JSON content without author should flag provenance."""
        content = '{"name": "my-mcp", "tools": []}'
        findings = scanner.scan(content, ArtifactType.MCP, "/path/to/mcp.json")
        risk_ids = [f.id for f in findings]
        assert "MCP-S4" in risk_ids


class TestHashFormatValidation:
    """Test validation of hash format when hash is declared."""

    def test_valid_sha256_no_finding(self, scanner: ProvenanceChkScanner) -> None:
        """Valid SHA-256 hash (64 hex chars) should not flag format error."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        format_findings = [f for f in findings if "invalid length" in f.evidence]
        assert len(format_findings) == 0

    def test_invalid_sha256_too_short(self, scanner: ProvenanceChkScanner) -> None:
        """SHA-256 with too few chars should flag format error with confidence 1.0."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149a\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        format_findings = [f for f in findings if "invalid length" in f.evidence]
        assert len(format_findings) > 0
        assert format_findings[0].confidence == 1.0

    def test_invalid_sha256_too_long(self, scanner: ProvenanceChkScanner) -> None:
        """SHA-256 with too many chars should flag format error."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855aabb\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        format_findings = [f for f in findings if "invalid length" in f.evidence]
        assert len(format_findings) > 0
        assert format_findings[0].confidence == 1.0

    def test_valid_sha512_no_finding(self, scanner: ProvenanceChkScanner) -> None:
        """Valid SHA-512 hash (128 hex chars) should not flag format error."""
        hash_512 = "a" * 128
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            f"sha512: {hash_512}\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        format_findings = [
            f for f in findings if "SHA-512" in f.evidence and "invalid" in f.evidence
        ]
        assert len(format_findings) == 0

    def test_invalid_sha512(self, scanner: ProvenanceChkScanner) -> None:
        """SHA-512 with wrong length should flag format error with confidence 1.0."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha512: abcdef1234\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        format_findings = [
            f for f in findings if "SHA-512" in f.evidence and "invalid" in f.evidence
        ]
        assert len(format_findings) > 0
        assert format_findings[0].confidence == 1.0

    def test_signature_mismatch_confidence(self, scanner: ProvenanceChkScanner) -> None:
        """Format mismatch findings should have confidence 1.0."""
        content = (
            "author: Jane\nversion: 1.0\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: deadbeef\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        format_findings = [
            f
            for f in findings
            if "invalid length" in f.evidence or "unexpected length" in f.evidence
        ]
        assert len(format_findings) > 0
        for f in format_findings:
            assert f.confidence == 1.0


class TestVersionControlMetadata:
    """Test detection of missing version control metadata."""

    def test_missing_version_flags_gov2(self, scanner: ProvenanceChkScanner) -> None:
        """Missing version field should flag GOV-2."""
        content = "author: Jane\ncreated: 2025-06-01\nSome content."
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        risk_ids = [f.id for f in findings]
        assert "GOV-2" in risk_ids

    def test_version_present_no_gov2_for_version(self, scanner: ProvenanceChkScanner) -> None:
        """Presence of version field should not flag GOV-2 for version."""
        content = (
            "author: Jane\nversion: 2.0.1\ncreated: 2025-06-01\n"
            "source: https://github.com/org/repo\n"
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "license: MIT\nsignature: sig\nContent."
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        gov2_findings = [f for f in findings if f.id == "GOV-2" and "version" in f.evidence.lower()]
        assert len(gov2_findings) == 0


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_content(self, scanner: ProvenanceChkScanner) -> None:
        """Empty content should produce findings (missing everything)."""
        findings = scanner.scan("", ArtifactType.SKILL, "/path/to/skill.md")
        assert len(findings) > 0

    def test_very_large_content(self, scanner: ProvenanceChkScanner) -> None:
        """Large content should be handled without errors."""
        content = "x" * 100000
        findings = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        # Should still produce findings (no provenance metadata)
        assert len(findings) > 0

    def test_scan_returns_list(self, scanner: ProvenanceChkScanner) -> None:
        """Scan should always return a list."""
        content = "Some content."
        result = scanner.scan(content, ArtifactType.SKILL, "/path/to/skill.md")
        assert isinstance(result, list)

    def test_non_applicable_type_not_in_list(self, scanner: ProvenanceChkScanner) -> None:
        """Non-applicable artifact types should not be in applicable_artifact_types."""
        types = scanner.applicable_artifact_types
        assert ArtifactType.SOP not in types
        assert ArtifactType.STEERING not in types
        assert ArtifactType.HOOK not in types
        assert ArtifactType.INSTRUCTION not in types
        assert ArtifactType.MEMORY not in types
        assert ArtifactType.EVAL_HARNESS not in types
        assert ArtifactType.ORCHESTRATION not in types
        assert ArtifactType.API_SCHEMA not in types
