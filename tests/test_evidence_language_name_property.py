"""Property-based tests for evidence language name inclusion.

Feature: extended-mcp-scanning
Property 22: Evidence Language Name Inclusion

**Validates: Requirements 4.6**

Property 22:
For any finding produced when scanning Go, Ruby, C#, or PHP files, the `evidence`
field SHALL contain the language name as determined by the LanguageDetector.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.generic_language_scanner import (
    GenericLanguageScanner,
)

# --- Language name mapping (must match scanner's _LANGUAGE_NAMES) ---
_EXPECTED_LANGUAGE_NAMES: dict[DetectedLanguage, str] = {
    DetectedLanguage.GO: "Go",
    DetectedLanguage.RUBY: "Ruby",
    DetectedLanguage.CSHARP: "C#",
    DetectedLanguage.PHP: "PHP",
}

# --- Strategies that generate code snippets triggering findings ---


@st.composite
def go_finding_snippet(draw: st.DrawFn) -> str:
    """Generate Go code that triggers at least one finding."""
    var = draw(st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{1,8}", fullmatch=True))
    pattern = draw(
        st.sampled_from(
            [
                f"cmd := exec.Command({var})",
                'import "os/exec"',
                f"resp, err := http.Get({var})",
                f"resp, err := http.Post({var})",
            ]
        )
    )
    return pattern


@st.composite
def ruby_finding_snippet(draw: st.DrawFn) -> str:
    """Generate Ruby code that triggers at least one finding."""
    var = draw(st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{1,8}", fullmatch=True))
    pattern = draw(
        st.sampled_from(
            [
                f"system({var})",
                f"`{var}`",
                f"exec({var})",
                f"%x{{{var}}}",
                "response = Net::HTTP.get(uri)",
                "require 'open-uri'",
            ]
        )
    )
    return pattern


@st.composite
def csharp_finding_snippet(draw: st.DrawFn) -> str:
    """Generate C# code that triggers at least one finding."""
    var = draw(st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{1,8}", fullmatch=True))
    pattern = draw(
        st.sampled_from(
            [
                f"Process.Start({var});",
                "var info = Process.StartInfo;",
                "var client = new HttpClient();",
                f"var req = new WebRequest({var});",
                "var wc = new WebClient();",
            ]
        )
    )
    return pattern


@st.composite
def php_finding_snippet(draw: st.DrawFn) -> str:
    """Generate PHP code that triggers at least one finding."""
    var = draw(st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{1,8}", fullmatch=True))
    pattern = draw(
        st.sampled_from(
            [
                f"shell_exec(${var});",
                f"exec(${var});",
                f"system(${var});",
                f"passthru(${var});",
                f"popen(${var}, 'r');",
                f"$result = file_get_contents(${var});",
                "$response = curl_exec($ch);",
            ]
        )
    )
    return pattern


# =============================================================================
# Property Tests - Evidence Language Name Inclusion (Property 22)
# =============================================================================


class TestEvidenceLanguageNameInclusion:
    """Property 22: Evidence Language Name Inclusion.

    **Validates: Requirements 4.6**

    For any finding produced when scanning Go, Ruby, C#, or PHP files, the
    `evidence` field SHALL contain the language name as determined by the
    LanguageDetector.
    """

    scanner = GenericLanguageScanner()

    @given(content=go_finding_snippet())
    @settings(max_examples=100)
    def test_go_findings_contain_language_name_in_evidence(self, content: str) -> None:
        """Any finding from scanning Go code SHALL have 'Go' in the evidence field."""
        findings = self.scanner.scan(content, DetectedLanguage.GO, ArtifactType.MCP, "server.go")

        assert len(findings) >= 1, (
            f"Expected at least one finding for Go code.\nContent:\n{content}"
        )
        for finding in findings:
            assert "Go" in finding.evidence, (
                f"Expected 'Go' in evidence field.\n"
                f"Evidence: {finding.evidence!r}\n"
                f"Content:\n{content}"
            )

    @given(content=ruby_finding_snippet())
    @settings(max_examples=100)
    def test_ruby_findings_contain_language_name_in_evidence(self, content: str) -> None:
        """Any finding from scanning Ruby code SHALL have 'Ruby' in the evidence field."""
        findings = self.scanner.scan(content, DetectedLanguage.RUBY, ArtifactType.MCP, "server.rb")

        assert len(findings) >= 1, (
            f"Expected at least one finding for Ruby code.\nContent:\n{content}"
        )
        for finding in findings:
            assert "Ruby" in finding.evidence, (
                f"Expected 'Ruby' in evidence field.\n"
                f"Evidence: {finding.evidence!r}\n"
                f"Content:\n{content}"
            )

    @given(content=csharp_finding_snippet())
    @settings(max_examples=100)
    def test_csharp_findings_contain_language_name_in_evidence(self, content: str) -> None:
        """Any finding from scanning C# code SHALL have 'C#' in the evidence field."""
        findings = self.scanner.scan(
            content, DetectedLanguage.CSHARP, ArtifactType.MCP, "Server.cs"
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding for C# code.\nContent:\n{content}"
        )
        for finding in findings:
            assert "C#" in finding.evidence, (
                f"Expected 'C#' in evidence field.\n"
                f"Evidence: {finding.evidence!r}\n"
                f"Content:\n{content}"
            )

    @given(content=php_finding_snippet())
    @settings(max_examples=100)
    def test_php_findings_contain_language_name_in_evidence(self, content: str) -> None:
        """Any finding from scanning PHP code SHALL have 'PHP' in the evidence field."""
        findings = self.scanner.scan(content, DetectedLanguage.PHP, ArtifactType.MCP, "server.php")

        assert len(findings) >= 1, (
            f"Expected at least one finding for PHP code.\nContent:\n{content}"
        )
        for finding in findings:
            assert "PHP" in finding.evidence, (
                f"Expected 'PHP' in evidence field.\n"
                f"Evidence: {finding.evidence!r}\n"
                f"Content:\n{content}"
            )
