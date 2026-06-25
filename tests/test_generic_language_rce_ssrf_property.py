"""Property-based tests for RCE and SSRF detection in Go, Ruby, C#, and PHP.

Feature: extended-mcp-scanning
Property 2: RCE Pattern Detection Across Languages (Go/Ruby/C#/PHP subset)
Property 3: SSRF Pattern Detection Across Languages (Go/Ruby/C#/PHP subset)

**Validates: Requirements 4.4, 4.5**

Property 2 (Go/Ruby/C#/PHP subset):
For any source file in Go/Ruby/C#/PHP containing language-specific RCE patterns,
the GenericLanguageScanner SHALL produce at least one ScanFinding with id="MCP-S1"
and confidence=0.80.

Property 3 (Go/Ruby/C#/PHP subset):
For any source file in Go/Ruby/C#/PHP containing language-specific SSRF patterns,
the GenericLanguageScanner SHALL produce at least one ScanFinding with id="MCP-S2"
and confidence=0.80.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.generic_language_scanner import (
    GenericLanguageScanner,
)

# --- Shared Strategies ---

# Safe code lines for padding (language-neutral comments)
_safe_code_line = st.sampled_from(
    [
        "// some comment",
        "/* block comment */",
        "var x = 1",
        "// TODO: refactor later",
        "// handler logic",
    ]
)

_padding_strategy = st.lists(_safe_code_line, min_size=0, max_size=3).map(
    lambda lines: "\n".join(lines)
)

# Variable name strategy for generated code
_var_name = st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{1,10}", fullmatch=True)


# =============================================================================
# Go RCE Strategies (MCP-S1)
# =============================================================================


@st.composite
def go_rce_snippet(draw: st.DrawFn) -> str:
    """Generate Go code containing an RCE pattern (exec.Command or os/exec)."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    var = draw(_var_name)

    variant = draw(st.sampled_from(["exec_command", "os_exec_import"]))

    if variant == "exec_command":
        pattern_line = f"cmd := exec.Command({var})"
    else:
        pattern_line = 'import "os/exec"'

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# Ruby RCE Strategies (MCP-S1)
# =============================================================================


@st.composite
def ruby_rce_snippet(draw: st.DrawFn) -> str:
    """Generate Ruby code containing an RCE pattern."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    var = draw(_var_name)

    variant = draw(st.sampled_from(["system", "backtick", "exec", "percent_x"]))

    if variant == "system":
        pattern_line = f"system({var})"
    elif variant == "backtick":
        pattern_line = f"`{var}`"
    elif variant == "exec":
        pattern_line = f"exec({var})"
    else:
        pattern_line = f"%x{{{var}}}"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# C# RCE Strategies (MCP-S1)
# =============================================================================


@st.composite
def csharp_rce_snippet(draw: st.DrawFn) -> str:
    """Generate C# code containing an RCE pattern."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    var = draw(_var_name)

    variant = draw(st.sampled_from(["process_start", "process_startinfo"]))

    if variant == "process_start":
        pattern_line = f"Process.Start({var});"
    else:
        pattern_line = "var info = Process.StartInfo;"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# PHP RCE Strategies (MCP-S1)
# =============================================================================


@st.composite
def php_rce_snippet(draw: st.DrawFn) -> str:
    """Generate PHP code containing an RCE pattern."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    var = draw(_var_name)

    variant = draw(
        st.sampled_from(
            [
                "shell_exec",
                "exec",
                "system",
                "passthru",
                "popen",
            ]
        )
    )

    if variant == "shell_exec":
        pattern_line = f"shell_exec(${var});"
    elif variant == "exec":
        pattern_line = f"exec(${var});"
    elif variant == "system":
        pattern_line = f"system(${var});"
    elif variant == "passthru":
        pattern_line = f"passthru(${var});"
    else:
        pattern_line = f"popen(${var}, 'r');"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# Go SSRF Strategies (MCP-S2)
# =============================================================================


@st.composite
def go_ssrf_snippet(draw: st.DrawFn) -> str:
    """Generate Go code containing an SSRF pattern (http.Get/Post with variable URL)."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    var = draw(_var_name)

    method = draw(st.sampled_from(["Get", "Post", "Head", "PostForm"]))
    pattern_line = f"resp, err := http.{method}({var})"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# Ruby SSRF Strategies (MCP-S2)
# =============================================================================


@st.composite
def ruby_ssrf_snippet(draw: st.DrawFn) -> str:
    """Generate Ruby code containing an SSRF pattern."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)

    variant = draw(st.sampled_from(["net_http", "open_uri"]))

    if variant == "net_http":
        pattern_line = "response = Net::HTTP.get(uri)"
    else:
        pattern_line = "require 'open-uri'"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# C# SSRF Strategies (MCP-S2)
# =============================================================================


@st.composite
def csharp_ssrf_snippet(draw: st.DrawFn) -> str:
    """Generate C# code containing an SSRF pattern."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    var = draw(_var_name)

    variant = draw(st.sampled_from(["httpclient", "webrequest", "webclient"]))

    if variant == "httpclient":
        pattern_line = "var client = new HttpClient();"
    elif variant == "webrequest":
        pattern_line = f"var req = new WebRequest({var});"
    else:
        pattern_line = "var wc = new WebClient();"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# PHP SSRF Strategies (MCP-S2)
# =============================================================================


@st.composite
def php_ssrf_snippet(draw: st.DrawFn) -> str:
    """Generate PHP code containing an SSRF pattern."""
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    var = draw(_var_name)

    variant = draw(st.sampled_from(["file_get_contents", "curl_exec"]))

    if variant == "file_get_contents":
        pattern_line = f"$result = file_get_contents(${var});"
    else:
        pattern_line = "$response = curl_exec($ch);"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# =============================================================================
# Property Tests - RCE Detection (Property 2)
# =============================================================================


class TestRCEPatternDetectionGenericLanguages:
    """Property 2: RCE Pattern Detection Across Languages (Go/Ruby/C#/PHP subset).

    **Validates: Requirements 4.4**

    For any source file in Go/Ruby/C#/PHP containing language-specific RCE patterns,
    the GenericLanguageScanner SHALL produce at least one ScanFinding with id="MCP-S1"
    and confidence=0.80.
    """

    scanner = GenericLanguageScanner()

    @given(content=go_rce_snippet())
    @settings(max_examples=100, deadline=None)
    def test_go_rce_detected_as_mcp_s1(self, content: str) -> None:
        """Any Go code with exec.Command or os/exec SHALL produce at least one
        MCP-S1 finding with confidence=0.80."""
        findings = self.scanner.scan(content, DetectedLanguage.GO, ArtifactType.MCP, "server.go")

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for Go RCE pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s1_findings), (
            f"Expected confidence=0.80 for all MCP-S1 findings, "
            f"got: {[f.confidence for f in mcp_s1_findings]}"
        )

    @given(content=ruby_rce_snippet())
    @settings(max_examples=100, deadline=None)
    def test_ruby_rce_detected_as_mcp_s1(self, content: str) -> None:
        """Any Ruby code with system()/backtick/exec()/%x{} SHALL produce at least one
        MCP-S1 finding with confidence=0.80."""
        findings = self.scanner.scan(content, DetectedLanguage.RUBY, ArtifactType.MCP, "server.rb")

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for Ruby RCE pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s1_findings), (
            f"Expected confidence=0.80 for all MCP-S1 findings, "
            f"got: {[f.confidence for f in mcp_s1_findings]}"
        )

    @given(content=csharp_rce_snippet())
    @settings(max_examples=100, deadline=None)
    def test_csharp_rce_detected_as_mcp_s1(self, content: str) -> None:
        """Any C# code with Process.Start/Process.StartInfo SHALL produce at least one
        MCP-S1 finding with confidence=0.80."""
        findings = self.scanner.scan(
            content, DetectedLanguage.CSHARP, ArtifactType.MCP, "Server.cs"
        )

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for C# RCE pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s1_findings), (
            f"Expected confidence=0.80 for all MCP-S1 findings, "
            f"got: {[f.confidence for f in mcp_s1_findings]}"
        )

    @given(content=php_rce_snippet())
    @settings(max_examples=100, deadline=None)
    def test_php_rce_detected_as_mcp_s1(self, content: str) -> None:
        """Any PHP code with shell_exec/exec/system/passthru/popen SHALL produce
        at least one MCP-S1 finding with confidence=0.80."""
        findings = self.scanner.scan(content, DetectedLanguage.PHP, ArtifactType.MCP, "server.php")

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for PHP RCE pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s1_findings), (
            f"Expected confidence=0.80 for all MCP-S1 findings, "
            f"got: {[f.confidence for f in mcp_s1_findings]}"
        )


# =============================================================================
# Property Tests - SSRF Detection (Property 3)
# =============================================================================


class TestSSRFPatternDetectionGenericLanguages:
    """Property 3: SSRF Pattern Detection Across Languages (Go/Ruby/C#/PHP subset).

    **Validates: Requirements 4.5**

    For any source file in Go/Ruby/C#/PHP containing language-specific SSRF patterns,
    the GenericLanguageScanner SHALL produce at least one ScanFinding with id="MCP-S2"
    and confidence=0.80.
    """

    scanner = GenericLanguageScanner()

    @given(content=go_ssrf_snippet())
    @settings(max_examples=100, deadline=None)
    def test_go_ssrf_detected_as_mcp_s2(self, content: str) -> None:
        """Any Go code with http.Get/Post/Head/PostForm with variable URL SHALL
        produce at least one MCP-S2 finding with confidence=0.80."""
        findings = self.scanner.scan(content, DetectedLanguage.GO, ArtifactType.MCP, "server.go")

        mcp_s2_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(mcp_s2_findings) >= 1, (
            f"Expected at least one MCP-S2 finding for Go SSRF pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s2_findings), (
            f"Expected confidence=0.80 for all MCP-S2 findings, "
            f"got: {[f.confidence for f in mcp_s2_findings]}"
        )

    @given(content=ruby_ssrf_snippet())
    @settings(max_examples=100, deadline=None)
    def test_ruby_ssrf_detected_as_mcp_s2(self, content: str) -> None:
        """Any Ruby code with Net::HTTP or open-uri SHALL produce at least one
        MCP-S2 finding with confidence=0.80."""
        findings = self.scanner.scan(content, DetectedLanguage.RUBY, ArtifactType.MCP, "server.rb")

        mcp_s2_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(mcp_s2_findings) >= 1, (
            f"Expected at least one MCP-S2 finding for Ruby SSRF pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s2_findings), (
            f"Expected confidence=0.80 for all MCP-S2 findings, "
            f"got: {[f.confidence for f in mcp_s2_findings]}"
        )

    @given(content=csharp_ssrf_snippet())
    @settings(max_examples=100, deadline=None)
    def test_csharp_ssrf_detected_as_mcp_s2(self, content: str) -> None:
        """Any C# code with HttpClient/WebRequest/WebClient SHALL produce at least
        one MCP-S2 finding with confidence=0.80."""
        findings = self.scanner.scan(
            content, DetectedLanguage.CSHARP, ArtifactType.MCP, "Server.cs"
        )

        mcp_s2_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(mcp_s2_findings) >= 1, (
            f"Expected at least one MCP-S2 finding for C# SSRF pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s2_findings), (
            f"Expected confidence=0.80 for all MCP-S2 findings, "
            f"got: {[f.confidence for f in mcp_s2_findings]}"
        )

    @given(content=php_ssrf_snippet())
    @settings(max_examples=100, deadline=None)
    def test_php_ssrf_detected_as_mcp_s2(self, content: str) -> None:
        """Any PHP code with file_get_contents($var)/curl_exec() SHALL produce
        at least one MCP-S2 finding with confidence=0.80."""
        findings = self.scanner.scan(content, DetectedLanguage.PHP, ArtifactType.MCP, "server.php")

        mcp_s2_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(mcp_s2_findings) >= 1, (
            f"Expected at least one MCP-S2 finding for PHP SSRF pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in mcp_s2_findings), (
            f"Expected confidence=0.80 for all MCP-S2 findings, "
            f"got: {[f.confidence for f in mcp_s2_findings]}"
        )
