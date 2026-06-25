"""Property-based test for unknown language fallback with reduced confidence.

**Validates: Requirements 4.1, 4.2**

Property 8: Unknown Language Fallback with Reduced Confidence
Tests that for any file whose language cannot be determined by the LanguageDetector
(returns UNKNOWN), the CodeAuditScanner SHALL apply language-agnostic regex patterns
and all resulting findings SHALL have a confidence value of exactly 0.60.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner
from ai_artifact_risk_validator.scanners.language_detector import LanguageDetector

# --- Strategies ---

# File extensions that the LanguageDetector does NOT recognize
_UNKNOWN_EXTENSIONS = st.sampled_from(
    [
        ".xyz",
        ".abc",
        ".unknown",
        ".dat",
        ".foo",
        ".bar",
        ".qux",
        ".zzz",
        ".bak",
        ".tmp",
        ".custom",
        ".ext123",
        ".myext",
        ".randomext",
    ]
)

# Security patterns that the regex-based scanner detects (language-agnostic)
_DANGEROUS_FUNC_PATTERNS = st.sampled_from(
    [
        "eval(",
        "exec(",
        "compile(",
        "__import__(",
    ]
)

_SUBPROCESS_PATTERNS = st.sampled_from(
    [
        "subprocess.call(",
        "subprocess.Popen(",
        "subprocess.run(",
        "subprocess.check_output(",
        "os.system(",
        "os.popen(",
    ]
)

# Combine all detectable patterns into one strategy
_SECURITY_PATTERNS = st.one_of(
    _DANGEROUS_FUNC_PATTERNS,
    _SUBPROCESS_PATTERNS,
)

# Random padding/context lines that don't trigger language content detection
# (avoid Python/Rust/Java/etc. markers that would allow content-based detection)
_NEUTRAL_LINES = st.sampled_from(
    [
        "# some comment",
        "// a remark",
        "data = 42",
        "x = 1 + 2",
        "result = process()",
        "value = get_value()",
        "count += 1",
        "flag = True",
        "name = 'test'",
        "",
    ]
)


@st.composite
def unknown_language_file_with_security_pattern(draw: st.DrawFn) -> tuple[str, str]:
    """Generate a filename with unknown extension and code containing security patterns.

    Returns:
        Tuple of (filename, code_content) where:
        - filename has an unrecognized extension
        - code_content contains at least one security pattern detectable by regex
        - code_content does NOT contain enough language-specific markers to trigger
          content-based language detection (threshold is 2 markers for any language)
    """
    ext = draw(_UNKNOWN_EXTENSIONS)
    filename = f"server{ext}"

    # Build code content with a security pattern but without language markers
    # Use at most 1 line that could be a marker to stay below detection threshold
    pattern = draw(_SECURITY_PATTERNS)

    # Add some neutral context lines
    num_prefix_lines = draw(st.integers(min_value=0, max_value=3))
    prefix_lines = [draw(_NEUTRAL_LINES) for _ in range(num_prefix_lines)]

    num_suffix_lines = draw(st.integers(min_value=0, max_value=3))
    suffix_lines = [draw(_NEUTRAL_LINES) for _ in range(num_suffix_lines)]

    all_lines = prefix_lines + [pattern] + suffix_lines
    content = "\n".join(all_lines)

    return filename, content


@st.composite
def unknown_extension_filename(draw: st.DrawFn) -> str:
    """Generate a filename with an unrecognized extension."""
    ext = draw(_UNKNOWN_EXTENSIONS)
    base = draw(
        st.sampled_from(
            [
                "server",
                "main",
                "app",
                "handler",
                "service",
                "tool",
                "mcp_server",
            ]
        )
    )
    return f"{base}{ext}"


# --- Property Tests ---


class TestUnknownLanguageFallback:
    """Property 8: Unknown Language Fallback with Reduced Confidence.

    **Validates: Requirements 4.1, 4.2**

    For any file whose language cannot be determined by the LanguageDetector
    (returns UNKNOWN), the CodeAuditScanner SHALL apply language-agnostic regex
    patterns and all resulting findings SHALL have a confidence value of exactly 0.60.
    """

    @given(data=unknown_language_file_with_security_pattern())
    @settings(max_examples=100, deadline=None)
    def test_unknown_language_detection(self, data: tuple[str, str]) -> None:
        """Files with unrecognized extensions are classified as UNKNOWN by LanguageDetector."""
        filename, content = data
        detector = LanguageDetector()
        detected = detector.detect(filename, content)

        assert detected == DetectedLanguage.UNKNOWN, (
            f"Expected UNKNOWN for file '{filename}', "
            f"but LanguageDetector returned {detected.value}. "
            f"Content: {content!r}"
        )

    @given(data=unknown_language_file_with_security_pattern())
    @settings(max_examples=100, deadline=None)
    def test_all_findings_have_confidence_060(self, data: tuple[str, str]) -> None:
        """All findings from UNKNOWN language files have confidence exactly 0.60."""
        filename, content = data
        scanner = CodeAuditScanner()

        findings = scanner.scan(content, ArtifactType.MCP, filename)

        # We expect at least one finding since content has security patterns
        assert len(findings) > 0, (
            f"Expected at least one finding for file '{filename}' "
            f"with content containing security patterns. Content: {content!r}"
        )

        for finding in findings:
            assert finding.confidence == 0.60, (
                f"Finding '{finding.id}' has confidence {finding.confidence}, "
                f"expected exactly 0.60 for unknown language fallback. "
                f"File: '{filename}', Evidence: {finding.evidence!r}"
            )

    @given(ext=_UNKNOWN_EXTENSIONS)
    @settings(max_examples=100, deadline=None)
    def test_unknown_extensions_not_in_language_detector(self, ext: str) -> None:
        """Verify that our test extensions are indeed unrecognized."""
        detector = LanguageDetector()
        # Use minimal content that won't trigger content-based detection
        detected = detector.detect(f"file{ext}", "x = 1")

        assert detected == DetectedLanguage.UNKNOWN, (
            f"Extension '{ext}' was unexpectedly recognized as {detected.value}"
        )
