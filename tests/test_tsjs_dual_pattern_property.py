"""Property-based tests for TS/JS dual pattern application.

**Property 9: TS/JS Dual Pattern Application**
**Validates: Requirements 1.9**

For any TypeScript/JavaScript file classified as ArtifactType.MCP, the
CodeAuditScanner SHALL apply BOTH the enhanced TS/JS-specific patterns AND the
existing language-agnostic regex patterns, such that a code snippet matching both
a TS-specific pattern and a generic pattern produces findings from both detection
sources.

This test generates TS/JS code that contains BOTH:
- A TS-specific pattern like `child_process.exec(cmd)` (TSJSEnhancedPatterns detects
  with confidence 0.90)
- A generic pattern like `eval(userInput)` (_scan_regex detects via _RE_DANGEROUS_FUNCS
  with confidence 0.85)

Then asserts that MCP-S1 findings are produced from both detection sources,
confirming dual application of enhanced AND generic patterns.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

# --- Strategies ---

# Valid JS/TS variable names (identifiers)
_identifier_strategy = st.from_regex(r"[a-zA-Z_$][a-zA-Z0-9_$]{0,15}", fullmatch=True)

# Random safe code lines used as padding noise
_safe_code_line = st.sampled_from(
    [
        "const x = 1;",
        "let result = [];",
        "function helper() { return true; }",
        "console.log('hello');",
        "import { something } from './module';",
        "export default class MyClass {}",
        "// a comment line",
        "const arr = [1, 2, 3].map(x => x * 2);",
        "if (condition) { doStuff(); }",
        "const obj = { key: 'value' };",
    ]
)

# Generate random padding (prefix and suffix lines)
_padding_strategy = st.lists(_safe_code_line, min_size=0, max_size=3).map(
    lambda lines: "\n".join(lines)
)

# TS-specific patterns that ONLY TSJSEnhancedPatterns can detect
# (child_process.exec/execSync/spawn/execFile)
_ts_specific_patterns = st.sampled_from(
    [
        "child_process.exec({var})",
        "child_process.execSync({var})",
        "child_process.spawn({var})",
        "child_process.execFile({var})",
        "require('child_process').exec({var})",
        "require('child_process').execSync({var})",
    ]
)

# Generic patterns that ONLY _scan_regex can detect via _RE_DANGEROUS_FUNCS
# eval() is detected by _RE_DANGEROUS_FUNCS but NOT by TSJSEnhancedPatterns
_generic_patterns = st.sampled_from(
    [
        "eval({var})",
        "eval({var}.toString())",
        "compile({var})",
    ]
)

# TS/JS file extensions
_tsjs_extensions = st.sampled_from(
    [
        ".ts",
        ".mts",
        ".cts",
        ".js",
        ".mjs",
        ".cjs",
    ]
)


@st.composite
def dual_pattern_snippet(draw: st.DrawFn) -> tuple[str, str]:
    """Generate a TS/JS snippet containing BOTH a TS-specific pattern AND a generic pattern.

    Returns a tuple of (content, file_extension).
    """
    var1 = draw(_identifier_strategy)
    var2 = draw(_identifier_strategy)
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)
    extension = draw(_tsjs_extensions)

    # Draw one TS-specific pattern (child_process) and one generic pattern (eval/compile)
    ts_pattern_template = draw(_ts_specific_patterns)
    generic_pattern_template = draw(_generic_patterns)

    ts_line = ts_pattern_template.replace("{var}", var1)
    generic_line = generic_pattern_template.replace("{var}", var2)

    # Compose the snippet with both patterns on separate lines
    parts = [p for p in [prefix, ts_line, generic_line, suffix] if p]
    content = "\n".join(parts)

    return content, extension


# --- Property Test ---


class TestTSJSDualPatternApplication:
    """Property 9: TS/JS Dual Pattern Application.

    **Validates: Requirements 1.9**

    For any TypeScript/JavaScript file classified as ArtifactType.MCP, the
    CodeAuditScanner SHALL apply BOTH the enhanced TS/JS-specific patterns
    AND the existing language-agnostic regex patterns.
    """

    @given(data=dual_pattern_snippet())
    @settings(max_examples=100)
    def test_dual_patterns_produce_findings_from_both_sources(self, data: tuple[str, str]) -> None:
        """Code with both a TS-specific pattern and a generic pattern SHALL
        produce MCP-S1 findings from both detection sources.

        The TS-specific pattern (child_process.exec) is detected by
        TSJSEnhancedPatterns (confidence 0.90). The generic pattern (eval/compile)
        is detected by _scan_regex via _RE_DANGEROUS_FUNCS (confidence 0.85).

        If both are found with their respective confidence levels, it confirms
        dual application of enhanced AND generic patterns.
        """
        content, extension = data
        artifact_path = f"server{extension}"

        scanner = CodeAuditScanner()
        findings = scanner.scan(content, ArtifactType.MCP, artifact_path)

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]

        # We expect at least 2 MCP-S1 findings: one from TSJSEnhancedPatterns
        # (child_process detection, confidence 0.90) and one from _scan_regex
        # (eval/compile detection, confidence 0.85)
        assert len(mcp_s1_findings) >= 2, (
            f"Expected at least 2 MCP-S1 findings (one from TS-specific patterns, "
            f"one from generic regex patterns) confirming dual application.\n"
            f"Got {len(mcp_s1_findings)} MCP-S1 finding(s).\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence, f.description[:60]) for f in findings]}"
        )

        # Verify that we have findings from TSJSEnhancedPatterns (confidence 0.90
        # for child_process detection)
        ts_specific_findings = [f for f in mcp_s1_findings if f.confidence == 0.90]
        assert len(ts_specific_findings) >= 1, (
            f"Expected at least one MCP-S1 finding with confidence 0.90 "
            f"(from TSJSEnhancedPatterns child_process detection).\n"
            f"MCP-S1 confidences: {[f.confidence for f in mcp_s1_findings]}\n"
            f"Content:\n{content}"
        )

        # Verify that we have findings from _scan_regex (confidence 0.85 for
        # dangerous function detection via _RE_DANGEROUS_FUNCS)
        generic_findings = [f for f in mcp_s1_findings if f.confidence == 0.85]
        assert len(generic_findings) >= 1, (
            f"Expected at least one MCP-S1 finding with confidence 0.85 "
            f"(from _scan_regex generic dangerous function detection).\n"
            f"MCP-S1 confidences: {[f.confidence for f in mcp_s1_findings]}\n"
            f"Content:\n{content}"
        )
