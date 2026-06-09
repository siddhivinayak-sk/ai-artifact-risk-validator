"""Property-based tests for RCE pattern detection in TypeScript/JavaScript.

**Property 2: RCE Pattern Detection Across Languages (TS/JS subset)**
**Validates: Requirements 1.1, 1.2, 1.3**

For any TypeScript/JavaScript source file containing a known RCE pattern
(child_process.exec/execSync/spawn/execFile, new Function() with dynamic args,
vm.runInNewContext/runInThisContext/vm.Script), the TSJSEnhancedPatterns scanner
SHALL produce at least one ScanFinding with id="MCP-S1" and confidence within
the specified ranges (0.90 for child_process and vm, 0.85 for new Function).
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.tsjs_enhanced import TSJSEnhancedPatterns

# --- Strategies ---

# Valid JS/TS variable names (identifiers)
_identifier_strategy = st.from_regex(r"[a-zA-Z_$][a-zA-Z0-9_$]{0,15}", fullmatch=True)

# Random code lines that don't contain RCE patterns (used as prefix/suffix noise)
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
_padding_strategy = st.lists(_safe_code_line, min_size=0, max_size=5).map(
    lambda lines: "\n".join(lines)
)

# child_process methods
_child_process_methods = st.sampled_from(["exec", "execSync", "spawn", "execFile"])

# vm module methods
_vm_methods = st.sampled_from(["runInNewContext", "runInThisContext", "Script"])


@st.composite
def child_process_snippet(draw: st.DrawFn) -> str:
    """Generate a TS/JS snippet containing a child_process RCE pattern."""
    method = draw(_child_process_methods)
    var_name = draw(_identifier_strategy)
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)

    # Choose a variant of child_process usage
    variant = draw(st.sampled_from(["direct", "require"]))

    if variant == "direct":
        pattern_line = f"child_process.{method}({var_name});"
    else:
        pattern_line = f"require('child_process').{method}({var_name});"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


@st.composite
def new_function_snippet(draw: st.DrawFn) -> str:
    """Generate a TS/JS snippet containing a new Function() with dynamic arg."""
    var_name = draw(_identifier_strategy)
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)

    # Choose a dynamic arg variant
    variant = draw(st.sampled_from(["variable", "template", "concatenation"]))

    if variant == "variable":
        pattern_line = f"const fn = new Function({var_name});"
    elif variant == "template":
        pattern_line = f"const fn = new Function(`return ${{{var_name}}}`);"
    else:
        pattern_line = f"const fn = new Function('return ' + {var_name});"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


@st.composite
def vm_module_snippet(draw: st.DrawFn) -> str:
    """Generate a TS/JS snippet containing a vm module RCE pattern."""
    method = draw(_vm_methods)
    var_name = draw(_identifier_strategy)
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)

    if method == "Script":
        pattern_line = f"const script = new vm.Script({var_name});"
    else:
        pattern_line = f"vm.{method}({var_name});"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


# --- Property Tests ---


class TestRCEPatternDetectionTSJS:
    """Property 2: RCE Pattern Detection Across Languages (TS/JS subset).

    **Validates: Requirements 1.1, 1.2, 1.3**
    """

    @given(content=child_process_snippet())
    @settings(max_examples=100)
    def test_child_process_detected_as_mcp_s1(self, content: str) -> None:
        """Any TS/JS code with child_process.exec/execSync/spawn/execFile
        SHALL produce at least one MCP-S1 finding with confidence 0.90."""
        scanner = TSJSEnhancedPatterns()
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for child_process pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.90 for f in mcp_s1_findings), (
            f"Expected at least one MCP-S1 finding with confidence 0.90.\n"
            f"Confidences: {[f.confidence for f in mcp_s1_findings]}"
        )

    @given(content=new_function_snippet())
    @settings(max_examples=100)
    def test_new_function_detected_as_mcp_s1(self, content: str) -> None:
        """Any TS/JS code with new Function() using dynamic args
        SHALL produce at least one MCP-S1 finding with confidence 0.85."""
        scanner = TSJSEnhancedPatterns()
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for new Function pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.85 for f in mcp_s1_findings), (
            f"Expected at least one MCP-S1 finding with confidence 0.85.\n"
            f"Confidences: {[f.confidence for f in mcp_s1_findings]}"
        )

    @given(content=vm_module_snippet())
    @settings(max_examples=100)
    def test_vm_module_detected_as_mcp_s1(self, content: str) -> None:
        """Any TS/JS code with vm.runInNewContext/runInThisContext/vm.Script
        SHALL produce at least one MCP-S1 finding with confidence 0.90."""
        scanner = TSJSEnhancedPatterns()
        findings = scanner.scan(content, ArtifactType.MCP, "server.ts")

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for vm module pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.90 for f in mcp_s1_findings), (
            f"Expected at least one MCP-S1 finding with confidence 0.90.\n"
            f"Confidences: {[f.confidence for f in mcp_s1_findings]}"
        )
