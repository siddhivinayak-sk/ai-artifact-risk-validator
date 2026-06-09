"""Property-based tests for SSRF pattern detection in TypeScript/JavaScript.

Feature: extended-mcp-scanning, Property 3: SSRF Pattern Detection Across Languages (TS/JS subset)

**Validates: Requirements 1.4**

Property 3: SSRF Pattern Detection Across Languages (TS/JS subset)
For any TypeScript/JavaScript source file containing a dynamic URL fetch pattern
(fetch/axios.get/axios.post/axios.put/axios.delete/got/node-fetch with template
literals containing ${...}), the TSJSEnhancedPatterns scanner SHALL produce at
least one ScanFinding with id="MCP-S2" and confidence=0.80.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.tsjs_enhanced import TSJSEnhancedPatterns

# --- HTTP client functions that should trigger SSRF detection ---

FETCH_FUNCTIONS = [
    "fetch",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.delete",
    "got",
    "node-fetch",
]

# --- Strategies ---

# Strategy for generating valid JS/TS variable names
variable_name_strategy = st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{0,15}", fullmatch=True)

# Strategy for generating URL path segments (alphanumeric)
url_path_strategy = st.from_regex(r"[a-z][a-z0-9]{0,10}", fullmatch=True)

# Strategy for choosing an HTTP client function
http_client_strategy = st.sampled_from(FETCH_FUNCTIONS)

# Strategy for generating a protocol prefix
protocol_strategy = st.sampled_from(["http://", "https://", ""])

# Strategy for generating a domain-like string
domain_strategy = st.from_regex(r"[a-z]{2,8}\.[a-z]{2,4}", fullmatch=True)


@st.composite
def dynamic_url_fetch_with_template_literal(draw: st.DrawFn) -> str:
    """Generate a TS/JS code snippet with a dynamic URL fetch using template literals.

    Produces code like:
        fetch(`http://api.example.com/${userId}`)
        axios.get(`${baseUrl}/users/${id}`)
        got(`https://service.io/${path}/data`)
    """
    func = draw(http_client_strategy)
    var_name = draw(variable_name_strategy)
    protocol = draw(protocol_strategy)
    domain = draw(domain_strategy)
    path_segment = draw(url_path_strategy)

    # Choose between different template literal patterns
    pattern_type = draw(st.integers(min_value=0, max_value=3))

    if pattern_type == 0:
        # Variable interpolation at end: fetch(`http://domain/path/${var}`)
        url = f"`{protocol}{domain}/{path_segment}/${{{var_name}}}`"
    elif pattern_type == 1:
        # Variable interpolation at start: axios.get(`${baseUrl}/path`)
        url = f"`${{{var_name}}}/{path_segment}`"
    elif pattern_type == 2:
        # Multiple interpolations: got(`${base}/${path}/${id}`)
        var_name2 = draw(variable_name_strategy)
        url = f"`${{{var_name}}}/{path_segment}/${{{var_name2}}}`"
    else:
        # Variable with domain in template: fetch(`${protocol}://${host}/path`)
        var_name2 = draw(variable_name_strategy)
        url = f"`${{{var_name}}}://${{{var_name2}}}/{path_segment}`"

    # Optional leading whitespace/indentation and context
    indent = draw(st.sampled_from(["", "  ", "    ", "\t"]))
    prefix = draw(st.sampled_from(["", "const resp = ", "await ", "const data = await "]))

    return f"{indent}{prefix}{func}({url});"


@st.composite
def dynamic_url_fetch_code_snippet(draw: st.DrawFn) -> str:
    """Generate a multi-line TS/JS code snippet with at least one dynamic URL fetch.

    Adds surrounding code context to make the snippet more realistic.
    """
    # Generate some context lines before/after
    context_lines = [
        "import express from 'express';",
        "const app = express();",
        "const port = 3000;",
        "// Handle API requests",
        "async function handler(req, res) {",
        "  const userId = req.params.id;",
        "  const baseUrl = process.env.API_URL;",
    ]

    # Pick 0-3 context lines as prefix
    num_prefix = draw(st.integers(min_value=0, max_value=3))
    prefix_lines = draw(
        st.lists(st.sampled_from(context_lines), min_size=num_prefix, max_size=num_prefix)
    )

    # Generate the dynamic fetch line
    fetch_line = draw(dynamic_url_fetch_with_template_literal())

    # Pick 0-2 context lines as suffix
    suffix_contexts = [
        "  return data;",
        "}",
        "app.listen(port);",
        "console.log('Server started');",
    ]
    num_suffix = draw(st.integers(min_value=0, max_value=2))
    suffix_lines = draw(
        st.lists(st.sampled_from(suffix_contexts), min_size=num_suffix, max_size=num_suffix)
    )

    all_lines = prefix_lines + [fetch_line] + suffix_lines
    return "\n".join(all_lines)


# --- Property Tests ---


class TestSSRFPatternDetectionTSJS:
    """Property 3: SSRF Pattern Detection Across Languages (TS/JS subset).

    Feature: extended-mcp-scanning, Property 3: SSRF Pattern Detection Across Languages (TS/JS subset)

    **Validates: Requirements 1.4**
    """

    scanner = TSJSEnhancedPatterns()

    @given(code=dynamic_url_fetch_with_template_literal())
    @settings(max_examples=100)
    def test_dynamic_url_fetch_produces_mcp_s2_finding(self, code: str) -> None:
        """For any TS/JS code containing a dynamic URL fetch with template literal,
        the scanner SHALL produce at least one ScanFinding with id='MCP-S2'
        and confidence=0.80."""
        findings = self.scanner.scan(code, ArtifactType.MCP, "server.ts")

        ssrf_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(ssrf_findings) >= 1, (
            f"Expected at least one MCP-S2 finding for code:\n{code}\n"
            f"Got findings: {[f.id for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in ssrf_findings), (
            f"Expected confidence=0.80 for all MCP-S2 findings, "
            f"got: {[f.confidence for f in ssrf_findings]}"
        )

    @given(code=dynamic_url_fetch_code_snippet())
    @settings(max_examples=100)
    def test_dynamic_url_in_context_produces_mcp_s2_finding(self, code: str) -> None:
        """For any TS/JS code snippet containing a dynamic URL fetch pattern
        embedded in surrounding code context, the scanner SHALL still detect
        and produce at least one MCP-S2 finding with confidence=0.80."""
        findings = self.scanner.scan(code, ArtifactType.MCP, "server.ts")

        ssrf_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(ssrf_findings) >= 1, (
            f"Expected at least one MCP-S2 finding for code:\n{code}\n"
            f"Got findings: {[f.id for f in findings]}"
        )
        assert all(f.confidence == 0.80 for f in ssrf_findings), (
            f"Expected confidence=0.80 for all MCP-S2 findings, "
            f"got: {[f.confidence for f in ssrf_findings]}"
        )

    @given(
        func=http_client_strategy,
        var_name=variable_name_strategy,
        path=url_path_strategy,
    )
    @settings(max_examples=100)
    def test_each_http_client_detected_with_template_literal(
        self, func: str, var_name: str, path: str
    ) -> None:
        """For each HTTP client function (fetch, axios.get, axios.post, axios.put,
        axios.delete, got, node-fetch) with a template literal URL containing ${},
        the scanner SHALL produce an MCP-S2 finding."""
        code = f"{func}(`https://api.example.com/{path}/${{{var_name}}}`);\n"
        findings = self.scanner.scan(code, ArtifactType.MCP, "server.ts")

        ssrf_findings = [f for f in findings if f.id == "MCP-S2"]
        assert len(ssrf_findings) >= 1, (
            f"Expected MCP-S2 finding for '{func}' with template literal URL.\n"
            f"Code: {code}\nAll findings: {[f.id for f in findings]}"
        )
        assert ssrf_findings[0].confidence == 0.80, (
            f"Expected confidence=0.80, got {ssrf_findings[0].confidence}"
        )
