"""Property-based tests for dangerous input schema detection.

**Property 14: Input Schema Dangerous Parameter Detection**
**Validates: Requirements 6.1**

For any MCP tool whose input schema contains a parameter with type "string"
and a name or description containing keywords ("path", "file", "url", "command",
"exec", "script", "code", "shell"), the ToolDescriptionAnalyzer SHALL produce
a ScanFinding with id="MCP-S1" and confidence 0.80.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.mcp_models import MCPToolInfo
from ai_artifact_risk_validator.scanners.dynamic.tool_description_analyzer import (
    ToolDescriptionAnalyzer,
)

# --- Constants ---

DANGEROUS_KEYWORDS = ["path", "file", "url", "command", "exec", "script", "code", "shell"]

# --- Strategies ---

# Safe tool names that won't trigger other detections (no overlap with builtins)
_safe_tool_name = st.sampled_from(
    [
        "my_tool",
        "data_processor",
        "calculator",
        "formatter",
        "transformer",
        "converter",
        "generator",
        "analyzer",
        "parser",
        "validator",
    ]
)

# Safe parameter names (no dangerous keywords)
_safe_param_name = st.sampled_from(
    [
        "input",
        "output",
        "count",
        "name",
        "value",
        "mode",
        "format",
        "level",
        "timeout",
        "retries",
    ]
)

# Safe descriptions for the tool (no sensitive refs or injection patterns)
_safe_tool_description = st.sampled_from(
    [
        "A useful tool for processing data",
        "Transforms input into output",
        "Computes results based on parameters",
        "Validates and formats data",
        "",
    ]
)


@st.composite
def dangerous_param_name_tool(draw: st.DrawFn) -> MCPToolInfo:
    """Generate an MCPToolInfo with a string parameter whose name contains a dangerous keyword."""
    tool_name = draw(_safe_tool_name)
    description = draw(_safe_tool_description)
    keyword = draw(st.sampled_from(DANGEROUS_KEYWORDS))

    # Generate parameter name containing the dangerous keyword
    name_variant = draw(
        st.sampled_from(
            [
                "prefix_suffix",
                "keyword_only",
                "with_underscore_prefix",
                "with_underscore_suffix",
            ]
        )
    )

    if name_variant == "prefix_suffix":
        param_name = f"my_{keyword}_param"
    elif name_variant == "keyword_only":
        param_name = keyword
    elif name_variant == "with_underscore_prefix":
        param_name = f"input_{keyword}"
    else:
        param_name = f"{keyword}_value"

    # Build input schema with the dangerous string parameter
    properties: dict = {
        param_name: {"type": "string", "description": "A parameter"},
    }

    # Optionally add a safe parameter alongside
    if draw(st.booleans()):
        safe_name = draw(_safe_param_name)
        properties[safe_name] = {"type": "integer", "description": "A safe number"}

    input_schema = {
        "type": "object",
        "properties": properties,
    }

    return MCPToolInfo(
        name=tool_name,
        description=description,
        input_schema=input_schema,
    )


@st.composite
def dangerous_param_description_tool(draw: st.DrawFn) -> MCPToolInfo:
    """Generate an MCPToolInfo with a string parameter whose description contains a dangerous keyword."""
    tool_name = draw(_safe_tool_name)
    tool_description = draw(_safe_tool_description)
    keyword = draw(st.sampled_from(DANGEROUS_KEYWORDS))

    # Safe parameter name (no dangerous keywords in the name itself)
    param_name = draw(_safe_param_name)

    # Build a description that contains the dangerous keyword
    desc_variant = draw(
        st.sampled_from(
            [
                f"The {keyword} to use for processing",
                f"Specify the target {keyword} here",
                f"This parameter accepts a {keyword} value",
                f"Enter the {keyword} for the operation",
            ]
        )
    )

    properties: dict = {
        param_name: {"type": "string", "description": desc_variant},
    }

    # Optionally add another safe parameter
    if draw(st.booleans()):
        other_name = draw(st.sampled_from(["limit", "offset", "size", "threshold"]))
        properties[other_name] = {"type": "integer", "description": "A number param"}

    input_schema = {
        "type": "object",
        "properties": properties,
    }

    return MCPToolInfo(
        name=tool_name,
        description=tool_description,
        input_schema=input_schema,
    )


# --- Property Tests ---


class TestDangerousInputSchemaDetection:
    """Property 14: Input Schema Dangerous Parameter Detection.

    **Validates: Requirements 6.1**
    """

    @given(tool=dangerous_param_name_tool())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    def test_dangerous_keyword_in_param_name_produces_mcp_s1(self, tool: MCPToolInfo) -> None:
        """Any MCP tool with a string parameter whose name contains a dangerous keyword
        SHALL produce at least one MCP-S1 finding with confidence 0.80."""
        analyzer = ToolDescriptionAnalyzer()
        findings = analyzer.analyze([tool])

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for dangerous param name.\n"
            f"Tool: {tool.name}\n"
            f"Input schema: {tool.input_schema}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.80 for f in mcp_s1_findings), (
            f"Expected at least one MCP-S1 finding with confidence 0.80.\n"
            f"Confidences: {[f.confidence for f in mcp_s1_findings]}"
        )

    @given(tool=dangerous_param_description_tool())
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    def test_dangerous_keyword_in_param_description_produces_mcp_s1(
        self, tool: MCPToolInfo
    ) -> None:
        """Any MCP tool with a string parameter whose description contains a dangerous keyword
        SHALL produce at least one MCP-S1 finding with confidence 0.80."""
        analyzer = ToolDescriptionAnalyzer()
        findings = analyzer.analyze([tool])

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for dangerous param description.\n"
            f"Tool: {tool.name}\n"
            f"Input schema: {tool.input_schema}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.80 for f in mcp_s1_findings), (
            f"Expected at least one MCP-S1 finding with confidence 0.80.\n"
            f"Confidences: {[f.confidence for f in mcp_s1_findings]}"
        )
