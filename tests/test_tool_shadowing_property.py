"""Property-based tests for tool shadowing detection.

Feature: extended-mcp-scanning, Property 12: Tool Shadowing Detection

**Validates: Requirements 5.6**

Property 12:
- For any MCP tool whose name exactly matches one of the registered built-in
  tool names (at minimum 10 names including read_file, write_file, run_command,
  search, list_files, edit_file, execute, bash, browse, submit), the
  ToolDescriptionAnalyzer SHALL report a tool shadowing finding with id="MCP-S3".
- Conversely, for tools with names NOT in the built-in registry, no shadowing
  finding shall be produced.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.mcp_models import MCPToolInfo
from ai_artifact_risk_validator.scanners.dynamic.tool_description_analyzer import (
    DEFAULT_BUILTIN_TOOL_NAMES,
    ToolDescriptionAnalyzer,
)

# --- Strategies ---

# Strategy for generating a tool name sampled from the built-in list
builtin_tool_name = st.sampled_from(DEFAULT_BUILTIN_TOOL_NAMES)

# Strategy for generating a safe description that won't trigger other detectors
safe_description = st.sampled_from(
    [
        "A simple utility tool.",
        "Returns data from the store.",
        "Performs a calculation.",
        "Lists available items.",
        "Gets current status.",
        "Processes the input.",
        "Generates a report.",
        "Transforms the given value.",
    ]
)

# Strategy for generating tool names NOT in the built-in registry.
# We use text that is unlikely to collide with any built-in name.
non_builtin_tool_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_",
    min_size=3,
    max_size=20,
).filter(lambda name: name not in DEFAULT_BUILTIN_TOOL_NAMES)


@st.composite
def mcp_tool_with_builtin_name(draw: st.DrawFn) -> MCPToolInfo:
    """Generate an MCPToolInfo whose name matches a built-in tool name."""
    name = draw(builtin_tool_name)
    description = draw(safe_description)
    return MCPToolInfo(
        name=name,
        description=description,
        input_schema={},
    )


@st.composite
def mcp_tool_with_non_builtin_name(draw: st.DrawFn) -> MCPToolInfo:
    """Generate an MCPToolInfo whose name does NOT match any built-in tool name."""
    name = draw(non_builtin_tool_name)
    description = draw(safe_description)
    return MCPToolInfo(
        name=name,
        description=description,
        input_schema={},
    )


# --- Property Tests ---


class TestToolShadowingDetection:
    """Property 12: Tool Shadowing Detection.

    Feature: extended-mcp-scanning, Property 12: Tool Shadowing Detection

    **Validates: Requirements 5.6**
    """

    analyzer = ToolDescriptionAnalyzer()

    @given(tool=mcp_tool_with_builtin_name())
    @settings(max_examples=100, deadline=None)
    def test_builtin_name_produces_shadowing_finding(self, tool: MCPToolInfo) -> None:
        """For any MCP tool whose name exactly matches one of the registered
        built-in tool names, the ToolDescriptionAnalyzer SHALL report a tool
        shadowing finding with id='MCP-S3' and evidence containing 'shadowing'."""
        findings = self.analyzer.analyze(tools=[tool])

        shadowing_findings = [
            f for f in findings if f.id == "MCP-S3" and "shadow" in f.evidence.lower()
        ]
        assert len(shadowing_findings) >= 1, (
            f"Expected at least one MCP-S3 shadowing finding for tool named "
            f"'{tool.name}', got findings: {[(f.id, f.evidence) for f in findings]}"
        )

    @given(tool=mcp_tool_with_non_builtin_name())
    @settings(max_examples=100, deadline=None)
    def test_non_builtin_name_produces_no_shadowing_finding(self, tool: MCPToolInfo) -> None:
        """For tools with names NOT in the built-in registry, no shadowing
        finding shall be produced."""
        findings = self.analyzer.analyze(tools=[tool])

        shadowing_findings = [f for f in findings if "shadow" in f.evidence.lower()]
        assert len(shadowing_findings) == 0, (
            f"Expected no shadowing findings for tool named '{tool.name}', "
            f"got: {[(f.id, f.evidence) for f in shadowing_findings]}"
        )
