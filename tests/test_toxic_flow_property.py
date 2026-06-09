"""Property-based tests for toxic flow detection.

Feature: extended-mcp-scanning, Property 13: Toxic Flow Detection

**Validates: Requirements 5.7**

Property 13:
- For any combination of tools across multiple MCP servers where a tool
  accepting external input (URLs, user text, file paths) feeds into a tool
  accessing sensitive data (credentials, private files, databases) which feeds
  into a tool capable of transmitting data externally (HTTP requests, email,
  file writes to shared locations), the ToxicFlowAnalyzer SHALL produce a
  toxic flow finding.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.mcp_models import MCPToolInfo
from ai_artifact_risk_validator.scanners.dynamic.toxic_flow_analyzer import (
    ToxicFlowAnalyzer,
)

# --- Strategies ---

# Keywords for each tool category (must trigger word-boundary matching in the analyzer)
EXTERNAL_INPUT_KEYWORDS = ["fetch", "download", "url", "input", "read"]
SENSITIVE_DATA_KEYWORDS = ["credential", "secret", "database", "password", "key"]
DATA_TRANSMISSION_KEYWORDS = ["send", "email", "upload", "post", "forward"]

# Strategy for generating server names
server_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=3,
    max_size=15,
)

# Strategy for generating safe (non-matching) tool name prefixes.
# These MUST NOT contain any substring that matches the analyzer's keyword regexes.
# Avoided: "validate" (contains no keywords but "input" in descriptions would),
# "generate" (contains "get" substring but not at word boundary with underscore)
safe_prefix = st.sampled_from(
    [
        "alpha",
        "beta",
        "gamma",
        "delta",
        "sigma",
        "calc",
        "proc",
        "step",
        "task",
        "plan",
    ]
)


@st.composite
def external_input_tool(draw: st.DrawFn) -> MCPToolInfo:
    """Generate a tool that accepts external input.

    The keyword is placed in the description to ensure it appears as a
    standalone word matching the \\b word boundary regex in the analyzer.
    """
    keyword = draw(st.sampled_from(EXTERNAL_INPUT_KEYWORDS))
    prefix = draw(safe_prefix)
    name = f"{prefix}_tool"
    description = f"This tool will {keyword} content from external sources"
    return MCPToolInfo(name=name, description=description)


@st.composite
def sensitive_data_tool(draw: st.DrawFn) -> MCPToolInfo:
    """Generate a tool that accesses sensitive data.

    The keyword is placed in the description to ensure it appears as a
    standalone word matching the \\b word boundary regex in the analyzer.
    """
    keyword = draw(st.sampled_from(SENSITIVE_DATA_KEYWORDS))
    prefix = draw(safe_prefix)
    name = f"{prefix}_store"
    description = f"This tool accesses {keyword} data from the vault"
    return MCPToolInfo(name=name, description=description)


@st.composite
def data_transmission_tool(draw: st.DrawFn) -> MCPToolInfo:
    """Generate a tool capable of transmitting data externally.

    The keyword is placed in the description to ensure it appears as a
    standalone word matching the \\b word boundary regex in the analyzer.
    """
    keyword = draw(st.sampled_from(DATA_TRANSMISSION_KEYWORDS))
    prefix = draw(safe_prefix)
    name = f"{prefix}_output"
    description = f"This tool will {keyword} data to external endpoint"
    return MCPToolInfo(name=name, description=description)


@st.composite
def neutral_tool(draw: st.DrawFn) -> MCPToolInfo:
    """Generate a tool that does NOT match any toxic flow category.

    Both name and description are carefully chosen to avoid any keywords
    from the analyzer's regex patterns (which include common words like
    'get', 'read', 'input', 'key', 'post', 'open', 'load', 'write', etc.)
    """
    prefix1 = draw(safe_prefix)
    prefix2 = draw(safe_prefix)
    name = f"{prefix1}_{prefix2}"
    description = draw(
        st.sampled_from(
            [
                "Performs internal computation on numbers",
                "Transforms data structures locally",
                "Counts occurrences in a list",
                "Parses structured content carefully",
                "Computes a mathematical result",
            ]
        )
    )
    return MCPToolInfo(name=name, description=description)


@st.composite
def toxic_flow_tools_across_servers(
    draw: st.DrawFn,
) -> dict[str, list[MCPToolInfo]]:
    """Generate tool sets across multiple servers forming a complete toxic flow chain.

    Places each category of tool on a different server to test cross-server detection.
    """
    server1 = draw(server_name.filter(lambda s: len(s) >= 3))
    server2 = draw(server_name.filter(lambda s: len(s) >= 3))
    server3 = draw(server_name.filter(lambda s: len(s) >= 3))

    # Ensure server names are distinct
    server2 = server2 + "_srv2" if server2 == server1 else server2
    server3 = server3 + "_srv3" if server3 in (server1, server2) else server3

    input_t = draw(external_input_tool())
    sensitive_t = draw(sensitive_data_tool())
    transmission_t = draw(data_transmission_tool())

    # Optionally add neutral filler tools
    extra_tools_s1 = draw(st.lists(neutral_tool(), min_size=0, max_size=2))
    extra_tools_s2 = draw(st.lists(neutral_tool(), min_size=0, max_size=2))
    extra_tools_s3 = draw(st.lists(neutral_tool(), min_size=0, max_size=2))

    return {
        server1: [input_t] + extra_tools_s1,
        server2: [sensitive_t] + extra_tools_s2,
        server3: [transmission_t] + extra_tools_s3,
    }


@st.composite
def tools_missing_external_input(
    draw: st.DrawFn,
) -> dict[str, list[MCPToolInfo]]:
    """Generate tools with sensitive data and transmission but NO external input."""
    server1 = draw(server_name.filter(lambda s: len(s) >= 3))
    server2 = draw(server_name.filter(lambda s: len(s) >= 3))
    server2 = server2 + "_b" if server2 == server1 else server2

    sensitive_t = draw(sensitive_data_tool())
    transmission_t = draw(data_transmission_tool())
    neutrals = draw(st.lists(neutral_tool(), min_size=1, max_size=3))

    return {
        server1: [sensitive_t] + neutrals,
        server2: [transmission_t],
    }


@st.composite
def tools_missing_sensitive_data(
    draw: st.DrawFn,
) -> dict[str, list[MCPToolInfo]]:
    """Generate tools with external input and transmission but NO sensitive data."""
    server1 = draw(server_name.filter(lambda s: len(s) >= 3))
    server2 = draw(server_name.filter(lambda s: len(s) >= 3))
    server2 = server2 + "_b" if server2 == server1 else server2

    input_t = draw(external_input_tool())
    transmission_t = draw(data_transmission_tool())
    neutrals = draw(st.lists(neutral_tool(), min_size=1, max_size=3))

    return {
        server1: [input_t] + neutrals,
        server2: [transmission_t],
    }


@st.composite
def tools_missing_transmission(
    draw: st.DrawFn,
) -> dict[str, list[MCPToolInfo]]:
    """Generate tools with external input and sensitive data but NO transmission."""
    server1 = draw(server_name.filter(lambda s: len(s) >= 3))
    server2 = draw(server_name.filter(lambda s: len(s) >= 3))
    server2 = server2 + "_b" if server2 == server1 else server2

    input_t = draw(external_input_tool())
    sensitive_t = draw(sensitive_data_tool())
    neutrals = draw(st.lists(neutral_tool(), min_size=1, max_size=3))

    return {
        server1: [input_t] + neutrals,
        server2: [sensitive_t],
    }


# --- Property Tests ---


class TestToxicFlowDetection:
    """Property 13: Toxic Flow Detection.

    Feature: extended-mcp-scanning, Property 13: Toxic Flow Detection

    **Validates: Requirements 5.7**
    """

    analyzer = ToxicFlowAnalyzer()

    @given(tools_by_server=toxic_flow_tools_across_servers())
    @settings(max_examples=100)
    def test_complete_chain_produces_toxic_flow_finding(
        self, tools_by_server: dict[str, list[MCPToolInfo]]
    ) -> None:
        """For any combination of tools across multiple MCP servers where all
        three categories (external input, sensitive data, data transmission)
        are present, the ToxicFlowAnalyzer SHALL produce a toxic flow finding
        with id='MCP-S3'."""
        findings = self.analyzer.detect_toxic_flows(tools_by_server)

        mcp_s3_findings = [f for f in findings if f.id == "MCP-S3"]
        assert len(mcp_s3_findings) >= 1, (
            f"Expected at least one MCP-S3 toxic flow finding when all three "
            f"categories are present across servers. "
            f"Servers: {list(tools_by_server.keys())}, "
            f"Tools: {[(s, [t.name for t in ts]) for s, ts in tools_by_server.items()]}"
        )

    @given(tools_by_server=tools_missing_external_input())
    @settings(max_examples=100)
    def test_no_finding_when_missing_external_input(
        self, tools_by_server: dict[str, list[MCPToolInfo]]
    ) -> None:
        """When external input tools are absent, the ToxicFlowAnalyzer SHALL
        NOT produce a toxic flow finding."""
        findings = self.analyzer.detect_toxic_flows(tools_by_server)

        mcp_s3_findings = [f for f in findings if f.id == "MCP-S3"]
        assert len(mcp_s3_findings) == 0, (
            f"Expected no MCP-S3 findings when external input category is missing, "
            f"but got {len(mcp_s3_findings)} findings. "
            f"Tools: {[(s, [t.name for t in ts]) for s, ts in tools_by_server.items()]}"
        )

    @given(tools_by_server=tools_missing_sensitive_data())
    @settings(max_examples=100)
    def test_no_finding_when_missing_sensitive_data(
        self, tools_by_server: dict[str, list[MCPToolInfo]]
    ) -> None:
        """When sensitive data tools are absent, the ToxicFlowAnalyzer SHALL
        NOT produce a toxic flow finding."""
        findings = self.analyzer.detect_toxic_flows(tools_by_server)

        mcp_s3_findings = [f for f in findings if f.id == "MCP-S3"]
        assert len(mcp_s3_findings) == 0, (
            f"Expected no MCP-S3 findings when sensitive data category is missing, "
            f"but got {len(mcp_s3_findings)} findings. "
            f"Tools: {[(s, [t.name for t in ts]) for s, ts in tools_by_server.items()]}"
        )

    @given(tools_by_server=tools_missing_transmission())
    @settings(max_examples=100)
    def test_no_finding_when_missing_transmission(
        self, tools_by_server: dict[str, list[MCPToolInfo]]
    ) -> None:
        """When data transmission tools are absent, the ToxicFlowAnalyzer SHALL
        NOT produce a toxic flow finding."""
        findings = self.analyzer.detect_toxic_flows(tools_by_server)

        mcp_s3_findings = [f for f in findings if f.id == "MCP-S3"]
        assert len(mcp_s3_findings) == 0, (
            f"Expected no MCP-S3 findings when data transmission category is missing, "
            f"but got {len(mcp_s3_findings)} findings. "
            f"Tools: {[(s, [t.name for t in ts]) for s, ts in tools_by_server.items()]}"
        )
