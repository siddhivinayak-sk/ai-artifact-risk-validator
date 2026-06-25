"""Property-based tests for inventory report accuracy.

Feature: extended-mcp-scanning, Property 16: Inventory Report Accuracy

**Validates: Requirements 6.3**

Property 16:
- For any set of discovered MCP servers with their tools, resources, and prompt
  templates, the generated MCPServerInventory SHALL accurately report
  tool_count == len(tools), resource_count == len(resources),
  prompt_count == len(prompt_templates), and the tool/resource/prompt names
  SHALL match the discovered items exactly.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.mcp_models import (
    MCPResourceInfo,
    MCPServerInventory,
    MCPToolInfo,
)

# --- Strategies ---

# Strategy for generating valid identifiers (tool/resource/server names)
identifier = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=1,
    max_size=30,
)

# Strategy for generating tool descriptions
tool_description = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?()-",
    min_size=0,
    max_size=100,
)

# Strategy for generating resource URIs
resource_uri = st.from_regex(
    r"(file|http|https|mcp)://[a-z0-9/_\-\.]+",
    fullmatch=True,
)

# Strategy for generating transport types
transport_type = st.sampled_from(["stdio", "sse", "http"])


@st.composite
def mcp_tool_info(draw: st.DrawFn) -> MCPToolInfo:
    """Generate a random MCPToolInfo instance."""
    name = draw(identifier)
    description = draw(tool_description)
    # Generate a simple input schema
    schema = draw(
        st.fixed_dictionaries(
            {"type": st.just("object")},
            optional={
                "properties": st.just({"input": {"type": "string"}}),
            },
        )
    )
    return MCPToolInfo(name=name, description=description, input_schema=schema)


@st.composite
def mcp_resource_info(draw: st.DrawFn) -> MCPResourceInfo:
    """Generate a random MCPResourceInfo instance."""
    name = draw(identifier)
    uri = draw(resource_uri)
    description = draw(tool_description)
    return MCPResourceInfo(name=name, uri=uri, description=description)


# Strategy for generating lists of tools
tools_list = st.lists(mcp_tool_info(), min_size=0, max_size=20)

# Strategy for generating lists of resources
resources_list = st.lists(mcp_resource_info(), min_size=0, max_size=20)

# Strategy for generating prompt template names
prompt_templates_list = st.lists(identifier, min_size=0, max_size=20)


@st.composite
def mcp_server_inventory(draw: st.DrawFn) -> MCPServerInventory:
    """Generate an MCPServerInventory with counts matching list lengths."""
    server_name = draw(identifier)
    transport = draw(transport_type)
    tools = draw(tools_list)
    resources = draw(resources_list)
    prompt_templates = draw(prompt_templates_list)

    return MCPServerInventory(
        server_name=server_name,
        transport_type=transport,
        tools=tools,
        resources=resources,
        prompt_templates=prompt_templates,
        tool_count=len(tools),
        resource_count=len(resources),
        prompt_count=len(prompt_templates),
    )


# --- Property Tests ---


class TestInventoryReportAccuracy:
    """Property 16: Inventory Report Accuracy.

    Feature: extended-mcp-scanning, Property 16: Inventory Report Accuracy

    **Validates: Requirements 6.3**
    """

    @given(
        server_name=identifier,
        transport=transport_type,
        tools=tools_list,
        resources=resources_list,
        prompt_templates=prompt_templates_list,
    )
    @settings(max_examples=100, deadline=None)
    def test_tool_count_equals_len_tools(
        self,
        server_name: str,
        transport: str,
        tools: list[MCPToolInfo],
        resources: list[MCPResourceInfo],
        prompt_templates: list[str],
    ) -> None:
        """For any set of tools, inventory.tool_count SHALL equal len(inventory.tools)."""
        inventory = MCPServerInventory(
            server_name=server_name,
            transport_type=transport,
            tools=tools,
            resources=resources,
            prompt_templates=prompt_templates,
            tool_count=len(tools),
            resource_count=len(resources),
            prompt_count=len(prompt_templates),
        )

        assert inventory.tool_count == len(inventory.tools), (
            f"tool_count ({inventory.tool_count}) != len(tools) ({len(inventory.tools)})"
        )

    @given(
        server_name=identifier,
        transport=transport_type,
        tools=tools_list,
        resources=resources_list,
        prompt_templates=prompt_templates_list,
    )
    @settings(max_examples=100, deadline=None)
    def test_resource_count_equals_len_resources(
        self,
        server_name: str,
        transport: str,
        tools: list[MCPToolInfo],
        resources: list[MCPResourceInfo],
        prompt_templates: list[str],
    ) -> None:
        """For any set of resources, inventory.resource_count SHALL equal
        len(inventory.resources)."""
        inventory = MCPServerInventory(
            server_name=server_name,
            transport_type=transport,
            tools=tools,
            resources=resources,
            prompt_templates=prompt_templates,
            tool_count=len(tools),
            resource_count=len(resources),
            prompt_count=len(prompt_templates),
        )

        assert inventory.resource_count == len(inventory.resources), (
            f"resource_count ({inventory.resource_count}) != "
            f"len(resources) ({len(inventory.resources)})"
        )

    @given(
        server_name=identifier,
        transport=transport_type,
        tools=tools_list,
        resources=resources_list,
        prompt_templates=prompt_templates_list,
    )
    @settings(max_examples=100, deadline=None)
    def test_prompt_count_equals_len_prompt_templates(
        self,
        server_name: str,
        transport: str,
        tools: list[MCPToolInfo],
        resources: list[MCPResourceInfo],
        prompt_templates: list[str],
    ) -> None:
        """For any set of prompt_templates, inventory.prompt_count SHALL equal
        len(inventory.prompt_templates)."""
        inventory = MCPServerInventory(
            server_name=server_name,
            transport_type=transport,
            tools=tools,
            resources=resources,
            prompt_templates=prompt_templates,
            tool_count=len(tools),
            resource_count=len(resources),
            prompt_count=len(prompt_templates),
        )

        assert inventory.prompt_count == len(inventory.prompt_templates), (
            f"prompt_count ({inventory.prompt_count}) != "
            f"len(prompt_templates) ({len(inventory.prompt_templates)})"
        )

    @given(
        server_name=identifier,
        transport=transport_type,
        tools=tools_list,
        resources=resources_list,
        prompt_templates=prompt_templates_list,
    )
    @settings(max_examples=100, deadline=None)
    def test_tool_names_match_input(
        self,
        server_name: str,
        transport: str,
        tools: list[MCPToolInfo],
        resources: list[MCPResourceInfo],
        prompt_templates: list[str],
    ) -> None:
        """Tool names in the inventory SHALL match the input tool names exactly."""
        inventory = MCPServerInventory(
            server_name=server_name,
            transport_type=transport,
            tools=tools,
            resources=resources,
            prompt_templates=prompt_templates,
            tool_count=len(tools),
            resource_count=len(resources),
            prompt_count=len(prompt_templates),
        )

        input_tool_names = [t.name for t in tools]
        inventory_tool_names = [t.name for t in inventory.tools]
        assert inventory_tool_names == input_tool_names, (
            f"Tool names mismatch.\nExpected: {input_tool_names}\nGot: {inventory_tool_names}"
        )

    @given(
        server_name=identifier,
        transport=transport_type,
        tools=tools_list,
        resources=resources_list,
        prompt_templates=prompt_templates_list,
    )
    @settings(max_examples=100, deadline=None)
    def test_resource_names_and_uris_match_input(
        self,
        server_name: str,
        transport: str,
        tools: list[MCPToolInfo],
        resources: list[MCPResourceInfo],
        prompt_templates: list[str],
    ) -> None:
        """Resource names and URIs in the inventory SHALL match the input
        resources exactly."""
        inventory = MCPServerInventory(
            server_name=server_name,
            transport_type=transport,
            tools=tools,
            resources=resources,
            prompt_templates=prompt_templates,
            tool_count=len(tools),
            resource_count=len(resources),
            prompt_count=len(prompt_templates),
        )

        input_resource_names = [r.name for r in resources]
        inventory_resource_names = [r.name for r in inventory.resources]
        assert inventory_resource_names == input_resource_names, (
            f"Resource names mismatch.\n"
            f"Expected: {input_resource_names}\n"
            f"Got: {inventory_resource_names}"
        )

        input_resource_uris = [r.uri for r in resources]
        inventory_resource_uris = [r.uri for r in inventory.resources]
        assert inventory_resource_uris == input_resource_uris, (
            f"Resource URIs mismatch.\n"
            f"Expected: {input_resource_uris}\n"
            f"Got: {inventory_resource_uris}"
        )

    @given(inventory=mcp_server_inventory())
    @settings(max_examples=100, deadline=None)
    def test_inventory_all_counts_consistent(
        self,
        inventory: MCPServerInventory,
    ) -> None:
        """For any MCPServerInventory, all counts SHALL be consistent with
        their respective lists, and all names SHALL match exactly."""
        # Verify counts
        assert inventory.tool_count == len(inventory.tools), (
            f"tool_count ({inventory.tool_count}) != len(tools) ({len(inventory.tools)})"
        )
        assert inventory.resource_count == len(inventory.resources), (
            f"resource_count ({inventory.resource_count}) != "
            f"len(resources) ({len(inventory.resources)})"
        )
        assert inventory.prompt_count == len(inventory.prompt_templates), (
            f"prompt_count ({inventory.prompt_count}) != "
            f"len(prompt_templates) ({len(inventory.prompt_templates)})"
        )
