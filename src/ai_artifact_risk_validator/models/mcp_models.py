"""MCP-related Pydantic models for the AI Artifact Risk Validator.

Defines data models for MCP server configuration, tool/resource metadata
discovered via dynamic scanning, server inventory reports, and dynamic
scan configuration.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field


class MCPServerConfig(BaseModel):
    """Parsed MCP server configuration for dynamic scanning."""

    name: str
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    transport: Literal["stdio", "sse", "http"] = "stdio"
    env: dict[str, str] = Field(default_factory=dict)


class MCPToolInfo(BaseModel):
    """Tool metadata discovered from a live MCP server."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class MCPResourceInfo(BaseModel):
    """Resource metadata discovered from a live MCP server."""

    name: str
    uri: str
    description: str = ""


class MCPServerInventory(BaseModel):
    """Inventory report for a single MCP server."""

    server_name: str
    transport_type: str
    tools: list[MCPToolInfo] = Field(default_factory=list)
    resources: list[MCPResourceInfo] = Field(default_factory=list)
    prompt_templates: list[str] = Field(default_factory=list)
    tool_count: int = 0
    resource_count: int = 0
    prompt_count: int = 0


class DynamicScanConfig(BaseModel):
    """Configuration for dynamic scanning behavior."""

    allow_dynamic_scan: bool = False
    interactive: bool = True
    connection_timeout: int = Field(default=10, ge=1, le=60)
    per_server_timeout: int = Field(default=30, ge=5, le=300)
    builtin_tool_names: list[str] = Field(
        default_factory=lambda: [
            "read_file",
            "write_file",
            "run_command",
            "search",
            "list_files",
            "edit_file",
            "execute",
            "bash",
            "browse",
            "submit",
        ]
    )
