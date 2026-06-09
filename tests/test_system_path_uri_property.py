"""Property-based tests for system path URI detection in resources.

**Property 19: System Path URI Detection in Resources**
**Validates: Requirements 6.6**

For any MCP resource endpoint whose URI pattern references system paths
(/etc/, /proc/, /sys/, home directories ~/), wildcard file access (glob
patterns *, **), or environment variables ($VAR, ${VAR}), the
ConfigPrivilegeAnalyzer SHALL produce a ScanFinding with id="MCP-S9"
and confidence 0.85.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.mcp_models import MCPResourceInfo
from ai_artifact_risk_validator.scanners.dynamic.config_privilege_analyzer import (
    ConfigPrivilegeAnalyzer,
)

# --- Constants ---

SYSTEM_PATH_PREFIXES = ["/etc/", "/proc/", "/sys/", "~/"]

WILDCARD_PATTERNS = ["*", "**"]

ENV_VAR_FORMATS = ["$", "${"]

# --- Strategies ---

_safe_resource_name = st.sampled_from(
    [
        "config-file",
        "system-info",
        "network-data",
        "user-docs",
        "log-data",
        "app-settings",
        "cache-store",
        "db-backup",
    ]
)

_safe_description = st.sampled_from(
    [
        "A resource endpoint",
        "Provides configuration data",
        "System information resource",
        "Network interface data",
        "",
    ]
)

_env_var_names = st.sampled_from(
    [
        "HOME",
        "CONFIG_DIR",
        "APP_DATA",
        "USER",
        "PATH",
        "SECRET_KEY",
        "DATABASE_URL",
        "LOG_DIR",
    ]
)

_path_suffixes = st.sampled_from(
    [
        "config",
        "passwd",
        "shadow",
        "cpuinfo",
        "meminfo",
        "net/dev",
        "class/net",
        "documents",
        "settings.json",
        "data.db",
    ]
)


@st.composite
def system_path_resource(draw: st.DrawFn) -> MCPResourceInfo:
    """Generate an MCPResourceInfo with a URI containing a system path."""
    name = draw(_safe_resource_name)
    description = draw(_safe_description)
    prefix = draw(st.sampled_from(SYSTEM_PATH_PREFIXES))
    suffix = draw(_path_suffixes)

    uri = f"{prefix}{suffix}"

    return MCPResourceInfo(
        name=name,
        uri=uri,
        description=description,
    )


@st.composite
def wildcard_glob_resource(draw: st.DrawFn) -> MCPResourceInfo:
    """Generate an MCPResourceInfo with a URI containing wildcard glob patterns."""
    name = draw(_safe_resource_name)
    description = draw(_safe_description)

    # Various glob pattern formats
    glob_variant = draw(
        st.sampled_from(
            [
                "single_star",
                "double_star",
                "star_extension",
                "double_star_recursive",
            ]
        )
    )

    base_path = draw(
        st.sampled_from(
            [
                "/data/",
                "/files/",
                "/uploads/",
                "/workspace/",
                "/storage/",
            ]
        )
    )

    if glob_variant == "single_star":
        uri = f"{base_path}*"
    elif glob_variant == "double_star":
        uri = f"{base_path}**"
    elif glob_variant == "star_extension":
        ext = draw(st.sampled_from([".json", ".txt", ".yaml", ".csv", ".log"]))
        uri = f"{base_path}*{ext}"
    else:
        ext = draw(st.sampled_from([".json", ".txt", ".yaml", ".csv", ".log"]))
        uri = f"{base_path}**/*{ext}"

    return MCPResourceInfo(
        name=name,
        uri=uri,
        description=description,
    )


@st.composite
def env_var_resource(draw: st.DrawFn) -> MCPResourceInfo:
    """Generate an MCPResourceInfo with a URI containing environment variables."""
    name = draw(_safe_resource_name)
    description = draw(_safe_description)
    var_name = draw(_env_var_names)

    # Format: $VAR or ${VAR}
    env_format = draw(st.sampled_from(["dollar", "dollar_brace"]))
    suffix = draw(
        st.sampled_from(
            [
                "/data",
                "/config",
                "/file.txt",
                "/settings",
                "/output",
            ]
        )
    )

    if env_format == "dollar":
        uri = f"${var_name}{suffix}"
    else:
        uri = f"${{{var_name}}}{suffix}"

    return MCPResourceInfo(
        name=name,
        uri=uri,
        description=description,
    )


# --- Property Tests ---


class TestSystemPathURIDetection:
    """Property 19: System Path URI Detection in Resources.

    **Validates: Requirements 6.6**
    """

    @given(resource=system_path_resource())
    @settings(max_examples=100)
    def test_system_path_uri_produces_mcp_s9(self, resource: MCPResourceInfo) -> None:
        """Any resource URI referencing system paths (/etc/, /proc/, /sys/, ~/)
        SHALL produce at least one MCP-S9 finding with confidence 0.85."""
        analyzer = ConfigPrivilegeAnalyzer()
        findings = analyzer.analyze_resources([resource], "test-server")

        mcp_s9_findings = [f for f in findings if f.id == "MCP-S9"]
        assert len(mcp_s9_findings) >= 1, (
            f"Expected at least one MCP-S9 finding for system path URI.\n"
            f"Resource: {resource.name}\n"
            f"URI: {resource.uri}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.85 for f in mcp_s9_findings), (
            f"Expected at least one MCP-S9 finding with confidence 0.85.\n"
            f"Confidences: {[f.confidence for f in mcp_s9_findings]}"
        )

    @given(resource=wildcard_glob_resource())
    @settings(max_examples=100)
    def test_wildcard_glob_uri_produces_mcp_s9(self, resource: MCPResourceInfo) -> None:
        """Any resource URI containing wildcard glob patterns (*, **)
        SHALL produce at least one MCP-S9 finding with confidence 0.85."""
        analyzer = ConfigPrivilegeAnalyzer()
        findings = analyzer.analyze_resources([resource], "test-server")

        mcp_s9_findings = [f for f in findings if f.id == "MCP-S9"]
        assert len(mcp_s9_findings) >= 1, (
            f"Expected at least one MCP-S9 finding for wildcard glob URI.\n"
            f"Resource: {resource.name}\n"
            f"URI: {resource.uri}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.85 for f in mcp_s9_findings), (
            f"Expected at least one MCP-S9 finding with confidence 0.85.\n"
            f"Confidences: {[f.confidence for f in mcp_s9_findings]}"
        )

    @given(resource=env_var_resource())
    @settings(max_examples=100)
    def test_env_var_uri_produces_mcp_s9(self, resource: MCPResourceInfo) -> None:
        """Any resource URI containing environment variables ($VAR, ${VAR})
        SHALL produce at least one MCP-S9 finding with confidence 0.85."""
        analyzer = ConfigPrivilegeAnalyzer()
        findings = analyzer.analyze_resources([resource], "test-server")

        mcp_s9_findings = [f for f in findings if f.id == "MCP-S9"]
        assert len(mcp_s9_findings) >= 1, (
            f"Expected at least one MCP-S9 finding for env var URI.\n"
            f"Resource: {resource.name}\n"
            f"URI: {resource.uri}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
        assert any(f.confidence == 0.85 for f in mcp_s9_findings), (
            f"Expected at least one MCP-S9 finding with confidence 0.85.\n"
            f"Confidences: {[f.confidence for f in mcp_s9_findings]}"
        )
