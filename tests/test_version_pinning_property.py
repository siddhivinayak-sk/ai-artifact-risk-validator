"""Property-based tests for version pinning verification.

Feature: extended-mcp-scanning, Property 18: Version Pinning Verification

**Validates: Requirements 6.5**

Property 18:
- For any MCP server source reference using unpinned version specifiers
  (including "latest", "*", "^x.y.z", "~x.y.z", or version ranges containing
  ">", "<", or "||"), the ConfigPrivilegeAnalyzer SHALL produce a ScanFinding
  with id="MCP-S5".
- Conversely, for exact version numbers or commit hashes, no MCP-S5 finding
  SHALL be produced.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.mcp_models import MCPServerConfig
from ai_artifact_risk_validator.scanners.dynamic.config_privilege_analyzer import (
    ConfigPrivilegeAnalyzer,
)

# --- Strategies for generating version specifiers ---

# Strategy for valid semver components
_semver_component = st.integers(min_value=0, max_value=99)


@st.composite
def semver_version(draw: st.DrawFn) -> str:
    """Generate a valid exact semver version string like '1.2.3'."""
    major = draw(_semver_component)
    minor = draw(_semver_component)
    patch = draw(_semver_component)
    return f"{major}.{minor}.{patch}"


@st.composite
def commit_hash(draw: st.DrawFn) -> str:
    """Generate a valid commit hash (7-40 hex characters)."""
    length = draw(st.integers(min_value=7, max_value=40))
    chars = draw(st.text(alphabet="0123456789abcdef", min_size=length, max_size=length))
    return chars


# Unpinned version strategies


@st.composite
def unpinned_latest(draw: st.DrawFn) -> str:
    """Generate a version string containing 'latest'."""
    prefix = draw(st.sampled_from(["", "docker pull myimage:", "npx server@"]))
    return f"{prefix}latest"


@st.composite
def unpinned_wildcard(draw: st.DrawFn) -> str:
    """Generate a version string containing wildcard '*'."""
    prefix = draw(st.sampled_from(["@", ":", "="]))
    return f"package{prefix}*"


@st.composite
def unpinned_caret(draw: st.DrawFn) -> str:
    """Generate a version string with caret range '^x.y.z'."""
    version = draw(semver_version())
    prefix = draw(st.sampled_from(["", "package@"]))
    return f"{prefix}^{version}"


@st.composite
def unpinned_tilde(draw: st.DrawFn) -> str:
    """Generate a version string with tilde range '~x.y.z'."""
    version = draw(semver_version())
    prefix = draw(st.sampled_from(["", "package@"]))
    return f"{prefix}~{version}"


@st.composite
def unpinned_gt_lt(draw: st.DrawFn) -> str:
    """Generate a version string with > or < range operators."""
    operator = draw(st.sampled_from([">=", ">", "<=", "<"]))
    version = draw(semver_version())
    # Only use major.minor (the regex matches x.y pattern)
    parts = version.split(".")
    short_version = f"{parts[0]}.{parts[1]}"
    return f"{operator}{short_version}"


@st.composite
def unpinned_or_range(draw: st.DrawFn) -> str:
    """Generate a version string with '||' OR operator."""
    v1 = draw(semver_version())
    v2 = draw(semver_version())
    return f"{v1} || {v2}"


# Combined strategies

unpinned_version_strategy = st.one_of(
    unpinned_latest(),
    unpinned_wildcard(),
    unpinned_caret(),
    unpinned_tilde(),
    unpinned_gt_lt(),
    unpinned_or_range(),
)

pinned_version_strategy = st.one_of(
    semver_version(),
    commit_hash(),
)

# Strategy for server names
server_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz-",
    min_size=3,
    max_size=15,
).map(lambda s: s if s[0].isalpha() else "srv" + s)


@st.composite
def unpinned_mcp_config(draw: st.DrawFn) -> MCPServerConfig:
    """Generate an MCPServerConfig with unpinned version in command or args."""
    name = draw(server_name)
    version_spec = draw(unpinned_version_strategy)

    # Place the unpinned version in command or args
    placement = draw(st.sampled_from(["command", "args", "both"]))

    if placement == "command":
        return MCPServerConfig(
            name=name,
            command=f"npx server@{version_spec}",
            args=[],
        )
    elif placement == "args":
        return MCPServerConfig(
            name=name,
            command="npx",
            args=[f"server@{version_spec}"],
        )
    else:
        return MCPServerConfig(
            name=name,
            command=f"docker run image:{version_spec}",
            args=[f"--version={version_spec}"],
        )


@st.composite
def pinned_mcp_config(draw: st.DrawFn) -> MCPServerConfig:
    """Generate an MCPServerConfig with only pinned versions (exact or commit hash)."""
    name = draw(server_name)
    version = draw(pinned_version_strategy)

    placement = draw(st.sampled_from(["command", "args"]))

    if placement == "command":
        return MCPServerConfig(
            name=name,
            command=f"npx server@{version}",
            args=[],
        )
    else:
        return MCPServerConfig(
            name=name,
            command="npx",
            args=[f"server@{version}"],
        )


# --- Property Tests ---


class TestVersionPinningVerification:
    """Property 18: Version Pinning Verification.

    Feature: extended-mcp-scanning, Property 18: Version Pinning Verification

    **Validates: Requirements 6.5**
    """

    analyzer = ConfigPrivilegeAnalyzer()

    @given(config=unpinned_mcp_config())
    @settings(max_examples=100)
    def test_unpinned_versions_produce_mcp_s5(self, config: MCPServerConfig) -> None:
        """For any MCP server source reference using unpinned version specifiers
        (including "latest", "*", "^x.y.z", "~x.y.z", or version ranges
        containing ">", "<", or "||"), the ConfigPrivilegeAnalyzer SHALL produce
        a ScanFinding with id="MCP-S5"."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s5_findings = [f for f in findings if f.id == "MCP-S5"]
        assert len(mcp_s5_findings) >= 1, (
            f"Expected at least one MCP-S5 finding for unpinned version config, "
            f"got {len(mcp_s5_findings)}. "
            f"Config: name={config.name}, command={config.command}, args={config.args}"
        )

    @given(config=pinned_mcp_config())
    @settings(max_examples=100)
    def test_pinned_versions_produce_no_mcp_s5(self, config: MCPServerConfig) -> None:
        """For exact version numbers or commit hashes, no MCP-S5 finding
        SHALL be produced."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s5_findings = [f for f in findings if f.id == "MCP-S5"]
        assert len(mcp_s5_findings) == 0, (
            f"Expected NO MCP-S5 findings for pinned version config, "
            f"got {len(mcp_s5_findings)}. "
            f"Config: name={config.name}, command={config.command}, args={config.args}. "
            f"Findings: {[f.evidence for f in mcp_s5_findings]}"
        )
