"""Property-based tests for elevated privilege detection.

Feature: extended-mcp-scanning, Property 17: Elevated Privilege Detection

**Validates: Requirements 6.4**

Property 17:
- For any MCP server configuration where the command field starts with "sudo",
  contains "--privileged", or the environment specifies USER=root or UID=0,
  the ConfigPrivilegeAnalyzer SHALL produce a ScanFinding with id="MCP-S7".
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.mcp_models import MCPServerConfig
from ai_artifact_risk_validator.scanners.dynamic.config_privilege_analyzer import (
    ConfigPrivilegeAnalyzer,
)

# --- Strategies ---

# Strategy for generating server names
server_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=3,
    max_size=20,
)

# Strategy for generating a command suffix (the part after "sudo ")
command_suffix = st.sampled_from(
    [
        "node server.js",
        "python app.py",
        "npm start",
        "docker run myimage",
        "./start.sh",
        "java -jar server.jar",
        "cargo run",
        "ruby server.rb",
    ]
)


@st.composite
def config_with_sudo_command(draw: st.DrawFn) -> MCPServerConfig:
    """Generate an MCPServerConfig whose command starts with 'sudo'."""
    name = draw(server_name)
    suffix = draw(command_suffix)
    # Optionally add leading whitespace that strip() would handle
    leading_space = draw(st.sampled_from(["", " ", "  "]))
    command = f"{leading_space}sudo {suffix}"
    return MCPServerConfig(
        name=name,
        command=command,
        args=[],
        env={},
    )


@st.composite
def config_with_privileged_in_command(draw: st.DrawFn) -> MCPServerConfig:
    """Generate an MCPServerConfig whose command contains '--privileged'."""
    name = draw(server_name)
    prefix = draw(
        st.sampled_from(
            [
                "docker run --privileged myimage",
                "podman run --privileged container",
                "run --privileged --rm image",
            ]
        )
    )
    return MCPServerConfig(
        name=name,
        command=prefix,
        args=[],
        env={},
    )


@st.composite
def config_with_privileged_in_args(draw: st.DrawFn) -> MCPServerConfig:
    """Generate an MCPServerConfig whose args contain '--privileged'."""
    name = draw(server_name)
    command = draw(st.sampled_from(["docker", "podman", "nerdctl"]))
    # Place --privileged somewhere in the args list
    pre_args = draw(
        st.lists(
            st.sampled_from(["run", "--rm", "-d", "-p", "8080:8080"]),
            min_size=0,
            max_size=3,
        )
    )
    post_args = draw(
        st.lists(
            st.sampled_from(["myimage", "container:latest", "--name=server"]),
            min_size=0,
            max_size=2,
        )
    )
    args = pre_args + ["--privileged"] + post_args
    return MCPServerConfig(
        name=name,
        command=command,
        args=args,
        env={},
    )


@st.composite
def config_with_user_root(draw: st.DrawFn) -> MCPServerConfig:
    """Generate an MCPServerConfig whose env specifies USER=root."""
    name = draw(server_name)
    command = draw(command_suffix)
    # Add other env vars alongside USER=root
    extra_env = draw(
        st.fixed_dictionaries(
            {},
            optional={
                "PATH": st.just("/usr/bin:/bin"),
                "HOME": st.just("/root"),
                "NODE_ENV": st.sampled_from(["production", "development"]),
            },
        )
    )
    env = {**extra_env, "USER": "root"}
    return MCPServerConfig(
        name=name,
        command=command,
        args=[],
        env=env,
    )


@st.composite
def config_with_uid_zero(draw: st.DrawFn) -> MCPServerConfig:
    """Generate an MCPServerConfig whose env specifies UID=0."""
    name = draw(server_name)
    command = draw(command_suffix)
    # Add other env vars alongside UID=0
    extra_env = draw(
        st.fixed_dictionaries(
            {},
            optional={
                "PATH": st.just("/usr/bin:/bin"),
                "HOME": st.just("/home/user"),
                "NODE_ENV": st.sampled_from(["production", "development"]),
            },
        )
    )
    env = {**extra_env, "UID": "0"}
    return MCPServerConfig(
        name=name,
        command=command,
        args=[],
        env=env,
    )


# Combined strategy: any privileged config
privileged_config = st.one_of(
    config_with_sudo_command(),
    config_with_privileged_in_command(),
    config_with_privileged_in_args(),
    config_with_user_root(),
    config_with_uid_zero(),
)


# --- Property Tests ---


class TestElevatedPrivilegeDetection:
    """Property 17: Elevated Privilege Detection.

    Feature: extended-mcp-scanning, Property 17: Elevated Privilege Detection

    **Validates: Requirements 6.4**
    """

    analyzer = ConfigPrivilegeAnalyzer()

    @given(config=config_with_sudo_command())
    @settings(max_examples=100)
    def test_sudo_command_produces_mcp_s7(self, config: MCPServerConfig) -> None:
        """For any config where command starts with 'sudo', the analyzer
        SHALL produce a ScanFinding with id='MCP-S7'."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s7_findings = [f for f in findings if f.id == "MCP-S7"]
        assert len(mcp_s7_findings) >= 1, (
            f"Expected at least one MCP-S7 finding for config with command "
            f"'{config.command}', got findings: {[(f.id, f.evidence) for f in findings]}"
        )

    @given(config=config_with_privileged_in_command())
    @settings(max_examples=100)
    def test_privileged_in_command_produces_mcp_s7(self, config: MCPServerConfig) -> None:
        """For any config where command contains '--privileged', the analyzer
        SHALL produce a ScanFinding with id='MCP-S7'."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s7_findings = [f for f in findings if f.id == "MCP-S7"]
        assert len(mcp_s7_findings) >= 1, (
            f"Expected at least one MCP-S7 finding for config with command "
            f"'{config.command}', got findings: {[(f.id, f.evidence) for f in findings]}"
        )

    @given(config=config_with_privileged_in_args())
    @settings(max_examples=100)
    def test_privileged_in_args_produces_mcp_s7(self, config: MCPServerConfig) -> None:
        """For any config where args contain '--privileged', the analyzer
        SHALL produce a ScanFinding with id='MCP-S7'."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s7_findings = [f for f in findings if f.id == "MCP-S7"]
        assert len(mcp_s7_findings) >= 1, (
            f"Expected at least one MCP-S7 finding for config with args "
            f"containing '--privileged' ({config.args}), got findings: "
            f"{[(f.id, f.evidence) for f in findings]}"
        )

    @given(config=config_with_user_root())
    @settings(max_examples=100)
    def test_user_root_env_produces_mcp_s7(self, config: MCPServerConfig) -> None:
        """For any config where env specifies USER=root, the analyzer
        SHALL produce a ScanFinding with id='MCP-S7'."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s7_findings = [f for f in findings if f.id == "MCP-S7"]
        assert len(mcp_s7_findings) >= 1, (
            f"Expected at least one MCP-S7 finding for config with "
            f"USER=root in env, got findings: {[(f.id, f.evidence) for f in findings]}"
        )

    @given(config=config_with_uid_zero())
    @settings(max_examples=100)
    def test_uid_zero_env_produces_mcp_s7(self, config: MCPServerConfig) -> None:
        """For any config where env specifies UID=0, the analyzer
        SHALL produce a ScanFinding with id='MCP-S7'."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s7_findings = [f for f in findings if f.id == "MCP-S7"]
        assert len(mcp_s7_findings) >= 1, (
            f"Expected at least one MCP-S7 finding for config with "
            f"UID=0 in env, got findings: {[(f.id, f.evidence) for f in findings]}"
        )

    @given(config=privileged_config)
    @settings(max_examples=100)
    def test_any_privileged_config_produces_mcp_s7(self, config: MCPServerConfig) -> None:
        """For any MCP server configuration with elevated privileges (sudo,
        --privileged, USER=root, or UID=0), the ConfigPrivilegeAnalyzer
        SHALL produce at least one ScanFinding with id='MCP-S7'."""
        findings = self.analyzer.analyze_configs([config])

        mcp_s7_findings = [f for f in findings if f.id == "MCP-S7"]
        assert len(mcp_s7_findings) >= 1, (
            f"Expected at least one MCP-S7 finding for privileged config "
            f"(command='{config.command}', args={config.args}, env={config.env}), "
            f"got findings: {[(f.id, f.evidence) for f in findings]}"
        )
