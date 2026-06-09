"""Dynamic scanner module integrating all dynamic MCP scanning components.

Connects to live MCP servers, discovers tools/resources, analyzes descriptions
for poisoning/shadowing, detects toxic flows, performs attack simulations,
and checks configuration for privilege/version issues.

Implements Requirements 5.1, 5.2, 5.3, 5.8, 5.9, 5.10, 6.3, 7.3, 7.7.
"""

from __future__ import annotations

import asyncio
import json
import logging

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.models.findings import ScanFinding
from ai_artifact_risk_validator.models.mcp_models import (
    DynamicScanConfig,
    MCPServerConfig,
    MCPServerInventory,
    MCPToolInfo,
)
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.scanners.dynamic.attack_simulator import AttackSimulator
from ai_artifact_risk_validator.scanners.dynamic.config_privilege_analyzer import (
    ConfigPrivilegeAnalyzer,
)
from ai_artifact_risk_validator.scanners.dynamic.mcp_client import MCPClient
from ai_artifact_risk_validator.scanners.dynamic.tool_description_analyzer import (
    ToolDescriptionAnalyzer,
)
from ai_artifact_risk_validator.scanners.dynamic.toxic_flow_analyzer import ToxicFlowAnalyzer

logger = logging.getLogger(__name__)


class DynamicScanner(BaseScanner):
    """Dynamic runtime scanner that connects to live MCP servers.

    Parses MCP configuration JSON, connects to each server, discovers
    tools and resources, and runs multiple analyzers to detect security
    risks that static analysis cannot identify.

    Components:
    - MCPClient: Connects via stdio or HTTP/SSE, invokes tools/list and resources/list
    - ToolDescriptionAnalyzer: Detects prompt injection, poisoning, shadowing
    - ToxicFlowAnalyzer: Detects cross-server toxic data flow chains
    - AttackSimulator: Executes path traversal attack simulations
    - ConfigPrivilegeAnalyzer: Detects elevated privileges and unpinned versions

    Consent model:
    - Interactive mode: prompts user before connecting
    - CI/CD mode: requires --allow-dynamic-scan flag
    """

    def __init__(self, config: DynamicScanConfig | None = None) -> None:
        """Initialize DynamicScanner with optional configuration.

        Args:
            config: Optional DynamicScanConfig controlling consent,
                timeouts, and built-in tool name registry. If None,
                defaults are used (dynamic scan NOT allowed).
        """
        self._config = config or DynamicScanConfig()
        self._tool_description_analyzer = ToolDescriptionAnalyzer()
        self._toxic_flow_analyzer = ToxicFlowAnalyzer()
        self._attack_simulator = AttackSimulator()
        self._config_privilege_analyzer = ConfigPrivilegeAnalyzer()
        self._inventories: list[MCPServerInventory] = []

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.DYNAMIC_SCAN

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return [ArtifactType.MCP]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        return ["MCP-S1", "MCP-S3", "MCP-S5", "MCP-S7", "MCP-S9"]

    @property
    def inventories(self) -> list[MCPServerInventory]:
        """Return inventory reports generated during the last scan."""
        return list(self._inventories)

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan MCP configuration for dynamic security risks.

        Parses the artifact_content as MCP config JSON, checks consent,
        connects to each server, runs all analyzers, and returns findings.

        Args:
            artifact_content: JSON string containing MCP server configuration
                with "mcpServers" key mapping server names to their configs.
            artifact_type: Should be ArtifactType.MCP.
            artifact_path: Path to the MCP configuration file.

        Returns:
            List of ScanFinding objects. Returns empty list if consent is
            not granted or if parsing fails.
        """
        # Check consent before proceeding
        if not self._check_consent():
            return []

        # Parse MCP configuration
        server_configs = self._parse_mcp_config(artifact_content)
        if not server_configs:
            return []

        # Run the async scanning logic
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, create a new loop in a thread
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(self._run_async_scan, server_configs)
                    return future.result()
            else:
                return loop.run_until_complete(self._async_scan(server_configs))
        except RuntimeError:
            # No event loop exists, create one
            return asyncio.run(self._async_scan(server_configs))

    def _run_async_scan(self, server_configs: list[MCPServerConfig]) -> list[ScanFinding]:
        """Run async scan in a new event loop (for thread-based execution)."""
        return asyncio.run(self._async_scan(server_configs))

    async def _async_scan(self, server_configs: list[MCPServerConfig]) -> list[ScanFinding]:
        """Async implementation of the scanning logic.

        Iterates over servers, connects, discovers tools/resources,
        runs analyzers, handles per-server timeouts, and builds inventories.
        """
        findings: list[ScanFinding] = []
        tools_by_server: dict[str, list[MCPToolInfo]] = {}
        self._inventories = []

        # Run config privilege analysis (doesn't require connection)
        config_findings = self._config_privilege_analyzer.analyze_configs(server_configs)
        findings.extend(config_findings)

        # Process each server with per-server timeout
        for config in server_configs:
            try:
                server_findings, server_tools = await asyncio.wait_for(
                    self._scan_server(config),
                    timeout=self._config.per_server_timeout,
                )
                findings.extend(server_findings)
                if server_tools:
                    tools_by_server[config.name] = server_tools
            except asyncio.TimeoutError:
                logger.warning(
                    "Per-server timeout (%ds) exceeded for server '%s'. "
                    "Preserving partial findings.",
                    self._config.per_server_timeout,
                    config.name,
                )
                # Build a minimal inventory for timed-out servers
                self._inventories.append(
                    MCPServerInventory(
                        server_name=config.name,
                        transport_type=config.transport,
                        tool_count=0,
                        resource_count=0,
                        prompt_count=0,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "Error scanning server '%s': %s",
                    config.name,
                    exc,
                )

        # Run toxic flow analysis across all servers
        if tools_by_server:
            toxic_findings = self._toxic_flow_analyzer.detect_toxic_flows(tools_by_server)
            findings.extend(toxic_findings)

        return findings

    async def _scan_server(
        self, config: MCPServerConfig
    ) -> tuple[list[ScanFinding], list[MCPToolInfo]]:
        """Scan a single MCP server: connect, discover, analyze.

        Args:
            config: Server configuration to connect to.

        Returns:
            Tuple of (findings, tools) discovered from this server.
        """
        findings: list[ScanFinding] = []
        tools: list[MCPToolInfo] = []
        resources = []

        # Create MCP client and attempt connection
        client = MCPClient(
            config=config,
            connection_timeout=self._config.connection_timeout,
            per_server_timeout=self._config.per_server_timeout,
        )

        connected = False
        try:
            connected = await client.connect()
        except Exception as exc:
            logger.warning(
                "Failed to connect to MCP server '%s': %s",
                config.name,
                exc,
            )

        if connected:
            # Discover tools via tools/list
            try:
                tools = await client.list_tools()
            except Exception as exc:
                logger.warning(
                    "Error listing tools from server '%s': %s",
                    config.name,
                    exc,
                )

            # Discover resources via resources/list
            try:
                resources = await client.list_resources()
            except Exception as exc:
                logger.warning(
                    "Error listing resources from server '%s': %s",
                    config.name,
                    exc,
                )

            # Run ToolDescriptionAnalyzer on discovered tools
            if tools:
                tool_findings = self._tool_description_analyzer.analyze(
                    tools,
                    builtin_names=self._config.builtin_tool_names,
                )
                findings.extend(tool_findings)

            # Run ConfigPrivilegeAnalyzer on resources
            if resources:
                resource_findings = self._config_privilege_analyzer.analyze_resources(
                    resources, config.name
                )
                findings.extend(resource_findings)

            # Run AttackSimulator if connected and tools are available
            if tools:
                try:
                    attack_findings = await self._attack_simulator.simulate_attacks(client, tools)
                    findings.extend(attack_findings)
                except Exception as exc:
                    logger.warning(
                        "Error during attack simulation on server '%s': %s",
                        config.name,
                        exc,
                    )

            # Disconnect from server
            await client.disconnect()
        else:
            logger.info(
                "Could not connect to MCP server '%s' (%s). "
                "Skipping dynamic analysis for this server.",
                config.name,
                config.transport,
            )

        # Build MCPServerInventory for this server
        inventory = MCPServerInventory(
            server_name=config.name,
            transport_type=config.transport,
            tools=tools,
            resources=resources,
            tool_count=len(tools),
            resource_count=len(resources),
            prompt_count=0,
        )
        self._inventories.append(inventory)

        return findings, tools

    def _check_consent(self) -> bool:
        """Check whether dynamic scanning is allowed based on config.

        In interactive mode, the consent is assumed to be handled externally
        (the CLI prompts before passing allow_dynamic_scan=True).
        In CI/CD mode (non-interactive), requires allow_dynamic_scan flag.

        Returns:
            True if scanning is permitted, False otherwise.
        """
        if self._config.allow_dynamic_scan:
            return True

        if not self._config.interactive:
            # CI/CD mode without --allow-dynamic-scan flag
            logger.info(
                "Dynamic scanning skipped: --allow-dynamic-scan flag not provided. "
                "Set --allow-dynamic-scan to enable live MCP server connections in CI/CD."
            )
            return False

        # Interactive mode: prompt user for consent
        try:
            response = self._prompt_user_consent()
            return response
        except (EOFError, KeyboardInterrupt):
            logger.info("Dynamic scanning skipped: user declined consent.")
            return False

    def _prompt_user_consent(self) -> bool:
        """Prompt user for consent to perform dynamic scanning.

        Returns:
            True if user consents, False otherwise.
        """
        try:
            import sys

            sys.stdout.write(
                "\n⚠️  Dynamic MCP Scanning requires connecting to live MCP servers."
                "\n    This will establish network connections to the configured servers."
                "\n    Do you want to proceed? [y/N]: "
            )
            sys.stdout.flush()
            response = input().strip().lower()
            return response in ("y", "yes")
        except (EOFError, KeyboardInterrupt, OSError):
            return False

    def _parse_mcp_config(self, content: str) -> list[MCPServerConfig]:
        """Parse MCP configuration JSON into server configs.

        Expects JSON with a "mcpServers" key containing a dictionary
        of server names to their configurations.

        Args:
            content: JSON string to parse.

        Returns:
            List of MCPServerConfig objects. Empty list on parse failure.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("Failed to parse MCP config JSON: %s", exc)
            return []

        servers_data = data.get("mcpServers", {})
        if not isinstance(servers_data, dict):
            logger.error("Invalid MCP config: 'mcpServers' must be a dictionary")
            return []

        configs: list[MCPServerConfig] = []
        for server_name, server_data in servers_data.items():
            if not isinstance(server_data, dict):
                logger.warning(
                    "Skipping invalid server config for '%s': not a dictionary",
                    server_name,
                )
                continue

            try:
                # Determine transport type
                transport = "stdio"
                if "url" in server_data:
                    transport = server_data.get("transport", "sse")
                else:
                    transport = server_data.get("transport", "stdio")

                config = MCPServerConfig(
                    name=server_name,
                    command=server_data.get("command"),
                    args=server_data.get("args", []),
                    url=server_data.get("url"),
                    transport=transport,
                    env=server_data.get("env", {}),
                )
                configs.append(config)
            except Exception as exc:
                logger.warning(
                    "Failed to parse server config for '%s': %s",
                    server_name,
                    exc,
                )

        return configs
