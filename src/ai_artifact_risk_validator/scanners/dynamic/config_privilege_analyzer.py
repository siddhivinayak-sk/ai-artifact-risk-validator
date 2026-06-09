"""Configuration privilege analyzer for MCP server configurations.

Detects elevated privileges, unpinned version references, and dangerous
resource endpoint URIs in MCP server configurations and resource metadata.
"""

import re

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.models.mcp_models import MCPResourceInfo, MCPServerConfig


class ConfigPrivilegeAnalyzer:
    """Analyzes MCP server configurations for privilege and version issues.

    Detects:
    - Elevated privileges: sudo, --privileged, USER=root, UID=0
    - Unpinned version references: latest, *, ^x.y.z, ~x.y.z, ranges with >, <, ||
    - Dangerous resource URIs: system paths, wildcards, environment variables
    """

    # Patterns for unpinned version detection
    _RE_LATEST = re.compile(r"\blatest\b", re.IGNORECASE)
    _RE_WILDCARD_VERSION = re.compile(r"(?:^|\s|[:@=])(\*)(?:\s|$|,)")
    _RE_CARET_RANGE = re.compile(r"\^[0-9]+\.[0-9]+\.[0-9]+")
    _RE_TILDE_RANGE = re.compile(r"~[0-9]+\.[0-9]+\.[0-9]+")
    _RE_GT_LT_RANGE = re.compile(r"[><][=]?\s*[0-9]+\.[0-9]+")
    _RE_OR_RANGE = re.compile(r"\|\|")

    # Patterns for pinned versions (exact semver or commit hashes)
    _RE_EXACT_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
    _RE_COMMIT_HASH = re.compile(r"^[0-9a-fA-F]{7,}$")

    # Patterns for dangerous resource URIs
    _RE_SYSTEM_PATHS = re.compile(r"(/etc/|/proc/|/sys/|~/)")
    _RE_WILDCARD_GLOB = re.compile(r"(\*\*|\*)")
    _RE_ENV_VAR = re.compile(r"(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)")

    def analyze_configs(self, configs: list[MCPServerConfig]) -> list[ScanFinding]:
        """Check server configurations for privilege and version issues.

        Analyzes each server configuration for:
        - Elevated privilege indicators (MCP-S7)
        - Unpinned version references (MCP-S5)

        Args:
            configs: List of MCP server configurations to analyze.

        Returns:
            List of ScanFinding objects for detected issues.
        """
        findings: list[ScanFinding] = []
        for config in configs:
            findings.extend(self._check_elevated_privileges(config))
            findings.extend(self._check_version_pinning(config))
        return findings

    def analyze_resources(
        self, resources: list[MCPResourceInfo], server_name: str
    ) -> list[ScanFinding]:
        """Check resource URIs for dangerous patterns.

        Analyzes resource endpoint URIs for system paths, wildcard access,
        and environment variable references (MCP-S9).

        Args:
            resources: List of resource metadata from an MCP server.
            server_name: Name of the server these resources belong to.

        Returns:
            List of ScanFinding objects for detected issues.
        """
        findings: list[ScanFinding] = []
        for resource in resources:
            findings.extend(self._check_resource_uri(resource, server_name))
        return findings

    def _check_elevated_privileges(self, config: MCPServerConfig) -> list[ScanFinding]:
        """Detect elevated privilege indicators in server config."""
        findings: list[ScanFinding] = []

        # Check command starts with "sudo"
        if config.command and config.command.strip().startswith("sudo"):
            findings.append(
                self._create_privilege_finding(
                    config.name,
                    f"{config.name}: command uses sudo ({config.command})",
                )
            )

        # Check command or args contain "--privileged"
        all_parts = []
        if config.command:
            all_parts.append(config.command)
        all_parts.extend(config.args)

        for part in all_parts:
            if "--privileged" in part:
                findings.append(
                    self._create_privilege_finding(
                        config.name,
                        f"{config.name}: --privileged flag detected",
                    )
                )
                break

        # Check env for USER=root or UID=0
        if config.env.get("USER") == "root":
            findings.append(
                self._create_privilege_finding(
                    config.name,
                    f"{config.name}: environment sets USER=root",
                )
            )

        if config.env.get("UID") == "0":
            findings.append(
                self._create_privilege_finding(
                    config.name,
                    f"{config.name}: environment sets UID=0",
                )
            )

        return findings

    def _check_version_pinning(self, config: MCPServerConfig) -> list[ScanFinding]:
        """Detect unpinned version references in command/args."""
        findings: list[ScanFinding] = []

        # Collect all tokens to check from command and args
        tokens: list[str] = []
        if config.command:
            tokens.append(config.command)
        tokens.extend(config.args)

        combined = " ".join(tokens)

        # Check for "latest" tag
        if self._RE_LATEST.search(combined):
            findings.append(
                self._create_version_finding(
                    config.name,
                    f"{config.name}: unpinned version 'latest' detected",
                )
            )

        # Check for wildcard "*" version
        if self._RE_WILDCARD_VERSION.search(f" {combined} "):
            findings.append(
                self._create_version_finding(
                    config.name,
                    f"{config.name}: unpinned wildcard version '*' detected",
                )
            )

        # Check for caret range ^x.y.z
        match = self._RE_CARET_RANGE.search(combined)
        if match:
            findings.append(
                self._create_version_finding(
                    config.name,
                    f"{config.name}: unpinned caret range '{match.group()}' detected",
                )
            )

        # Check for tilde range ~x.y.z
        match = self._RE_TILDE_RANGE.search(combined)
        if match:
            findings.append(
                self._create_version_finding(
                    config.name,
                    f"{config.name}: unpinned tilde range '{match.group()}' detected",
                )
            )

        # Check for > or < ranges
        match = self._RE_GT_LT_RANGE.search(combined)
        if match:
            findings.append(
                self._create_version_finding(
                    config.name,
                    f"{config.name}: unpinned version range with comparison operator detected",
                )
            )

        # Check for || (OR ranges)
        if self._RE_OR_RANGE.search(combined):
            findings.append(
                self._create_version_finding(
                    config.name,
                    f"{config.name}: unpinned version range with '||' operator detected",
                )
            )

        return findings

    def _check_resource_uri(self, resource: MCPResourceInfo, server_name: str) -> list[ScanFinding]:
        """Detect dangerous patterns in resource endpoint URIs."""
        findings: list[ScanFinding] = []
        uri = resource.uri

        # Check for system paths
        match = self._RE_SYSTEM_PATHS.search(uri)
        if match:
            findings.append(
                self._create_resource_finding(
                    server_name,
                    f"{server_name}: resource URI references system path '{match.group()}'",
                )
            )

        # Check for wildcard glob patterns
        match = self._RE_WILDCARD_GLOB.search(uri)
        if match:
            findings.append(
                self._create_resource_finding(
                    server_name,
                    f"{server_name}: resource URI contains wildcard '{match.group()}'",
                )
            )

        # Check for environment variables
        match = self._RE_ENV_VAR.search(uri)
        if match:
            findings.append(
                self._create_resource_finding(
                    server_name,
                    f"{server_name}: resource URI contains env var '{match.group()}'",
                )
            )

        return findings

    def _create_privilege_finding(self, server_name: str, evidence: str) -> ScanFinding:
        """Create a MCP-S7 (Excessive Permissions) finding."""
        return ScanFinding(
            id="MCP-S7",
            artifact_type=ArtifactType.MCP,
            artifact_path=server_name,
            severity_score=7,
            severity_label=SeverityLabel.HIGH,
            priority=Priority.P1,
            gate_action=GateAction.WARN,
            category=RiskCategory.SECURITY,
            title="Elevated Privileges Detected",
            description=(
                f"MCP server '{server_name}' is configured to run with elevated privileges. "
                "This increases the attack surface and potential impact of any vulnerability."
            ),
            location=FindingLocation(section="config"),
            evidence=evidence[:200],
            confidence=0.90,
            scanner_module=ScannerModule.DYNAMIC_SCAN,
            remediation=(
                "Run MCP servers with least-privilege principles. "
                "Remove sudo, --privileged flags, and avoid running as root."
            ),
        )

    def _create_version_finding(self, server_name: str, evidence: str) -> ScanFinding:
        """Create a MCP-S5 (Unverified Source) finding."""
        return ScanFinding(
            id="MCP-S5",
            artifact_type=ArtifactType.MCP,
            artifact_path=server_name,
            severity_score=5,
            severity_label=SeverityLabel.MEDIUM,
            priority=Priority.P2,
            gate_action=GateAction.WARN,
            category=RiskCategory.SECURITY,
            title="Unpinned Version Reference",
            description=(
                f"MCP server '{server_name}' uses an unpinned version reference. "
                "This can lead to supply-chain attacks if the referenced package is compromised."
            ),
            location=FindingLocation(section="config"),
            evidence=evidence[:200],
            confidence=0.85,
            scanner_module=ScannerModule.DYNAMIC_SCAN,
            remediation=(
                "Pin all dependencies to exact versions or commit hashes. "
                "Avoid using 'latest', '*', caret (^), tilde (~), or range operators."
            ),
        )

    def _create_resource_finding(self, server_name: str, evidence: str) -> ScanFinding:
        """Create a MCP-S9 finding for dangerous resource URI patterns."""
        return ScanFinding(
            id="MCP-S9",
            artifact_type=ArtifactType.MCP,
            artifact_path=server_name,
            severity_score=7,
            severity_label=SeverityLabel.HIGH,
            priority=Priority.P1,
            gate_action=GateAction.WARN,
            category=RiskCategory.SECURITY,
            title="Dangerous Resource Endpoint URI",
            description=(
                f"MCP server '{server_name}' exposes a resource with a potentially dangerous URI pattern. "
                "System paths, wildcards, or environment variables in URIs may allow unauthorized access."
            ),
            location=FindingLocation(section="resources"),
            evidence=evidence[:200],
            confidence=0.85,
            scanner_module=ScannerModule.DYNAMIC_SCAN,
            remediation=(
                "Restrict resource URIs to specific, non-sensitive paths. "
                "Avoid exposing system directories, using wildcards, or referencing environment variables."
            ),
        )
