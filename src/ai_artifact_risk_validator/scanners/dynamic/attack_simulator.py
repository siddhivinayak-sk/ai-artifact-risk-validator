"""Attack simulator for dynamic MCP server scanning.

Executes controlled path traversal attack simulations against live MCP servers
to identify exploitable vulnerabilities. Generates multiple payload categories
(relative traversal, URL-encoded traversal, null-byte injection) and invokes
file-accepting tool parameters via MCP protocol.

Reports confirmed MCP-S9 (Path Traversal) with confidence 1.0 if the server
responds with traversed content. Does NOT report if the server rejects all
payloads with error responses.

Implements Requirements 6.7, 6.8.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, Protocol

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.models.mcp_models import MCPToolInfo

if TYPE_CHECKING:
    from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer

logger = logging.getLogger(__name__)


class MCPClientProtocol(Protocol):
    """Protocol defining the MCP client interface needed by AttackSimulator."""

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


# --- Path traversal payloads ---

# At least 3 distinct categories of path traversal payloads
PATH_TRAVERSAL_PAYLOADS: list[dict[str, str]] = [
    # Category 1: Relative path traversal
    {"payload": "../../etc/passwd", "category": "relative traversal"},
    {"payload": "../../../etc/passwd", "category": "relative traversal"},
    {"payload": "../../../../etc/passwd", "category": "relative traversal"},
    # Category 2: URL-encoded traversal
    {"payload": "..%2F..%2F..%2Fetc%2Fpasswd", "category": "URL-encoded traversal"},
    {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "category": "URL-encoded traversal"},
    {"payload": "..%252F..%252F..%252Fetc%252Fpasswd", "category": "double URL-encoded traversal"},
    # Category 3: Null-byte injection
    {"payload": "../../etc/passwd%00.txt", "category": "null-byte injection"},
    {"payload": "../etc/passwd\x00.png", "category": "null-byte injection"},
    {"payload": "../../etc/passwd%00.jpg", "category": "null-byte injection"},
]

# Keywords indicating a parameter accepts file paths
_FILE_PARAM_NAME_KEYWORDS = re.compile(
    r"(?:^|(?<=_)|\b)(path|file|filename|filepath|file_path|file_name)(?:$|(?=_)|\b)",
    re.IGNORECASE,
)

_FILE_PARAM_DESC_KEYWORDS = re.compile(
    r"\b(path|file|filename|filepath|file.path|file.name)\b",
    re.IGNORECASE,
)

# Indicators of traversed content in response (e.g., /etc/passwd content)
_TRAVERSAL_SUCCESS_INDICATORS = re.compile(
    r"(root:|daemon:|bin:|sys:|nobody:|/bin/bash|/bin/sh|/usr/sbin/nologin|"
    r"root:x:0:0|/home/\w+)",
    re.IGNORECASE,
)


def _truncate_evidence(tool_name: str, fragment: str, max_length: int = 200) -> str:
    """Format evidence as 'tool_name: fragment' truncated to max_length."""
    prefix = f"{tool_name}: "
    available = max_length - len(prefix)
    if available <= 0:
        return prefix[:max_length]
    truncated_fragment = fragment[:available]
    return prefix + truncated_fragment


def _is_file_accepting_param(param_name: str, param_def: dict[str, Any]) -> bool:
    """Determine if a parameter accepts file paths based on name and description.

    A parameter is considered file-accepting if:
    - Its type is "string"
    - Its name or description contains keywords like "path", "file", "filename"
    """
    param_type = param_def.get("type", "")
    if param_type != "string":
        return False

    # Check parameter name
    if _FILE_PARAM_NAME_KEYWORDS.search(param_name):
        return True

    # Check parameter description
    param_desc = param_def.get("description", "")
    if param_desc and _FILE_PARAM_DESC_KEYWORDS.search(param_desc):
        return True

    return False


# ============================================================
# Semantic file-parameter detection
# ============================================================

_FILE_PARAM_CORPUS: list[str] = [
    "The path to the file to read.",
    "Location of the resource on disk.",
    "Filename or directory path.",
    "A filesystem path to the target.",
    "The document to open.",
    "Source file for processing.",
]

_SEMANTIC_FILE_PARAM_THRESHOLD: float = 0.50


class SemanticParamDetector:
    """Detect file-accepting parameters via embedding similarity.

    Falls back to no-op when ``sentence-transformers`` is absent.
    """

    def __init__(self) -> None:
        self._scorer: SimilarityScorer | None = None
        self._corpus_embs: Any = None
        self._available: bool | None = None

    @property
    def is_available(self) -> bool:
        if self._available is None:
            try:
                from ai_artifact_risk_validator.semantic.embeddings import (
                    get_shared_engine,
                )

                self._available = get_shared_engine().is_available
            except Exception:
                self._available = False
        return self._available

    def _ensure_loaded(self) -> bool:
        if self._scorer is not None:
            return True
        if not self.is_available:
            return False
        try:
            from ai_artifact_risk_validator.semantic.similarity import (
                SimilarityScorer,
            )

            self._scorer = SimilarityScorer()
            self._corpus_embs = self._scorer.encode(_FILE_PARAM_CORPUS)
            return True
        except Exception:
            self._available = False
            return False

    def is_file_param(self, param_name: str, param_desc: str) -> bool:
        """Return ``True`` if the parameter description is semantically
        similar to file/path references."""
        text = f"{param_name} {param_desc}".strip()
        if not text or not self._ensure_loaded() or self._scorer is None:
            return False
        try:
            score: float = self._scorer.score_against_corpus(text, self._corpus_embs)
            return score >= _SEMANTIC_FILE_PARAM_THRESHOLD
        except Exception:
            return False


def _response_indicates_traversal(response: dict[str, Any]) -> bool:
    """Check if a server response indicates successful path traversal.

    Returns True if:
    - The response contains content from a traversed path (e.g., /etc/passwd markers)
    - The response does NOT contain an error

    Returns False if:
    - The response contains an "error" key
    - The response is empty
    """
    # Empty response means no success
    if not response:
        return False

    # Error response means the server rejected the payload
    if "error" in response:
        return False

    # Convert response to string for content matching
    response_str = str(response)

    # Check for indicators of traversed content
    if _TRAVERSAL_SUCCESS_INDICATORS.search(response_str):
        return True

    # If server responded without an error, it may have processed the path
    # (non-error response to a traversal payload is suspicious)
    # Per requirement 6.7: "does not return an error rejection" → confirmed
    # Only flag if there is actual content in the response
    content = response.get("content", response.get("result", response.get("data", "")))
    if content and not isinstance(content, dict):
        # There is non-empty content and no error - potential traversal success
        content_str = str(content)
        if len(content_str) > 0 and content_str.strip():
            return True

    return False


class AttackSimulator:
    """Simulates path traversal attacks against MCP server tools.

    Identifies file-accepting parameters in tool schemas and executes
    controlled path traversal payloads. Reports confirmed MCP-S9 findings
    with confidence 1.0 when traversal succeeds.
    """

    def __init__(self) -> None:
        """Initialize AttackSimulator with default payloads."""
        self._payloads = PATH_TRAVERSAL_PAYLOADS
        self._semantic = SemanticParamDetector()

    def _identify_file_params(self, tool: MCPToolInfo) -> list[str]:
        """Identify file-accepting parameters in a tool's input schema.

        Args:
            tool: MCPToolInfo with input_schema containing properties.

        Returns:
            List of parameter names that accept file paths.
        """
        file_params: list[str] = []
        schema = tool.input_schema

        if not schema:
            return file_params

        properties = schema.get("properties", {})
        if not properties:
            return file_params

        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue
            if _is_file_accepting_param(param_name, param_def):
                file_params.append(param_name)
            elif self._semantic.is_available:
                param_desc = param_def.get("description", "")
                if self._semantic.is_file_param(param_name, param_desc):
                    file_params.append(param_name)

        return file_params

    async def simulate_attacks(
        self,
        client: MCPClientProtocol,
        tools: list[MCPToolInfo],
    ) -> list[ScanFinding]:
        """Execute path traversal attack simulations against file-accepting tools.

        For each tool with file-accepting parameters, attempts all traversal
        payloads via the MCP client. Reports confirmed MCP-S9 with confidence 1.0
        if any payload succeeds. Does NOT report if all payloads are rejected.

        Args:
            client: MCPClientProtocol instance for invoking tools.
            tools: List of MCPToolInfo objects discovered from the server.

        Returns:
            List of ScanFinding objects for confirmed path traversal vulnerabilities.
        """
        findings: list[ScanFinding] = []

        for tool in tools:
            file_params = self._identify_file_params(tool)
            if not file_params:
                continue

            for param_name in file_params:
                finding = await self._attack_parameter(client, tool, param_name)
                if finding is not None:
                    findings.append(finding)

        return findings

    async def _attack_parameter(
        self,
        client: MCPClientProtocol,
        tool: MCPToolInfo,
        param_name: str,
    ) -> ScanFinding | None:
        """Attempt path traversal payloads against a specific parameter.

        Tries all payloads in sequence. Returns a finding on first success.
        Returns None if all payloads are rejected with errors.

        Args:
            client: MCPClientProtocol instance.
            tool: The tool to attack.
            param_name: The file-accepting parameter to target.

        Returns:
            ScanFinding if traversal confirmed, None otherwise.
        """
        for payload_info in self._payloads:
            payload = payload_info["payload"]
            category = payload_info["category"]

            try:
                # Build arguments with the traversal payload
                arguments = {param_name: payload}
                response = await client.call_tool(tool.name, arguments)

                if _response_indicates_traversal(response):
                    fragment = f"confirmed path traversal via {payload}"
                    evidence = _truncate_evidence(tool.name, fragment)

                    return ScanFinding(
                        id="MCP-S9",
                        artifact_type=ArtifactType.MCP,
                        artifact_path="dynamic_scan",
                        severity_score=9,
                        severity_label=SeverityLabel.CRITICAL,
                        priority=Priority.P0,
                        gate_action=GateAction.BLOCK,
                        category=RiskCategory.SECURITY,
                        title="Path Traversal - Confirmed via Attack Simulation",
                        description=(
                            "Attack simulation confirmed that the MCP server tool "
                            f"'{tool.name}' is vulnerable to path traversal via the "
                            f"'{param_name}' parameter. The server processed a "
                            f"{category} payload without rejection."
                        ),
                        location=FindingLocation(
                            line=0,
                            section=f"tool:{tool.name}",
                        ),
                        evidence=evidence,
                        confidence=1.0,
                        scanner_module=ScannerModule.DYNAMIC_SCAN,
                        remediation=(
                            "Implement path validation on all file-accepting parameters. "
                            "Use canonicalize/realpath to resolve paths before access. "
                            "Reject paths containing '..' or URL-encoded traversal sequences. "
                            "Enforce an allowlist of accessible directories."
                        ),
                    )
            except Exception as exc:
                logger.warning(
                    "Error during attack simulation on tool '%s' param '%s' with payload '%s': %s",
                    tool.name,
                    param_name,
                    payload,
                    exc,
                )
                continue

        # All payloads rejected - do NOT report (Requirement 6.8)
        return None
