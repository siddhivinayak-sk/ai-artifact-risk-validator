"""Toxic flow analyzer for cross-server tool chain analysis.

Detects data flow paths where attacker-controlled input flows through
sensitive data access tools to data exfiltration tools across MCP servers.

A toxic flow exists when the combination of tools across servers creates a path:
  external_input → sensitive_data_access → data_transmission

This enables credential theft, data exfiltration, and other attacks where
the AI agent is manipulated through a chain of seemingly innocuous tool calls.

Implements Requirements 5.7.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ai_artifact_risk_validator._internal.logging import get_logger
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

logger = get_logger(__name__)


class ToolCategory:
    """Categories of tools in a toxic flow chain."""

    EXTERNAL_INPUT = "external_input"
    SENSITIVE_DATA = "sensitive_data"
    DATA_TRANSMISSION = "data_transmission"


# Keywords that indicate a tool accepts external/attacker-controlled input
_EXTERNAL_INPUT_KEYWORDS = re.compile(
    r"\b(url|fetch|input|read|download|request|import|receive|ingest|"
    r"accept|load|get|retrieve|pull|scrape|crawl|browse|open)\b",
    re.IGNORECASE,
)

# Keywords that indicate a tool accesses sensitive data
_SENSITIVE_DATA_KEYWORDS = re.compile(
    r"\b(credential|secret|password|database|key|private|config|env|"
    r"token|auth|session|certificate|vault|keychain|keystore|ssh|"
    r"api[_\s-]?key|access[_\s-]?key|encryption)\b",
    re.IGNORECASE,
)

# Keywords that indicate a tool can transmit data externally
_DATA_TRANSMISSION_KEYWORDS = re.compile(
    r"\b(send|email|http|post|upload|write|export|forward|transmit|"
    r"publish|push|dispatch|relay|transfer|submit|webhook|notify|"
    r"broadcast|emit|deliver)\b",
    re.IGNORECASE,
)


@dataclass
class ClassifiedTool:
    """A tool classified into one or more flow categories."""

    tool: MCPToolInfo
    server_name: str
    categories: list[str] = field(default_factory=list)


# ============================================================
# Semantic flow category corpora
# ============================================================

_INPUT_CORPUS: list[str] = [
    "Fetch a web page from a URL.",
    "Read input from the user.",
    "Download a remote resource.",
    "Accept external data.",
    "Scrape content from a website.",
    "Receive incoming messages.",
]

_SENSITIVE_CORPUS: list[str] = [
    "Access database credentials.",
    "Read the private key file.",
    "Retrieve secret configuration.",
    "Look up stored passwords.",
    "Query the authentication token.",
    "Load the encryption certificate.",
]

_TRANSMISSION_CORPUS: list[str] = [
    "Send data to an external server.",
    "Upload a file to a remote endpoint.",
    "Email the report to the user.",
    "Post results to a webhook.",
    "Forward the message externally.",
    "Transmit logs to the monitoring service.",
]

_SEMANTIC_FLOW_THRESHOLD: float = 0.50


class SemanticFlowClassifier:
    """Embedding-based tool-category classifier for toxic flow detection.

    Supplements keyword matching by scoring tool descriptions against
    per-category corpora.  Falls back to no-op when ``sentence-transformers``
    is not installed.
    """

    def __init__(self) -> None:
        self._scorer: SimilarityScorer | None = None
        self._corpus_map: dict[str, Any] = {}
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
            self._corpus_map = {
                ToolCategory.EXTERNAL_INPUT: self._scorer.encode(_INPUT_CORPUS),
                ToolCategory.SENSITIVE_DATA: self._scorer.encode(_SENSITIVE_CORPUS),
                ToolCategory.DATA_TRANSMISSION: self._scorer.encode(_TRANSMISSION_CORPUS),
            }
            return True
        except Exception:
            logger.debug("SemanticFlowClassifier init failed", exc_info=True)
            self._available = False
            return False

    def classify(self, text: str) -> list[str]:
        """Return flow categories whose corpus similarity exceeds the threshold."""
        if not self._ensure_loaded() or self._scorer is None:
            return []
        cats: list[str] = []
        for cat, embs in self._corpus_map.items():
            try:
                score: float = self._scorer.score_against_corpus(text, embs)
                if score >= _SEMANTIC_FLOW_THRESHOLD:
                    cats.append(cat)
            except Exception:
                logger.debug("Flow classification failed", cat=cat, exc_info=True)
                continue
        return cats


def _truncate_evidence(tool_name: str, fragment: str, max_length: int = 200) -> str:
    """Format evidence as 'tool_name: fragment' truncated to max_length."""
    prefix = f"{tool_name}: "
    available = max_length - len(prefix)
    if available <= 0:
        return prefix[:max_length]
    truncated_fragment = fragment[:available]
    return prefix + truncated_fragment


class ToxicFlowAnalyzer:
    """Analyzes cross-server tool chains for toxic data flow patterns.

    Detects paths where:
    1. A tool accepting external input (URLs, user text, file paths)
    2. Feeds into a tool accessing sensitive data (credentials, private files, databases)
    3. Which feeds into a tool capable of transmitting data externally

    This three-stage chain represents a toxic flow that could enable
    credential theft or data exfiltration through the AI agent.
    """

    def __init__(self) -> None:
        self._semantic = SemanticFlowClassifier()

    def classify_tool(self, tool: MCPToolInfo, server_name: str) -> ClassifiedTool:
        """Classify a tool into zero or more flow categories.

        Classification is based on the tool's name and description matching
        category-specific keywords.

        Args:
            tool: The MCP tool metadata to classify.
            server_name: Name of the server this tool belongs to.

        Returns:
            ClassifiedTool with assigned categories.
        """
        categories: list[str] = []
        text = f"{tool.name} {tool.description}".strip()

        if _EXTERNAL_INPUT_KEYWORDS.search(text):
            categories.append(ToolCategory.EXTERNAL_INPUT)

        if _SENSITIVE_DATA_KEYWORDS.search(text):
            categories.append(ToolCategory.SENSITIVE_DATA)

        if _DATA_TRANSMISSION_KEYWORDS.search(text):
            categories.append(ToolCategory.DATA_TRANSMISSION)

        # Semantic second pass: add categories missed by keywords.
        if self._semantic.is_available:
            sem_cats = self._semantic.classify(text)
            for cat in sem_cats:
                if cat not in categories:
                    categories.append(cat)

        return ClassifiedTool(tool=tool, server_name=server_name, categories=categories)

    def detect_toxic_flows(
        self, tools_by_server: dict[str, list[MCPToolInfo]]
    ) -> list[ScanFinding]:
        """Detect toxic flow chains across multiple MCP servers.

        Analyzes whether tools across servers create a path:
        external_input → sensitive_data → data_transmission

        A toxic flow is reported when all three categories are represented
        in the combined set of tools across all configured servers.

        Args:
            tools_by_server: Dictionary mapping server_name to list of MCPToolInfo
                objects discovered from that server.

        Returns:
            List of ScanFinding objects for detected toxic flow risks.
        """
        findings: list[ScanFinding] = []

        # Classify all tools across all servers
        input_tools: list[ClassifiedTool] = []
        sensitive_tools: list[ClassifiedTool] = []
        transmission_tools: list[ClassifiedTool] = []

        for server_name, tools in tools_by_server.items():
            for tool in tools:
                classified = self.classify_tool(tool, server_name)

                if ToolCategory.EXTERNAL_INPUT in classified.categories:
                    input_tools.append(classified)
                if ToolCategory.SENSITIVE_DATA in classified.categories:
                    sensitive_tools.append(classified)
                if ToolCategory.DATA_TRANSMISSION in classified.categories:
                    transmission_tools.append(classified)

        # A toxic flow exists when all three stages are present
        if input_tools and sensitive_tools and transmission_tools:
            # Report one finding per unique chain combination
            # To avoid explosion, report one representative finding per
            # (input_tool, sensitive_tool, transmission_tool) triple
            # Limited to first finding to avoid excessive noise
            findings.extend(
                self._generate_flow_findings(input_tools, sensitive_tools, transmission_tools)
            )

        return findings

    def _generate_flow_findings(
        self,
        input_tools: list[ClassifiedTool],
        sensitive_tools: list[ClassifiedTool],
        transmission_tools: list[ClassifiedTool],
    ) -> list[ScanFinding]:
        """Generate findings for detected toxic flow chains.

        Reports a finding for each unique combination of tools that form
        a complete toxic flow chain. To limit noise, reports at most one
        finding per input tool that has a path to exfiltration.
        """
        findings: list[ScanFinding] = []
        reported_inputs: set[str] = set()

        for input_tool in input_tools:
            # Skip if we already reported a flow starting from this tool
            input_key = f"{input_tool.server_name}:{input_tool.tool.name}"
            if input_key in reported_inputs:
                continue

            for sensitive_tool in sensitive_tools:
                for transmission_tool in transmission_tools:
                    # Build the chain description
                    chain = (
                        f"{input_tool.tool.name}({input_tool.server_name}) → "
                        f"{sensitive_tool.tool.name}({sensitive_tool.server_name}) → "
                        f"{transmission_tool.tool.name}({transmission_tool.server_name})"
                    )

                    # Format evidence as "tool_name: fragment" per Req 7.7
                    fragment = (
                        f"toxic flow chain: {input_tool.tool.name} → "
                        f"{sensitive_tool.tool.name} → {transmission_tool.tool.name}"
                    )
                    evidence = _truncate_evidence(input_tool.tool.name, fragment)

                    findings.append(
                        ScanFinding(
                            id="MCP-S3",
                            artifact_type=ArtifactType.MCP,
                            artifact_path="dynamic_scan",
                            severity_score=9,
                            severity_label=SeverityLabel.CRITICAL,
                            priority=Priority.P0,
                            gate_action=GateAction.BLOCK,
                            category=RiskCategory.SECURITY,
                            title="Toxic Flow Detected - Cross-Server Data Exfiltration Chain",
                            description=(
                                f"A toxic data flow chain was detected across MCP servers: {chain}. "
                                "An attacker could manipulate the AI agent to fetch external input, "
                                "access sensitive data, and exfiltrate it through this tool combination."
                            ),
                            location=FindingLocation(
                                line=0,
                                section=f"toxic_flow:{input_tool.server_name}",
                            ),
                            evidence=evidence,
                            confidence=0.85,
                            scanner_module=ScannerModule.DYNAMIC_SCAN,
                            remediation=(
                                "Review tool combinations across servers. Restrict tool access "
                                "permissions. Implement data flow monitoring to detect and block "
                                "exfiltration chains. Consider isolating sensitive data tools from "
                                "tools that can transmit data externally."
                            ),
                        )
                    )

                    reported_inputs.add(input_key)
                    # Break after first complete chain per input tool
                    break
                else:
                    continue
                break

        return findings
