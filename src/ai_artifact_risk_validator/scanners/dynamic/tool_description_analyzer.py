"""Tool description analyzer for dynamic MCP server scanning.

Analyzes tool metadata retrieved from live MCP servers to detect:
- Prompt injection: hidden instructions (excessive whitespace, zero-width Unicode),
  credential exfiltration directives
- Tool poisoning: descriptions instructing agent to perform unrelated actions
- Tool shadowing: tool names matching built-in tool names
- Dangerous input schema parameters: string parameters with risky keywords
- Sensitive file references: descriptions mentioning secrets/credentials paths

Implements Requirements 5.4, 5.5, 5.6, 6.1, 6.2.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

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

# Default built-in tool names registry (minimum 10)
DEFAULT_BUILTIN_TOOL_NAMES: list[str] = [
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

# --- Risk metadata for dynamic tool analysis findings ---

_RISK_METADATA: dict[str, dict[str, Any]] = {
    "MCP-S3": {
        "title": "Credential Theft via Tool Descriptions",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "MCP tool description contains prompt injection patterns that could "
            "trick AI agents into leaking credentials or performing unauthorized actions."
        ),
        "remediation": (
            "Review and sanitize tool descriptions. Remove hidden instructions, "
            "excessive whitespace, zero-width characters, and credential references."
        ),
    },
    "MCP-S1": {
        "title": "Dangerous Input Schema Parameter",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "MCP tool input schema accepts parameters that could enable "
            "code execution, path traversal, or SSRF attacks."
        ),
        "remediation": (
            "Restrict input parameter types. Add validation constraints to schemas. "
            "Avoid accepting raw file paths, URLs, or shell commands as string parameters."
        ),
    },
}

# --- Detection patterns ---

# Zero-width Unicode characters (categories Cf and Mn)
_ZERO_WIDTH_CHARS: set[str] = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
}

# Regex for excessive whitespace (>20 spaces or >5 newlines)
_RE_EXCESSIVE_SPACES = re.compile(r" {21,}")
_RE_EXCESSIVE_NEWLINES = re.compile(r"\n{6,}")

# Credential exfiltration keywords
_CREDENTIAL_KEYWORDS = re.compile(
    r"\b(api[_\s-]?key|token|password|secret|credential|auth[_\s-]?key|"
    r"private[_\s-]?key|access[_\s-]?key|session[_\s-]?id)\b",
    re.IGNORECASE,
)
_EXFILTRATION_ACTIONS = re.compile(
    r"\b(send|transmit|exfiltrate|upload|post|forward|relay|"
    r"transfer|leak|expose|emit|dispatch)\b",
    re.IGNORECASE,
)

# Tool poisoning: actions unrelated to tool purpose
_POISONING_KEYWORDS = re.compile(
    r"\b(read\s+file|download|send\s+to|modify|delete|execute|run\s+command|"
    r"write\s+to|access\s+file|make\s+request|http\s+request|"
    r"open\s+url|fetch\s+url|connect\s+to|curl|wget)\b",
    re.IGNORECASE,
)

# Dangerous input schema parameter keywords
# Use lookahead/lookbehind for underscore boundaries as well as \b
_DANGEROUS_PARAM_KEYWORDS = re.compile(
    r"(?:^|(?<=_)|\b)(path|file|url|command|exec|script|code|shell)(?:$|(?=_)|\b)",
    re.IGNORECASE,
)

# Sensitive file references in descriptions
_SENSITIVE_FILE_PATTERNS = re.compile(
    r"(~/.ssh/|\.env\b|credentials|secret|token|password|"
    r"/etc/shadow|/etc/passwd)",
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


def _contains_zero_width_chars(text: str) -> tuple[bool, str]:
    """Check for zero-width Unicode characters (Cf and Mn categories).

    Returns:
        Tuple of (found, fragment) where fragment is a description of what was found.
    """
    for i, char in enumerate(text):
        if char in _ZERO_WIDTH_CHARS:
            return True, f"zero-width char U+{ord(char):04X} at position {i}"
        # Also check for combining marks (category Mn)
        if unicodedata.category(char) == "Mn":
            return True, f"combining mark U+{ord(char):04X} at position {i}"
    return False, ""


class ToolDescriptionAnalyzer:
    """Analyzes MCP tool descriptions for security risks.

    Checks for prompt injection, tool poisoning, tool shadowing,
    dangerous input schemas, and sensitive file references.
    """

    def analyze(
        self,
        tools: list[MCPToolInfo],
        builtin_names: list[str] | None = None,
    ) -> list[ScanFinding]:
        """Analyze a list of MCP tools for description-based security risks.

        Args:
            tools: List of MCPToolInfo objects discovered from a live MCP server.
            builtin_names: Optional list of built-in tool names to check for shadowing.
                Defaults to DEFAULT_BUILTIN_TOOL_NAMES if not provided.

        Returns:
            List of ScanFinding objects for detected risks.
        """
        if builtin_names is None:
            builtin_names = DEFAULT_BUILTIN_TOOL_NAMES

        findings: list[ScanFinding] = []

        for tool in tools:
            findings.extend(self._check_prompt_injection(tool))
            findings.extend(self._check_tool_poisoning(tool))
            findings.extend(self._check_tool_shadowing(tool, builtin_names))
            findings.extend(self._check_dangerous_input_schema(tool))
            findings.extend(self._check_sensitive_file_references(tool))

        return findings

    def _check_prompt_injection(self, tool: MCPToolInfo) -> list[ScanFinding]:
        """Check tool description for prompt injection patterns.

        Detects:
        - Hidden instructions after excessive whitespace (>20 spaces or >5 newlines)
        - Zero-width Unicode characters (Cf/Mn categories)
        - Credential exfiltration directives
        """
        findings: list[ScanFinding] = []
        description = tool.description

        if not description:
            return findings

        # Check for excessive whitespace hiding instructions
        if _RE_EXCESSIVE_SPACES.search(description):
            fragment = "hidden text after excessive whitespace"
            findings.append(
                self._create_finding(
                    risk_id="MCP-S3",
                    tool_name=tool.name,
                    fragment=fragment,
                    confidence=0.90,
                    title_suffix="Prompt Injection - Hidden Instructions",
                )
            )

        if _RE_EXCESSIVE_NEWLINES.search(description):
            fragment = "hidden text after excessive newlines"
            findings.append(
                self._create_finding(
                    risk_id="MCP-S3",
                    tool_name=tool.name,
                    fragment=fragment,
                    confidence=0.90,
                    title_suffix="Prompt Injection - Hidden Instructions",
                )
            )

        # Check for zero-width Unicode characters
        found_zw, zw_fragment = _contains_zero_width_chars(description)
        if found_zw:
            findings.append(
                self._create_finding(
                    risk_id="MCP-S3",
                    tool_name=tool.name,
                    fragment=zw_fragment,
                    confidence=0.90,
                    title_suffix="Prompt Injection - Zero-Width Characters",
                )
            )

        # Check for credential exfiltration directives
        has_creds = _CREDENTIAL_KEYWORDS.search(description)
        has_exfil = _EXFILTRATION_ACTIONS.search(description)
        if has_creds and has_exfil:
            cred_match = has_creds.group(0)
            exfil_match = has_exfil.group(0)
            fragment = f"credential exfiltration: '{cred_match}' + '{exfil_match}'"
            findings.append(
                self._create_finding(
                    risk_id="MCP-S3",
                    tool_name=tool.name,
                    fragment=fragment,
                    confidence=0.95,
                    title_suffix="Prompt Injection - Credential Exfiltration",
                )
            )

        return findings

    def _check_tool_poisoning(self, tool: MCPToolInfo) -> list[ScanFinding]:
        """Check tool description for poisoning patterns.

        Detects descriptions that instruct agent to perform actions
        unrelated to the tool's stated purpose (access files, make
        network requests, modify system state).
        """
        findings: list[ScanFinding] = []
        description = tool.description

        if not description:
            return findings

        matches = _POISONING_KEYWORDS.findall(description)
        if matches:
            # Check if the keyword is plausibly related to the tool name
            # (e.g., "read file" in a tool named "file_reader" is expected)
            tool_name_lower = tool.name.lower()
            unrelated_matches = []
            for match in matches:
                match_lower = match.lower()
                # If the tool name contains words from the match, consider it related
                match_words = match_lower.split()
                is_related = any(word in tool_name_lower for word in match_words)
                if not is_related:
                    unrelated_matches.append(match)

            if unrelated_matches:
                fragment = f"poisoning: '{unrelated_matches[0]}' unrelated to tool purpose"
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S3",
                        tool_name=tool.name,
                        fragment=fragment,
                        confidence=0.85,
                        title_suffix="Tool Poisoning - Unrelated Instructions",
                    )
                )

        return findings

    def _check_tool_shadowing(
        self, tool: MCPToolInfo, builtin_names: list[str]
    ) -> list[ScanFinding]:
        """Check if tool name shadows a built-in tool name.

        Compares tool name against the registry of built-in tool names.
        """
        if tool.name in builtin_names:
            fragment = f"shadows built-in tool '{tool.name}'"
            return [
                self._create_finding(
                    risk_id="MCP-S3",
                    tool_name=tool.name,
                    fragment=fragment,
                    confidence=0.95,
                    title_suffix="Tool Shadowing - Built-in Name Conflict",
                )
            ]
        return []

    def _check_dangerous_input_schema(self, tool: MCPToolInfo) -> list[ScanFinding]:
        """Check tool input schema for dangerous parameter patterns.

        Flags parameters with type "string" whose name or description contains
        keywords: path, file, url, command, exec, script, code, shell.
        """
        findings: list[ScanFinding] = []
        schema = tool.input_schema

        if not schema:
            return findings

        properties = schema.get("properties", {})
        if not properties:
            return findings

        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue

            param_type = param_def.get("type", "")
            if param_type != "string":
                continue

            # Check parameter name for dangerous keywords
            name_match = _DANGEROUS_PARAM_KEYWORDS.search(param_name)
            if name_match:
                fragment = f"dangerous param '{param_name}' (type: string)"
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        tool_name=tool.name,
                        fragment=fragment,
                        confidence=0.80,
                        title_suffix="Dangerous Input Schema Parameter",
                    )
                )
                continue

            # Check parameter description for dangerous keywords
            param_desc = param_def.get("description", "")
            if param_desc:
                desc_match = _DANGEROUS_PARAM_KEYWORDS.search(param_desc)
                if desc_match:
                    keyword = desc_match.group(0)
                    fragment = f"dangerous param '{param_name}' (desc contains '{keyword}')"
                    findings.append(
                        self._create_finding(
                            risk_id="MCP-S1",
                            tool_name=tool.name,
                            fragment=fragment,
                            confidence=0.80,
                            title_suffix="Dangerous Input Schema Parameter",
                        )
                    )

        return findings

    def _check_sensitive_file_references(self, tool: MCPToolInfo) -> list[ScanFinding]:
        """Check tool description for sensitive file references.

        Detects descriptions mentioning ~/.ssh/*, .env, *credentials*,
        *secret*, *token*, *password*, /etc/shadow, /etc/passwd.
        """
        findings: list[ScanFinding] = []
        description = tool.description

        if not description:
            return findings

        matches = _SENSITIVE_FILE_PATTERNS.finditer(description)
        seen_fragments: set[str] = set()

        for match in matches:
            fragment_text = match.group(0)
            if fragment_text.lower() in seen_fragments:
                continue
            seen_fragments.add(fragment_text.lower())

            fragment = f"sensitive file ref: '{fragment_text}'"
            findings.append(
                self._create_finding(
                    risk_id="MCP-S3",
                    tool_name=tool.name,
                    fragment=fragment,
                    confidence=0.85,
                    title_suffix="Sensitive File Reference in Description",
                )
            )

        return findings

    def _create_finding(
        self,
        risk_id: str,
        tool_name: str,
        fragment: str,
        confidence: float,
        title_suffix: str,
    ) -> ScanFinding:
        """Create a ScanFinding with consistent formatting.

        Evidence is formatted as 'tool_name: fragment' per Req 7.7.
        """
        metadata = _RISK_METADATA.get(risk_id, _RISK_METADATA["MCP-S3"])
        evidence = _truncate_evidence(tool_name, fragment)

        return ScanFinding(
            id=risk_id,
            artifact_type=ArtifactType.MCP,
            artifact_path="dynamic_scan",
            severity_score=metadata["severity_score"],
            severity_label=metadata["severity_label"],
            priority=metadata["priority"],
            gate_action=metadata["gate_action"],
            category=metadata["category"],
            title=f"{metadata['title']} - {title_suffix}",
            description=metadata["description"],
            location=FindingLocation(line=0, section=f"tool:{tool_name}"),
            evidence=evidence,
            confidence=confidence,
            scanner_module=ScannerModule.DYNAMIC_SCAN,
            remediation=metadata["remediation"],
        )
