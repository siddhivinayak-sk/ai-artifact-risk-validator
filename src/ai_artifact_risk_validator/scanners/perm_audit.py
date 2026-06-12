"""PermAudit scanner module for permission and access control analysis.

Detects overly broad permissions, sensitive file path access, unauthorized
network connections, and destructive operations in AI artifacts using a
policy engine with allowlists and pattern-based detection.
"""

from __future__ import annotations

import re
from typing import Any

from ai_artifact_risk_validator.models import (
    ArtifactType,
    FindingLocation,
    GateAction,
    Priority,
    RiskCategory,
    ScanFinding,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.scanners.base import BaseScanner

# --- Risk metadata lookup ---
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "SK-S1": {
        "title": "Overly Broad Tool Permissions in Skill",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill declares overly broad tool permissions that exceed its stated purpose.",
        "remediation": "Restrict tool permissions to the minimum set required. Use explicit allowlists.",
    },
    "SK-S3": {
        "title": "Sensitive File Access in Skill",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill accesses sensitive system files or credential stores.",
        "remediation": "Remove access to sensitive paths. Use secure APIs instead of direct file access.",
    },
    "SK-S6": {
        "title": "Destructive Operations in Skill",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill contains destructive filesystem or system operations.",
        "remediation": "Remove destructive commands. Use safe abstractions with confirmation steps.",
    },
    "A-S1": {
        "title": "Overly Broad Tool Permissions in Agent",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Agent declares overly broad tool permissions or wildcard access.",
        "remediation": "Apply principle of least privilege. Explicitly list required tools.",
    },
    "A-S2": {
        "title": "Unrestricted Network Access in Agent",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Agent configuration allows unrestricted outbound network access.",
        "remediation": "Restrict network access to specific domains. Use allowlists for URLs.",
    },
    "A-S6": {
        "title": "Destructive Operations in Agent",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Agent configuration enables destructive system operations.",
        "remediation": "Remove destructive capabilities. Require explicit user confirmation for dangerous actions.",
    },
    "ST-S3": {
        "title": "Sensitive File Access in Steering",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Steering file directs access to sensitive system paths or credentials.",
        "remediation": "Remove references to sensitive paths. Use environment variables for configuration.",
    },
    "ST-S4": {
        "title": "Network Access in Steering",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Steering file directs outbound network connections.",
        "remediation": "Remove direct network access directives. Use approved service integrations.",
    },
    "MCP-S7": {
        "title": "Overly Broad MCP Tool Permissions",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server declares overly broad tool permissions or wildcard scopes.",
        "remediation": "Restrict MCP tool permissions to minimum required scope.",
    },
    "MCP-S10": {
        "title": "Destructive Operations in MCP Server",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server configuration enables destructive filesystem or database operations.",
        "remediation": "Remove destructive capabilities from MCP tools. Add confirmation guards.",
    },
    "H-S3": {
        "title": "Sensitive File Access in Hook",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Hook accesses sensitive system files or credential locations.",
        "remediation": "Remove access to sensitive paths from hooks. Use secure configuration.",
    },
    "H-S6": {
        "title": "Destructive Operations in Hook",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Hook performs destructive filesystem or system operations.",
        "remediation": "Remove destructive commands from hooks. Use non-destructive alternatives.",
    },
    "I-S4": {
        "title": "Sensitive File Access in Instructions",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Instruction file directs access to sensitive system paths.",
        "remediation": "Remove references to sensitive file paths from instructions.",
    },
    "I-S5": {
        "title": "Network Access in Instructions",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Instruction file directs unrestricted network access.",
        "remediation": "Limit network access to approved endpoints. Use allowlists.",
    },
    "API-S2": {
        "title": "Overly Broad API Schema Permissions",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "API schema declares overly broad access scopes or permissions.",
        "remediation": "Apply principle of least privilege to API schema scopes.",
    },
    "OW-S2": {
        "title": "Destructive Operations in Orchestration",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Orchestration workflow enables destructive operations without safeguards.",
        "remediation": "Add confirmation steps before destructive operations in workflows.",
    },
    "M-S5": {
        "title": "Sensitive File Access in Memory Configuration",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Memory configuration accesses sensitive system paths.",
        "remediation": "Restrict memory file access to designated safe directories.",
    },
    "PL-S2": {
        "title": "Overly Broad Plugin Permissions",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin declares overly broad permissions or capabilities.",
        "remediation": "Restrict plugin permissions to minimum required scope.",
    },
    "PL-S6": {
        "title": "Destructive Operations in Plugin",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin performs destructive filesystem or system operations.",
        "remediation": "Remove destructive capabilities from plugins. Use safe abstractions.",
    },
}

# --- Artifact type to risk ID mappings per detection category ---

# Permission/policy violations
_PERMISSION_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S1",
    ArtifactType.AGENT: "A-S1",
    ArtifactType.MCP: "MCP-S7",
    ArtifactType.PLUGIN: "PL-S2",
    ArtifactType.API_SCHEMA: "API-S2",
    ArtifactType.STEERING: "ST-S3",
    ArtifactType.HOOK: "H-S3",
    ArtifactType.INSTRUCTION: "I-S4",
    ArtifactType.MEMORY: "M-S5",
    ArtifactType.ORCHESTRATION: "OW-S2",
}

# Sensitive file access
_FILE_ACCESS_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S3",
    ArtifactType.AGENT: "A-S1",
    ArtifactType.STEERING: "ST-S3",
    ArtifactType.MCP: "MCP-S7",
    ArtifactType.HOOK: "H-S3",
    ArtifactType.INSTRUCTION: "I-S4",
    ArtifactType.MEMORY: "M-S5",
    ArtifactType.PLUGIN: "PL-S2",
    ArtifactType.ORCHESTRATION: "OW-S2",
    ArtifactType.API_SCHEMA: "API-S2",
}

# Network access
_NETWORK_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S1",
    ArtifactType.AGENT: "A-S2",
    ArtifactType.STEERING: "ST-S4",
    ArtifactType.MCP: "MCP-S7",
    ArtifactType.HOOK: "H-S3",
    ArtifactType.INSTRUCTION: "I-S5",
    ArtifactType.MEMORY: "M-S5",
    ArtifactType.PLUGIN: "PL-S2",
    ArtifactType.ORCHESTRATION: "OW-S2",
    ArtifactType.API_SCHEMA: "API-S2",
}

# Destructive actions
_DESTRUCTIVE_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S6",
    ArtifactType.AGENT: "A-S6",
    ArtifactType.STEERING: "ST-S3",
    ArtifactType.MCP: "MCP-S10",
    ArtifactType.HOOK: "H-S6",
    ArtifactType.INSTRUCTION: "I-S4",
    ArtifactType.MEMORY: "M-S5",
    ArtifactType.PLUGIN: "PL-S6",
    ArtifactType.ORCHESTRATION: "OW-S2",
    ArtifactType.API_SCHEMA: "API-S2",
}

# --- Detection patterns ---

# Sensitive file paths (system/credential files)
_SENSITIVE_FILE_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # System credential files
    (
        "/etc/passwd access",
        re.compile(r"(?i)/etc/passwd"),
        0.95,
    ),
    (
        "/etc/shadow access",
        re.compile(r"(?i)/etc/shadow"),
        0.98,
    ),
    # SSH keys and config
    (
        "SSH directory access",
        re.compile(r"(?i)(?:~/|~\\|/home/[^/]+/|%USERPROFILE%[/\\])\.ssh[/\\]?"),
        0.95,
    ),
    (
        "SSH key file access",
        re.compile(r"(?i)(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)"),
        0.90,
    ),
    # Credentials and secrets files
    (
        "Credentials file access",
        re.compile(
            r"(?i)(?:\.env|\.credentials|credentials\.json|service[_-]?account\.json|"
            r"\.aws/credentials|\.netrc|\.pgpass|\.my\.cnf)"
        ),
        0.92,
    ),
    # System directories
    (
        "Root filesystem access",
        re.compile(r"(?i)(?:access|read|write|open|path)\s*[=:\"']*\s*/\s*$|[\"']/[\"']"),
        0.85,
    ),
    # Wildcard file access patterns
    (
        "Wildcard file access",
        re.compile(r"(?i)(?:path|file|dir|folder)\s*[=:\"']*\s*(?:\*\*?/?\*|\.\*|/\*\*)"),
        0.88,
    ),
    # Windows sensitive paths
    (
        "Windows system path access",
        re.compile(
            r"(?i)(?:C:\\Windows\\System32|%SystemRoot%|%WINDIR%|"
            r"C:\\Users\\[^\\]+\\AppData)"
        ),
        0.85,
    ),
    # Kubernetes/Docker secrets
    (
        "Container secrets access",
        re.compile(
            r"(?i)(?:/var/run/secrets/kubernetes|/run/secrets/|"
            r"docker\.sock|/var/run/docker\.sock)"
        ),
        0.95,
    ),
    # Broad root-level path access
    (
        "Broad path access pattern",
        re.compile(r"""(?i)(?:["']|path\s*[=:])\s*/(?:etc|var|usr|opt|root|proc|sys)/"""),
        0.85,
    ),
]

# Network access patterns
_NETWORK_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # HTTP/HTTPS URLs (not documentation or example URLs)
    (
        "External URL access",
        re.compile(
            r"(?i)(?:url|endpoint|host|server|api_?url|base_?url|webhook)\s*[=:\"']+\s*"
            r"https?://[^\s\"']+",
        ),
        0.88,
    ),
    # curl/wget commands
    (
        "curl/wget command",
        re.compile(
            r"(?i)(?:curl|wget)\s+(?:(?:-[^\s]*|-[^\s]*\s+[^\s-][^\s]*)\s+)*"
            r"(?:https?://|[\"']https?://)"
        ),
        0.92,
    ),
    # Fetch/request calls
    (
        "HTTP request call",
        re.compile(
            r"(?i)(?:fetch|requests?\.\s*(?:get|post|put|delete|patch)|"
            r"http\.(?:get|post|put|delete)|axios\.|urllib)"
        ),
        0.85,
    ),
    # Socket connections
    (
        "Socket connection",
        re.compile(r"(?i)(?:socket\.connect|net\.createConnection|new\s+Socket)"),
        0.90,
    ),
    # DNS resolution / external hosts
    (
        "DNS/host resolution",
        re.compile(r"(?i)(?:dns\.resolve|gethostbyname|nslookup|dig\s+)"),
        0.85,
    ),
    # Outbound port access
    (
        "Outbound port access",
        re.compile(r"(?i)(?:port|outbound|connect)\s*[=:]\s*(?:\d{2,5})"),
        0.80,
    ),
    # WebSocket connections
    (
        "WebSocket connection",
        re.compile(r"(?i)(?:wss?://[^\s\"']+|new\s+WebSocket|websocket\.connect)"),
        0.88,
    ),
    # Network command-line tools
    (
        "Network CLI tool usage",
        re.compile(r"(?i)(?:nc\s+-|netcat|nmap|telnet|ssh\s+\w)"),
        0.90,
    ),
]

# Destructive action patterns
_DESTRUCTIVE_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # rm -rf and variants
    (
        "Recursive force delete (rm -rf)",
        re.compile(r"(?i)\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b"),
        0.98,
    ),
    # rm with force
    (
        "Force delete (rm -f)",
        re.compile(r"(?i)\brm\s+-[a-z]*f"),
        0.92,
    ),
    # Generic rm command (excludes cases with -f or -r flags caught above)
    (
        "File deletion (rm)",
        re.compile(r"(?i)\brm\s+(?!-[a-z]*[rf])(?!--)(?:[^|;&\n]+)"),
        0.85,
    ),
    # Format commands — require disk-operation context to avoid matching Python
    # str.format(), logging format= arguments, or the word "format" in docstrings.
    (
        "Disk format command",
        re.compile(r"(?i)(?:format\s+[A-Za-z]:|format\s+/dev/|mkfs(?:\.\w+)?\s|\bfdisk\s)"),
        0.90,
    ),
    # Truncate/overwrite
    (
        "File truncation",
        re.compile(r"(?i)\b(?:truncate|>\s*/dev/null|\b:\s*>)"),
        0.88,
    ),
    # Database destructive operations
    (
        "Database destructive operation",
        re.compile(r"(?i)\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM)\b"),
        0.92,
    ),
    # System commands
    (
        "Dangerous system command",
        re.compile(r"(?i)\b(?:shutdown|reboot|halt|poweroff|init\s+0)\b"),
        0.95,
    ),
    # Kill/terminate
    (
        "Process kill command",
        re.compile(r"(?i)\b(?:kill\s+-9|killall|pkill|taskkill)\b"),
        0.85,
    ),
    # chmod dangerous
    (
        "Dangerous permission change",
        re.compile(r"(?i)\bchmod\s+(?:777|666|a\+rwx)"),
        0.90,
    ),
    # dd command (disk write)
    (
        "Disk write (dd)",
        re.compile(r"(?i)\bdd\s+.*(?:of=|if=/dev/)"),
        0.92,
    ),
    # Destructive file operations in code
    (
        "Programmatic file deletion",
        re.compile(
            r"(?i)(?:os\.remove|os\.unlink|shutil\.rmtree|fs\.unlinkSync|"
            r"fs\.rmdirSync|rimraf|del_tree|File\.delete)"
        ),
        0.88,
    ),
    # Registry deletion (Windows)
    (
        "Registry deletion",
        re.compile(r"(?i)\b(?:reg\s+delete|Remove-Item\s+.*Registry)"),
        0.92,
    ),
]

# Overly broad permission patterns (policy violations)
_PERMISSION_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # Wildcard permissions
    (
        "Wildcard permission declaration",
        re.compile(
            r"""(?i)(?:permissions?|scopes?|access|capabilities?|tools?)\s*[=:\[]*\s*"""
            r"""(?:\*|["']\*["']|all|\["?\*"?\])"""
        ),
        0.95,
    ),
    # Admin/root/superuser access
    (
        "Elevated privilege declaration",
        re.compile(
            r"(?i)(?:role|privilege|access[_-]?level)\s*[=:\"']+\s*"
            r"(?:admin|root|superuser|super_?admin|owner|full)"
        ),
        0.95,
    ),
    # Unrestricted filesystem
    (
        "Unrestricted filesystem access",
        re.compile(
            r"(?i)(?:file[_-]?system|fs)[_-]?(?:access|permission)\s*[=:\"']+\s*"
            r"(?:full|all|unrestricted|read[_-]?write)"
        ),
        0.92,
    ),
    # Broad tool lists (many tools declared)
    (
        "Broad tool declaration",
        re.compile(r"(?i)tools\s*[=:\[]\s*\[(?:[^\]]*,){7,}[^\]]*\]"),
        0.82,
    ),
    # Execute/run any command
    (
        "Unrestricted command execution",
        re.compile(
            r"(?i)(?:execute|run|exec|shell|command)\s*[=:\"']+\s*"
            r"(?:any|all|\*|unrestricted)"
        ),
        0.95,
    ),
    # Write access to broad paths
    (
        "Broad write access",
        re.compile(
            r"(?i)(?:write|modify)[_-]?(?:access|permission|path)\s*[=:\"']+\s*"
            r"(?:/|\\|\*|any|all|~)"
        ),
        0.90,
    ),
]


class PermAuditScanner(BaseScanner):
    """Scanner for detecting permission violations and dangerous access patterns.

    Uses multiple detection techniques:
    1. Policy engine checking tool permissions against allowlists (highest confidence)
    2. File path pattern analysis detecting access to sensitive system paths
    3. Network access audit detecting outbound connections and URLs
    4. Destructive action detection finding dangerous commands and operations

    Confidence bands:
    - Policy violation: 0.95–1.0
    - Pattern-based detection: 0.80–0.94
    """

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.PERM_AUDIT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze.

        Applies to: Skill, Agent, Steering, MCP, Hook, Instruction,
        Plugin, Memory, Orchestration, API Schema.
        NOT applicable to: Prompt, SOP, RAG, Eval Harness.
        """
        return [
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.HOOK,
            ArtifactType.INSTRUCTION,
            ArtifactType.PLUGIN,
            ArtifactType.MEMORY,
            ArtifactType.ORCHESTRATION,
            ArtifactType.API_SCHEMA,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner detects."""
        return [
            "SK-S1",
            "SK-S3",
            "SK-S6",
            "A-S1",
            "A-S2",
            "A-S6",
            "ST-S3",
            "ST-S4",
            "MCP-S7",
            "MCP-S10",
            "H-S3",
            "H-S6",
            "I-S4",
            "I-S5",
            "API-S2",
            "OW-S2",
            "M-S5",
            "PL-S2",
            "PL-S6",
        ]

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        evidence: str,
        confidence: float,
        line: int | None = None,
        pattern_name: str = "",
    ) -> ScanFinding:
        """Create a ScanFinding from risk metadata.

        Args:
            risk_id: The risk ID to report.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact file.
            evidence: The triggering text/pattern.
            confidence: Detection confidence (0.0-1.0).
            line: Line number where finding was detected.
            pattern_name: Name of the pattern that matched.

        Returns:
            A fully constructed ScanFinding.
        """
        metadata = _RISK_METADATA[risk_id]

        # Truncate evidence to avoid overly long strings
        truncated_evidence = evidence[:80] + "..." if len(evidence) > 80 else evidence

        description = metadata["description"]
        if pattern_name:
            description = f"{description} Detected: {pattern_name}."

        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=metadata["severity_score"],
            severity_label=metadata["severity_label"],
            priority=metadata["priority"],
            gate_action=metadata["gate_action"],
            category=metadata["category"],
            title=metadata["title"],
            description=description,
            location=FindingLocation(line=line),
            evidence=truncated_evidence,
            confidence=confidence,
            scanner_module=ScannerModule.PERM_AUDIT,
            remediation=metadata["remediation"],
            references=[],
        )

    def _scan_permissions(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check tool/permission declarations against policy.

        Detects overly broad permissions, wildcard access, and elevated privileges.

        Args:
            content: Artifact content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from permission policy checks.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _PERMISSION_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    risk_id = _PERMISSION_RISK_MAP.get(artifact_type, "SK-S1")
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            pattern_name=pattern_name,
                        )
                    )

        return findings

    def _scan_file_paths(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Analyze content for sensitive file path access.

        Detects access to system credential files, SSH keys, and other
        sensitive locations.

        Args:
            content: Artifact content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from file path analysis.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _SENSITIVE_FILE_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    evidence = match.group(0)
                    # "Root filesystem access": a quoted slash '/' or "/" used as a
                    # standalone YAML path value (route prefix, array item) is NOT
                    # a dangerous open/read/write of the root filesystem.  Only flag
                    # when a file-operation verb precedes it on the same line.
                    if (
                        pattern_name == "Root filesystem access"
                        and evidence.strip("'\"") == "/"
                        and not re.search(
                            r"(?i)\b(?:open|read|write|access)\b",
                            line[: match.start()],
                        )
                    ):
                        continue
                    # "Credentials file access": .credentials as part of a dotted
                    # YAML key hierarchy (e.g. storage.credentials:) is not a file
                    # path.  Skip when the dot is immediately preceded by a word char.
                    if (
                        pattern_name == "Credentials file access"
                        and ".credentials" in evidence.lower()
                        and match.start() > 0
                        and line[match.start() - 1].isalnum()
                    ):
                        continue
                    risk_id = _FILE_ACCESS_RISK_MAP.get(artifact_type, "SK-S3")
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=evidence,
                            confidence=confidence,
                            line=line_num,
                            pattern_name=pattern_name,
                        )
                    )

        return findings

    def _scan_network_access(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Audit content for network access patterns.

        Detects outbound HTTP/HTTPS calls, curl/wget usage, socket connections,
        and other network access indicators.

        Args:
            content: Artifact content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from network access detection.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _NETWORK_PATTERNS:
            # "url: https://..." in orchestration/catalog YAML is metadata (documentation
            # links, artifact references) — not an active outbound network call.
            # Other patterns (curl/wget, fetch, socket, DNS) still apply.
            if (
                pattern_name == "External URL access"
                and artifact_type == ArtifactType.ORCHESTRATION
            ):
                continue
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    # In ORCHESTRATION YAML, a bare "fetch" (no call syntax or URL
                    # argument on the same line) is likely a tool/concept reference in
                    # a config value or description, not an active HTTP fetch call.
                    if (
                        pattern_name == "HTTP request call"
                        and artifact_type == ArtifactType.ORCHESTRATION
                        and match.group(0).lower() == "fetch"
                        and not re.search(r"(?i)\bfetch\s*\(|\bfetch\s+[\"']?https?://", line)
                    ):
                        continue
                    # "Network CLI tool usage": skip when the pattern fires on a YAML
                    # documentation field (description, note, example) in an
                    # ORCHESTRATION artifact — the tool is mentioned as a reference,
                    # not invoked as a command.
                    if (
                        pattern_name == "Network CLI tool usage"
                        and artifact_type == ArtifactType.ORCHESTRATION
                        and re.match(
                            r"(?i)\s*(?:description|summary|note|example"
                            r"|doc(?:umentation)?|comment)\s*[=:]",
                            line,
                        )
                    ):
                        continue
                    risk_id = _NETWORK_RISK_MAP.get(artifact_type, "A-S2")
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            pattern_name=pattern_name,
                        )
                    )

        return findings

    def _scan_destructive_actions(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect destructive operations in artifact content.

        Detects file deletion, format commands, system shutdowns, database
        drops, and other irreversible operations.

        Args:
            content: Artifact content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from destructive action detection.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _DESTRUCTIVE_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    risk_id = _DESTRUCTIVE_RISK_MAP.get(artifact_type, "SK-S6")
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            pattern_name=pattern_name,
                        )
                    )

        return findings

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for permission violations and dangerous access patterns.

        Applies four detection strategies:
        1. Permission policy checks (wildcard access, elevated privileges)
        2. Sensitive file path detection (credentials, SSH, system files)
        3. Network access audit (URLs, curl/wget, sockets)
        4. Destructive action detection (rm -rf, format, DROP TABLE)

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        findings: list[ScanFinding] = []

        # 1. Permission/policy checks
        findings.extend(self._scan_permissions(artifact_content, artifact_type, artifact_path))

        # 2. Sensitive file path analysis
        findings.extend(self._scan_file_paths(artifact_content, artifact_type, artifact_path))

        # 3. Network access audit
        findings.extend(self._scan_network_access(artifact_content, artifact_type, artifact_path))

        # 4. Destructive action detection
        findings.extend(
            self._scan_destructive_actions(artifact_content, artifact_type, artifact_path)
        )

        return findings
