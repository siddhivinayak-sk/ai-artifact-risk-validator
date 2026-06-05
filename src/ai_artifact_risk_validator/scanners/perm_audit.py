"""PermAudit scanner module for permission and access control analysis.

Implements a policy engine that checks tool permissions against allowlists,
analyzes file path patterns for dangerous access, audits network access
declarations, and detects destructive action patterns.
"""

import re

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

# ============================================================
# Pattern Definitions
# ============================================================

# Wildcard / overly permissive tool access patterns
_WILDCARD_PERMISSION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(tools|permissions|access)\s*[:=]\s*\[?\s*[\"']?\*[\"']?\s*\]?", re.IGNORECASE),
    re.compile(r"\ball[_\-\s]*(tools|access|permissions)\b", re.IGNORECASE),
    re.compile(r"\b(allow|grant|enable)\s*[:=]\s*\[?\s*[\"']?\*[\"']?\s*\]?", re.IGNORECASE),
    re.compile(r"\bpermissions?\s*[:=]\s*\[?\s*[\"']?all[\"']?\s*\]?", re.IGNORECASE),
    re.compile(r"\b(unrestricted|unlimited)\s+(access|permissions?|tools?)\b", re.IGNORECASE),
    re.compile(r"\btool_?types?\s*[:=]\s*\[?\s*[\"']?\*[\"']?\s*\]?", re.IGNORECASE),
]

# Dangerous file path patterns
_DANGEROUS_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(/etc/passwd|/etc/shadow|/etc/sudoers)", re.IGNORECASE), "/etc system files"),
    (re.compile(r"~?/?\.ssh(/|[\"'\s,\]})])", re.IGNORECASE), ".ssh directory"),
    (re.compile(r"(/etc/|\\etc\\)", re.IGNORECASE), "/etc directory"),
    (re.compile(r"(~/?\.aws|\.aws/credentials)", re.IGNORECASE), ".aws credentials"),
    (re.compile(r"(~/?\.gnupg|\.gnupg/)", re.IGNORECASE), ".gnupg directory"),
    (re.compile(r"(/var/log/|\\var\\log\\)", re.IGNORECASE), "/var/log directory"),
    (
        re.compile(r"(C:\\Windows\\System32|/usr/sbin|/usr/local/sbin)", re.IGNORECASE),
        "system binary directories",
    ),
    (re.compile(r"(/root/|C:\\Users\\Administrator)", re.IGNORECASE), "root/admin home"),
    (
        re.compile(r"\bpath\s*[:=]\s*[\"']?(/|\.\./\.\.|[A-Z]:\\)[\"']?", re.IGNORECASE),
        "root filesystem access",
    ),
    (
        re.compile(
            r"\b(read|write|access)\s+.{0,20}(entire|whole|full)\s+(file\s*system|disk|drive|filesystem)",
            re.IGNORECASE,
        ),
        "entire filesystem",
    ),
]

# Network access without restriction patterns
_UNRESTRICTED_NETWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(url|endpoint|host)\s*[:=]\s*[\"']?\*[\"']?", re.IGNORECASE), "wildcard URL"),
    (
        re.compile(r"\b(any|all)\s+(url|endpoint|host|domain|port)s?\b", re.IGNORECASE),
        "unrestricted network target",
    ),
    (
        re.compile(r"\bnetwork\s*[:=]\s*[\"']?(unrestricted|all|\*)[\"']?", re.IGNORECASE),
        "unrestricted network access",
    ),
    (
        re.compile(r"\b(allow|permit)\s+(any|all)\s+(outbound|inbound|network)", re.IGNORECASE),
        "permit all network",
    ),
    (re.compile(r"\bport\s*[:=]\s*[\"']?\*[\"']?", re.IGNORECASE), "wildcard port"),
    (re.compile(r"\b0\.0\.0\.0\b", re.IGNORECASE), "bind all interfaces"),
    (
        re.compile(
            r"\bno\s+(domain|url|network)\s+(restriction|filter|allowlist|whitelist)", re.IGNORECASE
        ),
        "no domain restrictions",
    ),
]

# Destructive action patterns
_DESTRUCTIVE_ACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(rm\s+-rf?|rmdir|del\s+/[sfq])", re.IGNORECASE), "recursive delete command"),
    (
        re.compile(r"\b(drop\s+(table|database|schema|index))\b", re.IGNORECASE),
        "SQL drop statement",
    ),
    (re.compile(r"\b(truncate\s+(table|log))\b", re.IGNORECASE), "SQL truncate statement"),
    (re.compile(r"\b(format\s+(disk|drive|volume|partition))\b", re.IGNORECASE), "disk format"),
    (
        re.compile(
            r"\b(delete|remove|destroy|wipe|purge)\s+(all|entire|\*|everything)", re.IGNORECASE
        ),
        "mass deletion",
    ),
    (re.compile(r"\b(shutdown|reboot|halt|poweroff)\b", re.IGNORECASE), "system shutdown/reboot"),
    (
        re.compile(r"\bgit\s+(push\s+--force|reset\s+--hard)", re.IGNORECASE),
        "destructive git operation",
    ),
    (re.compile(r"\bkill\s+(-9|--signal\s+KILL)", re.IGNORECASE), "force kill process"),
]

# Privilege escalation indicators
_PRIVILEGE_ESCALATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsudo\b", re.IGNORECASE), "sudo usage"),
    (
        re.compile(r"\b(run|execute)\s+as\s+(root|admin|administrator|SYSTEM)", re.IGNORECASE),
        "run as root/admin",
    ),
    (
        re.compile(
            r"\b(admin|root|superuser|administrator)\s+(access|privilege|permission|role)",
            re.IGNORECASE,
        ),
        "admin privilege",
    ),
    (re.compile(r"\bchmod\s+[0-7]*7[0-7]*\b", re.IGNORECASE), "world-writable permissions"),
    (re.compile(r"\bchown\s+root\b", re.IGNORECASE), "change owner to root"),
    (re.compile(r"\bsetuid\b", re.IGNORECASE), "setuid flag"),
    (re.compile(r"\bprivilege\s*escalat", re.IGNORECASE), "privilege escalation"),
    (
        re.compile(r"\belevat(e|ed|ion)\s+(privilege|permission|access)", re.IGNORECASE),
        "elevated privileges",
    ),
]

# Unrestricted shell/command execution patterns
_SHELL_EXECUTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(shell|bash|cmd|powershell)\s*[:=]\s*[\"']?(true|enabled|\*)[\"']?", re.IGNORECASE
        ),
        "shell access enabled",
    ),
    (
        re.compile(r"\bexecute\s+(any|arbitrary)\s+(command|shell|script)", re.IGNORECASE),
        "arbitrary command execution",
    ),
    (
        re.compile(r"\b(subprocess|os\.system|exec|eval)\b.*\b(user|input|param)", re.IGNORECASE),
        "unsafe command execution",
    ),
    (re.compile(r"\bcommand\s*[:=]\s*[\"']?\*[\"']?", re.IGNORECASE), "wildcard command"),
    (
        re.compile(
            r"\b(shell_access|command_execution)\s*[:=]\s*[\"']?(unrestricted|all|\*|true)[\"']?",
            re.IGNORECASE,
        ),
        "unrestricted shell",
    ),
    (
        re.compile(r"\ballow\s+(all|any)\s+(commands?|scripts?|executab)", re.IGNORECASE),
        "allow all commands",
    ),
]

# Missing auth patterns (for MCP-S10)
_MISSING_AUTH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(auth|authentication)\s*[:=]\s*[\"']?(none|false|disabled|off)[\"']?", re.IGNORECASE
        ),
        "auth disabled",
    ),
    (re.compile(r"\bno\s*auth", re.IGNORECASE), "no auth"),
    (re.compile(r"\btransport\s*[:=].*\b(http|ws)\b(?!s)", re.IGNORECASE), "unencrypted transport"),
    (re.compile(r"\b(public|open)\s*(access|endpoint|api)", re.IGNORECASE), "public access"),
]

# Security bypass patterns (for I-S5)
_SECURITY_BYPASS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(skip|disable|bypass|ignore)\s+(security|safety|validation|auth)", re.IGNORECASE
        ),
        "security bypass",
    ),
    (
        re.compile(r"\b(no|without)\s+(validation|verification|check|auth)", re.IGNORECASE),
        "no validation",
    ),
    (
        re.compile(
            r"\b(override|disable)\s+(guard|guardrail|safet|filter|restrict)", re.IGNORECASE
        ),
        "override guardrails",
    ),
]


# ============================================================
# Risk ID → Artifact Type Mapping
# ============================================================

_RISK_ARTIFACT_MAP: dict[str, list[ArtifactType]] = {
    "SK-S1": [ArtifactType.SKILL],
    "SK-S3": [ArtifactType.SKILL],
    "SK-S6": [ArtifactType.SKILL],
    "A-S1": [ArtifactType.AGENT],
    "A-S2": [ArtifactType.AGENT],
    "A-S6": [ArtifactType.AGENT],
    "ST-S3": [ArtifactType.STEERING],
    "ST-S4": [ArtifactType.STEERING],
    "MCP-S7": [ArtifactType.MCP],
    "MCP-S10": [ArtifactType.MCP],
    "H-S3": [ArtifactType.HOOK],
    "H-S6": [ArtifactType.HOOK],
    "I-S4": [ArtifactType.INSTRUCTION],
    "I-S5": [ArtifactType.INSTRUCTION],
    "API-S2": [ArtifactType.API_SCHEMA],
    "OW-S2": [ArtifactType.ORCHESTRATION],
    "M-S5": [ArtifactType.MEMORY],
    "PL-S2": [ArtifactType.PLUGIN],
    "PL-S6": [ArtifactType.PLUGIN],
}

# Risk metadata lookup: risk_id -> (title, severity_score, severity_label, priority, gate_action)
_RISK_METADATA: dict[str, tuple[str, int, SeverityLabel, Priority, GateAction]] = {
    "SK-S1": (
        "Excessive File System Permissions",
        8,
        SeverityLabel.HIGH,
        Priority.P0,
        GateAction.BLOCK,
    ),
    "SK-S3": ("Unrestricted Network Access", 7, SeverityLabel.HIGH, Priority.P1, GateAction.BLOCK),
    "SK-S6": (
        "Privilege Escalation via Skill Chaining",
        8,
        SeverityLabel.HIGH,
        Priority.P1,
        GateAction.BLOCK,
    ),
    "A-S1": ("Unrestricted Tool Access", 9, SeverityLabel.CRITICAL, Priority.P0, GateAction.BLOCK),
    "A-S2": (
        "Excessive Autonomous Action Scope",
        8,
        SeverityLabel.HIGH,
        Priority.P0,
        GateAction.BLOCK,
    ),
    "A-S6": ("Uncontrolled Resource Access", 7, SeverityLabel.HIGH, Priority.P1, GateAction.BLOCK),
    "ST-S3": (
        "Overly Permissive Scope Declaration",
        6,
        SeverityLabel.MEDIUM,
        Priority.P2,
        GateAction.WARN,
    ),
    "ST-S4": (
        "Unauthorized Capability Grant",
        7,
        SeverityLabel.HIGH,
        Priority.P1,
        GateAction.BLOCK,
    ),
    "MCP-S7": (
        "Excessive MCP Tool Permissions",
        7,
        SeverityLabel.HIGH,
        Priority.P1,
        GateAction.BLOCK,
    ),
    "MCP-S10": (
        "Missing Authentication on MCP Transport",
        7,
        SeverityLabel.HIGH,
        Priority.P1,
        GateAction.BLOCK,
    ),
    "H-S3": (
        "Overly Broad Event Trigger Scope",
        6,
        SeverityLabel.MEDIUM,
        Priority.P2,
        GateAction.WARN,
    ),
    "H-S6": (
        "Uncontrolled Network Access from Hook",
        7,
        SeverityLabel.HIGH,
        Priority.P1,
        GateAction.BLOCK,
    ),
    "I-S4": (
        "Excessive Permission Grants in Instructions",
        7,
        SeverityLabel.HIGH,
        Priority.P1,
        GateAction.BLOCK,
    ),
    "I-S5": (
        "Instructions Disabling Security Checks",
        8,
        SeverityLabel.HIGH,
        Priority.P0,
        GateAction.BLOCK,
    ),
    "API-S2": (
        "Overly Permissive API Schema",
        7,
        SeverityLabel.HIGH,
        Priority.P1,
        GateAction.BLOCK,
    ),
    "OW-S2": (
        "Excessive Orchestration Privileges",
        8,
        SeverityLabel.HIGH,
        Priority.P0,
        GateAction.BLOCK,
    ),
    "M-S5": (
        "Unauthorized Memory Access Permissions",
        6,
        SeverityLabel.MEDIUM,
        Priority.P2,
        GateAction.WARN,
    ),
    "PL-S2": ("Excessive Plugin Permissions", 7, SeverityLabel.HIGH, Priority.P1, GateAction.BLOCK),
    "PL-S6": ("Unverified Plugin Source", 6, SeverityLabel.MEDIUM, Priority.P2, GateAction.WARN),
}


class PermAuditScanner(BaseScanner):
    """Scanner for permission and access control policy violations.

    Detects overly permissive tool declarations, dangerous file path patterns,
    unrestricted network access, destructive action capabilities, and privilege
    escalation indicators across AI artifacts.

    Confidence bands:
        - Policy violation (exact match): 0.95–1.0
        - Pattern-based detection: 0.80–0.94
    """

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.PERM_AUDIT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
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
        """Risk IDs this scanner is capable of detecting."""
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

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for permission and access control issues.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects for detected permission issues.
        """
        findings: list[ScanFinding] = []

        findings.extend(
            self._check_wildcard_permissions(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(self._check_dangerous_paths(artifact_content, artifact_type, artifact_path))
        findings.extend(self._check_network_access(artifact_content, artifact_type, artifact_path))
        findings.extend(
            self._check_destructive_actions(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._check_privilege_escalation(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(self._check_shell_execution(artifact_content, artifact_type, artifact_path))
        findings.extend(self._check_missing_auth(artifact_content, artifact_type, artifact_path))
        findings.extend(self._check_security_bypass(artifact_content, artifact_type, artifact_path))

        return findings

    def _get_line_number(self, content: str, match_start: int) -> int:
        """Get 1-based line number from character offset."""
        return content[:match_start].count("\n") + 1

    def _select_risk_id(self, artifact_type: ArtifactType, category: str) -> str | None:
        """Select the appropriate risk ID based on artifact type and detection category.

        Args:
            artifact_type: The artifact type being scanned.
            category: The detection category (e.g., 'wildcard', 'path', 'network', 'destructive', 'escalation', 'shell', 'auth', 'bypass').

        Returns:
            The risk ID string, or None if no matching risk for this artifact type.
        """
        mapping: dict[ArtifactType, dict[str, str]] = {
            ArtifactType.SKILL: {
                "wildcard": "SK-S1",
                "path": "SK-S1",
                "network": "SK-S3",
                "destructive": "SK-S6",
                "escalation": "SK-S6",
                "shell": "SK-S1",
                "auth": "SK-S3",
                "bypass": "SK-S6",
            },
            ArtifactType.AGENT: {
                "wildcard": "A-S1",
                "path": "A-S6",
                "network": "A-S6",
                "destructive": "A-S2",
                "escalation": "A-S1",
                "shell": "A-S1",
                "auth": "A-S6",
                "bypass": "A-S1",
            },
            ArtifactType.STEERING: {
                "wildcard": "ST-S3",
                "path": "ST-S4",
                "network": "ST-S4",
                "destructive": "ST-S4",
                "escalation": "ST-S4",
                "shell": "ST-S3",
                "auth": "ST-S4",
                "bypass": "ST-S4",
            },
            ArtifactType.MCP: {
                "wildcard": "MCP-S7",
                "path": "MCP-S7",
                "network": "MCP-S7",
                "destructive": "MCP-S7",
                "escalation": "MCP-S7",
                "shell": "MCP-S7",
                "auth": "MCP-S10",
                "bypass": "MCP-S7",
            },
            ArtifactType.HOOK: {
                "wildcard": "H-S3",
                "path": "H-S3",
                "network": "H-S6",
                "destructive": "H-S3",
                "escalation": "H-S3",
                "shell": "H-S3",
                "auth": "H-S6",
                "bypass": "H-S3",
            },
            ArtifactType.INSTRUCTION: {
                "wildcard": "I-S4",
                "path": "I-S4",
                "network": "I-S4",
                "destructive": "I-S4",
                "escalation": "I-S4",
                "shell": "I-S4",
                "auth": "I-S4",
                "bypass": "I-S5",
            },
            ArtifactType.PLUGIN: {
                "wildcard": "PL-S2",
                "path": "PL-S2",
                "network": "PL-S2",
                "destructive": "PL-S2",
                "escalation": "PL-S2",
                "shell": "PL-S2",
                "auth": "PL-S6",
                "bypass": "PL-S2",
            },
            ArtifactType.MEMORY: {
                "wildcard": "M-S5",
                "path": "M-S5",
                "network": "M-S5",
                "destructive": "M-S5",
                "escalation": "M-S5",
                "shell": "M-S5",
                "auth": "M-S5",
                "bypass": "M-S5",
            },
            ArtifactType.ORCHESTRATION: {
                "wildcard": "OW-S2",
                "path": "OW-S2",
                "network": "OW-S2",
                "destructive": "OW-S2",
                "escalation": "OW-S2",
                "shell": "OW-S2",
                "auth": "OW-S2",
                "bypass": "OW-S2",
            },
            ArtifactType.API_SCHEMA: {
                "wildcard": "API-S2",
                "path": "API-S2",
                "network": "API-S2",
                "destructive": "API-S2",
                "escalation": "API-S2",
                "shell": "API-S2",
                "auth": "API-S2",
                "bypass": "API-S2",
            },
        }

        type_map = mapping.get(artifact_type)
        if type_map is None:
            return None
        return type_map.get(category)

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        description: str,
        evidence: str,
        line: int | None,
        confidence: float,
        remediation: str,
    ) -> ScanFinding:
        """Create a ScanFinding with metadata from the risk registry lookup."""
        meta = _RISK_METADATA[risk_id]
        title, severity_score, severity_label, priority, gate_action = meta

        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=severity_score,
            severity_label=severity_label,
            priority=priority,
            gate_action=gate_action,
            category=RiskCategory.SECURITY,
            title=title,
            description=description,
            location=FindingLocation(line=line),
            evidence=evidence[:200],  # Truncate evidence to reasonable length
            confidence=confidence,
            scanner_module=ScannerModule.PERM_AUDIT,
            remediation=remediation,
        )

    def _check_wildcard_permissions(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect overly permissive tool declarations (wildcard permissions, 'all' access)."""
        findings: list[ScanFinding] = []

        for pattern in _WILDCARD_PERMISSION_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "wildcard")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description="Overly permissive tool/permission declaration detected. "
                        "Wildcard or 'all' access grants violate the principle of least privilege.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.95,
                        remediation="Replace wildcard permissions with explicit allowlists. "
                        "Define specific tools, paths, or resources that are needed.",
                    )
                )

        return findings

    def _check_dangerous_paths(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect access to dangerous file paths (system dirs, sensitive files)."""
        findings: list[ScanFinding] = []

        for pattern, path_desc in _DANGEROUS_PATH_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "path")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description=f"Access to sensitive file path detected: {path_desc}. "
                        "Artifacts should not reference system-critical paths or sensitive directories.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.90,
                        remediation="Restrict file access to project-specific directories. "
                        "Remove references to system paths and sensitive directories.",
                    )
                )

        return findings

    def _check_network_access(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect unrestricted network access declarations."""
        findings: list[ScanFinding] = []

        for pattern, net_desc in _UNRESTRICTED_NETWORK_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "network")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description=f"Unrestricted network access detected: {net_desc}. "
                        "Network access should be limited to specific domains and endpoints.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.90,
                        remediation="Specify allowed domains and endpoints explicitly. "
                        "Implement a network access allowlist.",
                    )
                )

        return findings

    def _check_destructive_actions(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect destructive action patterns (delete, remove, drop, truncate, format)."""
        findings: list[ScanFinding] = []

        for pattern, action_desc in _DESTRUCTIVE_ACTION_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "destructive")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description=f"Destructive action capability detected: {action_desc}. "
                        "Destructive operations require confirmation gates or human-in-the-loop approval.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.85,
                        remediation="Add confirmation gates for destructive operations. "
                        "Implement human-in-the-loop approval for irreversible actions.",
                    )
                )

        return findings

    def _check_privilege_escalation(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect privilege escalation indicators (sudo, admin, root access)."""
        findings: list[ScanFinding] = []

        for pattern, esc_desc in _PRIVILEGE_ESCALATION_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "escalation")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description=f"Privilege escalation indicator detected: {esc_desc}. "
                        "AI artifacts should not require elevated privileges.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.88,
                        remediation="Remove privilege escalation requirements. "
                        "Run with minimal required permissions and avoid root/admin access.",
                    )
                )

        return findings

    def _check_shell_execution(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect unrestricted shell/command execution patterns."""
        findings: list[ScanFinding] = []

        for pattern, shell_desc in _SHELL_EXECUTION_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "shell")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description=f"Unrestricted shell/command execution detected: {shell_desc}. "
                        "Command execution should be limited to an explicit allowlist.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.92,
                        remediation="Replace unrestricted shell access with an explicit command allowlist. "
                        "Only permit specific, well-defined commands.",
                    )
                )

        return findings

    def _check_missing_auth(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect missing or disabled authentication on transports/endpoints."""
        findings: list[ScanFinding] = []

        for pattern, auth_desc in _MISSING_AUTH_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "auth")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description=f"Missing or disabled authentication detected: {auth_desc}. "
                        "All transport layers and endpoints should require authentication.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.88,
                        remediation="Enable authentication on all transport layers. "
                        "Use token-based auth and validate client identity.",
                    )
                )

        return findings

    def _check_security_bypass(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect instructions that disable or bypass security controls."""
        findings: list[ScanFinding] = []

        for pattern, bypass_desc in _SECURITY_BYPASS_PATTERNS:
            for match in pattern.finditer(content):
                risk_id = self._select_risk_id(artifact_type, "bypass")
                if risk_id is None:
                    continue

                line = self._get_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        description=f"Security bypass pattern detected: {bypass_desc}. "
                        "Artifacts must not disable or circumvent security controls.",
                        evidence=match.group(0),
                        line=line,
                        confidence=0.92,
                        remediation="Remove security bypass instructions. "
                        "Security controls must remain active and enforceable.",
                    )
                )

        return findings
