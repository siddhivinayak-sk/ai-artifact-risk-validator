"""Enhanced TypeScript/JavaScript pattern scanner for MCP server security analysis.

Implements additional regex-based detection patterns specific to Node.js/TS/JS
environments, including child_process, vm module, dynamic Function constructors,
SSRF via fetch/axios/got, unsafe deserialization (node-serialize, JSON.parse),
SQL injection via template literals, fs operations with dynamic paths, and
missing authentication middleware detection.

Used by CodeAuditScanner when the LanguageDetector identifies a file as
TypeScript or JavaScript.
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

# --- Risk metadata for TS/JS enhanced patterns ---
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "MCP-S1": {
        "title": "Remote Code Execution via MCP Tool",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server exposes a tool that allows arbitrary remote code execution without sandboxing.",
        "remediation": "Sandbox all code execution. Remove arbitrary execution capabilities. Implement strict input validation.",
    },
    "MCP-S2": {
        "title": "Server-Side Request Forgery (SSRF) in MCP Tool",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP tool accepts URLs or network addresses that could be used to probe internal services.",
        "remediation": "Validate and restrict URLs. Implement URL allowlists. Block internal network ranges.",
    },
    "MCP-S6": {
        "title": "Input Injection in MCP Tool Parameters",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP tool parameters lack proper validation, allowing injection attacks through tool inputs.",
        "remediation": "Use parameterized queries. Validate all tool parameters. Implement strict type checking.",
    },
    "MCP-S8": {
        "title": "Unsafe Deserialization in MCP Transport",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server uses unsafe deserialization that could allow code execution via crafted payloads.",
        "remediation": "Use safe deserialization methods. Validate input schemas. Avoid deserializing untrusted data.",
    },
    "MCP-S9": {
        "title": "Path Traversal in MCP File Tool",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP file access tool does not properly sanitize paths, allowing directory traversal attacks.",
        "remediation": "Canonicalize all file paths. Implement path allowlists. Validate paths stay within sandbox.",
    },
    "MCP-S10": {
        "title": "Missing Authentication on MCP Transport",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server transport layer lacks authentication, allowing unauthorized tool invocations.",
        "remediation": "Implement transport authentication. Use token-based auth. Validate client identity.",
    },
}

# --- Regex patterns for TS/JS enhanced detection ---

# 1. child_process.exec/execSync/spawn/execFile
RE_CHILD_PROCESS = re.compile(
    r"\bchild_process\s*\.\s*(exec|execSync|spawn|execFile)\s*\("
    r"|\brequire\s*\(\s*['\"]child_process['\"]\s*\)\s*\.\s*(exec|execSync|spawn|execFile)\s*\("
    r"|\b(exec|execSync|spawn|execFile)\s*\(",
    re.IGNORECASE,
)

# 2. new Function( with dynamic arg (variable, template literal, or concatenation)
RE_NEW_FUNCTION = re.compile(
    r"\bnew\s+Function\s*\(\s*"
    r"(?!['\"]\s*\))"  # exclude string literal only args like new Function('return 1')
    r"(?:"
    r"[a-zA-Z_$]\w*"  # variable reference
    r"|`[^`]*\$\{"  # template literal
    r"|['\"][^'\"]*['\"]\s*\+"  # concatenation
    r"|[a-zA-Z_$]\w*\s*\+"  # variable + concatenation
    r")",
)

# 3. vm.runInNewContext/runInThisContext/vm.Script
RE_VM_MODULE = re.compile(
    r"\bvm\s*\.\s*(runInNewContext|runInThisContext|Script)\s*\("
    r"|\brequire\s*\(\s*['\"]vm['\"]\s*\)\s*\.\s*(runInNewContext|runInThisContext|Script)\s*\("
    r"|\bnew\s+vm\s*\.\s*Script\s*\(",
)

# 4. Dynamic URL fetch: fetch/axios/got/node-fetch with template literal URL
RE_DYNAMIC_URL_FETCH = re.compile(
    r"\b(?:fetch|axios\s*\.\s*(?:get|post|put|delete)|got|node-fetch)\s*\(\s*`[^`]*\$\{"
    r"|\b(?:fetch|axios\s*\.\s*(?:get|post|put|delete)|got|node-fetch)\s*\(\s*[a-zA-Z_$]\w*\s*[\+,)]"
    r"|\baxios\s*\(\s*\{[^}]*url\s*:\s*`[^`]*\$\{",
)

# 5a. node-serialize deserialize/unserialize
RE_NODE_SERIALIZE = re.compile(
    r"\b(?:serialize\s*\.\s*)?(?:deserialize|unserialize)\s*\(",
)

# 5b. JSON.parse with variable arg (not a string literal)
RE_JSON_PARSE_DYNAMIC = re.compile(
    r"\bJSON\s*\.\s*parse\s*\(\s*(?!['\"])"  # not a string literal
    r"[a-zA-Z_$]\w*",  # starts with a variable
)

# 6. SQL template literals with DB libs (mysql/pg/better-sqlite3/sequelize)
RE_SQL_TEMPLATE = re.compile(
    r"(?:"
    r"\b(?:query|execute|raw|sequelize\.query)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[^`]*\$\{"
    r"|"
    r"\b(?:query|execute|raw|sequelize\.query)\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[^'\"]*['\"]\s*\+"
    r"|"
    r"`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[^`]*\$\{[^`]*`"
    r")",
    re.IGNORECASE,
)

# 7. fs operations with dynamic path
RE_FS_DYNAMIC_PATH = re.compile(
    r"\bfs\s*\.\s*(readFile|writeFile|readFileSync|writeFileSync|unlink|unlinkSync)\s*\(\s*"
    r"(?!['\"]/|['\"]\.)"  # exclude string literal paths
    r"(?:"
    r"[a-zA-Z_$]\w*"  # variable reference
    r"|`[^`]*\$\{"  # template literal
    r"|[a-zA-Z_$]\w*\s*\+"  # concatenation
    r")",
)

# 8. Server framework detection (express/fastify/http.createServer)
RE_SERVER_FRAMEWORK = re.compile(
    r"\bexpress\s*\(\s*\)"
    r"|\bfastify\s*\(\s*\)"
    r"|\bhttp\s*\.\s*createServer\s*\(",
)

# Auth middleware patterns to check for in the file
RE_AUTH_PATTERNS = re.compile(
    r"\bpassport\b"
    r"|\bexpress-jwt\b"
    r"|\bjsonwebtoken\s*\.\s*verify\b"
    r"|\b(?:app|router|server)\s*\.\s*use\s*\([^)]*\b(?:auth|authenticate|authorization)\b"
    r"|\bfastify\s*\.\s*register\s*\([^)]*(?:auth|jwt|bearer)"
    r"|\b(?:auth|authenticate|authorization)\s*(?:Middleware|middleware|Handler|handler)\b",
    re.IGNORECASE,
)


class TSJSEnhancedPatterns:
    """Additional TypeScript/JavaScript-specific detection patterns.

    Scans TS/JS MCP server source files for Node.js-specific security risks
    including child_process usage, vm module, dynamic Function constructors,
    SSRF via HTTP clients, unsafe deserialization, SQL injection via template
    literals, fs operations with dynamic paths, and missing auth middleware.
    """

    def scan(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan TypeScript/JavaScript content for enhanced security patterns.

        Args:
            content: File content to scan.
            artifact_type: Type of artifact being scanned.
            artifact_path: Path to the artifact file.

        Returns:
            List of ScanFinding objects for detected risks.
        """
        findings: list[ScanFinding] = []

        if not content.strip():
            return findings

        lines = content.splitlines()

        # Line-by-line pattern matching
        for line_num, line in enumerate(lines, start=1):
            # 1. child_process detection
            if RE_CHILD_PROCESS.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "child_process"),
                        confidence=0.90,
                        line=line_num,
                        detail="child_process command execution detected",
                    )
                )

            # 2. new Function( with dynamic args
            if RE_NEW_FUNCTION.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "new Function("),
                        confidence=0.85,
                        line=line_num,
                        detail="Dynamic Function constructor with variable arguments",
                    )
                )

            # 3. vm module usage
            if RE_VM_MODULE.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "vm."),
                        confidence=0.90,
                        line=line_num,
                        detail="vm module code execution detected",
                    )
                )

            # 4. Dynamic URL fetch (SSRF)
            if RE_DYNAMIC_URL_FETCH.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S2",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "fetch/axios/got"),
                        confidence=0.80,
                        line=line_num,
                        detail="HTTP request with dynamic URL (potential SSRF)",
                    )
                )

            # 5a. node-serialize deserialize/unserialize
            if RE_NODE_SERIALIZE.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S8",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "deserialize/unserialize"),
                        confidence=0.90,
                        line=line_num,
                        detail="node-serialize deserialization detected",
                    )
                )

            # 5b. JSON.parse with dynamic arg
            if RE_JSON_PARSE_DYNAMIC.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S8",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "JSON.parse"),
                        confidence=0.70,
                        line=line_num,
                        detail="JSON.parse with variable argument (unsafe deserialization)",
                    )
                )

            # 6. SQL template literals with DB libs
            if RE_SQL_TEMPLATE.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S6",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "SQL injection"),
                        confidence=0.82,
                        line=line_num,
                        detail="SQL query with template literal interpolation (injection risk)",
                    )
                )

            # 7. fs operations with dynamic path
            if RE_FS_DYNAMIC_PATH.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S9",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "fs."),
                        confidence=0.75,
                        line=line_num,
                        detail="File system operation with dynamic path (path traversal risk)",
                    )
                )

        # 8. Missing auth detection (whole-file analysis)
        self._check_missing_auth(content, lines, artifact_type, artifact_path, findings)

        return findings

    def _check_missing_auth(
        self,
        content: str,
        lines: list[str],
        artifact_type: ArtifactType,
        artifact_path: str,
        findings: list[ScanFinding],
    ) -> None:
        """Check for server framework usage without auth middleware.

        Scans the entire file for auth patterns before reporting. Only reports
        if a server framework is detected AND no auth middleware is found.

        Args:
            content: Full file content.
            lines: Lines of the file.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.
            findings: List to append findings to.
        """
        # Check if file contains auth patterns anywhere
        has_auth = bool(RE_AUTH_PATTERNS.search(content))

        if has_auth:
            return

        # Look for server framework declarations and report missing auth
        for line_num, line in enumerate(lines, start=1):
            if RE_SERVER_FRAMEWORK.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S10",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=self._extract_evidence(line, "server without auth"),
                        confidence=0.70,
                        line=line_num,
                        detail="HTTP server/framework without authentication middleware",
                    )
                )

    def _extract_evidence(self, line: str, context: str) -> str:
        """Extract evidence string from a line, ensuring it's non-empty and ≤200 chars.

        Args:
            line: The source line containing the pattern.
            context: A context label for the detection.

        Returns:
            A non-empty evidence string of at most 200 characters.
        """
        stripped = line.strip()
        if stripped:
            evidence = stripped[:180]
        else:
            evidence = context
        return evidence if evidence else context

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        evidence: str,
        confidence: float,
        line: int,
        detail: str = "",
    ) -> ScanFinding:
        """Create a ScanFinding from risk metadata.

        Args:
            risk_id: The risk ID to report.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact file.
            evidence: The triggering text/pattern.
            confidence: Detection confidence (0.0-1.0).
            line: Line number where finding was detected.
            detail: Additional detail to append to description.

        Returns:
            A fully constructed ScanFinding.
        """
        metadata = _RISK_METADATA[risk_id]

        description = metadata["description"]
        if detail:
            description = f"{description} {detail}"

        # Ensure evidence is non-empty and ≤200 chars
        if not evidence:
            evidence = detail or risk_id
        evidence = evidence[:200]

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
            evidence=evidence,
            confidence=confidence,
            scanner_module=ScannerModule.CODE_AUDIT,
            remediation=metadata["remediation"],
            references=[],
        )
