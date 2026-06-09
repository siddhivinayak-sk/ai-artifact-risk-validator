"""Java/Kotlin security analyzer for the AI Artifact Risk Validator.

Detects security risks in Java and Kotlin MCP server source files using
regex-based pattern matching. Covers:
- Remote Code Execution (Runtime.exec, ProcessBuilder, ScriptEngine.eval)
- Unsafe Deserialization (ObjectInputStream, XMLDecoder, XStream, Kryo)
- Input Injection (JNDI lookups, SQL concatenation, Spring AI @Tool patterns)
- SSRF (HTTP clients with dynamic URLs)
- Path Traversal (File/Path operations with user-controlled paths)
- Missing Authentication (absent Spring Security configuration)
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

# --- Risk metadata for Java/Kotlin-specific findings ---
_JAVA_RISK_METADATA: dict[str, dict[str, Any]] = {
    "MCP-S1": {
        "title": "Remote Code Execution via MCP Tool",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "Java/Kotlin MCP server uses command execution APIs that allow "
            "arbitrary remote code execution."
        ),
        "remediation": (
            "Avoid Runtime.exec() and ProcessBuilder with user input. "
            "Use allowlisted commands with strict input validation."
        ),
    },
    "MCP-S2": {
        "title": "Server-Side Request Forgery (SSRF) in MCP Tool",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "Java/Kotlin MCP server constructs HTTP requests with dynamic URLs "
            "that could target internal services."
        ),
        "remediation": (
            "Validate and restrict URLs to an allowlist. Block requests to internal network ranges."
        ),
    },
    "MCP-S6": {
        "title": "Input Injection in MCP Tool Parameters",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "Java/Kotlin MCP server is vulnerable to input injection via "
            "JNDI lookups, SQL concatenation, or Spring AI @Tool parameter passing."
        ),
        "remediation": (
            "Use parameterized queries. Avoid JNDI lookups with user-controlled names. "
            "Validate all @Tool method parameters before passing to sensitive operations."
        ),
    },
    "MCP-S8": {
        "title": "Unsafe Deserialization in MCP Transport",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "Java/Kotlin MCP server uses unsafe deserialization that could "
            "allow remote code execution via crafted payloads."
        ),
        "remediation": (
            "Avoid ObjectInputStream for untrusted data. Use safe alternatives like "
            "JSON with strict type validation. Configure deserialization filters."
        ),
    },
    "MCP-S9": {
        "title": "Path Traversal in MCP File Tool",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "Java/Kotlin MCP server performs file operations with user-controlled "
            "paths without proper validation, enabling directory traversal."
        ),
        "remediation": (
            "Canonicalize file paths with Path.normalize(). Validate paths with "
            "startsWith() checks against allowed directories. Use allowlists."
        ),
    },
    "MCP-S10": {
        "title": "Missing Authentication on MCP Transport",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "Java/Kotlin MCP server exposes HTTP endpoints without Spring Security "
            "or equivalent authentication configuration."
        ),
        "remediation": (
            "Add @EnableWebSecurity and configure SecurityFilterChain. "
            "Implement proper authentication for all exposed endpoints."
        ),
    },
}

# --- Regex patterns for Java/Kotlin security risk detection ---

# 1. RCE: Runtime.exec(), ProcessBuilder, ScriptEngine.eval()
_RE_RUNTIME_EXEC = re.compile(
    r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("
    r"|\bRuntime\s*\.\s*exec\s*\(",
)
_RE_PROCESS_BUILDER = re.compile(
    r"\bProcessBuilder\s*\(",
)
_RE_SCRIPT_ENGINE_EVAL = re.compile(
    r"\bScriptEngine\s*.*?\.\s*eval\s*\("
    r"|\bengine\s*\.\s*eval\s*\("
    r"|\bscriptEngine\s*\.\s*eval\s*\(",
    re.IGNORECASE,
)

# 2. Unsafe Deserialization: ObjectInputStream.readObject(), XMLDecoder, XStream, Kryo
_RE_OBJECT_INPUT_STREAM = re.compile(
    r"\bObjectInputStream\b.*?\.\s*readObject\s*\("
    r"|\bnew\s+ObjectInputStream\s*\(",
)
_RE_XML_DECODER = re.compile(
    r"\bXMLDecoder\s*\("
    r"|\bnew\s+XMLDecoder\s*\(",
)
_RE_XSTREAM = re.compile(
    r"\bXStream\b.*?\.\s*fromXML\s*\("
    r"|\bxstream\s*\.\s*fromXML\s*\(",
    re.IGNORECASE,
)
_RE_KRYO = re.compile(
    r"\bKryo\b.*?\.\s*readObject\s*\("
    r"|\bkryo\s*\.\s*readObject\s*\(",
    re.IGNORECASE,
)

# 3. JNDI lookups with non-constant argument
_RE_JNDI_LOOKUP = re.compile(
    r"\b(?:InitialContext|JndiTemplate)\s*(?:\(\s*\))?\s*\.\s*lookup\s*\(\s*"
    r"(?![\"'])"  # Negative lookahead: NOT a string literal
    r"[a-zA-Z_]",  # Starts with a variable name
)

# SQL string concatenation (non-parameterized queries)
_RE_SQL_CONCAT = re.compile(
    r"(?:\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s[^\"]*\"\s*\+)"
    r"|(?:\+\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s)"
    r"|(?:(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s[^;]*\"\s*\+\s*[a-zA-Z_])",
    re.IGNORECASE,
)

# 4. HTTP clients with dynamic (non-constant) URLs
_RE_HTTP_DYNAMIC_URL = re.compile(
    r"\bnew\s+URL\s*\(\s*(?![\"'])[a-zA-Z_]"
    r"|\bHttpURLConnection\b.*?\.\s*openConnection\s*\("
    r"|\bHttpClient\b.*?\.\s*(?:send|newBuilder)\s*\("
    r"|\bRestTemplate\b.*?\.\s*(?:getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\(\s*(?![\"'])[a-zA-Z_]"
    r"|\bWebClient\b.*?\.\s*(?:get|post|put|delete)\s*\(\s*\)"
    r"|\bWebClient\b.*?\.\s*uri\s*\(\s*(?![\"'])[a-zA-Z_]",
    re.IGNORECASE,
)

# 5. File operations with user-controlled paths
_RE_FILE_OPS_DYNAMIC = re.compile(
    r"\bnew\s+File\s*\(\s*(?![\"'])"
    r"[a-zA-Z_]*(?:request|param|input|arg|path|uri|filename|filePath)\w*"
    r"|\bnew\s+FileInputStream\s*\(\s*(?![\"'])"
    r"[a-zA-Z_]*(?:request|param|input|arg|path|uri|filename|filePath)\w*"
    r"|\bnew\s+FileOutputStream\s*\(\s*(?![\"'])"
    r"[a-zA-Z_]*(?:request|param|input|arg|path|uri|filename|filePath)\w*"
    r"|\bPath\s*\.\s*of\s*\(\s*(?![\"'])"
    r"[a-zA-Z_]*(?:request|param|input|arg|path|uri|filename|filePath)\w*"
    r"|\bPaths\s*\.\s*get\s*\(\s*(?![\"'])"
    r"[a-zA-Z_]*(?:request|param|input|arg|path|uri|filename|filePath)\w*",
    re.IGNORECASE,
)

# Also detect File/Path with simple concatenation patterns
_RE_FILE_OPS_CONCAT = re.compile(
    r"\bnew\s+File\s*\(\s*[a-zA-Z_]\w*\s*\+"
    r"|\bnew\s+FileInputStream\s*\(\s*[a-zA-Z_]\w*\s*\+"
    r"|\bnew\s+FileOutputStream\s*\(\s*[a-zA-Z_]\w*\s*\+"
    r"|\bPath\s*\.\s*of\s*\(\s*[a-zA-Z_]\w*\s*\+"
    r"|\bPaths\s*\.\s*get\s*\(\s*[a-zA-Z_]\w*\s*\+",
    re.IGNORECASE,
)

# 6. Spring AI @Tool annotated methods passing String params to dangerous ops
_RE_TOOL_ANNOTATION = re.compile(r"@Tool\b")
_RE_SPRING_TOOL_METHOD = re.compile(
    r"@Tool\b[^}]*?"
    r"(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec"
    r"|ProcessBuilder"
    r"|\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s[^\"]*\"\s*\+"
    r"|\bnew\s+File\s*\(\s*[a-zA-Z_]\w*"
    r"|\bPath\s*\.\s*of\s*\(\s*[a-zA-Z_]\w*)",
    re.DOTALL | re.IGNORECASE,
)

# 7. Missing Spring Security indicators
_RE_SPRING_SECURITY_MARKERS = re.compile(
    r"@EnableWebSecurity"
    r"|SecurityFilterChain"
    r"|WebSecurityConfigurerAdapter"
    r"|@EnableGlobalMethodSecurity"
    r"|@EnableMethodSecurity"
    r"|@Secured\b"
    r"|@PreAuthorize\b"
    r"|@RolesAllowed\b"
    r"|HttpSecurity\b"
    r"|AuthenticationManager\b",
    re.IGNORECASE,
)

# HTTP endpoint indicators (Spring)
_RE_HTTP_ENDPOINT_MARKERS = re.compile(
    r"@RestController\b"
    r"|@Controller\b"
    r"|@RequestMapping\b"
    r"|@GetMapping\b"
    r"|@PostMapping\b"
    r"|@PutMapping\b"
    r"|@DeleteMapping\b"
    r"|@PatchMapping\b"
    r"|@SpringBootApplication\b",
)


class JavaAnalyzer:
    """Regex-based security analyzer for Java/Kotlin MCP server source files.

    Detects Remote Code Execution, Unsafe Deserialization, Input Injection,
    SSRF, Path Traversal, and Missing Authentication patterns specific to
    Java/Kotlin and Spring AI framework code.
    """

    def scan(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan Java/Kotlin source for security risks.

        Args:
            content: The full text content of the Java/Kotlin source file.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects for detected security risks.
        """
        findings: list[ScanFinding] = []

        if not content.strip():
            return findings

        lines = content.splitlines()

        # 1. RCE detection
        findings.extend(self._detect_rce(lines, artifact_type, artifact_path))

        # 2. Unsafe deserialization
        findings.extend(self._detect_deserialization(lines, artifact_type, artifact_path))

        # 3. JNDI lookups and SQL injection
        findings.extend(self._detect_injection(lines, artifact_type, artifact_path))

        # 4. SSRF via HTTP clients with dynamic URLs
        findings.extend(self._detect_ssrf(lines, artifact_type, artifact_path))

        # 5. Path traversal via file operations
        findings.extend(self._detect_path_traversal(lines, artifact_type, artifact_path))

        # 6. Spring AI @Tool patterns
        findings.extend(self._detect_spring_tool_risks(content, artifact_type, artifact_path))

        # 7. Missing Spring Security (file-level check)
        findings.extend(self._detect_missing_auth(content, lines, artifact_type, artifact_path))

        return findings

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        evidence: str,
        confidence: float,
        line: int | None = None,
    ) -> ScanFinding:
        """Create a ScanFinding from Java risk metadata.

        Args:
            risk_id: The risk ID to report.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact file.
            evidence: The triggering text/pattern (truncated to 200 chars).
            confidence: Detection confidence (0.0-1.0).
            line: Line number where finding was detected.

        Returns:
            A fully constructed ScanFinding.
        """
        metadata = _JAVA_RISK_METADATA[risk_id]

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
            description=metadata["description"],
            location=FindingLocation(line=line),
            evidence=evidence[:200] if len(evidence) > 200 else evidence,
            confidence=confidence,
            scanner_module=ScannerModule.CODE_AUDIT,
            remediation=metadata["remediation"],
            references=[],
        )

    def _detect_rce(
        self,
        lines: list[str],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect Remote Code Execution patterns.

        Looks for Runtime.exec(), ProcessBuilder, and ScriptEngine.eval().
        """
        findings: list[ScanFinding] = []

        for line_num, line in enumerate(lines, start=1):
            # Runtime.exec()
            if _RE_RUNTIME_EXEC.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"Runtime.exec() call: {line.strip()[:150]}",
                        confidence=0.90,
                        line=line_num,
                    )
                )

            # ProcessBuilder
            if _RE_PROCESS_BUILDER.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"ProcessBuilder usage: {line.strip()[:150]}",
                        confidence=0.90,
                        line=line_num,
                    )
                )

            # ScriptEngine.eval()
            if _RE_SCRIPT_ENGINE_EVAL.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"ScriptEngine.eval() call: {line.strip()[:150]}",
                        confidence=0.90,
                        line=line_num,
                    )
                )

        return findings

    def _detect_deserialization(
        self,
        lines: list[str],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect unsafe deserialization patterns.

        Looks for ObjectInputStream.readObject(), XMLDecoder, XStream.fromXML(),
        and Kryo.readObject().
        """
        findings: list[ScanFinding] = []

        for line_num, line in enumerate(lines, start=1):
            # ObjectInputStream
            if _RE_OBJECT_INPUT_STREAM.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S8",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"ObjectInputStream usage: {line.strip()[:150]}",
                        confidence=0.90,
                        line=line_num,
                    )
                )

            # XMLDecoder
            if _RE_XML_DECODER.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S8",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"XMLDecoder usage: {line.strip()[:150]}",
                        confidence=0.90,
                        line=line_num,
                    )
                )

            # XStream.fromXML()
            if _RE_XSTREAM.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S8",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"XStream.fromXML() call: {line.strip()[:150]}",
                        confidence=0.90,
                        line=line_num,
                    )
                )

            # Kryo.readObject()
            if _RE_KRYO.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S8",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"Kryo.readObject() call: {line.strip()[:150]}",
                        confidence=0.90,
                        line=line_num,
                    )
                )

        return findings

    def _detect_injection(
        self,
        lines: list[str],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect input injection patterns.

        Looks for JNDI lookups with non-constant arguments and SQL string
        concatenation (non-parameterized queries).
        """
        findings: list[ScanFinding] = []

        for line_num, line in enumerate(lines, start=1):
            # JNDI lookups with non-constant arg
            if _RE_JNDI_LOOKUP.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S6",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"JNDI lookup with dynamic name: {line.strip()[:150]}",
                        confidence=0.85,
                        line=line_num,
                    )
                )

            # SQL string concatenation
            if _RE_SQL_CONCAT.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S6",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"SQL concatenation: {line.strip()[:150]}",
                        confidence=0.82,
                        line=line_num,
                    )
                )

        return findings

    def _detect_ssrf(
        self,
        lines: list[str],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect SSRF patterns via HTTP clients with dynamic URLs.

        Looks for URL, HttpURLConnection, HttpClient, RestTemplate, and WebClient
        usage where the URL is a non-constant expression.
        """
        findings: list[ScanFinding] = []

        for line_num, line in enumerate(lines, start=1):
            if _RE_HTTP_DYNAMIC_URL.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S2",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"HTTP client with dynamic URL: {line.strip()[:150]}",
                        confidence=0.80,
                        line=line_num,
                    )
                )

        return findings

    def _detect_path_traversal(
        self,
        lines: list[str],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect path traversal via file operations with user-controlled paths.

        Looks for File, Path, FileInputStream, FileOutputStream with non-constant
        paths involving user-facing identifiers (request, param, input, arg, path).
        """
        findings: list[ScanFinding] = []

        for line_num, line in enumerate(lines, start=1):
            # Check for file ops with user-controlled path identifiers
            if _RE_FILE_OPS_DYNAMIC.search(line):
                # Check that there's no preceding path validation on the same line
                if not self._has_path_validation(line):
                    findings.append(
                        self._create_finding(
                            risk_id="MCP-S9",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=f"File operation with user-controlled path: {line.strip()[:150]}",
                            confidence=0.80,
                            line=line_num,
                        )
                    )

            # Check for file ops with concatenation
            elif _RE_FILE_OPS_CONCAT.search(line):
                if not self._has_path_validation(line):
                    findings.append(
                        self._create_finding(
                            risk_id="MCP-S9",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=f"File operation with concatenated path: {line.strip()[:150]}",
                            confidence=0.75,
                            line=line_num,
                        )
                    )

        return findings

    def _has_path_validation(self, line: str) -> bool:
        """Check if a line contains path validation calls.

        Args:
            line: The source code line to check.

        Returns:
            True if the line contains normalize(), startsWith(), or allowlist checks.
        """
        validation_patterns = (
            "normalize()",
            "startsWith(",
            ".toRealPath(",
            ".canonicalize(",
            "allowlist",
            "whitelist",
            "allowedPaths",
        )
        return any(pattern in line for pattern in validation_patterns)

    def _detect_spring_tool_risks(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect Spring AI @Tool annotated methods passing params to dangerous ops.

        Looks for @Tool methods where String parameters are passed directly to
        shell execution, SQL construction, or file path operations.
        """
        findings: list[ScanFinding] = []

        # Find all @Tool method blocks and check for dangerous operations within
        for match in _RE_SPRING_TOOL_METHOD.finditer(content):
            matched_text = match.group(0)
            # Calculate line number from offset
            line_num = content[: match.start()].count("\n") + 1

            findings.append(
                self._create_finding(
                    risk_id="MCP-S6",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=f"Spring AI @Tool with unsafe param usage: {matched_text.strip()[:150]}",
                    confidence=0.85,
                    line=line_num,
                )
            )

        return findings

    def _detect_missing_auth(
        self,
        content: str,
        lines: list[str],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect missing Spring Security configuration on HTTP endpoints.

        Checks the entire file for Spring Security markers. If HTTP endpoint
        annotations are present but no security configuration is found, reports
        MCP-S10.
        """
        findings: list[ScanFinding] = []

        # First check if the file has HTTP endpoints
        has_endpoints = bool(_RE_HTTP_ENDPOINT_MARKERS.search(content))

        if not has_endpoints:
            return findings

        # Check for Spring Security markers across the entire file
        has_security = bool(_RE_SPRING_SECURITY_MARKERS.search(content))

        if has_security:
            return findings

        # File has HTTP endpoints but no security config — find the first
        # endpoint marker line for the finding location
        for line_num, line in enumerate(lines, start=1):
            if _RE_HTTP_ENDPOINT_MARKERS.search(line):
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S10",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"HTTP endpoint without Spring Security: {line.strip()[:150]}",
                        confidence=0.70,
                        line=line_num,
                    )
                )
                break  # Report once per file

        return findings
