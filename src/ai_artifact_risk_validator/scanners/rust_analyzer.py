"""Rust-specific security analyzer for MCP server source files.

Detects security risks in Rust-based MCP server implementations using
regex-based pattern matching. Covers:
- Remote Code Execution (std::process::Command, unsafe blocks with FFI/pointers)
- SSRF (reqwest/hyper/surf with dynamic URLs)
- Path Traversal (std::fs/tokio::fs without validation)
- Unsafe Deserialization (serde_json/bincode/serde_yaml with dynamic input)
- SQL Injection (format! with SQL keywords)
- Missing Authentication (actix-web/axum/warp/rocket without auth middleware)

Implements Requirement 2 acceptance criteria (2.2-2.9).
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

# --- Risk metadata for Rust-specific findings ---
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "MCP-S1": {
        "title": "Remote Code Execution via MCP Tool",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "MCP server exposes a tool that allows arbitrary remote code execution "
            "without sandboxing."
        ),
        "remediation": (
            "Sandbox all code execution. Remove arbitrary execution capabilities. "
            "Implement strict input validation."
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
            "MCP tool accepts URLs or network addresses that could be used to probe "
            "internal services."
        ),
        "remediation": (
            "Validate and restrict URLs. Implement URL allowlists. Block internal network ranges."
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
            "MCP tool parameters lack proper validation, allowing injection attacks "
            "through tool inputs."
        ),
        "remediation": (
            "Validate all tool parameters. Use parameterized queries. "
            "Implement strict type checking."
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
            "MCP server uses unsafe deserialization that could allow code execution "
            "via crafted payloads."
        ),
        "remediation": (
            "Use safe deserialization methods. Validate input schemas. "
            "Avoid deserializing untrusted data without validation."
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
            "MCP file access tool does not properly sanitize paths, allowing "
            "directory traversal attacks."
        ),
        "remediation": (
            "Canonicalize all file paths. Implement path allowlists. "
            "Validate paths stay within sandbox."
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
            "MCP server transport layer lacks authentication, allowing unauthorized "
            "tool invocations."
        ),
        "remediation": (
            "Implement transport authentication. Use token-based auth. Validate client identity."
        ),
    },
}

# --- Regex patterns for Rust security risks ---

# 1. std::process::Command / tokio::process::Command usage (MCP-S1)
_RE_PROCESS_COMMAND = re.compile(
    r"\b(std::process::Command|tokio::process::Command|Command)\s*::\s*new\s*\(",
)

# Also detect `use std::process::Command` or `use tokio::process::Command` imports
# followed by Command::new usage
_RE_COMMAND_USE = re.compile(
    r"\buse\s+(std|tokio)::process::Command\b",
)

# Detect Command::new with variable argument (not a string literal)
_RE_COMMAND_NEW_DYNAMIC = re.compile(
    r"\bCommand\s*::\s*new\s*\(\s*(?!\")",
)

# Detect Command::new with string literal (less risky but still flagged)
_RE_COMMAND_NEW_LITERAL = re.compile(
    r"\bCommand\s*::\s*new\s*\(\s*\"",
)

# 2. Unsafe blocks with FFI/pointer operations (MCP-S1)
_RE_UNSAFE_BLOCK = re.compile(
    r"\bunsafe\s*\{",
)

# Patterns inside unsafe blocks that indicate FFI or pointer operations
_RE_UNSAFE_FFI_INDICATORS = re.compile(
    r"(\*\w+\s*\.|\*\s*\w+|"  # pointer dereference
    r"\bas\s+\*(?:const|mut)\b|"  # cast to raw pointer
    r"\bstd::ptr::|"  # ptr module usage
    r"\bstd::mem::transmute\b|"  # transmute
    r"\bmem::transmute\b|"  # transmute without full path
    r"\btransmute\s*[<(]|"  # transmute call
    r"\bextern\s+\"C\"\s*\{|"  # extern "C" block (FFI)
    r"\bextern\s+\"C\"\s+fn\b|"  # extern "C" fn (FFI)
    r"\blibc::|"  # libc crate usage
    r"\bffi::|"  # ffi module usage
    r"\bCStr::|CString::|"  # C string interop
    r"\b(?:read|write)_volatile\b|"  # volatile operations
    r"\bptr::(?:read|write|null|copy)\b)",  # ptr operations
    re.MULTILINE,
)

# 3. HTTP clients with dynamic URLs (MCP-S2)
# reqwest::get/Client::get/post/etc with variable URL
_RE_HTTP_CLIENT_DYNAMIC = re.compile(
    r"\b(reqwest|hyper|surf)\s*::"
    r"|\.get\s*\(\s*(?!\")"
    r"|\.post\s*\(\s*(?!\")"
    r"|\.put\s*\(\s*(?!\")"
    r"|\.delete\s*\(\s*(?!\")"
    r"|\.request\s*\(\s*(?!\")",
)

# More specific: reqwest::get(variable) or Client methods with dynamic URL
_RE_REQWEST_DYNAMIC_URL = re.compile(
    r"\breqwest\s*::\s*get\s*\(\s*(?!\")|"
    r"\breqwest\s*::\s*Client\s*::\s*new\s*\(\s*\)|"
    r"\.get\s*\(\s*&?format!\s*\(|"
    r"\.post\s*\(\s*&?format!\s*\(|"
    r"\.put\s*\(\s*&?format!\s*\(|"
    r"\.delete\s*\(\s*&?format!\s*\(",
)

# HTTP client usage with a variable (not string literal) as URL
_RE_HTTP_VARIABLE_URL = re.compile(
    r"\b(?:reqwest|hyper|surf)\b.*?\.\s*(?:get|post|put|delete|patch|head|request)\s*\(\s*(?!\")",
    re.DOTALL,
)

# Format! macro used in HTTP calls
_RE_HTTP_FORMAT_URL = re.compile(
    r"\.(?:get|post|put|delete|patch|head|request)\s*\(\s*&?format!\s*\(",
)

# 4. File system operations without path validation (MCP-S9)
_RE_FS_OPS = re.compile(
    r"\b(?:std::fs|tokio::fs|fs)\s*::\s*(?:read|write|read_to_string|read_dir|remove_file|"
    r"remove_dir|create_dir|copy|rename|metadata|symlink_metadata)\s*\(",
)

# Path validation calls (canonicalize, starts_with)
_RE_PATH_VALIDATION = re.compile(
    r"\b(?:canonicalize|starts_with|strip_prefix)\s*\(",
)

# 5. Deserialization with dynamic input (MCP-S8)
_RE_SERDE_DESER = re.compile(
    r"\b(?:serde_json\s*::\s*(?:from_str|from_slice|from_value|from_reader)|"
    r"bincode\s*::\s*(?:deserialize|deserialize_from)|"
    r"serde_yaml\s*::\s*from_str|"
    r"serde_cbor\s*::\s*from_slice)\s*\(",
)

# Check if the argument to deserialization is a literal
_RE_DESER_LITERAL_ARG = re.compile(
    r"\b(?:serde_json::from_str|serde_yaml::from_str)\s*\(\s*\"",
)

# 6. SQL via format! macro (MCP-S6)
_RE_SQL_FORMAT = re.compile(
    r"format!\s*\(\s*\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b",
    re.IGNORECASE,
)

# 7. Web frameworks without auth middleware (MCP-S10)
_RE_WEB_FRAMEWORK = re.compile(
    r"\b(?:actix_web|actix-web|axum|warp|rocket)\b",
)

# Auth-related patterns in Rust web frameworks
_RE_AUTH_PATTERNS = re.compile(
    r"\b(?:auth|guard|login|token|session|middleware|Bearer|jwt|"
    r"Authorization|authenticate|identity|credentials)\b",
    re.IGNORECASE,
)


def _find_line_number(content: str, match_start: int) -> int:
    """Find the 1-based line number for a character offset in content.

    Args:
        content: Full file content.
        match_start: Character offset of the match.

    Returns:
        1-based line number.
    """
    return content[:match_start].count("\n") + 1


def _has_path_validation_nearby(content: str, match_start: int, window: int = 500) -> bool:
    """Check if path validation (canonicalize/starts_with) appears near a file op.

    Looks backward from the match position within a configurable window
    for path validation calls.

    Args:
        content: Full file content.
        match_start: Start position of the file operation match.
        window: Number of characters to look back.

    Returns:
        True if path validation is found nearby.
    """
    start = max(0, match_start - window)
    context = content[start:match_start]
    return bool(_RE_PATH_VALIDATION.search(context))


def _is_dynamic_input(content: str, match_start: int, match_end: int) -> bool:
    """Determine if the argument to a function call is dynamic (not a literal).

    Checks if the content after the opening parenthesis starts with a string
    literal. If it does, the input is not dynamic.

    Args:
        content: Full file content.
        match_start: Start position of the match.
        match_end: End position of the match (just after opening paren).

    Returns:
        True if the input appears to be dynamic (variable, parameter, etc.).
    """
    # Look at what follows the opening paren
    after_paren = content[match_end : match_end + 50].lstrip()
    # If it starts with a string literal, it's not dynamic
    if after_paren.startswith('"') or after_paren.startswith('r"') or after_paren.startswith('b"'):
        return False
    return True


def _has_command_import(content: str) -> bool:
    """Check if the file imports Command from std::process or tokio::process.

    Args:
        content: Full file content.

    Returns:
        True if Command import is found.
    """
    return bool(_RE_COMMAND_USE.search(content))


class RustAnalyzer:
    """Regex-based security analyzer for Rust MCP server source files.

    Detects Rust-specific security patterns including command execution,
    unsafe blocks with FFI/pointer operations, HTTP clients with dynamic URLs,
    file system operations without path validation, unsafe deserialization,
    SQL injection via format! macro, and missing authentication on web frameworks.

    Confidence scores are capped at 0.70 when input source is ambiguous
    (Requirement 2.9).
    """

    def scan(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan Rust source code for security risks.

        Args:
            content: Rust source file content.
            artifact_type: Classified artifact type.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects for detected risks.
        """
        if not content or not content.strip():
            return []

        findings: list[ScanFinding] = []

        findings.extend(self._detect_command_execution(content, artifact_type, artifact_path))
        findings.extend(self._detect_unsafe_blocks(content, artifact_type, artifact_path))
        findings.extend(self._detect_ssrf(content, artifact_type, artifact_path))
        findings.extend(self._detect_path_traversal(content, artifact_type, artifact_path))
        findings.extend(self._detect_deserialization(content, artifact_type, artifact_path))
        findings.extend(self._detect_sql_injection(content, artifact_type, artifact_path))
        findings.extend(self._detect_missing_auth(content, artifact_type, artifact_path))

        return findings

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
            evidence: The triggering text/pattern (truncated to 200 chars).
            confidence: Detection confidence (0.0-1.0).
            line: Line number where finding was detected.
            detail: Additional context appended to description.

        Returns:
            A fully constructed ScanFinding.
        """
        metadata = _RISK_METADATA[risk_id]

        description = metadata["description"]
        if detail:
            description = f"{description} {detail}"

        # Truncate evidence to 200 chars max
        truncated_evidence = evidence[:200] if len(evidence) > 200 else evidence

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
            scanner_module=ScannerModule.CODE_AUDIT,
            remediation=metadata["remediation"],
            references=[],
        )

    def _detect_command_execution(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect std::process::Command and tokio::process::Command usage.

        Assigns confidence 0.85-0.95 based on whether the command argument
        is dynamic or a literal.

        Validates: Requirement 2.2
        """
        findings: list[ScanFinding] = []
        has_import = _has_command_import(content)

        # Detect full-path Command::new calls
        for match in _RE_PROCESS_COMMAND.finditer(content):
            line_num = _find_line_number(content, match.start())
            evidence = match.group(0).strip()

            # Check if the argument is dynamic
            after = content[match.end() : match.end() + 100].lstrip()
            if after and not after.startswith('"'):
                confidence = 0.95
            else:
                confidence = 0.85

            findings.append(
                self._create_finding(
                    risk_id="MCP-S1",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=confidence,
                    line=line_num,
                    detail="Rust process::Command usage detected.",
                )
            )

        # If file has Command import, detect Command::new without full path
        if has_import:
            for match in _RE_COMMAND_NEW_DYNAMIC.finditer(content):
                line_num = _find_line_number(content, match.start())
                # Avoid duplicates from the full-path match
                if not _RE_PROCESS_COMMAND.match(content, match.start()):
                    findings.append(
                        self._create_finding(
                            risk_id="MCP-S1",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0).strip(),
                            confidence=0.95,
                            line=line_num,
                            detail="Rust Command::new with dynamic argument.",
                        )
                    )

            for match in _RE_COMMAND_NEW_LITERAL.finditer(content):
                line_num = _find_line_number(content, match.start())
                if not _RE_PROCESS_COMMAND.match(content, match.start()):
                    findings.append(
                        self._create_finding(
                            risk_id="MCP-S1",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0).strip(),
                            confidence=0.85,
                            line=line_num,
                            detail="Rust Command::new with literal command.",
                        )
                    )

        return findings

    def _detect_unsafe_blocks(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect unsafe blocks with raw pointer deref, FFI calls, or transmutation.

        Assigns confidence 0.65-0.75 based on the type of unsafe operation.

        Validates: Requirement 2.3
        """
        findings: list[ScanFinding] = []

        for match in _RE_UNSAFE_BLOCK.finditer(content):
            # Extract the unsafe block content (approximate: up to matching brace)
            block_start = match.end()
            brace_depth = 1
            block_end = block_start
            for i in range(block_start, min(block_start + 2000, len(content))):
                if content[i] == "{":
                    brace_depth += 1
                elif content[i] == "}":
                    brace_depth -= 1
                    if brace_depth == 0:
                        block_end = i
                        break

            block_content = content[block_start:block_end]

            # Check if the unsafe block contains FFI/pointer operations
            ffi_match = _RE_UNSAFE_FFI_INDICATORS.search(block_content)
            if ffi_match:
                line_num = _find_line_number(content, match.start())
                indicator = ffi_match.group(0).strip()

                # Higher confidence for transmute/FFI, lower for pointer deref
                if (
                    "transmute" in indicator
                    or "extern" in indicator
                    or "ffi" in indicator.lower()
                    or "libc" in indicator
                ):
                    confidence = 0.75
                else:
                    confidence = 0.65

                evidence = f"unsafe block: {indicator}"
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=confidence,
                        line=line_num,
                        detail="Unsafe block with FFI/pointer operations detected.",
                    )
                )

        return findings

    def _detect_ssrf(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect HTTP client usage with dynamic URLs.

        Detects reqwest, hyper, and surf usage where the URL is a variable,
        parameter, or constructed via format! macro.

        Confidence is capped at 0.70 when the input source is ambiguous (Req 2.9).

        Validates: Requirement 2.4
        """
        findings: list[ScanFinding] = []

        # Check if any HTTP client crate is used
        has_http_client = bool(_RE_WEB_FRAMEWORK.search(content)) or bool(
            re.search(r"\b(?:reqwest|hyper|surf)\b", content)
        )

        if not has_http_client:
            return findings

        # Detect format! macro in HTTP calls (clear dynamic URL)
        for match in _RE_HTTP_FORMAT_URL.finditer(content):
            line_num = _find_line_number(content, match.start())
            evidence = match.group(0).strip()
            findings.append(
                self._create_finding(
                    risk_id="MCP-S2",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.85,
                    line=line_num,
                    detail="HTTP request with format! macro URL construction.",
                )
            )

        # Detect reqwest::get with dynamic argument
        for match in _RE_REQWEST_DYNAMIC_URL.finditer(content):
            line_num = _find_line_number(content, match.start())
            evidence = match.group(0).strip()
            # Skip if already covered by format! detection
            if "format!" in evidence:
                continue
            # Ambiguous source - cap at 0.70
            findings.append(
                self._create_finding(
                    risk_id="MCP-S2",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.70,
                    line=line_num,
                    detail="HTTP client with potentially dynamic URL.",
                )
            )

        # Detect generic HTTP client method calls with non-literal URL
        for match in _RE_HTTP_VARIABLE_URL.finditer(content):
            line_num = _find_line_number(content, match.start())
            evidence = match.group(0).strip()[:100]
            # Check for duplicates
            is_duplicate = any(f.location.line == line_num and f.id == "MCP-S2" for f in findings)
            if not is_duplicate:
                # Ambiguous input source - cap confidence at 0.70
                findings.append(
                    self._create_finding(
                        risk_id="MCP-S2",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.70,
                        line=line_num,
                        detail="HTTP client with dynamic URL argument.",
                    )
                )

        return findings

    def _detect_path_traversal(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect file system operations without path validation.

        Flags std::fs and tokio::fs operations where the path argument
        is a variable without preceding canonicalize/starts_with validation.

        Confidence is capped at 0.70 for ambiguous input sources (Req 2.9).

        Validates: Requirement 2.5
        """
        findings: list[ScanFinding] = []

        for match in _RE_FS_OPS.finditer(content):
            line_num = _find_line_number(content, match.start())

            # Check if the argument is dynamic (not a literal)
            if not _is_dynamic_input(content, match.start(), match.end()):
                continue

            # Check if path validation exists nearby (before this call)
            if _has_path_validation_nearby(content, match.start()):
                continue

            evidence = match.group(0).strip()
            # Ambiguous input source - cap at 0.70
            findings.append(
                self._create_finding(
                    risk_id="MCP-S9",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.70,
                    line=line_num,
                    detail="File system operation without path validation.",
                )
            )

        return findings

    def _detect_deserialization(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect unsafe deserialization with dynamic input.

        Flags serde_json::from_str, serde_json::from_slice, bincode::deserialize,
        serde_yaml::from_str when the input argument is not a hardcoded literal.

        Confidence is capped at 0.70 for ambiguous input sources (Req 2.9).

        Validates: Requirement 2.6
        """
        findings: list[ScanFinding] = []

        for match in _RE_SERDE_DESER.finditer(content):
            line_num = _find_line_number(content, match.start())

            # Check if the argument is dynamic
            if not _is_dynamic_input(content, match.start(), match.end()):
                continue

            evidence = match.group(0).strip()
            # Ambiguous input source - cap at 0.70
            findings.append(
                self._create_finding(
                    risk_id="MCP-S8",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.70,
                    line=line_num,
                    detail="Deserialization with dynamic input detected.",
                )
            )

        return findings

    def _detect_sql_injection(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect SQL query construction via format! macro.

        Flags format! macro usage where the format string contains SQL keywords.

        Validates: Requirement 2.7
        """
        findings: list[ScanFinding] = []

        for match in _RE_SQL_FORMAT.finditer(content):
            line_num = _find_line_number(content, match.start())
            evidence = match.group(0).strip()[:200]
            findings.append(
                self._create_finding(
                    risk_id="MCP-S6",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.85,
                    line=line_num,
                    detail="SQL query constructed via format! macro.",
                )
            )

        return findings

    def _detect_missing_auth(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect web frameworks without authentication middleware.

        Flags actix-web, axum, warp, and rocket usage where no auth/guard/login/
        token/session middleware references are found in the same file scope.

        Confidence is capped at 0.70 for ambiguous cases (Req 2.9).

        Validates: Requirement 2.8
        """
        findings: list[ScanFinding] = []

        # Check if a web framework is in use
        framework_match = _RE_WEB_FRAMEWORK.search(content)
        if not framework_match:
            return findings

        # Check if auth patterns exist anywhere in the file
        has_auth = bool(_RE_AUTH_PATTERNS.search(content))
        if has_auth:
            return findings

        # Web framework present but no auth references found
        line_num = _find_line_number(content, framework_match.start())
        evidence = framework_match.group(0).strip()
        findings.append(
            self._create_finding(
                risk_id="MCP-S10",
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                evidence=f"Web framework '{evidence}' without auth middleware",
                confidence=0.70,
                line=line_num,
                detail="No authentication middleware detected in web framework setup.",
            )
        )

        return findings
