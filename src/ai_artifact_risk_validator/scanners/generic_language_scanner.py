"""Generic language scanner for Go, Ruby, C#, and PHP MCP servers.

Provides language-specific regex-based detection of security risks for languages
that do not have a dedicated analyzer. Detects Remote Code Execution (MCP-S1)
and Server-Side Request Forgery (MCP-S2) patterns with a confidence of 0.80.

All findings include the language name in the evidence field as required by
Requirement 4.6.
"""

from __future__ import annotations

import re
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
from ai_artifact_risk_validator.models.language import DetectedLanguage

# Confidence score for all generic language-specific patterns
_CONFIDENCE = 0.80

# Human-readable language names for evidence fields
_LANGUAGE_NAMES: dict[DetectedLanguage, str] = {
    DetectedLanguage.GO: "Go",
    DetectedLanguage.RUBY: "Ruby",
    DetectedLanguage.CSHARP: "C#",
    DetectedLanguage.PHP: "PHP",
}

# --- Risk metadata for findings ---
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "MCP-S1": {
        "title": "Remote Code Execution via MCP Tool",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "MCP server exposes a tool that allows arbitrary remote code "
            "execution without sandboxing."
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
            "MCP tool accepts URLs or network addresses that could be used "
            "to probe internal services."
        ),
        "remediation": (
            "Validate and restrict URLs. Implement URL allowlists. Block internal network ranges."
        ),
    },
}


# --- Pattern definitions per language ---
# Each entry maps a risk_id to a list of (compiled regex, short description) tuples.

_PatternEntry = tuple[re.Pattern[str], str]

_GO_PATTERNS: dict[str, list[_PatternEntry]] = {
    "MCP-S1": [
        (
            re.compile(r"""(?:os/exec|exec\.Command)"""),
            "os/exec command execution",
        ),
    ],
    "MCP-S2": [
        (
            re.compile(r"""http\.(Get|Post|Head|PostForm)\s*\(\s*[a-zA-Z_]"""),
            "http.Get/Post with variable URL",
        ),
    ],
}

_RUBY_PATTERNS: dict[str, list[_PatternEntry]] = {
    "MCP-S1": [
        (
            re.compile(r"""\bsystem\s*\("""),
            "system() command execution",
        ),
        (
            re.compile(r"""`[^`]*`"""),
            "backtick command execution",
        ),
        (
            re.compile(r"""\bexec\s*\("""),
            "exec() command execution",
        ),
        (
            re.compile(r"""%x\{[^}]*\}"""),
            "%x{} command execution",
        ),
    ],
    "MCP-S2": [
        (
            re.compile(r"""Net::HTTP"""),
            "Net::HTTP network request",
        ),
        (
            re.compile(r"""open-uri"""),
            "open-uri network request",
        ),
        (
            re.compile(r"""\bopen\s*\(\s*['"]https?://"""),
            "open() with URL",
        ),
    ],
}

_CSHARP_PATTERNS: dict[str, list[_PatternEntry]] = {
    "MCP-S1": [
        (
            re.compile(r"""Process\.Start"""),
            "Process.Start command execution",
        ),
        (
            re.compile(r"""Process\.StartInfo"""),
            "Process.StartInfo command execution",
        ),
    ],
    "MCP-S2": [
        (
            re.compile(r"""(?:HttpClient|WebRequest|WebClient)\s*[\.(]"""),
            "HttpClient/WebRequest with variable URL",
        ),
        (
            re.compile(r"""new\s+(?:HttpClient|WebRequest|WebClient)"""),
            "HttpClient/WebRequest instantiation",
        ),
    ],
}

_PHP_PATTERNS: dict[str, list[_PatternEntry]] = {
    "MCP-S1": [
        (
            re.compile(r"""\bshell_exec\s*\("""),
            "shell_exec() command execution",
        ),
        (
            re.compile(r"""\bexec\s*\("""),
            "exec() command execution",
        ),
        (
            re.compile(r"""\bsystem\s*\("""),
            "system() command execution",
        ),
        (
            re.compile(r"""\bpassthru\s*\("""),
            "passthru() command execution",
        ),
        (
            re.compile(r"""\bpopen\s*\("""),
            "popen() command execution",
        ),
    ],
    "MCP-S2": [
        (
            re.compile(r"""\bfile_get_contents\s*\(\s*\$"""),
            "file_get_contents with variable URL",
        ),
        (
            re.compile(r"""\bcurl_exec\s*\("""),
            "curl_exec with variable URL",
        ),
    ],
}

# Master mapping from DetectedLanguage to pattern dictionaries
LANGUAGE_PATTERNS: dict[DetectedLanguage, dict[str, list[_PatternEntry]]] = {
    DetectedLanguage.GO: _GO_PATTERNS,
    DetectedLanguage.RUBY: _RUBY_PATTERNS,
    DetectedLanguage.CSHARP: _CSHARP_PATTERNS,
    DetectedLanguage.PHP: _PHP_PATTERNS,
}


class GenericLanguageScanner:
    """Language-specific pattern scanner for Go, Ruby, C#, and PHP.

    Detects Remote Code Execution (MCP-S1) and Server-Side Request Forgery
    (MCP-S2) patterns using regex-based detection. All findings are reported
    with a confidence of 0.80 and include the language name in the evidence field.

    Examples:
        >>> scanner = GenericLanguageScanner()
        >>> findings = scanner.scan(
        ...     'exec.Command("ls")',
        ...     DetectedLanguage.GO,
        ...     ArtifactType.MCP,
        ...     "server.go",
        ... )
        >>> len(findings) >= 1
        True
    """

    def scan(
        self,
        content: str,
        language: DetectedLanguage,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan source code for language-specific security patterns.

        Args:
            content: The source file content to scan.
            language: The detected programming language.
            artifact_type: The type of artifact being scanned.
            artifact_path: Path to the artifact file.

        Returns:
            A list of ScanFinding objects for detected security risks.
        """
        if not content or not content.strip():
            return []

        patterns = LANGUAGE_PATTERNS.get(language)
        if patterns is None:
            return []

        language_name = _LANGUAGE_NAMES.get(language, language.value)
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for risk_id, pattern_entries in patterns.items():
            for pattern, description in pattern_entries:
                for line_num, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        evidence = self._build_evidence(language_name, description, line.strip())
                        metadata = _RISK_METADATA[risk_id]
                        finding = ScanFinding(
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
                            location=FindingLocation(line=line_num),
                            evidence=evidence,
                            confidence=_CONFIDENCE,
                            scanner_module=ScannerModule.CODE_AUDIT,
                            remediation=metadata["remediation"],
                        )
                        findings.append(finding)

        return findings

    @staticmethod
    def _build_evidence(language_name: str, description: str, line_content: str) -> str:
        """Build an evidence string including the language name.

        The evidence field is capped at 200 characters and always includes
        the language name as required by Requirement 4.6.

        Args:
            language_name: Human-readable language name (e.g., "Go", "Ruby").
            description: Short description of the detected pattern.
            line_content: The source line that matched.

        Returns:
            A non-empty evidence string of at most 200 characters.
        """
        # Format: "[Language] description: <snippet>"
        prefix = f"[{language_name}] {description}"
        # Reserve space for prefix + ": " + snippet
        max_snippet_len = 200 - len(prefix) - 2
        if max_snippet_len > 0 and line_content:
            snippet = line_content[:max_snippet_len]
            evidence = f"{prefix}: {snippet}"
        else:
            evidence = prefix
        # Final safety truncation
        return evidence[:200]
