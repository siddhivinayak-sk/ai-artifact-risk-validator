"""Language detection component for the AI Artifact Risk Validator.

Determines the programming language of MCP server source files using a two-phase
approach:
1. File extension matching against known mappings
2. Content marker analysis for language-specific patterns

Used by CodeAuditScanner to route files to the appropriate language-specific analyzer.
"""

from __future__ import annotations

import os
import re

from ai_artifact_risk_validator.models.language import DetectedLanguage

# --- Extension to language mappings ---
_EXTENSION_MAP: dict[str, DetectedLanguage] = {
    ".py": DetectedLanguage.PYTHON,
    ".ts": DetectedLanguage.TYPESCRIPT,
    ".mts": DetectedLanguage.TYPESCRIPT,
    ".cts": DetectedLanguage.TYPESCRIPT,
    ".js": DetectedLanguage.JAVASCRIPT,
    ".mjs": DetectedLanguage.JAVASCRIPT,
    ".cjs": DetectedLanguage.JAVASCRIPT,
    ".rs": DetectedLanguage.RUST,
    ".java": DetectedLanguage.JAVA,
    ".kt": DetectedLanguage.KOTLIN,
    ".go": DetectedLanguage.GO,
    ".rb": DetectedLanguage.RUBY,
    ".cs": DetectedLanguage.CSHARP,
    ".php": DetectedLanguage.PHP,
    ".md": DetectedLanguage.MARKDOWN,
    ".mdx": DetectedLanguage.MARKDOWN,
}

# --- Content markers for language detection ---
# Each entry is a tuple of (compiled regex pattern, minimum matches needed)
# We use patterns that are highly specific to each language to avoid false positives.

_RUST_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\bfn\s+\w+\s*\("),  # any fn declaration
    re.compile(r"\buse\s+std::"),
    re.compile(r"#\[tokio::main\]"),
    re.compile(r"#\[derive\("),
    re.compile(r"\bimpl\s+\w+"),
    re.compile(r"\bpub\s+fn\s+"),
    re.compile(r"\blet\s+mut\s+"),
    re.compile(r"\bmod\s+\w+\s*[;{]"),
    re.compile(r"->\s*\w+"),
    re.compile(r"\buse\s+\w+::\w+"),
    re.compile(r"\basync\s+fn\s+"),
    re.compile(r"#\[\w+"),  # attribute macros
]

_JAVA_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\bpublic\s+class\s+"),
    re.compile(r"\bimport\s+java\."),
    re.compile(r"\bpublic\s+static\s+void\s+main\s*\("),
    re.compile(r"@Override\b"),
    re.compile(r"\bprivate\s+\w+\s+\w+\s*;"),
    re.compile(r"\bpackage\s+[\w.]+\s*;"),
    re.compile(r"\bimport\s+javax?\."),
    re.compile(r"\bextends\s+\w+"),
    re.compile(r"\bimplements\s+\w+"),
]

_KOTLIN_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\bfun\s+main\s*\("),
    re.compile(r"\bimport\s+kotlin\."),
    re.compile(r"\bdata\s+class\s+"),
    re.compile(r"\bsuspend\s+fun\s+"),
    re.compile(r"\bval\s+\w+\s*[=:]"),
    re.compile(r"\bvar\s+\w+\s*[=:]"),
    re.compile(r"\bobject\s+\w+\s*[:{]"),
    re.compile(r"\bsealed\s+class\s+"),
    re.compile(r"\bcompanion\s+object\b"),
]

_PYTHON_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"^import\s+\w+", re.MULTILINE),
    re.compile(r"^from\s+\w+\s+import\s+", re.MULTILINE),
    re.compile(r"^def\s+\w+\s*\(", re.MULTILINE),
    re.compile(r"^class\s+\w+[\s(:]", re.MULTILINE),
    re.compile(r"if\s+__name__\s*==\s*['\"]__main__['\"]"),
    re.compile(r"^\s*self\.\w+", re.MULTILINE),
    re.compile(r":\s*$", re.MULTILINE),
]

_GO_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\bpackage\s+main\b"),
    re.compile(r"\bfunc\s+main\s*\("),
    re.compile(r'\bimport\s+"fmt"'),
    re.compile(r"\bfunc\s+\w+\s*\([^)]*\)\s*\w*\s*\{"),
    re.compile(r"\bvar\s+\w+\s+\w+"),
    re.compile(r":=\s*"),
    re.compile(r'\bimport\s+\(\s*\n\s*"'),
    re.compile(r"\bgo\s+func\b"),
]

_RUBY_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"^require\s+['\"]", re.MULTILINE),
    re.compile(r"\bdef\s+\w+"),
    re.compile(r"\bclass\s+\w+\s*<\s*\w+"),
    re.compile(r"\bmodule\s+\w+"),
    re.compile(r"\bend\s*$", re.MULTILINE),
    re.compile(r"\battr_(accessor|reader|writer)\b"),
    re.compile(r"\bdo\s*\|"),
    re.compile(r"\bputs\s+"),
]

_CSHARP_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\busing\s+System"),
    re.compile(r"\bnamespace\s+\w+"),
    re.compile(r"\bclass\s+\w+\s*:\s*\w+"),
    re.compile(r"\bpublic\s+(static\s+)?(void|int|string|Task)\s+\w+"),
    re.compile(r"\bvar\s+\w+\s*="),
    re.compile(r"\basync\s+Task"),
    re.compile(r"\bConsole\.(Write|ReadLine)"),
    re.compile(r"\[.*Attribute\]"),
]

_PHP_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"<\?php"),
    re.compile(r"\$\w+\s*="),
    re.compile(r"\bfunction\s+\w+\s*\("),
    re.compile(r"\becho\s+"),
    re.compile(r"\brequire(_once)?\s*\("),
    re.compile(r"\binclude(_once)?\s*\("),
    re.compile(r"\buse\s+\w+\\"),
    re.compile(r"\bnamespace\s+\w+\\"),
]

_TYPESCRIPT_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\binterface\s+\w+\s*\{"),
    re.compile(r":\s*(string|number|boolean|void|any|unknown)\b"),
    re.compile(r"\btype\s+\w+\s*="),
    re.compile(r"\bimport\s+.*\bfrom\s+['\"]"),
    re.compile(r"\bexport\s+(default\s+)?(class|function|interface|type|const|enum)\b"),
    re.compile(r"<\w+>"),  # generics
    re.compile(r"\bas\s+\w+"),
    re.compile(r"\benum\s+\w+\s*\{"),
]

_JAVASCRIPT_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\bconst\s+\w+\s*=\s*require\s*\("),
    re.compile(r"\bmodule\.exports\s*="),
    re.compile(r"\bexport\s+(default\s+)?(function|class|const)\b"),
    re.compile(r"\bimport\s+.*\bfrom\s+['\"]"),
    re.compile(r"\bconsole\.(log|error|warn)\s*\("),
    re.compile(r"\bfunction\s+\w+\s*\("),
    re.compile(r"=>\s*\{"),
    re.compile(r"\blet\s+\w+\s*="),
]

# Ordered list for content-based detection. Order matters: more specific languages first.
# Kotlin before Java (Kotlin has unique markers that overlap with Java).
# TypeScript before JavaScript (TypeScript has type annotations that distinguish it).
_CONTENT_MARKERS: list[tuple[DetectedLanguage, list[re.Pattern[str]], int]] = [
    (DetectedLanguage.RUST, _RUST_MARKERS, 2),
    (DetectedLanguage.KOTLIN, _KOTLIN_MARKERS, 2),
    (DetectedLanguage.JAVA, _JAVA_MARKERS, 2),
    (DetectedLanguage.GO, _GO_MARKERS, 2),
    (DetectedLanguage.PHP, _PHP_MARKERS, 2),
    (DetectedLanguage.CSHARP, _CSHARP_MARKERS, 2),
    (DetectedLanguage.RUBY, _RUBY_MARKERS, 2),
    (DetectedLanguage.PYTHON, _PYTHON_MARKERS, 2),
    (DetectedLanguage.TYPESCRIPT, _TYPESCRIPT_MARKERS, 2),
    (DetectedLanguage.JAVASCRIPT, _JAVASCRIPT_MARKERS, 2),
]


class LanguageDetector:
    """Determines the programming language of source files.

    Uses a two-phase detection strategy:
    1. File extension matching (fast, high confidence)
    2. Content marker analysis (fallback for extensionless files or ambiguous cases)

    Examples:
        >>> detector = LanguageDetector()
        >>> detector.detect("server.rs", "fn main() { }")
        <DetectedLanguage.RUST: 'rust'>
        >>> detector.detect("unknown.txt", "some random text")
        <DetectedLanguage.UNKNOWN: 'unknown'>
    """

    def detect(self, file_path: str, content: str) -> DetectedLanguage:
        """Detect the programming language from file extension and content markers.

        Args:
            file_path: Path to the source file. Extension is checked first.
            content: File content used for content-based marker analysis.

        Returns:
            The detected language, or DetectedLanguage.UNKNOWN if no match is found.
        """
        # Phase 1: Extension-based detection
        language = self._detect_by_extension(file_path)
        if language is not None:
            return language

        # Phase 2: Content-based detection
        language = self._detect_by_content(content)
        if language is not None:
            return language

        return DetectedLanguage.UNKNOWN

    def _detect_by_extension(self, file_path: str) -> DetectedLanguage | None:
        """Detect language by file extension.

        Args:
            file_path: Path to the source file.

        Returns:
            Detected language or None if extension is not recognized.
        """
        _, ext = os.path.splitext(file_path.lower())
        return _EXTENSION_MAP.get(ext)

    def _detect_by_content(self, content: str) -> DetectedLanguage | None:
        """Detect language by analyzing content for language-specific markers.

        Args:
            content: File content to analyze.

        Returns:
            Detected language or None if no sufficient markers are found.
        """
        if not content or not content.strip():
            return None

        for language, markers, threshold in _CONTENT_MARKERS:
            matches = sum(1 for pattern in markers if pattern.search(content))
            if matches >= threshold:
                return language

        return None
