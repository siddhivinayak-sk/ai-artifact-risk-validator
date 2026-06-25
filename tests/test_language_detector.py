"""Property-based tests for LanguageDetector.

Feature: extended-mcp-scanning, Property 1: Language Detection Correctness

**Validates: Requirements 2.1, 3.1, 4.3**

Property 1: Language Detection Correctness
For any file path with a known extension (.rs, .java, .kt, .go, .rb, .cs, .php,
.ts, .mts, .cts, .js, .mjs, .cjs, .py) or content containing language-specific
markers, the LanguageDetector.detect() method SHALL return the correct
DetectedLanguage enum value corresponding to that language.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.language_detector import LanguageDetector

# --- Extension to expected language mapping ---

EXTENSION_LANGUAGE_MAP: dict[str, DetectedLanguage] = {
    ".rs": DetectedLanguage.RUST,
    ".java": DetectedLanguage.JAVA,
    ".kt": DetectedLanguage.KOTLIN,
    ".go": DetectedLanguage.GO,
    ".rb": DetectedLanguage.RUBY,
    ".cs": DetectedLanguage.CSHARP,
    ".php": DetectedLanguage.PHP,
    ".ts": DetectedLanguage.TYPESCRIPT,
    ".mts": DetectedLanguage.TYPESCRIPT,
    ".cts": DetectedLanguage.TYPESCRIPT,
    ".js": DetectedLanguage.JAVASCRIPT,
    ".mjs": DetectedLanguage.JAVASCRIPT,
    ".cjs": DetectedLanguage.JAVASCRIPT,
    ".py": DetectedLanguage.PYTHON,
}

# --- Content markers for each language (at least 2 markers each to trigger detection) ---

LANGUAGE_CONTENT_MARKERS: dict[DetectedLanguage, list[str]] = {
    DetectedLanguage.RUST: [
        "fn main() {\n    use std::io;\n}",
        "use std::collections::HashMap;\nfn process() {}",
        "#[tokio::main]\nasync fn main() {}",
        "#[derive(Debug)]\nimpl Server {}",
        "pub fn serve() {\n    let mut x = 5;\n}",
    ],
    DetectedLanguage.JAVA: [
        "public class Server {\n    import java.util.List;\n}",
        "import java.io.File;\npublic static void main(String[] args) {}",
        "@Override\nprivate String name;",
        "package com.example;\nimport javax.servlet.http.*;",
        "public class App extends BaseClass {\n    implements Serializable\n}",
    ],
    DetectedLanguage.KOTLIN: [
        "fun main(args: Array<String>) {\n    val x = 5\n}",
        "import kotlin.collections.List\ndata class User(val name: String)",
        "suspend fun fetchData() {\n    var result = 0\n}",
        "object Singleton {\n    companion object {}\n}",
        "sealed class Result {\n    val value: Int = 0\n}",
    ],
    DetectedLanguage.GO: [
        'package main\n\nfunc main() {\n    fmt.Println("hello")\n}',
        'import "fmt"\nfunc serve(w http.ResponseWriter) {\n    x := 5\n}',
        'import (\n    "net/http"\n)\nvar port int',
        "package main\ngo func() {}()",
    ],
    DetectedLanguage.RUBY: [
        "require 'json'\ndef process\n  puts 'hello'\nend",
        "class Server < Base\n  module Utils\n  end\nend",
        "attr_accessor :name\ndef run\n  do |item|\n  end\nend",
    ],
    DetectedLanguage.CSHARP: [
        "using System;\nnamespace App {\n    class Main : Base {}\n}",
        "public static void Main() {\n    var x = 5;\n    Console.WriteLine(x);\n}",
        "using System.Threading.Tasks;\nasync Task Run() {}",
    ],
    DetectedLanguage.PHP: [
        "<?php\n$name = 'hello';\nfunction process() {}",
        "<?php\necho 'hello';\nrequire_once('config.php');",
        "<?php\nuse App\\Models\\User;\nnamespace App\\Controllers;",
    ],
    DetectedLanguage.PYTHON: [
        "import os\nfrom pathlib import Path\ndef main():\n    pass",
        "class Server:\n    def __init__(self):\n        self.name = 'test'",
        "import sys\nif __name__ == '__main__':\n    pass",
    ],
    DetectedLanguage.TYPESCRIPT: [
        "interface Config {\n    port: number;\n}\ntype Handler = () => void;",
        "export default class Server {\n    name: string;\n}",
        "import { Router } from 'express';\nenum Status {\n    Active\n}",
    ],
    DetectedLanguage.JAVASCRIPT: [
        "const express = require('express');\nmodule.exports = app;",
        "export default function handler() {\n    console.log('hi');\n}",
        "import app from './app';\nlet port = 3000;\n=> {\n    return;\n}",
    ],
}

# --- Strategies ---

# Strategy for generating random base file names (without extension)
base_filename_strategy = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_0123456789",
    min_size=1,
    max_size=20,
).map(lambda s: s if s[0].isalpha() else "f" + s)

# Strategy for known extensions
known_extension_strategy = st.sampled_from(list(EXTENSION_LANGUAGE_MAP.keys()))

# Strategy for unknown extensions
unknown_extension_strategy = st.sampled_from(
    [".txt", ".yml", ".yaml", ".json", ".xml", ".html", ".css", ".log", ".dat"]
)

# Strategy for directory prefixes
dir_prefix_strategy = st.sampled_from(
    ["src/", "lib/", "app/", "pkg/", "internal/", "cmd/", "server/", ""]
)


@st.composite
def file_path_with_known_extension(draw: st.DrawFn) -> tuple[str, DetectedLanguage]:
    """Generate a file path with a known extension and its expected language."""
    prefix = draw(dir_prefix_strategy)
    name = draw(base_filename_strategy)
    ext = draw(known_extension_strategy)
    expected_language = EXTENSION_LANGUAGE_MAP[ext]
    file_path = f"{prefix}{name}{ext}"
    return file_path, expected_language


@st.composite
def content_with_language_markers(draw: st.DrawFn) -> tuple[str, DetectedLanguage]:
    """Generate content with language-specific markers and the expected language."""
    # Pick a language that has content markers
    language = draw(st.sampled_from(list(LANGUAGE_CONTENT_MARKERS.keys())))
    content = draw(st.sampled_from(LANGUAGE_CONTENT_MARKERS[language]))
    return content, language


@st.composite
def unrecognizable_content(draw: st.DrawFn) -> str:
    """Generate content that shouldn't match any language patterns."""
    # Use generic text with no language-specific markers
    templates = [
        "Hello World",
        "This is a plain text file with no code.",
        "Data: 123, 456, 789",
        "Config value = true",
        "Some random notes about the project.",
        "TODO: fix the thing",
        "Version 1.0.0 released",
        "README content here",
    ]
    return draw(st.sampled_from(templates))


# --- Property Tests ---


class TestLanguageDetectionCorrectness:
    """Property 1: Language Detection Correctness.

    Feature: extended-mcp-scanning, Property 1: Language Detection Correctness

    **Validates: Requirements 2.1, 3.1, 4.3**
    """

    detector = LanguageDetector()

    @given(data=file_path_with_known_extension())
    @settings(max_examples=200)
    def test_extension_based_detection_returns_correct_language(
        self, data: tuple[str, DetectedLanguage]
    ) -> None:
        """For any file path with a known extension, detect() SHALL return
        the correct DetectedLanguage enum value corresponding to that language."""
        file_path, expected_language = data

        result = self.detector.detect(file_path, "")

        assert result == expected_language, (
            f"Expected {expected_language} for path '{file_path}', got {result}"
        )

    @given(data=file_path_with_known_extension())
    @settings(max_examples=200)
    def test_extension_detection_case_insensitive(self, data: tuple[str, DetectedLanguage]) -> None:
        """Extension detection should work regardless of path casing."""
        file_path, expected_language = data

        # Test with upper-cased path (extension should still be matched since
        # the implementation lowercases before lookup)
        result = self.detector.detect(file_path.upper(), "")

        assert result == expected_language, (
            f"Expected {expected_language} for uppercased path '{file_path.upper()}', got {result}"
        )

    @given(data=content_with_language_markers())
    @settings(max_examples=200)
    def test_content_based_detection_returns_correct_language(
        self, data: tuple[str, DetectedLanguage]
    ) -> None:
        """For content containing language-specific markers with an unknown file
        extension, detect() SHALL return the correct DetectedLanguage enum value."""
        content, expected_language = data

        # Use an unknown extension so content-based detection is triggered
        result = self.detector.detect("unknown_file.txt", content)

        assert result == expected_language, (
            f"Expected {expected_language} for content markers, got {result}. "
            f"Content: {content[:80]}..."
        )

    @given(content=unrecognizable_content())
    @settings(max_examples=100)
    def test_unknown_returned_for_unrecognizable_content(self, content: str) -> None:
        """For content that doesn't match any language patterns and a file
        with an unknown extension, detect() SHALL return UNKNOWN."""
        result = self.detector.detect("unknown.txt", content)

        assert result == DetectedLanguage.UNKNOWN, (
            f"Expected UNKNOWN for unrecognizable content, got {result}. Content: {content[:80]}..."
        )

    @given(
        data=file_path_with_known_extension(),
        content=content_with_language_markers(),
    )
    @settings(max_examples=100)
    def test_extension_takes_precedence_over_content(
        self,
        data: tuple[str, DetectedLanguage],
        content: tuple[str, DetectedLanguage],
    ) -> None:
        """Extension-based detection SHALL take precedence over content-based
        detection when a known extension is present."""
        file_path, expected_language = data
        content_str, _content_language = content

        result = self.detector.detect(file_path, content_str)

        # The result should match the extension-based language, not the content-based one
        assert result == expected_language, (
            f"Expected extension-based {expected_language} for path '{file_path}', "
            f"got {result} (content suggests {_content_language})"
        )

    @given(
        ext=unknown_extension_strategy,
        name=base_filename_strategy,
    )
    @settings(max_examples=100)
    def test_unknown_extension_with_empty_content_returns_unknown(
        self, ext: str, name: str
    ) -> None:
        """An unknown extension with empty content SHALL return UNKNOWN."""
        result = self.detector.detect(f"{name}{ext}", "")

        assert result == DetectedLanguage.UNKNOWN, (
            f"Expected UNKNOWN for unknown extension '{ext}' with empty content, got {result}"
        )
