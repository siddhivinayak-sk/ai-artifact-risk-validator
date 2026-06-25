"""Language detection enum for the AI Artifact Risk Validator.

Defines the DetectedLanguage enum used by the LanguageDetector to classify
MCP server source files by programming language.
"""

from enum import Enum


class DetectedLanguage(str, Enum):
    """Programming languages detectable by the LanguageDetector."""

    PYTHON = "python"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    RUST = "rust"
    JAVA = "java"
    KOTLIN = "kotlin"
    GO = "go"
    RUBY = "ruby"
    CSHARP = "csharp"
    PHP = "php"
    MARKDOWN = "markdown"
    UNKNOWN = "unknown"
