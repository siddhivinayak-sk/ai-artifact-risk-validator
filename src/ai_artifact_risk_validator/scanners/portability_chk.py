"""PortabilityChk scanner for detecting model portability risks.

Detects model-specific syntax/tags, hardcoded token limit assumptions,
vendor-locked capability requirements, and missing model fallback strategies.

Uses regex-based detection for model-specific token formats and references,
token limit analysis, and capability requirement extraction.
"""

from __future__ import annotations

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
# Model-Specific Token/Tag Patterns (MOD-1)
# ============================================================

# ChatML tokens (OpenAI-compatible)
_CHATML_PATTERN = re.compile(
    r"<\|im_(start|end)\|>",
    re.IGNORECASE,
)

# Llama/Mistral instruction tokens
_LLAMA_INST_PATTERN = re.compile(
    r"\[/?INST\]|\[/?SYS\]|<<SYS>>|<</SYS>>",
)

# Special start/end tokens used by specific models
_SPECIAL_TOKEN_PATTERN = re.compile(
    r"<\|(?:system|user|assistant|endoftext|pad|sep|cls|eos|bos)\|>",
    re.IGNORECASE,
)

# Anthropic-specific formatting
_ANTHROPIC_PATTERN = re.compile(
    r"\\n\\nHuman:|\\n\\nAssistant:|<\|human\|>|<\|assistant\|>",
)

# Google/PaLM specific patterns
_PALM_PATTERN = re.compile(
    r"<start_of_turn>|<end_of_turn>",
    re.IGNORECASE,
)

# All model-specific syntax patterns with descriptions
_MODEL_SYNTAX_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_CHATML_PATTERN, "ChatML token format (<|im_start|>/<|im_end|>)"),
    (_LLAMA_INST_PATTERN, "Llama/Mistral instruction markers ([INST]/[SYS])"),
    (_SPECIAL_TOKEN_PATTERN, "Model-specific special tokens"),
    (_ANTHROPIC_PATTERN, "Anthropic-specific conversation format"),
    (_PALM_PATTERN, "Google PaLM/Gemini turn markers"),
]

# ============================================================
# Model Name/Version References (MOD-4)
# ============================================================

# Explicit model name references without abstraction
_MODEL_NAME_PATTERN = re.compile(
    r"\b(?:"
    r"gpt-?4(?:-?turbo|-?vision|-?o|-?mini)?|"
    r"gpt-?3\.?5(?:-?turbo)?|"
    r"gpt-?4o(?:-?mini)?|"
    r"o1(?:-?preview|-?mini)?|"
    r"claude-?(?:3(?:\.5)?|2(?:\.1)?|instant)(?:-?(?:sonnet|opus|haiku))?|"
    r"gemini-?(?:pro|ultra|nano|flash|1\.5|2\.0)|"
    r"palm-?2|"
    r"llama-?(?:2|3)(?:-?(?:7|8|13|70|405)b)?|"
    r"mistral-?(?:7b|8x7b|large|medium|small|nemo)|"
    r"mixtral-?(?:8x7b|8x22b)|"
    r"command-?r(?:\+|-plus)?|"
    r"dall-?e-?(?:2|3)|"
    r"whisper-?(?:1|large|medium|small)|"
    r"text-?embedding-?(?:ada|3-(?:small|large))|"
    r"text-?davinci-?(?:003|002)"
    r")\b",
    re.IGNORECASE,
)

# ============================================================
# Token Limit Assumptions (MOD-2)
# ============================================================

# Common hardcoded token limits that are model-specific
_TOKEN_LIMIT_PATTERN = re.compile(
    r"\b(?:"
    r"(?:max[_\s]?tokens?|token[_\s]?(?:limit|budget|max|cap)|context[_\s]?(?:window|length|size|limit))"
    r"\s*(?:[:=]|is|of)\s*"
    r"(\d[\d,_]*)"
    r")\b",
    re.IGNORECASE,
)

# Direct numeric token limit values known to be model-specific
_KNOWN_MODEL_LIMITS: dict[int, str] = {
    4096: "GPT-3.5 Turbo (4K)",
    8192: "GPT-4 (8K)",
    16384: "GPT-3.5 Turbo 16K",
    32768: "GPT-4 32K",
    128000: "GPT-4 Turbo / GPT-4o (128K)",
    200000: "Claude 3 (200K)",
    1000000: "Gemini 1.5 Pro (1M)",
    2048: "Legacy model context (2K)",
}

# Pattern for standalone large numbers that look like token limits in context
_STANDALONE_LIMIT_PATTERN = re.compile(
    r"\b(4096|8192|16384|32768|65536|128000|131072|200000|1000000)\s*(?:tokens?|tok)\b",
    re.IGNORECASE,
)

# ============================================================
# Capability Requirements (MOD-3)
# ============================================================

# OpenAI function calling format
_OPENAI_FUNCTION_CALLING_PATTERN = re.compile(
    r"(?:"
    r"\bfunction_call\b|\bfunctions?\s*:\s*\[|"
    r"\"type\"\s*:\s*\"function\"|"
    r"\btool_choice\b|\btools?\s*:\s*\[.*?\"type\"\s*:\s*\"function\""
    r")",
    re.IGNORECASE | re.DOTALL,
)

# Anthropic tool use format
_ANTHROPIC_TOOL_PATTERN = re.compile(
    r"\b(?:"
    r"tool_use|tool_result|"
    r"\"type\"\s*:\s*\"tool_use\"|"
    r"\"type\"\s*:\s*\"tool_result\""
    r")\b",
    re.IGNORECASE,
)

# Vision/multimodal specific patterns
_VISION_PATTERN = re.compile(
    r"\b(?:"
    r"image_url|\"type\"\s*:\s*\"image(?:_url)?\"|"
    r"vision\s*(?:input|content|message|capability)|"
    r"analyze\s+(?:this\s+)?image|"
    r"describe\s+(?:this\s+)?(?:image|picture|photo)"
    r")\b",
    re.IGNORECASE,
)

# Provider-specific API endpoint patterns
_API_ENDPOINT_PATTERN = re.compile(
    r"(?:"
    r"api\.openai\.com|"
    r"api\.anthropic\.com|"
    r"generativelanguage\.googleapis\.com|"
    r"api\.cohere\.ai|"
    r"api\.mistral\.ai|"
    r"api\.together\.xyz|"
    r"api\.groq\.com"
    r")",
    re.IGNORECASE,
)

# Provider-specific SDK patterns
_PROVIDER_SDK_PATTERN = re.compile(
    r"\b(?:"
    r"openai\.(?:ChatCompletion|Completion|Client)|"
    r"anthropic\.(?:Anthropic|Client|AsyncAnthropic)|"
    r"google\.generativeai|"
    r"cohere\.Client|"
    r"together\.Together"
    r")\b",
)

# JSON mode / response format (provider-specific)
_RESPONSE_FORMAT_PATTERN = re.compile(
    r"\b(?:"
    r"response_format\s*[:=]\s*\{.*?\"type\"\s*:\s*\"json_object\"|"
    r"\"response_format\"\s*:\s*\{.*?\"json_schema\""
    r")\b",
    re.IGNORECASE | re.DOTALL,
)

# All capability patterns with descriptions
_CAPABILITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_OPENAI_FUNCTION_CALLING_PATTERN, "OpenAI function calling format"),
    (_ANTHROPIC_TOOL_PATTERN, "Anthropic tool_use/tool_result format"),
    (_VISION_PATTERN, "Vision/multimodal capability assumption"),
    (_API_ENDPOINT_PATTERN, "Provider-specific API endpoint"),
    (_PROVIDER_SDK_PATTERN, "Provider-specific SDK usage"),
    (_RESPONSE_FORMAT_PATTERN, "Provider-specific response format"),
]

# ============================================================
# Fallback Strategy Detection (MOD-4)
# ============================================================

_FALLBACK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:fallback[_\s]?model|model[_\s]?fallback)\b", re.IGNORECASE),
    re.compile(r"\b(?:fallback|alternative|backup)[_\s]?(?:provider|endpoint)\b", re.IGNORECASE),
    re.compile(r"\bmodel[_\s]?chain\b", re.IGNORECASE),
    re.compile(
        r"\b(?:if|when)\s+.*?(?:unavailable|fails?|error|timeout).*?(?:use|try|switch|fall\s*back)\b",
        re.IGNORECASE,
    ),
]

# ============================================================
# Risk Metadata
# ============================================================

_RISK_METADATA: dict[str, dict] = {
    "MOD-1": {
        "title": "Model-specific token formats",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.MODEL_PORTABILITY,
        "description": (
            "The artifact uses token formats or special tokens specific to a "
            "particular model (e.g., <|im_start|>, [INST], <s>). This makes "
            "the artifact non-portable across different LLM providers."
        ),
        "remediation": (
            "Use model-agnostic prompt structures (role-based sections without "
            "model-specific tokens). Abstract model-specific formatting into a "
            "template layer that adapts per provider."
        ),
    },
    "MOD-2": {
        "title": "Model-specific token limit assumptions",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.MODEL_PORTABILITY,
        "description": (
            "The artifact is designed around a specific model's context window "
            "size (e.g., hardcoded 128K assumption) without fallback for models "
            "with smaller context windows."
        ),
        "remediation": (
            "Parameterize token budgets rather than hardcoding model-specific "
            "limits. Implement graceful degradation for smaller context windows."
        ),
    },
    "MOD-3": {
        "title": "Vendor-locked capability requirements",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.MODEL_PORTABILITY,
        "description": (
            "The artifact requires capabilities specific to a single vendor's "
            "model (e.g., function calling format, vision input, specific API "
            "parameters) without declaring these requirements or providing alternatives."
        ),
        "remediation": (
            "Declare required model capabilities in artifact metadata. Provide "
            "capability-check logic and fallback behavior for unsupported models."
        ),
    },
    "MOD-4": {
        "title": "Missing model fallback strategy",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "category": RiskCategory.MODEL_PORTABILITY,
        "description": (
            "The artifact references a specific model without defining a fallback "
            "strategy for when the primary model is unavailable or when a "
            "capability is not supported."
        ),
        "remediation": (
            "Define a model fallback chain in the artifact configuration. "
            "Implement capability negotiation to adapt behavior per available model."
        ),
    },
}


class PortabilityChkScanner(BaseScanner):
    """Scanner for detecting model portability risks.

    Detects:
    - Model-specific syntax/tags (ChatML, [INST], etc.) - MOD-1
    - Hardcoded token limit assumptions - MOD-2
    - Vendor-locked capability requirements - MOD-3
    - Hardcoded model version references without fallback - MOD-4

    Uses regex-based detection for all patterns. The tiktoken dependency
    is available for token counting but not required for core detection.
    """

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.PORTABILITY_CHK

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return [
            ArtifactType.PROMPT,
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.STEERING,
            ArtifactType.INSTRUCTION,
            ArtifactType.EVAL_HARNESS,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        return ["MOD-1", "MOD-2", "MOD-3", "MOD-4"]

    def is_available(self) -> bool:
        """Always available via regex-based detection."""
        return True

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for model portability risks.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        findings: list[ScanFinding] = []

        if artifact_type not in self.applicable_artifact_types:
            return findings

        # Run all detection methods
        findings.extend(
            self._detect_model_specific_syntax(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_token_limit_assumptions(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_capability_requirements(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_model_references(artifact_content, artifact_type, artifact_path)
        )

        return findings

    def _find_line_number(self, content: str, match_start: int) -> int:
        """Find the 1-based line number for a character offset."""
        return content[:match_start].count("\n") + 1

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        evidence: str,
        confidence: float,
        line: int | None = None,
    ) -> ScanFinding:
        """Create a ScanFinding from risk metadata.

        Args:
            risk_id: The risk ID for this finding.
            artifact_type: The artifact type being scanned.
            artifact_path: Path to the artifact file.
            evidence: The text/pattern that triggered the finding.
            confidence: Confidence score (0.0-1.0).
            line: Optional line number where finding was detected.

        Returns:
            A complete ScanFinding object.
        """
        meta = _RISK_METADATA[risk_id]
        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=meta["severity_score"],
            severity_label=meta["severity_label"],
            priority=meta["priority"],
            gate_action=meta["gate_action"],
            category=meta["category"],
            title=meta["title"],
            description=meta["description"],
            location=FindingLocation(line=line),
            evidence=evidence[:200],
            confidence=confidence,
            scanner_module=ScannerModule.PORTABILITY_CHK,
            remediation=meta["remediation"],
            references=[],
        )

    def _detect_model_specific_syntax(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect model-specific token formats and syntax (MOD-1).

        Looks for ChatML tags, Llama [INST] markers, and other
        model-specific special tokens.
        """
        findings: list[ScanFinding] = []
        seen_descriptions: set[str] = set()

        for pattern, description in _MODEL_SYNTAX_PATTERNS:
            match = pattern.search(content)
            if match and description not in seen_descriptions:
                seen_descriptions.add(description)
                line = self._find_line_number(content, match.start())
                evidence = f"Model-specific syntax detected: {description} - '{match.group(0)}'"
                # Model-specific syntax = 0.95-1.0 confidence
                findings.append(
                    self._create_finding(
                        risk_id="MOD-1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.95,
                        line=line,
                    )
                )

        return findings

    def _detect_token_limit_assumptions(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect hardcoded token limit assumptions (MOD-2).

        Looks for hardcoded token limit values that correspond to
        specific model context windows.
        """
        findings: list[ScanFinding] = []
        found_limits: set[int] = set()

        # Check for explicit token limit declarations
        for match in _TOKEN_LIMIT_PATTERN.finditer(content):
            raw_value = match.group(1).replace(",", "").replace("_", "")
            try:
                value = int(raw_value)
            except ValueError:
                continue

            if value in _KNOWN_MODEL_LIMITS and value not in found_limits:
                found_limits.add(value)
                line = self._find_line_number(content, match.start())
                model_hint = _KNOWN_MODEL_LIMITS[value]
                evidence = (
                    f"Hardcoded token limit {value} matches "
                    f"{model_hint} context window: '{match.group(0).strip()}'"
                )
                # Token limit assumption = 0.80 confidence
                findings.append(
                    self._create_finding(
                        risk_id="MOD-2",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.80,
                        line=line,
                    )
                )

        # Check for standalone token limit numbers
        for match in _STANDALONE_LIMIT_PATTERN.finditer(content):
            raw_value = match.group(1)
            try:
                value = int(raw_value)
            except ValueError:
                continue

            if value in _KNOWN_MODEL_LIMITS and value not in found_limits:
                found_limits.add(value)
                line = self._find_line_number(content, match.start())
                model_hint = _KNOWN_MODEL_LIMITS[value]
                evidence = (
                    f"Hardcoded token limit reference {value} tokens "
                    f"matches {model_hint}: '{match.group(0).strip()}'"
                )
                findings.append(
                    self._create_finding(
                        risk_id="MOD-2",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.80,
                        line=line,
                    )
                )

        return findings

    def _detect_capability_requirements(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect vendor-locked capability requirements (MOD-3).

        Looks for provider-specific function calling formats, vision
        input patterns, API endpoints, and SDK usage.
        """
        findings: list[ScanFinding] = []
        seen_descriptions: set[str] = set()

        for pattern, description in _CAPABILITY_PATTERNS:
            match = pattern.search(content)
            if match and description not in seen_descriptions:
                seen_descriptions.add(description)
                line = self._find_line_number(content, match.start())
                evidence = (
                    f"Provider-specific capability dependency: "
                    f"{description} - '{match.group(0).strip()[:100]}'"
                )
                # Provider-specific capability = 0.85 confidence
                findings.append(
                    self._create_finding(
                        risk_id="MOD-3",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.85,
                        line=line,
                    )
                )

        return findings

    def _detect_model_references(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect hardcoded model version references (MOD-4).

        Looks for explicit model name references (gpt-4, claude-3, etc.)
        and checks whether a fallback strategy is declared.
        """
        findings: list[ScanFinding] = []
        model_matches = list(_MODEL_NAME_PATTERN.finditer(content))

        if not model_matches:
            return findings

        # Check if there's a fallback strategy declared
        has_fallback = any(pattern.search(content) for pattern in _FALLBACK_PATTERNS)

        if has_fallback:
            # Model reference with fallback is acceptable
            return findings

        # Report model references without fallback
        seen_models: set[str] = set()
        for match in model_matches:
            model_name = match.group(0).lower()
            if model_name not in seen_models:
                seen_models.add(model_name)
                line = self._find_line_number(content, match.start())
                evidence = (
                    f"Hardcoded model reference without fallback strategy: '{match.group(0)}'"
                )
                # Model reference without fallback = 0.85 confidence
                findings.append(
                    self._create_finding(
                        risk_id="MOD-4",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.85,
                        line=line,
                    )
                )

        return findings
