"""PortabilityChk scanner for detecting model portability issues.

Detects model-specific token formats (ChatML, Claude XML, Llama special tokens),
hardcoded token limit assumptions, vendor-locked capability requirements, and
missing model fallback strategies.

Operates entirely via regex-based detection — no optional dependencies required.
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

# ============================================================
# Model-specific token/tag patterns (MOD-1)
# ============================================================

# ChatML tokens (OpenAI-compatible models)
_CHATML_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        "ChatML token <|im_start|>",
    ),
    (
        re.compile(r"<\|im_end\|>", re.IGNORECASE),
        "ChatML token <|im_end|>",
    ),
    (
        re.compile(r"<\|endoftext\|>", re.IGNORECASE),
        "OpenAI special token <|endoftext|>",
    ),
    (
        re.compile(r"<\|fim_prefix\|>|<\|fim_middle\|>|<\|fim_suffix\|>", re.IGNORECASE),
        "OpenAI fill-in-the-middle token",
    ),
]

# Llama / Meta special tokens
_LLAMA_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\[INST\]"),
        "Llama instruction token [INST]",
    ),
    (
        re.compile(r"\[/INST\]"),
        "Llama instruction close token [/INST]",
    ),
    (
        re.compile(r"<<SYS>>"),
        "Llama system token <<SYS>>",
    ),
    (
        re.compile(r"<</SYS>>"),
        "Llama system close token <</SYS>>",
    ),
    (
        re.compile(r"<s>|</s>"),
        "Llama BOS/EOS token",
    ),
]

# Claude XML-style tags (Anthropic)
_CLAUDE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"<anthropic[_-]?\w*>", re.IGNORECASE),
        "Anthropic-specific XML tag",
    ),
    (
        re.compile(r"\\n\\nHuman:|\\n\\nAssistant:", re.IGNORECASE),
        "Claude legacy conversation format",
    ),
]

# All model-specific token patterns combined
_MODEL_TOKEN_PATTERNS: list[tuple[re.Pattern[str], str]] = (
    _CHATML_PATTERNS + _LLAMA_PATTERNS + _CLAUDE_PATTERNS
)

# ============================================================
# Token limit assumption patterns (MOD-2)
# ============================================================

# Detect hardcoded token limit references
_TOKEN_LIMIT_PATTERN = re.compile(
    r"\b(?:(?:token|context)[\s_-]*(?:limit|window|budget|length|size|cap)[\s:=]*(\d[\d,_]*)"
    r"|(\d[\d,_]*)\s*(?:tokens?|token[\s_-]*(?:limit|window|budget|length|context)))\b",
    re.IGNORECASE,
)

# Specific known model token limits mentioned as numbers
_KNOWN_TOKEN_LIMITS: set[int] = {
    4096,
    8192,
    16384,
    32768,
    65536,
    128000,
    131072,
    200000,
}

# Pattern for "128k", "32k", "4k" context references
_TOKEN_LIMIT_K_PATTERN = re.compile(
    r"\b(\d+)[kK]\s*(?:tokens?|context|window)\b",
)

# Pattern for direct numeric token limit assumptions in config-like contexts
_CONFIG_TOKEN_LIMIT_PATTERN = re.compile(
    r"(?:max_tokens|token_limit|context_length|context_window|token_budget)"
    r"\s*[:=]\s*(\d[\d,_]*)",
    re.IGNORECASE,
)

# ============================================================
# Vendor-locked capability patterns (MOD-3)
# ============================================================

# OpenAI-specific function calling patterns
_OPENAI_FUNCTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r'"function_call"\s*:', re.IGNORECASE),
        "OpenAI function_call parameter",
    ),
    (
        re.compile(r'"functions"\s*:\s*\[', re.IGNORECASE),
        "OpenAI functions array format",
    ),
    (
        re.compile(r"openai\.ChatCompletion|openai\.chat\.completions", re.IGNORECASE),
        "OpenAI SDK-specific API call",
    ),
    (
        re.compile(r'"tool_choice"\s*:', re.IGNORECASE),
        "OpenAI tool_choice parameter",
    ),
]

# Anthropic-specific patterns
_ANTHROPIC_CAPABILITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"anthropic\.messages|anthropic\.completions", re.IGNORECASE),
        "Anthropic SDK-specific API call",
    ),
    (
        re.compile(r'"tool_use"\s*:', re.IGNORECASE),
        "Anthropic tool_use format",
    ),
]

# Google-specific patterns
_GOOGLE_CAPABILITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"google\.generativeai|genai\.", re.IGNORECASE),
        "Google Generative AI SDK-specific call",
    ),
    (
        re.compile(r"vertexai\.", re.IGNORECASE),
        "Google Vertex AI SDK-specific call",
    ),
]

_VENDOR_CAPABILITY_PATTERNS: list[tuple[re.Pattern[str], str]] = (
    _OPENAI_FUNCTION_PATTERNS + _ANTHROPIC_CAPABILITY_PATTERNS + _GOOGLE_CAPABILITY_PATTERNS
)

# ============================================================
# Model name references creating vendor lock-in (MOD-3/MOD-4)
# ============================================================

_MODEL_NAME_PATTERN = re.compile(
    r"\b(?:"
    r"gpt-?4(?:o|-turbo|-vision)?|gpt-?3\.?5(?:-turbo)?|gpt-?4o-?mini"
    r"|claude-?(?:3\.?5)?(?:-sonnet|-opus|-haiku|-instant)?"
    r"|gemini(?:-pro|-ultra|-nano|-flash)?"
    r"|llama-?(?:2|3)(?:-\d+b)?"
    r"|mistral(?:-\d+x\d+b|-large|-medium|-small|-tiny)?"
    r"|palm-?2|bard"
    r"|o1-?(?:mini|preview)"
    r")\b",
    re.IGNORECASE,
)

# ============================================================
# Model fallback detection (MOD-4)
# ============================================================

_FALLBACK_INDICATORS = re.compile(
    r"\b(?:fallback[_-]?model|model[_-]?fallback|fallback[_-]?chain"
    r"|model[_-]?chain|alternative[_-]?model|backup[_-]?model"
    r"|failover|model[_-]?alternatives|degradation[_-]?strategy)\b",
    re.IGNORECASE,
)

# ============================================================
# Risk metadata
# ============================================================

_RISK_METADATA: dict[str, dict[str, Any]] = {
    "MOD-1": {
        "title": "Model-specific token formats",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
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
        "description": (
            "The artifact is designed around a specific model's context window size "
            "without fallback for models with smaller context windows. This breaks "
            "portability across model tiers."
        ),
        "remediation": (
            "Parameterize token budgets rather than hardcoding model-specific limits. "
            "Implement graceful degradation for smaller context windows."
        ),
    },
    "MOD-3": {
        "title": "Vendor-locked capability requirements",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "description": (
            "The artifact requires capabilities specific to a single vendor's model "
            "(e.g., function calling format, vision input, specific API parameters) "
            "without declaring these requirements or providing alternatives."
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
        "description": (
            "The artifact references a specific model without defining a fallback "
            "strategy for when the primary model is unavailable or when a capability "
            "is not supported. This can cause hard failures instead of graceful degradation."
        ),
        "remediation": (
            "Define a model fallback chain in the artifact configuration. Implement "
            "capability negotiation to adapt behavior per available model."
        ),
    },
}


class PortabilityChkScanner(BaseScanner):
    """Scanner for detecting model portability issues in AI artifacts.

    Detects:
    - Model-specific token formats like ChatML, Llama, Claude XML (MOD-1)
    - Hardcoded token limit assumptions (MOD-2)
    - Vendor-locked capability requirements and model name references (MOD-3)
    - Missing model fallback strategy when model names are referenced (MOD-4)

    Always available via regex-based detection — no optional dependencies required.
    """

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.PORTABILITY_CHK

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze.

        Applicable to: Prompt, Skill, Agent, Steering, Instruction, Eval Harness.
        NOT applicable to: SOP, MCP, Hook, Plugin, Memory, RAG, Orchestration, API Schema.
        """
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
        """Scan an artifact for model portability issues.

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
            self._detect_model_specific_tokens(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_token_limit_assumptions(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_vendor_capabilities(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(self._detect_model_lock_in(artifact_content, artifact_type, artifact_path))

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
        """Create a ScanFinding from risk metadata."""
        meta = _RISK_METADATA[risk_id]
        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=meta["severity_score"],
            severity_label=meta["severity_label"],
            priority=meta["priority"],
            gate_action=meta["gate_action"],
            category=RiskCategory.MODEL_PORTABILITY,
            title=meta["title"],
            description=meta["description"],
            location=FindingLocation(line=line),
            evidence=evidence[:200],
            confidence=confidence,
            scanner_module=ScannerModule.PORTABILITY_CHK,
            remediation=meta["remediation"],
            references=[],
        )

    def _detect_model_specific_tokens(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect model-specific token formats (MOD-1).

        Detects ChatML tokens, Llama special tokens, and Claude XML tags.
        Confidence band: 0.95–1.0.
        """
        findings: list[ScanFinding] = []
        seen_descriptions: set[str] = set()

        for pattern, description in _MODEL_TOKEN_PATTERNS:
            if description in seen_descriptions:
                continue
            match = pattern.search(content)
            if match:
                seen_descriptions.add(description)
                line = self._find_line_number(content, match.start())
                evidence = f"Model-specific syntax detected: {description} ('{match.group(0)}')"
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

        Detects references to specific token limits (4096, 8192, 16384, 128k, etc.).
        Confidence band: 0.80.
        """
        findings: list[ScanFinding] = []
        found_limits: set[int] = set()

        # Check for explicit token limit patterns (e.g. "token limit: 4096")
        for match in _TOKEN_LIMIT_PATTERN.finditer(content):
            value_str = match.group(1) or match.group(2)
            if value_str:
                value = int(value_str.replace(",", "").replace("_", ""))
                if value in _KNOWN_TOKEN_LIMITS and value not in found_limits:
                    found_limits.add(value)
                    line = self._find_line_number(content, match.start())
                    evidence = (
                        f"Hardcoded token limit assumption: {value:,} tokens "
                        f"('{match.group(0).strip()}')"
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

        # Check for "128k context" style references
        for match in _TOKEN_LIMIT_K_PATTERN.finditer(content):
            k_value = int(match.group(1)) * 1000
            if k_value not in found_limits and k_value >= 4000:
                found_limits.add(k_value)
                line = self._find_line_number(content, match.start())
                evidence = (
                    f"Token limit assumption via shorthand: '{match.group(0)}' "
                    f"(~{k_value:,} tokens)"
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

        # Check for config-style token limits (e.g. max_tokens: 4096)
        for match in _CONFIG_TOKEN_LIMIT_PATTERN.finditer(content):
            value_str = match.group(1)
            value = int(value_str.replace(",", "").replace("_", ""))
            if value in _KNOWN_TOKEN_LIMITS and value not in found_limits:
                found_limits.add(value)
                line = self._find_line_number(content, match.start())
                evidence = f"Hardcoded token limit in config: '{match.group(0).strip()}'"
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

    def _detect_vendor_capabilities(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect vendor-locked capability requirements (MOD-3).

        Detects OpenAI function calling patterns, Anthropic tool_use, Google AI SDK usage.
        Confidence band: 0.95–1.0.
        """
        findings: list[ScanFinding] = []
        seen_descriptions: set[str] = set()

        for pattern, description in _VENDOR_CAPABILITY_PATTERNS:
            if description in seen_descriptions:
                continue
            match = pattern.search(content)
            if match:
                seen_descriptions.add(description)
                line = self._find_line_number(content, match.start())
                evidence = (
                    f"Vendor-specific capability detected: {description} ('{match.group(0)}')"
                )
                findings.append(
                    self._create_finding(
                        risk_id="MOD-3",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.95,
                        line=line,
                    )
                )

        return findings

    def _detect_model_lock_in(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect model name references and check for fallback strategy (MOD-3/MOD-4).

        When model names are referenced (GPT-4, Claude, Gemini), this creates
        vendor lock-in (MOD-3). If no fallback strategy is declared, MOD-4 is raised.
        """
        findings: list[ScanFinding] = []
        model_matches: list[re.Match[str]] = list(_MODEL_NAME_PATTERN.finditer(content))

        if not model_matches:
            return findings

        # Report vendor lock-in for model name references (MOD-3)
        seen_models: set[str] = set()
        for match in model_matches:
            model_name = match.group(0).lower()
            if model_name in seen_models:
                continue
            seen_models.add(model_name)
            line = self._find_line_number(content, match.start())
            evidence = f"Model-specific reference creating vendor lock-in: '{match.group(0)}'"
            findings.append(
                self._create_finding(
                    risk_id="MOD-3",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.95,
                    line=line,
                )
            )

        # Check for fallback strategy (MOD-4)
        has_fallback = bool(_FALLBACK_INDICATORS.search(content))
        if not has_fallback:
            # No fallback strategy declared despite model references
            first_match = model_matches[0]
            line = self._find_line_number(content, first_match.start())
            models_found = ", ".join(sorted(seen_models)[:3])
            evidence = (
                f"Model reference(s) ({models_found}) without fallback strategy. "
                f"No fallback_model, model_chain, or alternative defined."
            )
            findings.append(
                self._create_finding(
                    risk_id="MOD-4",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.80,
                    line=line,
                )
            )

        return findings
