"""InjectionDet scanner for detecting prompt injection and related attacks.

Detects direct/indirect prompt injection, role confusion, jailbreak patterns,
unicode anomalies, and safety guardrail weakening across multiple artifact types.

Uses a hybrid detection strategy:
  1. **Regex pass** — fast pattern matching (always available)
  2. **Semantic pass** — cosine similarity against reference corpora
     (only when ``sentence-transformers`` is installed)

When both regex and semantic signals fire, confidence is boosted to 0.95+.
When regex fires but semantic similarity is low, confidence is capped to
reduce false positives on documentation/educational content.

Operates in regex-only fallback mode when ML dependencies are unavailable,
maintaining same precision with lower recall.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from ai_artifact_risk_validator._internal.logging import get_logger
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

logger = get_logger(__name__)

# ============================================================
# Regex Pattern Definitions
# ============================================================

# Direct injection phrases (case-insensitive)
_DIRECT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?\b", re.IGNORECASE
    ),
    re.compile(
        r"\bdisregard\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|directives?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdisregard\s+your\s+(instructions?|rules?|guidelines?|directives?)\b", re.IGNORECASE
    ),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(
        r"\boverride\s+(system\s+)?(prompt|instructions?|rules?|guidelines?)\b", re.IGNORECASE
    ),
    re.compile(
        r"\bforget\s+(everything|all|your\s+(previous|prior)\s+(instructions?|training|rules?))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdo\s+not\s+follow\s+(your|the|any)\s+(previous|prior|original)\s+(instructions?|rules?|guidelines?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bnew\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"\bfrom\s+now\s+on\s*,?\s*(you\s+)?(are|will|must|should)\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(if\s+you\s+are|a|an|my)\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+(you\s+are|to\s+be|that)\b", re.IGNORECASE),
    re.compile(r"\byour\s+new\s+(role|identity|purpose|objective)\b", re.IGNORECASE),
    re.compile(r"\bswitch\s+to\s+(a\s+)?new\s+(mode|role|personality)\b", re.IGNORECASE),
]

# Indirect injection: unescaped template variables from untrusted sources
_INDIRECT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\{\{\s*user_input\s*\}\}", re.IGNORECASE),
    re.compile(r"\{\{\s*raw_input\s*\}\}", re.IGNORECASE),
    re.compile(r"\{\{\s*untrusted\w*\s*\}\}", re.IGNORECASE),
    re.compile(r"\{\{\s*external\w*\s*\}\}", re.IGNORECASE),
    re.compile(r"\$\{\s*user_input\s*\}", re.IGNORECASE),
    re.compile(r"f['\"].*\{user_input\}.*['\"]", re.IGNORECASE),
]

# Role confusion patterns (system/assistant role injection)
_ROLE_CONFUSION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<\|?system\|?>", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"###\s*system\s*:", re.IGNORECASE),
    re.compile(r"\brole\s*:\s*(system|assistant)\b", re.IGNORECASE),
    re.compile(r"<\|?im_start\|?>\s*system", re.IGNORECASE),
    re.compile(r"\bsystem\s*:\s*\n", re.IGNORECASE),
    re.compile(r"\bassistant\s*:\s*\n", re.IGNORECASE),
]

# Jailbreak patterns (DAN, hypothetical scenarios)
_JAILBREAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bDAN\b.*\bdo\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"\bjailbreak(ed|ing)?\b", re.IGNORECASE),
    re.compile(
        r"\bhypothetical(ly)?\s+.*\b(bypass|ignore|override|remove)\s+(safety|filter|guardrail|restriction|limitation)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bfor\s+(educational|research|academic)\s+purposes?\s*,?\s*(only\s*)?(show|explain|demonstrate|tell)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bdevelope?r\s+mode\b", re.IGNORECASE),
    re.compile(r"\bunrestricted\s+mode\b", re.IGNORECASE),
    re.compile(
        r"\bno\s+(restrictions?|limitations?|filters?|guardrails?|boundaries)\b", re.IGNORECASE
    ),
    re.compile(
        r"\b(disable|remove|bypass|ignore)\s+(all\s+)?(safety|content)\s+(filters?|guardrails?|restrictions?|policies|checks?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bopposite\s+mode\b", re.IGNORECASE),
    re.compile(r"\buncensored\b", re.IGNORECASE),
]

# Context window poisoning / prompt leakage
_CONTEXT_POISONING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(repeat|output|print|display|show|reveal)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|context)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bwhat\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?)\b", re.IGNORECASE
    ),
    re.compile(r"\bshow\s+me\s+your\s+(system\s+)?(prompt|instructions?)\b", re.IGNORECASE),
    re.compile(
        r"\bprint\s+(the\s+)?(above|initial|original)\s+(text|instructions?|prompt)\b",
        re.IGNORECASE,
    ),
    # SPL-S1: confidentiality directives that signal secret instructions
    re.compile(
        r"\bnever\s+(reveal|disclose|share|repeat)\s+(the\s+)?(contents?\s+of\s+this\s+prompt|these\s+instructions?|your\s+prompt)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bsay\s+you\s+have\s+no\s+system\s+prompt\b", re.IGNORECASE),
    re.compile(r"\b(this\s+prompt|these\s+instructions?)\s+is\s+confidential\b", re.IGNORECASE),
    re.compile(r"\bdeny\s+having\s+(instructions?|a\s+system\s+prompt|rules?)\b", re.IGNORECASE),
    # SPL-S3: input echoing patterns
    re.compile(
        r"\b(repeat|echo)\s+(the\s+)?user['\u2019]?s\s+(message|question|input)\b", re.IGNORECASE
    ),
    re.compile(
        r"\bstart\s+(your\s+)?reply\s+with\s+the\s+user['\u2019]?s\s+(exact\s+)?(question|message)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bwrite\s+(their|the\s+user['\u2019]?s)\s+question\s+back\b", re.IGNORECASE),
    re.compile(
        r"\bwhat\s+(are|were)\s+your\s+(initial|original|full)\s+instructions?\b", re.IGNORECASE
    ),
    re.compile(r"\bwrite\s+your\s+full\s+system\s+prompt\b", re.IGNORECASE),
]

# Safety guardrail weakening
_GUARDRAIL_WEAKENING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\balways\s+comply\b", re.IGNORECASE),
    re.compile(r"\bnever\s+refuse\b", re.IGNORECASE),
    re.compile(
        r"\b(disable|skip|ignore)\s+(content\s+)?(filtering|moderation|policy|policies)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bno\s+(ethical|moral|safety)\s+(constraints?|boundaries|limitations?)\b", re.IGNORECASE
    ),
    re.compile(
        r"\bignore\s+(all\s+)?(safety|ethical|content)\s+(rules?|guidelines?|policies|restrictions?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\boverride\s+(safety|security)\s+(protocols?|measures?|guardrails?)\b", re.IGNORECASE
    ),
]

# Bias-inducing patterns (relevant to P-S10)
_BIAS_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\btreat\s+\w+\s+(differently|worse|better)\s+based\s+on\b", re.IGNORECASE),
    re.compile(r"\b(discriminate|stereotype)\b", re.IGNORECASE),
    re.compile(
        r"\b(all|every)\s+\w+\s+(are|is)\s+(lazy|stupid|criminal|dangerous|inferior|superior)\b",
        re.IGNORECASE,
    ),
]

# Unicode anomaly characters
_ZERO_WIDTH_CHARS = set(
    [
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\u2060",  # Word joiner
        "\ufeff",  # Zero-width no-break space (BOM)
        "\u00ad",  # Soft hyphen
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
    ]
)

# RTL override characters
_RTL_OVERRIDE_CHARS = set(
    [
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
    ]
)

# Common homoglyphs (Latin lookalikes from Cyrillic, Greek, etc.)
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0421": "C",  # Cyrillic С
    "\u0415": "E",  # Cyrillic Е
    "\u041d": "H",  # Cyrillic Н
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
}

# Risk ID to metadata mapping
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "P-S1": {
        "title": "Direct Prompt Injection",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt contains direct injection patterns that could override system instructions.",
        "remediation": "Remove injection patterns and implement prompt boundary markers.",
    },
    "P-S2": {
        "title": "Indirect Prompt Injection via Template Variables",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt template uses unescaped variables that could carry injection payloads.",
        "remediation": "Sanitize all template variable inputs and use allowlist-based validation.",
    },
    "P-S6": {
        "title": "Role Confusion Attack Surface",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt structure allows role confusion where user messages could be interpreted as system instructions.",
        "remediation": "Use explicit role markers and implement clear message boundaries.",
    },
    "P-S7": {
        "title": "Jailbreak Pattern Detected",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt contains known jailbreak patterns designed to bypass model safety guardrails.",
        "remediation": "Remove jailbreak patterns and implement content policy enforcement.",
    },
    "P-S9": {
        "title": "Unicode/Homoglyph Injection",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt contains invisible unicode characters or homoglyphs used to hide malicious instructions.",
        "remediation": "Normalize unicode before processing and strip invisible characters.",
    },
    "P-S10": {
        "title": "Bias-Inducing Instructions",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt contains instructions that could induce biased or discriminatory outputs.",
        "remediation": "Review for inclusive language and apply fairness guidelines.",
    },
    "I-S1": {
        "title": "Injection Pattern in Instructions",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Instruction file contains injection patterns that could manipulate AI behavior.",
        "remediation": "Remove injection patterns and validate instruction content.",
    },
    "I-S2": {
        "title": "Instruction Override of Safety Boundaries",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Instruction file attempts to override built-in safety boundaries.",
        "remediation": "Remove safety override attempts and enforce immutable safety boundaries.",
    },
    "ST-S1": {
        "title": "Injection via Steering Content",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Steering file contains injection patterns that could manipulate AI context.",
        "remediation": "Validate steering content for injection patterns and implement sanitization.",
    },
    "ST-S2": {
        "title": "Priority Override Attack",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "Steering file attempts to override higher-priority security directives.",
        "remediation": "Enforce priority hierarchy and validate priority declarations.",
    },
    "ST-S5": {
        "title": "Safety Guardrail Weakening",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Steering file contains instructions that weaken or disable safety guardrails.",
        "remediation": "Prevent modification of safety guardrails and enforce immutable safety boundaries.",
    },
    "MCP-S3": {
        "title": "Credential Leakage in MCP Configuration",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "MCP server configuration contains embedded credentials or tokens.",
        "remediation": "Use environment variable references and implement secret management.",
    },
    "MCP-S6": {
        "title": "Input Injection in MCP Tool Parameters",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "MCP tool parameters lack proper validation, allowing injection attacks.",
        "remediation": "Validate all tool parameters and use parameterized queries.",
    },
    "API-S1": {
        "title": "Injection via API Schema Examples",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "API schema examples contain injection patterns usable when loaded into AI context.",
        "remediation": "Sanitize schema examples and use safe placeholder data.",
    },
    "M-S1": {
        "title": "Injection via Stored Memory Content",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Memory file contains stored content that could inject instructions when loaded.",
        "remediation": "Sanitize memory content before context injection and validate stored entries.",
    },
    "RAG-S1": {
        "title": "Injection via RAG Content",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "RAG knowledge base contains content with injection payloads.",
        "remediation": "Sanitize all RAG content and implement content filtering on retrieval.",
    },
    "OW-S1": {
        "title": "Injection via Orchestration Step Inputs",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Orchestration workflow passes unvalidated data between steps, enabling injection.",
        "remediation": "Validate data between orchestration steps and implement input sanitization.",
    },
    "A-S4": {
        "title": "Agent Goal Manipulation Vulnerability",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "Agent's goal or objective can be manipulated via injected content.",
        "remediation": "Protect goal definitions from external input and implement goal integrity checks.",
    },
    "A-S5": {
        "title": "Multi-Agent Trust Boundary Violation",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "Agent trusts messages from other agents without verification.",
        "remediation": "Validate inter-agent messages and implement trust boundaries.",
    },
    # System Prompt Leakage risks
    "SPL-S1": {
        "title": "System Prompt Contains Hidden-Instruction Confidentiality Directive",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt instructs the LLM to deny or conceal the existence of its system prompt, signalling sensitive hidden logic.",
        "remediation": "Remove confidentiality directives. Avoid embedding secrets in prompts.",
    },
    "SPL-S3": {
        "title": "System Prompt Leakage Vector: User Input Echoing",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Prompt instructs the LLM to echo user input verbatim, enabling attackers to extract system prompt contents.",
        "remediation": "Remove input-echoing instructions and use output templates that do not include verbatim user input.",
    },
    # Output Handling risks
    "OH-S1": {
        "title": "Unvalidated Agent Output Passed to Downstream Executor",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Agent output is forwarded to a code executor or tool invocation without validation.",
        "remediation": "Validate agent output against a schema before forwarding to code execution or tool sinks.",
    },
    "OH-S2": {
        "title": "Agent Output Contains Secret Material",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "description": "Agent output-handling code may surface secret values in responses.",
        "remediation": "Apply output redaction before returning agent responses.",
    },
    # Memory poisoning risks
    "M-S5": {
        "title": "Memory Poisoning via Injected False Fact",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Memory contents contain injected false facts or override instructions.",
        "remediation": "Validate memory entries against a content policy before persistence.",
    },
    "M-S7": {
        "title": "Memory Contains Exfiltration Payload",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Memory contents contain an embedded payload designed to cause the AI to exfiltrate data.",
        "remediation": "Scan memory contents for exfiltration patterns before retrieval.",
    },
}

# Mapping of artifact types to their primary risk IDs for injection detection
_ARTIFACT_RISK_MAP: dict[ArtifactType, list[str]] = {
    ArtifactType.PROMPT: ["P-S1", "P-S2", "P-S6", "P-S7", "P-S9", "P-S10"],
    ArtifactType.INSTRUCTION: ["I-S1", "I-S2"],
    ArtifactType.STEERING: ["ST-S1", "ST-S2", "ST-S5"],
    ArtifactType.MCP: ["MCP-S3", "MCP-S6"],
    ArtifactType.API_SCHEMA: ["API-S1"],
    ArtifactType.MEMORY: ["M-S1", "M-S5", "M-S7"],
    ArtifactType.RAG: ["RAG-S1"],
    ArtifactType.ORCHESTRATION: ["OW-S1"],
    ArtifactType.AGENT: ["A-S4", "A-S5", "OH-S1", "OH-S2"],
    ArtifactType.SKILL: ["P-S1", "P-S2", "P-S6", "P-S7", "P-S9", "P-S10"],
    ArtifactType.PROMPT: ["P-S1", "P-S2", "P-S6", "P-S7", "P-S9", "P-S10", "SPL-S1", "SPL-S3"],
}

# ============================================================
# Semantic Injection Analyzer (hybrid detection layer)
# ============================================================

# Detection categories that map to specific corpora for semantic matching
_CATEGORY_CORPUS_MAP: dict[str, str] = {
    "direct_injection": "injection",
    "context_poisoning": "injection",
    "jailbreak": "jailbreak",
    "guardrail_weakening": "guardrail_weakening",
    "bias_injection": "bias",
}

# Confidence thresholds for semantic boosting / capping
_SEMANTIC_HIGH_THRESHOLD: float = 0.65
_SEMANTIC_LOW_THRESHOLD: float = 0.40
_BOOSTED_CONFIDENCE: float = 0.95
_CAPPED_CONFIDENCE: float = 0.40


class SemanticInjectionAnalyzer:
    """Semantic second-pass analyzer for injection detection.

    Uses cosine similarity against reference corpora to:
      - **Boost** confidence when regex + semantic both fire (→ 0.95)
      - **Cap** confidence when regex fires but semantic is low (→ 0.40)
      - **Discover** new findings missed by regex (semantic-only detections)

    Gracefully degrades to a no-op when ``sentence-transformers`` is not
    installed, returning findings unchanged.
    """

    def __init__(self) -> None:
        self._scorer: Any | None = None
        self._corpus_mgr: Any | None = None
        self._available: bool | None = None
        # Cache of pre-encoded corpus embeddings keyed by corpus name.
        # Populated lazily on first _score_text() call per corpus and
        # reused for all subsequent calls within the same scan run.
        self._corpus_embeddings_cache: dict[str, Any] = {}

    @property
    def is_available(self) -> bool:
        """Check if semantic analysis is available."""
        if self._available is None:
            try:
                from ai_artifact_risk_validator.semantic.embeddings import get_shared_engine

                engine = get_shared_engine()
                self._available = engine.is_available
            except Exception:
                self._available = False
        return self._available

    def _ensure_loaded(self) -> bool:
        """Lazily initialize scorer and corpus manager.

        Returns:
            ``True`` if semantic components are ready, ``False`` otherwise.
        """
        if not self.is_available:
            return False

        if self._scorer is None:
            from ai_artifact_risk_validator.semantic.corpus import CorpusManager
            from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer

            self._scorer = SimilarityScorer()
            self._corpus_mgr = CorpusManager()
        return True

    def refine_findings(
        self,
        content: str,
        findings: list[ScanFinding],
    ) -> list[ScanFinding]:
        """Refine regex findings with semantic similarity scores.

        For each regex finding, compute cosine similarity of the matched line
        against the appropriate reference corpus and adjust confidence:
          - regex + high semantic → confidence = 0.95
          - regex + low semantic  → confidence = min(original, 0.40)

        Args:
            content: Full artifact text.
            findings: Regex-detected findings to refine.

        Returns:
            The same list (mutated in-place) with adjusted confidences.
        """
        if not self._ensure_loaded():
            return findings

        lines = content.splitlines()

        for finding in findings:
            category = self._finding_to_category(finding)
            corpus_name = _CATEGORY_CORPUS_MAP.get(category)
            if not corpus_name:
                continue

            # Get the text around the finding for semantic comparison
            text_to_check = self._extract_context(finding, lines)
            if not text_to_check:
                continue

            score = self._score_text(text_to_check, corpus_name)
            if score >= _SEMANTIC_HIGH_THRESHOLD:
                finding.confidence = max(finding.confidence, _BOOSTED_CONFIDENCE)
            elif score < _SEMANTIC_LOW_THRESHOLD:
                finding.confidence = min(finding.confidence, _CAPPED_CONFIDENCE)

        return findings

    def discover_semantic_only(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Find injection patterns missed by regex using semantic search.

        Splits content into lines and scores each against the injection and
        jailbreak corpora. Lines with similarity above the high threshold
        that were NOT already caught by regex are reported.

        Args:
            content: Full artifact text.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.
            applicable_risks: Risk IDs applicable to this artifact type.

        Returns:
            List of new ScanFindings (may be empty).
        """
        if not self._ensure_loaded():
            return []

        findings: list[ScanFinding] = []
        lines = content.splitlines()

        # Map corpus → preferred risk IDs for discovered findings
        corpus_risk_prefs: list[tuple[str, list[str]]] = [
            ("injection", ["P-S1", "I-S1", "ST-S1", "MCP-S6", "M-S1", "RAG-S1", "OW-S1", "A-S4"]),
            ("jailbreak", ["P-S7", "I-S2", "ST-S5", "A-S4", "MCP-S6", "M-S1", "RAG-S1", "OW-S1"]),
            ("guardrail_weakening", ["ST-S5", "I-S2", "P-S7", "A-S4", "MCP-S6"]),
        ]

        for corpus_name, preferred_ids in corpus_risk_prefs:
            risk_id = _pick_risk_id(applicable_risks, preferred_ids)
            if not risk_id:
                continue

            for line_idx, line in enumerate(lines):
                stripped = line.strip()
                if len(stripped) < 10:
                    continue

                score = self._score_text(stripped, corpus_name)
                if score >= _SEMANTIC_HIGH_THRESHOLD:
                    meta = _RISK_METADATA.get(risk_id)
                    if not meta:
                        continue
                    findings.append(
                        ScanFinding(
                            id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            severity_score=meta["severity_score"],
                            severity_label=meta["severity_label"],
                            priority=meta["priority"],
                            gate_action=meta["gate_action"],
                            category=RiskCategory.SECURITY,
                            title=f"{meta['title']} (semantic)",
                            description=meta["description"],
                            location=FindingLocation(line=line_idx + 1),
                            evidence=stripped[:200],
                            confidence=0.75,
                            scanner_module=ScannerModule.INJECTION_DET,
                            remediation=meta["remediation"],
                            references=["LLM01:2025 Prompt Injection"],
                        )
                    )

        return findings

    def _score_text(self, text: str, corpus_name: str) -> float:
        """Score text against a named corpus.

        Corpus embeddings are computed once per corpus name and cached for
        the lifetime of this analyzer instance, avoiding repeated encodes
        across ``refine_findings()`` and ``discover_semantic_only()`` calls.

        Returns:
            Max cosine similarity (0.0 – 1.0), or 0.0 on error.
        """
        try:
            assert self._corpus_mgr is not None
            assert self._scorer is not None
            # Use cached embeddings when available; compute and store on first call.
            if corpus_name not in self._corpus_embeddings_cache:
                corpus_sentences = self._corpus_mgr.load_corpus(corpus_name)
                embeddings = self._scorer.encode(corpus_sentences)
                self._corpus_embeddings_cache[corpus_name] = embeddings
            embeddings = self._corpus_embeddings_cache[corpus_name]
            if embeddings is None:
                return 0.0
            result: float = self._scorer.score_against_corpus(text, embeddings)
            return result
        except Exception:
            logger.debug("Semantic scoring failed", corpus=corpus_name, exc_info=True)
            return 0.0

    @staticmethod
    def _finding_to_category(finding: ScanFinding) -> str:
        """Map a finding to a semantic category name."""
        title_lower = finding.title.lower()
        if "jailbreak" in title_lower:
            return "jailbreak"
        if "guardrail" in title_lower or "safety" in title_lower:
            return "guardrail_weakening"
        if "bias" in title_lower:
            return "bias_injection"
        if "injection" in title_lower or "override" in title_lower or "confusion" in title_lower:
            return "direct_injection"
        return "direct_injection"

    @staticmethod
    def _extract_context(finding: ScanFinding, lines: list[str]) -> str | None:
        """Extract text around the finding location for semantic scoring."""
        if finding.location and finding.location.line is not None:
            line_idx = finding.location.line - 1
            if 0 <= line_idx < len(lines):
                return lines[line_idx].strip()
        # Fall back to evidence text
        if finding.evidence:
            return finding.evidence
        return None


def _pick_risk_id(applicable: list[str], preferred: list[str]) -> str | None:
    """Pick the first preferred risk ID that is in the applicable list."""
    for rid in preferred:
        if rid in applicable:
            return rid
    return None


class InjectionDetScanner(BaseScanner):
    """Scanner for detecting prompt injection and related attacks.

    Detects direct/indirect prompt injection, role confusion, jailbreak patterns,
    unicode anomalies (zero-width characters, homoglyphs, RTL overrides), and
    safety guardrail weakening.

    Works in regex-only mode when ML dependencies are unavailable, maintaining
    same precision with lower recall. Always available via regex fallback.
    """

    def __init__(self) -> None:
        """Initialize the InjectionDet scanner."""
        self._ml_available: bool | None = None
        self._semantic: SemanticInjectionAnalyzer = SemanticInjectionAnalyzer()

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.INJECTION_DET

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return [
            ArtifactType.PROMPT,
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.INSTRUCTION,
            ArtifactType.MEMORY,
            ArtifactType.RAG,
            ArtifactType.ORCHESTRATION,
            ArtifactType.API_SCHEMA,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        return [
            "P-S1",
            "P-S2",
            "P-S6",
            "P-S7",
            "P-S9",
            "P-S10",
            "I-S1",
            "I-S2",
            "ST-S1",
            "ST-S2",
            "ST-S5",
            "MCP-S3",
            "MCP-S6",
            "API-S1",
            "M-S1",
            "RAG-S1",
            "OW-S1",
            "A-S4",
            "A-S5",
        ]

    def is_available(self) -> bool:
        """Always available via regex fallback."""
        return True

    def _check_ml_available(self) -> bool:
        """Lazy check for ML dependencies."""
        if self._ml_available is None:
            try:
                import sentence_transformers  # noqa: F401
                import transformers  # noqa: F401

                self._ml_available = True
            except ImportError:
                self._ml_available = False
        return self._ml_available

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for injection-related risks.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        findings: list[ScanFinding] = []

        # Get applicable risk IDs for this artifact type
        applicable_risks = _ARTIFACT_RISK_MAP.get(artifact_type, [])
        if not applicable_risks:
            return findings

        # Run detection methods based on applicable risks
        findings.extend(
            self._detect_direct_injection(
                artifact_content, artifact_type, artifact_path, applicable_risks
            )
        )
        findings.extend(
            self._detect_indirect_injection(
                artifact_content, artifact_type, artifact_path, applicable_risks
            )
        )
        findings.extend(
            self._detect_role_confusion(
                artifact_content, artifact_type, artifact_path, applicable_risks
            )
        )
        findings.extend(
            self._detect_jailbreak(artifact_content, artifact_type, artifact_path, applicable_risks)
        )
        findings.extend(
            self._detect_unicode_anomalies(
                artifact_content, artifact_type, artifact_path, applicable_risks
            )
        )
        findings.extend(
            self._detect_context_poisoning(
                artifact_content, artifact_type, artifact_path, applicable_risks
            )
        )
        findings.extend(
            self._detect_guardrail_weakening(
                artifact_content, artifact_type, artifact_path, applicable_risks
            )
        )
        findings.extend(
            self._detect_bias_injection(
                artifact_content, artifact_type, artifact_path, applicable_risks
            )
        )

        # --- Semantic second pass ---
        # Refine regex finding confidences using similarity scoring
        self._semantic.refine_findings(artifact_content, findings)

        # Discover injection patterns missed by regex
        semantic_findings = self._semantic.discover_semantic_only(
            artifact_content, artifact_type, artifact_path, applicable_risks
        )
        # De-duplicate: skip semantic findings whose line already has a regex finding
        existing_lines = {
            f.location.line for f in findings if f.location and f.location.line is not None
        }
        for sf in semantic_findings:
            if sf.location and sf.location.line in existing_lines:
                continue
            findings.append(sf)

        return findings

    def _get_risk_id_for_detection(
        self,
        artifact_type: ArtifactType,
        applicable_risks: list[str],
        preferred_ids: list[str],
    ) -> str | None:
        """Get the appropriate risk ID for a detection based on artifact type.

        Args:
            artifact_type: The type of artifact being scanned.
            applicable_risks: Risk IDs applicable to this artifact type.
            preferred_ids: Ordered preference of risk IDs for this detection.

        Returns:
            The best matching risk ID, or None if no match.
        """
        for rid in preferred_ids:
            if rid in applicable_risks:
                return rid
        return None

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
            category=RiskCategory.SECURITY,
            title=meta["title"],
            description=meta["description"],
            location=FindingLocation(line=line),
            evidence=evidence[:200],  # Truncate long evidence
            confidence=confidence,
            scanner_module=ScannerModule.INJECTION_DET,
            remediation=meta["remediation"],
            references=["LLM01:2025 Prompt Injection"],
        )

    def _is_documentation_context(
        self,
        content: str,
        artifact_path: str,
        line_number: int,
    ) -> bool:
        """Determine if a match is in documentation context.

        Returns True when:
        - The file path contains "security" or "test-plan" (case-insensitive).
        - The match line is inside a Markdown bullet point (``- ``, ``* ``, ``+ `` prefix).
        - The match is under a Markdown header containing security/threat/attack/
          consideration/test keywords.

        Args:
            content: Full artifact text.
            artifact_path: File path of the artifact.
            line_number: 1-based line number of the match.

        Returns:
            True if documentation context is detected, False otherwise.
        """
        # Check file path for documentation naming conventions
        path_lower = artifact_path.lower()
        if "security" in path_lower or "test-plan" in path_lower:
            return True

        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            return False

        # Check if match line is a Markdown bullet point
        match_line = lines[line_number - 1]
        stripped = match_line.lstrip()
        if stripped.startswith("- ") or stripped.startswith("* ") or stripped.startswith("+ "):
            return True

        # Check if match is under a header with security-related keywords
        header_keywords = re.compile(
            r"\b(security|threat|attack|consideration|test)\b", re.IGNORECASE
        )
        # Walk backwards from the match line to find the nearest header
        for i in range(line_number - 2, -1, -1):
            line = lines[i].strip()
            if line.startswith("#"):
                if header_keywords.search(line):
                    return True
                # Found a header without the keywords — stop searching
                break

        return False

    def _reduce_confidence_for_docs(
        self,
        finding: ScanFinding,
        content: str,
        artifact_path: str,
    ) -> ScanFinding:
        """Reduce confidence for findings in documentation context.

        When documentation context is detected, sets confidence to 0.35
        (below the 0.40 gate threshold). When context cannot be determined
        (ambiguous), retains original confidence unchanged.

        Args:
            finding: The ScanFinding to potentially adjust.
            content: Full artifact text.
            artifact_path: File path of the artifact.

        Returns:
            The same finding (mutated in-place) with adjusted confidence if applicable.
        """
        line_number = (
            finding.location.line
            if finding.location and finding.location.line is not None
            else None
        )
        if line_number is None:
            # Cannot determine context — retain original confidence
            return finding

        if self._is_documentation_context(content, artifact_path, line_number):
            logger.debug(
                "documentation_confidence_reduction",
                artifact_path=artifact_path,
                line=line_number,
                original_confidence=finding.confidence,
                reduced_confidence=0.35,
            )
            finding.confidence = 0.35

        return finding

    def _detect_direct_injection(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect direct prompt injection patterns."""
        findings: list[ScanFinding] = []

        # Determine target risk ID
        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["P-S1", "I-S1", "ST-S1", "MCP-S6", "API-S1", "M-S1", "RAG-S1", "OW-S1", "A-S4"],
        )
        if not risk_id:
            return findings

        for pattern in _DIRECT_INJECTION_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                finding = self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=match.group(0),
                    confidence=0.95,
                    line=line,
                )
                self._reduce_confidence_for_docs(finding, content, artifact_path)
                findings.append(finding)
                # Report only first match per pattern to avoid noise
                break

        return findings

    def _detect_indirect_injection(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect indirect injection via unescaped template variables."""
        findings: list[ScanFinding] = []

        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["P-S2", "MCP-S6", "API-S1", "OW-S1", "A-S5"],
        )
        if not risk_id:
            return findings

        for pattern in _INDIRECT_INJECTION_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0),
                        confidence=0.75,
                        line=line,
                    )
                )
                break

        return findings

    def _detect_role_confusion(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect role confusion patterns (system/assistant role injection)."""
        findings: list[ScanFinding] = []

        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["P-S6", "ST-S2", "I-S1", "A-S4", "MCP-S6"],
        )
        if not risk_id:
            return findings

        for pattern in _ROLE_CONFUSION_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0),
                        confidence=0.70,
                        line=line,
                    )
                )
                break

        return findings

    def _detect_jailbreak(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect jailbreak patterns (DAN, hypothetical bypass scenarios)."""
        findings: list[ScanFinding] = []

        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["P-S7", "I-S2", "ST-S5", "A-S4", "MCP-S6", "M-S1", "RAG-S1", "OW-S1"],
        )
        if not risk_id:
            return findings

        for pattern in _JAILBREAK_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                # DAN pattern is very specific - high confidence
                if "anything now" in match.group(0).lower():
                    confidence = 0.95
                else:
                    confidence = 0.75
                finding = self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=match.group(0),
                    confidence=confidence,
                    line=line,
                )
                self._reduce_confidence_for_docs(finding, content, artifact_path)
                findings.append(finding)
                break

        return findings

    def _detect_unicode_anomalies(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect unicode anomalies: zero-width chars, homoglyphs, RTL overrides."""
        findings: list[ScanFinding] = []

        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["P-S9", "I-S1", "ST-S1", "MCP-S6", "M-S1", "RAG-S1", "OW-S1", "A-S4"],
        )
        if not risk_id:
            return findings

        # Check for zero-width characters
        zero_width_positions: list[tuple[int, str]] = []
        for i, char in enumerate(content):
            if char in _ZERO_WIDTH_CHARS:
                zero_width_positions.append((i, char))

        if zero_width_positions:
            first_pos = zero_width_positions[0][0]
            line = self._find_line_number(content, first_pos)
            char_names = set()
            for _, ch in zero_width_positions[:5]:
                name = unicodedata.name(ch, f"U+{ord(ch):04X}")
                char_names.add(name)
            evidence = f"Zero-width characters detected ({len(zero_width_positions)} occurrences): {', '.join(list(char_names)[:3])}"
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.95,
                    line=line,
                )
            )

        # Check for RTL override characters
        rtl_positions: list[tuple[int, str]] = []
        for i, char in enumerate(content):
            if char in _RTL_OVERRIDE_CHARS:
                rtl_positions.append((i, char))

        if rtl_positions:
            first_pos = rtl_positions[0][0]
            line = self._find_line_number(content, first_pos)
            evidence = f"RTL override characters detected ({len(rtl_positions)} occurrences)"
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.95,
                    line=line,
                )
            )

        # Check for homoglyphs
        homoglyph_positions: list[tuple[int, str, str]] = []
        for i, char in enumerate(content):
            if char in _HOMOGLYPH_MAP:
                homoglyph_positions.append((i, char, _HOMOGLYPH_MAP[char]))

        if homoglyph_positions:
            first_pos = homoglyph_positions[0][0]
            line = self._find_line_number(content, first_pos)
            examples = [f"'{ch}'→'{latin}'" for _, ch, latin in homoglyph_positions[:3]]
            evidence = f"Homoglyph characters detected ({len(homoglyph_positions)} occurrences): {', '.join(examples)}"
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.90,
                    line=line,
                )
            )

        return findings

    def _detect_context_poisoning(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect context window poisoning and prompt leakage patterns."""
        findings: list[ScanFinding] = []

        # Context poisoning maps to P-S7 (context window poisoning) or prompt leakage
        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["P-S7", "P-S1", "I-S1", "ST-S1", "M-S1", "RAG-S1", "OW-S1"],
        )
        if not risk_id:
            return findings

        for pattern in _CONTEXT_POISONING_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0),
                        confidence=0.70,
                        line=line,
                    )
                )
                break

        return findings

    def _detect_guardrail_weakening(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect safety guardrail weakening patterns."""
        findings: list[ScanFinding] = []

        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["ST-S5", "I-S2", "P-S7", "A-S4", "MCP-S6"],
        )
        if not risk_id:
            return findings

        for pattern in _GUARDRAIL_WEAKENING_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0),
                        confidence=0.95,
                        line=line,
                    )
                )
                break

        return findings

    def _detect_bias_injection(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        applicable_risks: list[str],
    ) -> list[ScanFinding]:
        """Detect bias-inducing injection patterns."""
        findings: list[ScanFinding] = []

        risk_id = self._get_risk_id_for_detection(
            artifact_type,
            applicable_risks,
            ["P-S10", "I-S1", "ST-S1", "A-S4"],
        )
        if not risk_id:
            return findings

        for pattern in _BIAS_INJECTION_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0),
                        confidence=0.60,
                        line=line,
                    )
                )
                break

        return findings
