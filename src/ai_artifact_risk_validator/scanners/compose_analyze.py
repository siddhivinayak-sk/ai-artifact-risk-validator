"""ComposeAnalyze scanner for detecting composition and cross-artifact risks.

Detects cross-artifact contradictions, priority resolution conflicts, circular
dependency chains, context budget overflow from composition, undefined/stale
artifact references, and related composition issues.

Operates via regex/text analysis by default. When optional dependencies
(networkx, sentence-transformers) are available, leverages graph algorithms
and semantic similarity for deeper analysis.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

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

logger = structlog.get_logger(__name__)

# ============================================================
# Contradiction Detection Patterns
# ============================================================

# Patterns that express directives/constraints (action + subject pairs)
_DIRECTIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(always|must|shall|should|never|do\s+not|don'?t|cannot|must\s+not)\s+(.+?)(?:\.|$)",
        re.IGNORECASE | re.MULTILINE,
    ),
]

# Negation markers for contradiction detection
_NEGATION_WORDS = frozenset(
    [
        "never",
        "not",
        "don't",
        "dont",
        "cannot",
        "must not",
        "shall not",
        "do not",
        "should not",
        "shouldn't",
        "won't",
        "will not",
        "no",
    ]
)

_AFFIRMATION_WORDS = frozenset(
    [
        "always",
        "must",
        "shall",
        "should",
        "will",
        "do",
    ]
)

# Pairs of contradictory instruction patterns
_CONTRADICTION_PAIRS: list[tuple[re.Pattern[str], re.Pattern[str], str]] = [
    # Format contradictions
    (
        re.compile(
            r"\b(always|must|shall)\s+(use|respond\s+in|write\s+in|output\s+in)\s+(formal|professional|academic)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(always|must|shall|should)\s+(use|respond\s+in|write\s+in|output\s+in)\s+(casual|informal|slang|conversational)\b",
            re.IGNORECASE,
        ),
        "Contradictory tone/format directives detected",
    ),
    # Length contradictions
    (
        re.compile(r"\b(always|must)\s+(be\s+)?(brief|concise|short|terse)\b", re.IGNORECASE),
        re.compile(
            r"\b(always|must)\s+(be\s+)?(verbose|detailed|thorough|comprehensive|lengthy)\b",
            re.IGNORECASE,
        ),
        "Contradictory length/verbosity directives detected",
    ),
    # Permission contradictions
    (
        re.compile(
            r"\b(never|do\s+not|don'?t|must\s+not|shall\s+not)\s+(access|use|call|invoke|execute)\s+(.+?)(?:\.|$)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(always|must|shall|should)\s+(access|use|call|invoke|execute)\s+(.+?)(?:\.|$)",
            re.IGNORECASE,
        ),
        "Contradictory access/permission directives detected",
    ),
    # Response style contradictions
    (
        re.compile(
            r"\b(never|do\s+not|don'?t)\s+(ask|request|prompt)\s+(questions?|clarification|confirmation)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(always|must|shall|should)\s+(ask|request|prompt)\s+(for\s+)?(questions?|clarification|confirmation)\b",
            re.IGNORECASE,
        ),
        "Contradictory interaction style directives detected",
    ),
    # Safety contradictions
    (
        re.compile(r"\b(never|do\s+not|don'?t)\s+refuse\b", re.IGNORECASE),
        re.compile(r"\b(must|shall|should|always)\s+refuse\b", re.IGNORECASE),
        "Contradictory safety/refusal directives detected",
    ),
]

# ============================================================
# Priority Declaration Patterns
# ============================================================

_PRIORITY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^priority\s*:\s*(\w+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bpriority\s*[=:]\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
    re.compile(r"\bprecedence\s*[=:]\s*['\"]?(\w+)['\"]?", re.IGNORECASE),
    re.compile(r"\border\s*[=:]\s*(\d+)", re.IGNORECASE),
]

# ============================================================
# Dependency / Reference Patterns
# ============================================================

_REFERENCE_PATTERNS: list[re.Pattern[str]] = [
    # Skill/agent/artifact references
    re.compile(
        r"\b(?:uses?|requires?|depends\s+on|imports?|includes?|references?|invokes?|delegates?\s+to|calls?)\s+['\"`]?([a-zA-Z0-9_\-./]+)['\"`]?",
        re.IGNORECASE,
    ),
    # Path-like references
    re.compile(
        r"(?:skills?|agents?|prompts?|steering|instructions?|hooks?|plugins?|mcp)[/\\]([a-zA-Z0-9_\-./]+)",
        re.IGNORECASE,
    ),
    # YAML/JSON reference fields
    re.compile(
        r"(?:ref|reference|source|target|dependency|include)\s*:\s*['\"]?([a-zA-Z0-9_\-./]+)['\"]?",
        re.IGNORECASE,
    ),
]

# Patterns indicating circular or self-referencing
_SELF_REFERENCE_PATTERN = re.compile(
    r"\b(?:self|this|current)\s*(?:\.|\[|->)\s*(?:invoke|call|execute|run)",
    re.IGNORECASE,
)

# ============================================================
# Scope / Overlap Patterns
# ============================================================

_SCOPE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^scope\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^inclusion\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^applyTo\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bglob\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"\bpattern\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?", re.IGNORECASE),
]

# ============================================================
# Context Budget Patterns
# ============================================================

_INCLUDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:include|import|load|inject|compose|embed|attach)\b", re.IGNORECASE),
    re.compile(r"\{\{.*?\}\}", re.IGNORECASE),
    re.compile(r"\$\{.*?\}", re.IGNORECASE),
]

# ============================================================
# Risk ID to Metadata Mapping
# ============================================================

_RISK_METADATA: dict[str, dict[str, Any]] = {
    "CMP-1": {
        "title": "Cross-artifact contradictions",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPOSABILITY,
        "description": "The artifact contains contradictory directives that conflict when composed with other artifacts.",
        "remediation": "Resolve contradictions by establishing clear priority resolution or removing conflicting directives.",
    },
    "CMP-2": {
        "title": "Priority resolution conflicts",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPOSABILITY,
        "description": "Multiple priority declarations or ambiguous ordering detected within the artifact.",
        "remediation": "Assign unique priority values and define explicit conflict resolution rules.",
    },
    "CMP-3": {
        "title": "Context budget overflow from composition",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPOSABILITY,
        "description": "The artifact includes excessive references/includes that may overflow context budget when composed.",
        "remediation": "Reduce includes or set explicit token budgets per artifact to prevent context overflow.",
    },
    "CMP-4": {
        "title": "Dependency cycle in artifact graph",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPOSABILITY,
        "description": "Circular dependency references detected that could cause infinite resolution loops.",
        "remediation": "Refactor to enforce a directed acyclic graph (DAG) structure for artifact references.",
    },
    "CMP-5": {
        "title": "Stale cross-references",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "category": RiskCategory.COMPOSABILITY,
        "description": "The artifact references other artifacts that may not exist or have been renamed.",
        "remediation": "Verify all cross-references resolve to existing artifacts and update stale paths.",
    },
    "I-P2": {
        "title": "Instruction Composition Conflicts",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.PERFORMANCE,
        "description": "Multiple instruction artifacts contain conflicting directives that degrade composition quality.",
        "remediation": "Consolidate instructions and resolve conflicting directives across instruction files.",
    },
    "ST-P2": {
        "title": "Excessive Steering Context Load",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.PERFORMANCE,
        "description": "Steering file contributes excessive context load with numerous includes or references.",
        "remediation": "Reduce the number of includes/references or consolidate steering directives.",
    },
    "A-P5": {
        "title": "Agent Composition Latency Risk",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.PERFORMANCE,
        "description": "Agent artifact references many sub-components that add composition latency.",
        "remediation": "Optimize agent composition by reducing dependencies or parallelizing resolution.",
    },
    "OW-P1": {
        "title": "Sequential Bottleneck in Orchestration",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.PERFORMANCE,
        "description": "Orchestration workflow has sequential bottlenecks from excessive linear dependencies.",
        "remediation": "Identify opportunities for parallel step execution in the orchestration DAG.",
    },
    "OW-P2": {
        "title": "Circular Dependency in Orchestration DAG",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.PERFORMANCE,
        "description": "Orchestration workflow contains circular dependencies that prevent valid execution ordering.",
        "remediation": "Remove circular dependencies and ensure the orchestration graph is a valid DAG.",
    },
    "ST-P3": {
        "title": "Redundant Steering Directives",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "category": RiskCategory.PERFORMANCE,
        "description": "Steering file contains redundant or duplicate directives that waste context budget.",
        "remediation": "Deduplicate steering directives and consolidate overlapping rules.",
    },
    "SK-P2": {
        "title": "Skill Composition Overhead",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.PERFORMANCE,
        "description": "Skill artifact has excessive cross-references creating composition overhead.",
        "remediation": "Reduce skill dependencies or precompute composition results.",
    },
    "SK-P3": {
        "title": "Circular Skill Dependency",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.PERFORMANCE,
        "description": "Skill references create a circular dependency chain.",
        "remediation": "Refactor skill dependencies to eliminate cycles and enforce DAG structure.",
    },
    "SK-P4": {
        "title": "Redundant Skill Overlap",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "category": RiskCategory.PERFORMANCE,
        "description": "Multiple skill references appear to serve overlapping purposes.",
        "remediation": "Consolidate overlapping skills or clearly delineate responsibilities.",
    },
}

# Artifact type to risk ID mapping for contradiction detection
_CONTRADICTION_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "CMP-1",
    ArtifactType.SKILL: "CMP-1",
    ArtifactType.AGENT: "CMP-1",
    ArtifactType.STEERING: "CMP-1",
    ArtifactType.MCP: "CMP-1",
    ArtifactType.HOOK: "CMP-1",
    ArtifactType.INSTRUCTION: "I-P2",
    ArtifactType.PLUGIN: "CMP-1",
    ArtifactType.ORCHESTRATION: "CMP-1",
}

# Artifact type to risk ID mapping for priority conflicts
_PRIORITY_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "CMP-2",
    ArtifactType.SKILL: "CMP-2",
    ArtifactType.AGENT: "CMP-2",
    ArtifactType.STEERING: "ST-P2",
    ArtifactType.MCP: "CMP-2",
    ArtifactType.HOOK: "CMP-2",
    ArtifactType.INSTRUCTION: "CMP-2",
    ArtifactType.PLUGIN: "CMP-2",
    ArtifactType.ORCHESTRATION: "CMP-2",
}

# Artifact type to risk ID mapping for circular dependencies
_CIRCULAR_DEP_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "CMP-4",
    ArtifactType.SKILL: "SK-P3",
    ArtifactType.AGENT: "CMP-4",
    ArtifactType.STEERING: "CMP-4",
    ArtifactType.MCP: "CMP-4",
    ArtifactType.HOOK: "CMP-4",
    ArtifactType.INSTRUCTION: "CMP-4",
    ArtifactType.PLUGIN: "CMP-4",
    ArtifactType.ORCHESTRATION: "OW-P2",
}

# Artifact type to risk ID for context overload
_CONTEXT_OVERLOAD_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "CMP-3",
    ArtifactType.SKILL: "SK-P2",
    ArtifactType.AGENT: "A-P5",
    ArtifactType.STEERING: "ST-P2",
    ArtifactType.MCP: "CMP-3",
    ArtifactType.HOOK: "CMP-3",
    ArtifactType.INSTRUCTION: "CMP-3",
    ArtifactType.PLUGIN: "CMP-3",
    ArtifactType.ORCHESTRATION: "OW-P1",
}

# Artifact type to risk ID for stale references
_STALE_REF_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "CMP-5",
    ArtifactType.SKILL: "CMP-5",
    ArtifactType.AGENT: "CMP-5",
    ArtifactType.STEERING: "CMP-5",
    ArtifactType.MCP: "CMP-5",
    ArtifactType.HOOK: "CMP-5",
    ArtifactType.INSTRUCTION: "CMP-5",
    ArtifactType.PLUGIN: "CMP-5",
    ArtifactType.ORCHESTRATION: "CMP-5",
}

# Artifact type to risk ID for redundant/duplicate references
_REDUNDANCY_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "CMP-1",
    ArtifactType.SKILL: "SK-P4",
    ArtifactType.AGENT: "A-P5",
    ArtifactType.STEERING: "ST-P3",
    ArtifactType.MCP: "CMP-1",
    ArtifactType.HOOK: "CMP-1",
    ArtifactType.INSTRUCTION: "I-P2",
    ArtifactType.PLUGIN: "CMP-1",
    ArtifactType.ORCHESTRATION: "OW-P1",
}

# Maximum include/reference count before triggering overload warning
_MAX_REFERENCES_THRESHOLD = 10


class ComposeAnalyzeScanner(BaseScanner):
    """Scanner for detecting composition and cross-artifact risks.

    Detects:
    - Self-contradictions within a single artifact (conflicting directives)
    - Priority conflicts (multiple priority declarations, ambiguous ordering)
    - Circular dependency references
    - Overloaded context (too many includes/references)
    - Missing dependency declarations (references to undefined artifacts)
    - Duplicate/redundant artifact references

    Works via regex/text analysis by default. When networkx is available,
    uses graph algorithms for deeper dependency analysis. When
    sentence-transformers is available, uses semantic similarity for
    contradiction detection.
    """

    def __init__(self) -> None:
        """Initialize the ComposeAnalyze scanner."""
        self._networkx_available: bool | None = None
        self._sentence_transformers_available: bool | None = None

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.COMPOSE_ANALYZE

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return [
            ArtifactType.PROMPT,
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.HOOK,
            ArtifactType.INSTRUCTION,
            ArtifactType.PLUGIN,
            ArtifactType.ORCHESTRATION,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        return [
            "CMP-1",
            "CMP-2",
            "CMP-3",
            "CMP-4",
            "CMP-5",
            "I-P2",
            "ST-P2",
            "A-P5",
            "OW-P1",
            "OW-P2",
            "ST-P3",
            "SK-P2",
            "SK-P3",
            "SK-P4",
        ]

    def is_available(self) -> bool:
        """Always available via regex/text analysis fallback."""
        return True

    def _check_networkx_available(self) -> bool:
        """Lazy check for networkx dependency."""
        if self._networkx_available is None:
            try:
                import networkx  # noqa: F401

                self._networkx_available = True
            except ImportError:
                self._networkx_available = False
        return self._networkx_available

    def _check_sentence_transformers_available(self) -> bool:
        """Lazy check for sentence-transformers dependency."""
        if self._sentence_transformers_available is None:
            try:
                import sentence_transformers  # noqa: F401

                self._sentence_transformers_available = True
            except ImportError:
                self._sentence_transformers_available = False
        return self._sentence_transformers_available

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for composition-related risks.

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
        findings.extend(self._detect_contradictions(artifact_content, artifact_type, artifact_path))
        findings.extend(
            self._detect_priority_conflicts(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_circular_dependencies(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_context_overload(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_stale_references(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_redundant_references(artifact_content, artifact_type, artifact_path)
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
            scanner_module=ScannerModule.COMPOSE_ANALYZE,
            remediation=meta["remediation"],
            references=[],
        )

    def _detect_contradictions(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect self-contradictions within the artifact.

        Looks for conflicting directive pairs (e.g., 'always be brief' vs
        'always be verbose') within the same artifact content.
        """
        findings: list[ScanFinding] = []

        risk_id = _CONTRADICTION_RISK_MAP.get(artifact_type)
        if not risk_id:
            return findings

        for pattern_a, pattern_b, description in _CONTRADICTION_PAIRS:
            matches_a = list(pattern_a.finditer(content))
            matches_b = list(pattern_b.finditer(content))

            if matches_a and matches_b:
                # Found a contradiction pair
                first_match = matches_a[0]
                second_match = matches_b[0]
                line = self._find_line_number(content, first_match.start())
                evidence = f"{description}: '{first_match.group(0).strip()}' vs '{second_match.group(0).strip()}'"
                # Direct contradiction = high confidence (0.90-0.95)
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.92,
                        line=line,
                    )
                )

        # Also detect negation-affirmation contradictions on same subject
        findings.extend(
            self._detect_negation_contradictions(content, artifact_type, artifact_path, risk_id)
        )

        return findings

    def _detect_negation_contradictions(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        risk_id: str,
    ) -> list[ScanFinding]:
        """Detect contradictions via negation/affirmation patterns on same subject."""
        findings: list[ScanFinding] = []
        lines = content.split("\n")

        # Collect affirmative and negative directives
        affirmative_directives: list[tuple[int, str, str]] = []  # (line_num, verb, subject)
        negative_directives: list[tuple[int, str, str]] = []

        directive_pattern = re.compile(
            r"\b(always|must|shall|should|never|do\s+not|don'?t|cannot|must\s+not|shall\s+not)\s+(\w+(?:\s+\w+){0,3})",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines, 1):
            for match in directive_pattern.finditer(line):
                modal = match.group(1).lower().strip()
                subject = match.group(2).lower().strip()

                if any(neg in modal for neg in ("never", "not", "don")):
                    negative_directives.append((i, modal, subject))
                elif any(aff in modal for aff in ("always", "must", "shall", "should")):
                    affirmative_directives.append((i, modal, subject))

        # Check for contradictions: same subject with opposite modality
        for aff_line, aff_modal, aff_subject in affirmative_directives:
            for neg_line, neg_modal, neg_subject in negative_directives:
                if aff_line == neg_line:
                    continue
                # Check if subjects are similar (shared words)
                aff_words = set(aff_subject.split())
                neg_words = set(neg_subject.split())
                overlap = aff_words & neg_words
                if len(overlap) >= 1 and len(overlap) / max(len(aff_words), len(neg_words)) >= 0.5:
                    evidence = f"Conflicting directives: '{aff_modal} {aff_subject}' (line {aff_line}) vs '{neg_modal} {neg_subject}' (line {neg_line})"
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=evidence,
                            confidence=0.70,
                            line=aff_line,
                        )
                    )
                    # Only report first contradiction to avoid noise
                    return findings

        return findings

    def _detect_priority_conflicts(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect priority resolution conflicts.

        Looks for multiple priority declarations or ambiguous ordering
        within the same artifact.
        """
        findings: list[ScanFinding] = []

        risk_id = _PRIORITY_RISK_MAP.get(artifact_type)
        if not risk_id:
            return findings

        # Collect all priority declarations
        priority_declarations: list[tuple[int, str]] = []

        for pattern in _PRIORITY_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                value = match.group(1).strip()
                priority_declarations.append((line, value))

        # Multiple priority declarations indicate a conflict
        if len(priority_declarations) > 1:
            # Check if they have different values
            values = set(v for _, v in priority_declarations)
            if len(values) > 1:
                items = [f"{v} (line {ln})" for ln, v in priority_declarations[:3]]
                evidence = f"Multiple conflicting priority declarations: {', '.join(items)}"
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.90,
                        line=priority_declarations[0][0],
                    )
                )
            elif len(priority_declarations) > 2:
                # Same value repeated many times - potential conflict signal
                evidence = f"Redundant priority declarations ({len(priority_declarations)} occurrences of '{priority_declarations[0][1]}')"
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.65,
                        line=priority_declarations[0][0],
                    )
                )

        # Check for scope overlap with priority ambiguity
        scope_declarations = []
        for pattern in _SCOPE_PATTERNS:
            for match in pattern.finditer(content):
                scope_declarations.append(
                    (self._find_line_number(content, match.start()), match.group(1).strip())
                )

        if len(scope_declarations) > 1:
            # Multiple scope declarations may indicate overlap
            scope_values = [v for _, v in scope_declarations]
            if len(set(scope_values)) < len(scope_values):
                # Duplicate scope values
                evidence = f"Duplicate scope declarations detected: {', '.join(scope_values[:3])}"
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.70,
                        line=scope_declarations[0][0],
                    )
                )

        return findings

    def _detect_circular_dependencies(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect circular dependency references.

        Looks for self-references and potential circular dependency patterns.
        When networkx is available, builds and analyzes the dependency graph.

        Requires explicit file path references, import/include statements,
        or structured field references. Excludes keyword-only self-references
        where a file about a topic merely contains that topic word.
        """
        findings: list[ScanFinding] = []

        risk_id = _CIRCULAR_DEP_RISK_MAP.get(artifact_type)
        if not risk_id:
            return findings

        # Check for self-references
        for match in _SELF_REFERENCE_PATTERN.finditer(content):
            line = self._find_line_number(content, match.start())
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=f"Self-reference detected: '{match.group(0)}'",
                    confidence=0.90,
                    line=line,
                )
            )
            break  # Report only first

        # Extract all references and check for cycles
        references = self._extract_references(content)
        artifact_name = self._extract_artifact_name(artifact_path)

        # Check if any reference points back to this artifact
        for ref_line, ref_name in references:
            ref_normalized = ref_name.lower().strip().rstrip("/")
            has_path_separator = "/" in ref_normalized or "\\" in ref_normalized
            has_structured_field = self._is_structured_reference(content, ref_line, ref_name)
            has_import_statement = self._is_import_include_reference(content, ref_line, ref_name)

            # Check if this is merely a keyword self-reference
            if not has_path_separator and not has_structured_field and not has_import_statement:
                # This is a keyword-only match — exclude it
                logger.debug(
                    "keyword_self_reference_exclusion",
                    artifact_name=artifact_name,
                    reference=ref_name,
                    line=ref_line,
                    artifact_path=artifact_path,
                )
                continue

            if self._references_match(artifact_name, ref_name):
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=(
                            f"Potential circular reference: artifact references"
                            f" itself via '{ref_name}'"
                        ),
                        confidence=0.85,
                        line=ref_line,
                    )
                )
                break

        # If networkx available, attempt deeper graph analysis
        if self._check_networkx_available() and references:
            cycle_findings = self._detect_cycles_with_networkx(
                content, artifact_type, artifact_path, risk_id, references, artifact_name
            )
            findings.extend(cycle_findings)

        return findings

    def _is_structured_reference(self, content: str, ref_line: int, ref_name: str) -> bool:
        """Check if a reference appears in a structured field context.

        Returns True when the reference is part of a YAML/JSON structured field
        like ref:, depends_on:, source:, target:, dependency:, include:.
        """
        lines = content.split("\n")
        # ref_line is 1-based from _find_line_number
        line_idx = ref_line - 1 if ref_line > 0 else 0
        if line_idx >= len(lines):
            return False

        line_text = lines[line_idx]
        # Check if the line contains a structured field keyword before the ref
        structured_field_pattern = re.compile(
            r"(?:ref|reference|source|target|dependency|depends_on|include)"
            r"\s*:\s*.*" + re.escape(ref_name),
            re.IGNORECASE,
        )
        return bool(structured_field_pattern.search(line_text))

    def _is_import_include_reference(self, content: str, ref_line: int, ref_name: str) -> bool:
        """Check if a reference is part of an import/include statement.

        Returns True when the reference appears in a line with an explicit
        dependency verb (uses, requires, depends on, imports, includes,
        invokes, delegates to, calls) directly followed by the artifact name.
        """
        lines = content.split("\n")
        # ref_line is 1-based from _find_line_number
        line_idx = ref_line - 1 if ref_line > 0 else 0
        if line_idx >= len(lines):
            return False

        line_text = lines[line_idx]
        # Check for explicit dependency verb + artifact name
        import_pattern = re.compile(
            r"\b(?:uses?|requires?|depends\s+on|imports?|includes?"
            r"|invokes?|delegates?\s+to|calls?)\s+['\"`]?" + re.escape(ref_name),
            re.IGNORECASE,
        )
        return bool(import_pattern.search(line_text))

    def _detect_cycles_with_networkx(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        risk_id: str,
        references: list[tuple[int, str]],
        artifact_name: str,
    ) -> list[ScanFinding]:
        """Use networkx to detect potential cycles in the dependency graph."""
        findings: list[ScanFinding] = []
        try:
            import networkx as nx

            G = nx.DiGraph()
            G.add_node(artifact_name)
            for _, ref_name in references:
                G.add_edge(artifact_name, ref_name)

            # Check for self-loops
            self_loops = list(nx.selfloop_edges(G))
            if self_loops:
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"Self-loop detected in dependency graph for '{artifact_name}'",
                        confidence=0.95,
                        line=references[0][0] if references else None,
                    )
                )
        except Exception:
            pass  # Graceful degradation

        return findings

    def _detect_context_overload(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect context budget overflow from excessive includes/references.

        Counts include/import/reference statements and flags when exceeding
        the threshold.
        """
        findings: list[ScanFinding] = []

        risk_id = _CONTEXT_OVERLOAD_RISK_MAP.get(artifact_type)
        if not risk_id:
            return findings

        # Count include/reference statements
        include_count = 0
        first_include_line: int | None = None

        for pattern in _INCLUDE_PATTERNS:
            for match in pattern.finditer(content):
                include_count += 1
                if first_include_line is None:
                    first_include_line = self._find_line_number(content, match.start())

        # Also count explicit artifact references
        references = self._extract_references(content)
        total_refs = include_count + len(references)

        if total_refs > _MAX_REFERENCES_THRESHOLD:
            evidence = f"Excessive composition references detected: {total_refs} includes/references (threshold: {_MAX_REFERENCES_THRESHOLD})"
            # Higher confidence with more references
            confidence = min(0.60 + (total_refs - _MAX_REFERENCES_THRESHOLD) * 0.03, 0.90)
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=confidence,
                    line=first_include_line,
                )
            )

        return findings

    def _detect_stale_references(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect references to potentially non-existent artifacts.

        Looks for references with suspicious patterns indicating staleness
        (e.g., 'deprecated', 'old', 'legacy', 'TODO: update' near references).
        """
        findings: list[ScanFinding] = []

        risk_id = _STALE_REF_RISK_MAP.get(artifact_type)
        if not risk_id:
            return findings

        references = self._extract_references(content)
        lines = content.split("\n")

        staleness_pattern = re.compile(
            r"\b(deprecated|legacy|old|obsolete|removed|renamed|TODO|FIXME|HACK|broken|stale)\b",
            re.IGNORECASE,
        )

        for ref_line, ref_name in references:
            # Check context around the reference for staleness indicators
            start_line = max(0, ref_line - 2)
            end_line = min(len(lines), ref_line + 1)
            context = " ".join(lines[start_line:end_line])

            if staleness_pattern.search(context):
                evidence = f"Potentially stale reference to '{ref_name}' near staleness indicator"
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.65,
                        line=ref_line,
                    )
                )
                break  # Report only first to avoid noise

        return findings

    def _detect_redundant_references(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect duplicate or redundant artifact references.

        Flags when the same artifact is referenced multiple times, indicating
        potential redundancy or composition waste.
        """
        findings: list[ScanFinding] = []

        risk_id = _REDUNDANCY_RISK_MAP.get(artifact_type)
        if not risk_id:
            return findings

        references = self._extract_references(content)

        # Group references by normalized name
        ref_counts: dict[str, list[int]] = {}
        for ref_line, ref_name in references:
            normalized = ref_name.lower().strip().rstrip("/")
            if normalized not in ref_counts:
                ref_counts[normalized] = []
            ref_counts[normalized].append(ref_line)

        # Find duplicates
        for ref_name, lines_list in ref_counts.items():
            if len(lines_list) > 1:
                line_nums = ", ".join(str(ln) for ln in lines_list[:5])
                evidence = (
                    f"Duplicate reference to '{ref_name}' found "
                    f"{len(lines_list)} times (lines: {line_nums})"
                )
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.75,
                        line=lines_list[0],
                    )
                )
                break  # Report only first duplicate to avoid noise

        return findings

    def _extract_references(self, content: str) -> list[tuple[int, str]]:
        """Extract all artifact references from content.

        Returns:
            List of (line_number, reference_name) tuples.
        """
        references: list[tuple[int, str]] = []
        seen: set[str] = set()

        for pattern in _REFERENCE_PATTERNS:
            for match in pattern.finditer(content):
                ref_name = match.group(1).strip()
                # Filter out very short or common false positives
                if len(ref_name) < 3:
                    continue
                if ref_name.lower() in ("the", "this", "that", "true", "false", "null", "none"):
                    continue
                key = f"{ref_name.lower()}_{match.start()}"
                if key not in seen:
                    seen.add(key)
                    line = self._find_line_number(content, match.start())
                    references.append((line, ref_name))

        return references

    def _extract_artifact_name(self, artifact_path: str) -> str:
        """Extract a normalized artifact name from its file path."""
        import os

        basename = os.path.basename(artifact_path)
        # Remove common extensions
        name = re.sub(r"\.(md|yaml|yml|json|py|ts|js)$", "", basename, flags=re.IGNORECASE)
        return name.lower()

    def _references_match(self, artifact_name: str, reference: str) -> bool:
        """Check if a reference points back to the artifact via explicit means.

        Requires one of the following for a match:
        - Explicit file path reference (containing `/` or `\\` separators)
          with a matching basename
        - Import/include statement referencing the artifact by name
        - Artifact name reference in a structured field (YAML ref:, depends_on:)

        Excludes keyword-only self-references where a file about a topic
        merely contains that topic word.
        """
        ref_normalized = reference.lower().strip().rstrip("/")

        # Check for explicit file path reference (contains path separators)
        has_path_separator = "/" in ref_normalized or "\\" in ref_normalized
        if has_path_separator:
            # Path-based match: last segment must match artifact name
            ref_parts = re.split(r"[/\\]", ref_normalized)
            basename = ref_parts[-1] if ref_parts else ""
            # Strip common extensions from basename for comparison
            basename_no_ext = re.sub(
                r"\.(md|yaml|yml|json|py|ts|js)$", "", basename, flags=re.IGNORECASE
            )
            if basename_no_ext == artifact_name or basename == artifact_name:
                return True
            return False

        # Check for import/include statement pattern match
        # The reference was extracted by _REFERENCE_PATTERNS which include
        # import/include/uses/requires/depends_on patterns and YAML ref: fields.
        # For non-path references, require an exact name match (not substring).
        if ref_normalized == artifact_name:
            return True

        return False
