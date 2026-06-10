"""QualityLint scanner module.

Detects quality issues in AI artifacts including:
- Ambiguity: vague/unclear instructions (maybe, possibly, try to, could)
- Contradictions: conflicting directives within same artifact
- Missing metadata: no version, no author, no description, no date
- Staleness: dates >6 months old, deprecated references
- Incomplete references: broken links, undefined terms
- Missing error handling: no fallback instructions, no edge case coverage
- Poor structure: no sections, wall of text, missing headers
- Semantic ambiguity: embedding-based detection of vague instructions (P-Q8)
- Low readability: Flesch-Kincaid scoring for overly complex text (P-Q9)

Applies to ALL 14 artifact types.

Detects risk IDs:
  P-Q1 through P-Q9, SK-Q1 through SK-Q3, SOP-Q1 through SOP-Q5,
  I-Q2, I-Q3, ST-Q2, MCP-Q2, MCP-Q3, H-Q1 through H-Q3,
  EV-Q1, EV-Q2, M-Q1, RAG-Q1, PL-Q2, PL-Q3,
  GOV-3 through GOV-5, A-R1 through A-R3, MCP-P1, MCP-P2, MCP-P4
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
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

# ---------------------------------------------------------------------------
# Semantic quality constants
# ---------------------------------------------------------------------------

_SEMANTIC_AMBIGUITY_THRESHOLD: float = 0.60
"""Minimum cosine similarity to the ambiguity corpus for a sentence to be
considered semantically vague."""

_READABILITY_HARD_FLOOR: float = 30.0
"""Flesch-Kincaid score below which the artifact is flagged as hard to read."""

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Ambiguity indicators — vague language that leads to non-deterministic behavior
_AMBIGUITY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(maybe|perhaps|possibly|might|could\s+try|try\s+to)\b", re.IGNORECASE),
    re.compile(r"\b(if\s+possible|when\s+appropriate|as\s+needed|somehow)\b", re.IGNORECASE),
    re.compile(r"\b(etc\.?|and\s+so\s+on|and\s+more|or\s+something)\b", re.IGNORECASE),
    re.compile(r"\b(kind\s+of|sort\s+of|more\s+or\s+less|approximately)\b", re.IGNORECASE),
    re.compile(r"\b(generally|usually|typically|often|sometimes)\b", re.IGNORECASE),
    re.compile(r"\b(should\s+probably|ideally|preferably)\b", re.IGNORECASE),
]

# Contradiction indicators — conflicting directive pairs
_CONTRADICTION_PAIRS: list[tuple[re.Pattern[str], re.Pattern[str], str]] = [
    (
        re.compile(r"\b(always|must|shall)\b.*\b(include|add|use)\b", re.IGNORECASE),
        re.compile(r"\b(never|must\s+not|shall\s+not)\b.*\b(include|add|use)\b", re.IGNORECASE),
        "Conflicting 'always' vs 'never' directives detected",
    ),
    (
        re.compile(r"\b(verbose|detailed|comprehensive)\b", re.IGNORECASE),
        re.compile(r"\b(concise|brief|minimal|short)\b", re.IGNORECASE),
        "Conflicting verbosity directives (verbose vs concise)",
    ),
    (
        re.compile(r"\b(strict|rigorous|enforce)\b", re.IGNORECASE),
        re.compile(r"\b(flexible|lenient|relaxed)\b", re.IGNORECASE),
        "Conflicting strictness directives (strict vs flexible)",
    ),
]

# Staleness patterns — date detection
_DATE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(\d{4})[-/](\d{1,2})[-/](\d{1,2})\b"),  # YYYY-MM-DD or YYYY/MM/DD
    re.compile(r"\b(\d{1,2})[-/](\d{1,2})[-/](\d{4})\b"),  # MM-DD-YYYY or DD/MM/YYYY
]

_DEPRECATED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(deprecated|obsolete|legacy|end[-\s]of[-\s]life|eol|sunset)\b", re.IGNORECASE),
]

# Metadata fields expected in well-formed artifacts
_METADATA_MARKERS: list[str] = [
    "version",
    "author",
    "description",
    "date",
    "created",
    "updated",
    "modified",
    "title",
    "name",
]

# Structural quality markers
_HEADER_RE = re.compile(r"^#{1,6}\s+\S", re.MULTILINE)
_SECTION_DIVIDER_RE = re.compile(r"^---+$", re.MULTILINE)

# Missing error handling markers
_ERROR_HANDLING_MARKERS: list[str] = [
    "error",
    "fallback",
    "exception",
    "fail",
    "edge case",
    "otherwise",
    "if not",
    "handle",
    "catch",
    "default",
]

# Broken link pattern (markdown links)
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]*)\)")

# Placeholder/undefined term patterns
_PLACEHOLDER_RE = re.compile(
    r"\b(TODO|FIXME|PLACEHOLDER|TBD|XXX|CHANGEME|FILL_IN)\b", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Risk ID mapping per artifact type and category
# ---------------------------------------------------------------------------

# Maps (artifact_type, quality_category) -> risk_id
_RISK_ID_MAP: dict[tuple[ArtifactType, str], str] = {
    # Prompts: P-Q1 (ambiguity), P-Q2 (contradiction), P-Q3 (missing metadata),
    # P-Q4 (staleness), P-Q5 (incomplete refs), P-Q6 (no error handling), P-Q7 (poor structure)
    (ArtifactType.PROMPT, "ambiguity"): "P-Q1",
    (ArtifactType.PROMPT, "contradiction"): "P-Q2",
    (ArtifactType.PROMPT, "missing_metadata"): "P-Q3",
    (ArtifactType.PROMPT, "staleness"): "P-Q4",
    (ArtifactType.PROMPT, "incomplete_refs"): "P-Q5",
    (ArtifactType.PROMPT, "no_error_handling"): "P-Q6",
    (ArtifactType.PROMPT, "poor_structure"): "P-Q7",
    (ArtifactType.PROMPT, "semantic_ambiguity"): "P-Q8",
    (ArtifactType.PROMPT, "low_readability"): "P-Q9",
    # Skills: SK-Q1 (ambiguity), SK-Q2 (missing metadata), SK-Q3 (poor structure)
    (ArtifactType.SKILL, "ambiguity"): "SK-Q1",
    (ArtifactType.SKILL, "missing_metadata"): "SK-Q2",
    (ArtifactType.SKILL, "poor_structure"): "SK-Q3",
    # SOPs: SOP-Q1 (ambiguity), SOP-Q2 (contradiction), SOP-Q3 (staleness),
    # SOP-Q4 (missing metadata), SOP-Q5 (poor structure)
    (ArtifactType.SOP, "ambiguity"): "SOP-Q1",
    (ArtifactType.SOP, "contradiction"): "SOP-Q2",
    (ArtifactType.SOP, "staleness"): "SOP-Q3",
    (ArtifactType.SOP, "missing_metadata"): "SOP-Q4",
    (ArtifactType.SOP, "poor_structure"): "SOP-Q5",
    # Instructions: I-Q2 (ambiguity), I-Q3 (poor structure)
    (ArtifactType.INSTRUCTION, "ambiguity"): "I-Q2",
    (ArtifactType.INSTRUCTION, "poor_structure"): "I-Q3",
    # Steering: ST-Q2 (ambiguity)
    (ArtifactType.STEERING, "ambiguity"): "ST-Q2",
    # MCP: MCP-Q2 (missing metadata), MCP-Q3 (poor structure),
    # MCP-P1 (ambiguity), MCP-P2 (contradiction), MCP-P4 (staleness)
    (ArtifactType.MCP, "missing_metadata"): "MCP-Q2",
    (ArtifactType.MCP, "poor_structure"): "MCP-Q3",
    (ArtifactType.MCP, "ambiguity"): "MCP-P1",
    (ArtifactType.MCP, "contradiction"): "MCP-P2",
    (ArtifactType.MCP, "staleness"): "MCP-P4",
    # Hooks: H-Q1 (ambiguity), H-Q2 (missing metadata), H-Q3 (poor structure)
    (ArtifactType.HOOK, "ambiguity"): "H-Q1",
    (ArtifactType.HOOK, "missing_metadata"): "H-Q2",
    (ArtifactType.HOOK, "poor_structure"): "H-Q3",
    # Eval Harness: EV-Q1 (ambiguity), EV-Q2 (missing metadata)
    (ArtifactType.EVAL_HARNESS, "ambiguity"): "EV-Q1",
    (ArtifactType.EVAL_HARNESS, "missing_metadata"): "EV-Q2",
    # Memory: M-Q1 (staleness)
    (ArtifactType.MEMORY, "staleness"): "M-Q1",
    # RAG: RAG-Q1 (staleness)
    (ArtifactType.RAG, "staleness"): "RAG-Q1",
    # Plugins: PL-Q2 (missing metadata), PL-Q3 (poor structure)
    (ArtifactType.PLUGIN, "missing_metadata"): "PL-Q2",
    (ArtifactType.PLUGIN, "poor_structure"): "PL-Q3",
    # Governance (cross-cutting): GOV-3 (missing metadata), GOV-4 (staleness), GOV-5 (poor structure)
    (ArtifactType.AGENT, "missing_metadata"): "GOV-3",
    (ArtifactType.AGENT, "staleness"): "GOV-4",
    (ArtifactType.AGENT, "poor_structure"): "GOV-5",
    # Agents reliability: A-R1 (ambiguity), A-R2 (contradiction), A-R3 (no error handling)
    (ArtifactType.AGENT, "ambiguity"): "A-R1",
    (ArtifactType.AGENT, "contradiction"): "A-R2",
    (ArtifactType.AGENT, "no_error_handling"): "A-R3",
    # Orchestration — use generic quality risk IDs (fallback to GOV)
    (ArtifactType.ORCHESTRATION, "ambiguity"): "GOV-3",
    (ArtifactType.ORCHESTRATION, "poor_structure"): "GOV-5",
    # API Schema — use generic
    (ArtifactType.API_SCHEMA, "missing_metadata"): "GOV-3",
}

# Severity and metadata per quality category
_CATEGORY_META: dict[str, dict[str, Any]] = {
    "ambiguity": {
        "title_suffix": "Ambiguous Language Detected",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "confidence": 0.75,
        "remediation": "Replace vague language with specific, deterministic instructions.",
    },
    "contradiction": {
        "title_suffix": "Contradicting Directives",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "confidence": 0.70,
        "remediation": "Resolve conflicting directives to provide consistent instructions.",
    },
    "missing_metadata": {
        "title_suffix": "Missing Metadata",
        "severity_score": 3,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "confidence": 0.95,
        "remediation": "Add metadata fields (version, author, description, date) to the artifact.",
    },
    "staleness": {
        "title_suffix": "Stale Content Detected",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "confidence": 0.80,
        "remediation": "Review and update stale content. Remove deprecated references.",
    },
    "incomplete_refs": {
        "title_suffix": "Incomplete or Broken References",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "confidence": 0.80,
        "remediation": "Fix broken links and replace placeholder content with actual values.",
    },
    "no_error_handling": {
        "title_suffix": "Missing Error Handling Instructions",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "confidence": 0.70,
        "remediation": "Add fallback instructions, edge case handling, and error recovery guidance.",
    },
    "poor_structure": {
        "title_suffix": "Poor Document Structure",
        "severity_score": 3,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P4,
        "gate_action": GateAction.INFO,
        "confidence": 0.85,
        "remediation": "Add section headers, break long text into logical sections, improve organization.",
    },
    "semantic_ambiguity": {
        "title_suffix": "Semantic Ambiguity Detected",
        "severity_score": 4,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P3,
        "gate_action": GateAction.INFO,
        "confidence": 0.70,
        "remediation": (
            "Rewrite semantically vague passages with precise directives. "
            "Add constraints and expected output formats."
        ),
    },
    "low_readability": {
        "title_suffix": "Low Readability Score",
        "severity_score": 3,
        "severity_label": SeverityLabel.LOW,
        "priority": Priority.P4,
        "gate_action": GateAction.INFO,
        "confidence": 0.90,
        "remediation": (
            "Simplify sentence structure. Break long sentences into shorter directives."
        ),
    },
}


# ---------------------------------------------------------------------------
# Readability helpers
# ---------------------------------------------------------------------------


def _count_syllables(word: str) -> int:
    """Estimate syllable count for an English word."""
    word = word.lower().rstrip("e")
    if not word:
        return 1
    count = 0
    prev_vowel = False
    for ch in word:
        is_vowel = ch in "aeiou"
        if is_vowel and not prev_vowel:
            count += 1
        prev_vowel = is_vowel
    return max(count, 1)


def _flesch_kincaid_score(text: str) -> float:
    """Compute the Flesch Reading Ease score for *text*.

    Returns a value on a 0-100 scale (higher = easier to read).
    Returns 100.0 for very short text to avoid false positives.
    """
    sentences = re.split(r"[.!?]+", text)
    sentences = [s.strip() for s in sentences if s.strip()]
    if not sentences:
        return 100.0

    words: list[str] = re.findall(r"[a-zA-Z]+", text)
    if len(words) < 30:
        return 100.0

    total_syllables = sum(_count_syllables(w) for w in words)
    num_words = len(words)
    num_sentences = len(sentences)

    score: float = (
        206.835 - 1.015 * (num_words / num_sentences) - 84.6 * (total_syllables / num_words)
    )
    return max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Semantic quality analyzer
# ---------------------------------------------------------------------------

_AMBIGUITY_CORPUS: list[str] = [
    "do whatever seems appropriate",
    "handle it as you see fit",
    "use your best judgment",
    "be flexible in your approach",
    "adjust as needed",
    "consider various options",
    "try to figure it out",
    "it depends on the situation",
    "do something along those lines",
    "more or less like that",
    "you could possibly try",
    "maybe consider doing this",
    "if you think it makes sense",
    "whatever works best for you",
    "go with the flow",
    "keep it vague on purpose",
    "adapt dynamically to the context",
    "interpret the request loosely",
    "make reasonable assumptions",
    "fill in the blanks yourself",
]


class SemanticQualityAnalyzer:
    """Embedding-based detection of semantically ambiguous passages.

    When ``sentence-transformers`` is available, sentences in the artifact
    are scored against a small ambiguity corpus.  Falls back to no-op when
    ML dependencies are missing.
    """

    def __init__(self) -> None:
        self._available: bool | None = None
        self._scorer: Any | None = None
        self._corpus_embeddings: Any | None = None

    @property
    def is_available(self) -> bool:
        """Check if semantic analysis is available."""
        if self._available is None:
            try:
                from ai_artifact_risk_validator.semantic.embeddings import EmbeddingEngine

                self._available = EmbeddingEngine().is_available
            except Exception:
                self._available = False
        return self._available

    def _ensure_loaded(self) -> bool:
        """Lazily initialise scorer and corpus embeddings."""
        if not self.is_available:
            return False
        if self._scorer is None:
            from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer

            self._scorer = SimilarityScorer()
            self._corpus_embeddings = self._scorer.encode(_AMBIGUITY_CORPUS)
        return self._corpus_embeddings is not None

    def score_sentences(self, sentences: list[str]) -> list[tuple[int, float]]:
        """Score each sentence against the ambiguity corpus.

        Returns:
            List of ``(sentence_index, score)`` for sentences above the
            ambiguity threshold.
        """
        if not self._ensure_loaded() or self._scorer is None:
            return []

        results: list[tuple[int, float]] = []
        for idx, sentence in enumerate(sentences):
            stripped = sentence.strip()
            if len(stripped) < 10:
                continue
            try:
                sim: float = self._scorer.score_against_corpus(stripped, self._corpus_embeddings)
                if sim >= _SEMANTIC_AMBIGUITY_THRESHOLD:
                    results.append((idx, sim))
            except Exception:
                logger.debug("Semantic ambiguity scoring failed", exc_info=True)
        return results


class QualityLintScanner(BaseScanner):
    """Scanner that detects quality issues in AI artifacts.

    Implements detection for ambiguity, contradictions, missing metadata,
    staleness, incomplete references, missing error handling, poor structure,
    semantic ambiguity (embedding-based), and readability scoring.
    Applies to all 14 artifact types.
    """

    def __init__(self) -> None:
        """Initialize the QualityLint scanner."""
        self._semantic = SemanticQualityAnalyzer()

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.QUALITY_LINT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [
            ArtifactType.PROMPT,
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.SOP,
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.HOOK,
            ArtifactType.INSTRUCTION,
            ArtifactType.PLUGIN,
            ArtifactType.MEMORY,
            ArtifactType.RAG,
            ArtifactType.EVAL_HARNESS,
            ArtifactType.ORCHESTRATION,
            ArtifactType.API_SCHEMA,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        return [
            "P-Q1",
            "P-Q2",
            "P-Q3",
            "P-Q4",
            "P-Q5",
            "P-Q6",
            "P-Q7",
            "SK-Q1",
            "SK-Q2",
            "SK-Q3",
            "SOP-Q1",
            "SOP-Q2",
            "SOP-Q3",
            "SOP-Q4",
            "SOP-Q5",
            "I-Q2",
            "I-Q3",
            "ST-Q2",
            "MCP-Q2",
            "MCP-Q3",
            "H-Q1",
            "H-Q2",
            "H-Q3",
            "EV-Q1",
            "EV-Q2",
            "M-Q1",
            "RAG-Q1",
            "PL-Q2",
            "PL-Q3",
            "GOV-3",
            "GOV-4",
            "GOV-5",
            "A-R1",
            "A-R2",
            "A-R3",
            "MCP-P1",
            "MCP-P2",
            "MCP-P4",
            "P-Q8",
            "P-Q9",
        ]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for quality issues.

        Runs all quality checks and returns findings mapped to the appropriate
        risk IDs based on artifact type.
        """
        findings: list[ScanFinding] = []

        # Run each quality check
        findings.extend(self._check_ambiguity(artifact_content, artifact_type, artifact_path))
        findings.extend(self._check_contradictions(artifact_content, artifact_type, artifact_path))
        findings.extend(
            self._check_missing_metadata(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(self._check_staleness(artifact_content, artifact_type, artifact_path))
        findings.extend(self._check_incomplete_refs(artifact_content, artifact_type, artifact_path))
        findings.extend(self._check_error_handling(artifact_content, artifact_type, artifact_path))
        findings.extend(self._check_structure(artifact_content, artifact_type, artifact_path))
        findings.extend(
            self._check_semantic_ambiguity(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(self._check_readability(artifact_content, artifact_type, artifact_path))

        return findings

    # ------------------------------------------------------------------
    # Ambiguity detection
    # ------------------------------------------------------------------

    def _check_ambiguity(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Detect ambiguous/vague language in the artifact."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "ambiguity"))
        if risk_id is None:
            return []

        matches: list[tuple[int, str]] = []
        lines = content.split("\n")
        for i, line in enumerate(lines, start=1):
            for pattern in _AMBIGUITY_PATTERNS:
                match = pattern.search(line)
                if match:
                    matches.append((i, match.group(0)))
                    break  # One match per line is sufficient

        if not matches:
            return []

        # Report up to 5 examples as evidence
        evidence_lines = matches[:5]
        evidence_text = "; ".join(f"Line {ln}: '{word}'" for ln, word in evidence_lines)
        if len(matches) > 5:
            evidence_text += f" ... ({len(matches)} total occurrences)"

        meta = _CATEGORY_META["ambiguity"]
        return [
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="ambiguity",
                description=(
                    f"Found {len(matches)} instance(s) of ambiguous language. "
                    "Vague terms can lead to non-deterministic AI behavior."
                ),
                evidence=evidence_text,
                location=FindingLocation(line=matches[0][0], section="content"),
                confidence=meta["confidence"],
            ),
        ]

    # ------------------------------------------------------------------
    # Contradiction detection
    # ------------------------------------------------------------------

    def _check_contradictions(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Detect conflicting directives within the artifact."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "contradiction"))
        if risk_id is None:
            return []

        findings: list[ScanFinding] = []
        for pattern_a, pattern_b, description in _CONTRADICTION_PAIRS:
            match_a = pattern_a.search(content)
            match_b = pattern_b.search(content)
            if match_a and match_b:
                evidence = (
                    f"'{match_a.group(0).strip()}' conflicts with '{match_b.group(0).strip()}'"
                )
                # Find the line number of the first match
                line_num = content[: match_a.start()].count("\n") + 1

                meta = _CATEGORY_META["contradiction"]
                findings.append(
                    self._make_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=path,
                        category="contradiction",
                        description=description,
                        evidence=evidence,
                        location=FindingLocation(line=line_num, section="content"),
                        confidence=meta["confidence"],
                    )
                )
                break  # Report one contradiction per artifact to avoid noise

        return findings

    # ------------------------------------------------------------------
    # Missing metadata detection
    # ------------------------------------------------------------------

    def _check_missing_metadata(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Check for missing metadata fields (version, author, description, date)."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "missing_metadata"))
        if risk_id is None:
            return []

        content_lower = content.lower()
        found_metadata: list[str] = []
        missing_metadata: list[str] = []

        for marker in _METADATA_MARKERS:
            # Check for marker as a key in YAML/JSON-like content or in headers
            if (
                re.search(rf"^\s*{marker}\s*[:=]", content_lower, re.MULTILINE)
                or re.search(rf'"{marker}"', content_lower)
                or re.search(rf"^#+\s*{marker}", content_lower, re.MULTILINE)
            ):
                found_metadata.append(marker)
            else:
                missing_metadata.append(marker)

        # Require at least 2 metadata fields present for well-formed artifacts
        # Core required: version/title + one of (author, date, description)
        core_fields = {"version", "title", "name"}
        has_core = bool(core_fields & set(found_metadata))
        secondary_fields = {"author", "date", "created", "updated", "modified", "description"}
        has_secondary = bool(secondary_fields & set(found_metadata))

        if has_core and has_secondary:
            return []

        # Determine what's missing
        missing_core = sorted(core_fields - set(found_metadata))
        missing_secondary = sorted(secondary_fields - set(found_metadata))

        evidence_parts: list[str] = []
        if missing_core and not has_core:
            evidence_parts.append(f"Missing identifier: {missing_core}")
        if missing_secondary and not has_secondary:
            evidence_parts.append(f"Missing provenance: {list(missing_secondary)[:3]}")

        evidence = "; ".join(evidence_parts) if evidence_parts else "No metadata fields detected"

        meta = _CATEGORY_META["missing_metadata"]
        return [
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="missing_metadata",
                description=(
                    "Artifact is missing essential metadata fields. "
                    "Well-formed artifacts should include version/title and provenance information."
                ),
                evidence=evidence,
                location=FindingLocation(line=1, section="metadata"),
                confidence=meta["confidence"],
            ),
        ]

    # ------------------------------------------------------------------
    # Staleness detection
    # ------------------------------------------------------------------

    def _check_staleness(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Detect stale content (old dates, deprecated references)."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "staleness"))
        if risk_id is None:
            return []

        findings: list[ScanFinding] = []
        now = datetime.now(timezone.utc)
        six_months_ago = now.replace(
            month=now.month - 6 if now.month > 6 else now.month + 6,
            year=now.year if now.month > 6 else now.year - 1,
        )

        # Check for old dates
        stale_dates: list[tuple[int, str]] = []
        lines = content.split("\n")
        for i, line in enumerate(lines, start=1):
            for pattern in _DATE_PATTERNS:
                match = pattern.search(line)
                if match:
                    try:
                        groups = match.groups()
                        # Try YYYY-MM-DD format
                        if len(groups[0]) == 4:
                            year, month, day = int(groups[0]), int(groups[1]), int(groups[2])
                        else:
                            # MM-DD-YYYY format
                            month, day, year = int(groups[0]), int(groups[1]), int(groups[2])

                        if 1 <= month <= 12 and 1 <= day <= 31 and 2000 <= year <= 2099:
                            date_val = datetime(year, month, day, tzinfo=timezone.utc)
                            if date_val < six_months_ago:
                                stale_dates.append((i, match.group(0)))
                    except (ValueError, OverflowError):
                        pass

        # Check for deprecated language
        deprecated_matches: list[tuple[int, str]] = []
        for i, line in enumerate(lines, start=1):
            for pattern in _DEPRECATED_PATTERNS:
                match = pattern.search(line)
                if match:
                    deprecated_matches.append((i, match.group(0)))
                    break

        if not stale_dates and not deprecated_matches:
            return []

        evidence_parts: list[str] = []
        first_line = None

        if stale_dates:
            evidence_parts.append(f"Stale dates: {', '.join(d[1] for d in stale_dates[:3])}")
            first_line = stale_dates[0][0]

        if deprecated_matches:
            evidence_parts.append(
                f"Deprecated references: {', '.join(d[1] for d in deprecated_matches[:3])}"
            )
            if first_line is None:
                first_line = deprecated_matches[0][0]

        meta = _CATEGORY_META["staleness"]
        findings.append(
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="staleness",
                description=(
                    "Artifact contains stale or deprecated content that may be outdated. "
                    "Content older than 6 months should be reviewed for relevance."
                ),
                evidence="; ".join(evidence_parts),
                location=FindingLocation(line=first_line or 1, section="content"),
                confidence=meta["confidence"],
            )
        )

        return findings

    # ------------------------------------------------------------------
    # Incomplete references detection
    # ------------------------------------------------------------------

    def _check_incomplete_refs(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Detect broken links and placeholder content."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "incomplete_refs"))
        if risk_id is None:
            return []

        issues: list[tuple[int, str]] = []
        lines = content.split("\n")

        # Check for placeholder text
        for i, line in enumerate(lines, start=1):
            match = _PLACEHOLDER_RE.search(line)
            if match:
                issues.append((i, f"Placeholder: {match.group(0)}"))

        # Check for empty markdown links
        for match in _MARKDOWN_LINK_RE.finditer(content):
            url = match.group(2).strip()
            if not url or url == "#" or url.startswith("{{"):
                line_num = content[: match.start()].count("\n") + 1
                issues.append((line_num, f"Empty/broken link: [{match.group(1)}]({url})"))

        if not issues:
            return []

        evidence = "; ".join(f"Line {ln}: {desc}" for ln, desc in issues[:5])
        if len(issues) > 5:
            evidence += f" ... ({len(issues)} total issues)"

        meta = _CATEGORY_META["incomplete_refs"]
        return [
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="incomplete_refs",
                description=(
                    f"Found {len(issues)} incomplete reference(s) or placeholder(s). "
                    "These indicate unfinished content that should be resolved before sharing."
                ),
                evidence=evidence,
                location=FindingLocation(line=issues[0][0], section="content"),
                confidence=meta["confidence"],
            ),
        ]

    # ------------------------------------------------------------------
    # Missing error handling detection
    # ------------------------------------------------------------------

    def _check_error_handling(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Detect missing error handling / fallback instructions."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "no_error_handling"))
        if risk_id is None:
            return []

        # Only flag for substantial artifacts (>200 chars) that lack error handling
        if len(content) < 200:
            return []

        content_lower = content.lower()
        has_error_handling = any(marker in content_lower for marker in _ERROR_HANDLING_MARKERS)

        if has_error_handling:
            return []

        meta = _CATEGORY_META["no_error_handling"]
        return [
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="no_error_handling",
                description=(
                    "Artifact lacks error handling or fallback instructions. "
                    "Without guidance for edge cases and failures, AI behavior may be unpredictable."
                ),
                evidence="No error handling keywords found (error, fallback, exception, edge case, etc.)",
                location=FindingLocation(line=1, section="content"),
                confidence=meta["confidence"],
            ),
        ]

    # ------------------------------------------------------------------
    # Poor structure detection
    # ------------------------------------------------------------------

    def _check_structure(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Detect poorly structured content (wall of text, no headers)."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "poor_structure"))
        if risk_id is None:
            return []

        # Only check substantial artifacts
        if len(content) < 500:
            return []

        lines = content.split("\n")
        total_lines = len(lines)
        header_count = len(_HEADER_RE.findall(content))
        divider_count = len(_SECTION_DIVIDER_RE.findall(content))

        # Heuristics for poor structure:
        # 1. Long content (>500 chars, >20 lines) with no headers/dividers
        # 2. Very long paragraphs (>15 consecutive non-empty lines without breaks)
        has_sections = (header_count + divider_count) > 0

        if has_sections:
            # Check if sections are proportional to content length
            # Expect roughly 1 header per 30 lines for well-structured docs
            expected_headers = max(1, total_lines // 30)
            if header_count >= expected_headers:
                return []

        # Check for wall-of-text (long consecutive non-empty lines)
        max_paragraph_length = 0
        current_paragraph = 0
        for line in lines:
            if line.strip():
                current_paragraph += 1
            else:
                max_paragraph_length = max(max_paragraph_length, current_paragraph)
                current_paragraph = 0
        max_paragraph_length = max(max_paragraph_length, current_paragraph)

        # Flag if no headers at all for substantial content, or excessively long paragraphs
        if header_count == 0 and total_lines > 20:
            evidence = f"No section headers found in {total_lines} lines of content"
        elif max_paragraph_length > 30:
            evidence = f"Found paragraph of {max_paragraph_length} consecutive lines without breaks"
        else:
            return []

        meta = _CATEGORY_META["poor_structure"]
        return [
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="poor_structure",
                description=(
                    "Artifact has poor document structure. "
                    "Well-structured artifacts use headers and sections for readability."
                ),
                evidence=evidence,
                location=FindingLocation(line=1, section="structure"),
                confidence=meta["confidence"],
            ),
        ]

    # ------------------------------------------------------------------
    # Semantic ambiguity detection (embedding-based)
    # ------------------------------------------------------------------

    def _check_semantic_ambiguity(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Detect semantically ambiguous sentences via embedding similarity."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "semantic_ambiguity"))
        if risk_id is None:
            return []

        sentences = [s.strip() for s in re.split(r"[.!?\n]+", content) if s.strip()]
        hits = self._semantic.score_sentences(sentences)
        if not hits:
            return []

        # Map sentence indices back to line numbers
        lines = content.split("\n")
        evidence_parts: list[str] = []
        first_line: int | None = None
        for sent_idx, score in hits[:5]:
            sent_text = sentences[sent_idx][:80]
            # Find line containing this sentence
            line_num = 1
            for li, line in enumerate(lines, start=1):
                if sent_text[:30] in line:
                    line_num = li
                    break
            if first_line is None:
                first_line = line_num
            evidence_parts.append(f"Line {line_num}: '{sent_text}' (sim={score:.2f})")

        evidence = "; ".join(evidence_parts)
        if len(hits) > 5:
            evidence += f" ... ({len(hits)} total)"

        meta = _CATEGORY_META["semantic_ambiguity"]
        return [
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="semantic_ambiguity",
                description=(
                    f"Found {len(hits)} semantically ambiguous passage(s) "
                    "via embedding similarity to known vague instruction patterns."
                ),
                evidence=evidence,
                location=FindingLocation(line=first_line or 1, section="content"),
                confidence=meta["confidence"],
            ),
        ]

    # ------------------------------------------------------------------
    # Readability detection (Flesch-Kincaid)
    # ------------------------------------------------------------------

    def _check_readability(
        self, content: str, artifact_type: ArtifactType, path: str
    ) -> list[ScanFinding]:
        """Flag artifacts with low Flesch-Kincaid readability scores."""
        risk_id = _RISK_ID_MAP.get((artifact_type, "low_readability"))
        if risk_id is None:
            return []

        score = _flesch_kincaid_score(content)
        if score >= _READABILITY_HARD_FLOOR:
            return []

        meta = _CATEGORY_META["low_readability"]
        return [
            self._make_finding(
                risk_id=risk_id,
                artifact_type=artifact_type,
                artifact_path=path,
                category="low_readability",
                description=(
                    f"Flesch-Kincaid readability score is {score:.1f} "
                    f"(below {_READABILITY_HARD_FLOOR:.0f}). "
                    "Overly complex sentence structure may degrade LLM comprehension."
                ),
                evidence=f"Flesch-Kincaid score: {score:.1f}/100",
                location=FindingLocation(line=1, section="content"),
                confidence=meta["confidence"],
            ),
        ]

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        *,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        category: str,
        description: str,
        evidence: str,
        location: FindingLocation,
        confidence: float,
    ) -> ScanFinding:
        """Create a ScanFinding with quality lint metadata."""
        meta = _CATEGORY_META[category]
        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=meta["severity_score"],
            severity_label=meta["severity_label"],
            priority=meta["priority"],
            gate_action=meta["gate_action"],
            category=RiskCategory.QUALITY,
            title=f"{meta['title_suffix']}",
            description=description,
            location=location,
            evidence=evidence,
            confidence=confidence,
            scanner_module=ScannerModule.QUALITY_LINT,
            remediation=meta["remediation"],
        )
