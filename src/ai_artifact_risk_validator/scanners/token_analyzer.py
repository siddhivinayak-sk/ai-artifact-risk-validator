"""TokenAnalyzer scanner module.

Performs token counting, compression ratio analysis, and redundancy detection
to identify performance risks in AI artifacts. Uses tiktoken (cl100k_base)
for GPT-4 compatible token counting.
"""

import re
import zlib
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import tiktoken

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

# Default token budget limits per artifact type
DEFAULT_TOKEN_BUDGETS: dict[ArtifactType, int] = {
    ArtifactType.PROMPT: 4096,
    ArtifactType.SKILL: 2048,
    ArtifactType.AGENT: 8192,
    ArtifactType.INSTRUCTION: 4096,
    ArtifactType.STEERING: 4096,
    ArtifactType.MCP: 4096,
    ArtifactType.MEMORY: 8192,
    ArtifactType.RAG: 8192,
}

# Thresholds
COMPRESSION_RATIO_THRESHOLD = 3.0  # Content with ratio > 3.0 is suspicious
REDUNDANCY_SIMILARITY_THRESHOLD = 0.85  # Sentence similarity threshold for redundancy
CONTEXT_WINDOW_SATURATION_RATIO = 0.80  # >80% of budget = saturation warning
SECTION_DISPROPORTIONATE_RATIO = 0.50  # Section using >50% of total tokens


class TokenAnalyzerScanner(BaseScanner):
    """Scanner that analyzes token usage, compression ratio, and redundancy.

    Detects performance risks related to:
    - Token budget overflow
    - Section-level token disproportionality
    - Highly repetitive/redundant content
    - Context window inefficiency
    - Token waste from boilerplate
    """

    def __init__(self) -> None:
        """Initialize the TokenAnalyzer scanner with tiktoken encoding."""
        self._encoding = tiktoken.get_encoding("cl100k_base")

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.TOKEN_ANALYZER

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
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        return [
            "P-P1",
            "P-P2",
            "P-P3",
            "P-P4",
            "P-P5",
            "P-P6",
            "SK-P1",
            "A-P2",
            "A-P3",
            "A-P4",
            "I-P1",
            "I-P3",
            "I-P4",
            "M-P1",
            "CMP-3",
            "MCP-P3",
            "MOD-2",
        ]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for token-related performance risks.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects for detected token risks.
        """
        findings: list[ScanFinding] = []

        total_tokens = self._count_tokens(artifact_content)
        sections = self._extract_sections(artifact_content)
        budget = DEFAULT_TOKEN_BUDGETS.get(artifact_type, 4096)

        # Check token budget overflow
        findings.extend(
            self._check_budget_overflow(
                artifact_content, artifact_type, artifact_path, total_tokens, budget
            )
        )

        # Check section-level disproportionality
        findings.extend(
            self._check_section_disproportionality(
                artifact_content, artifact_type, artifact_path, sections, total_tokens
            )
        )

        # Check compression ratio (redundancy)
        findings.extend(
            self._check_compression_ratio(artifact_content, artifact_type, artifact_path)
        )

        # Check sentence-level redundancy
        findings.extend(self._check_redundancy(artifact_content, artifact_type, artifact_path))

        # Check context window saturation
        findings.extend(
            self._check_context_saturation(
                artifact_content, artifact_type, artifact_path, total_tokens, budget
            )
        )

        # Check for uncompressed verbose instructions
        findings.extend(
            self._check_verbosity(artifact_content, artifact_type, artifact_path, total_tokens)
        )

        # Check for unbounded dynamic content
        findings.extend(
            self._check_unbounded_dynamic(artifact_content, artifact_type, artifact_path)
        )

        return findings

    def _count_tokens(self, text: str) -> int:
        """Count tokens in text using cl100k_base encoding."""
        return len(self._encoding.encode(text))

    def _extract_sections(self, content: str) -> dict[str, str]:
        """Extract markdown sections from content.

        Splits on markdown headers (## or #) and returns a dict of
        section_name -> section_content.
        """
        sections: dict[str, str] = {}
        current_section = "_preamble"
        current_lines: list[str] = []

        for line in content.split("\n"):
            header_match = re.match(r"^(#{1,6})\s+(.+)$", line)
            if header_match:
                # Save previous section
                if current_lines:
                    sections[current_section] = "\n".join(current_lines)
                current_section = header_match.group(2).strip()
                current_lines = []
            else:
                current_lines.append(line)

        # Save last section
        if current_lines:
            sections[current_section] = "\n".join(current_lines)

        return sections

    def _compute_compression_ratio(self, text: str) -> float:
        """Compute the compression ratio of text content.

        A higher ratio means more repetitive content.
        """
        if not text:
            return 1.0
        text_bytes = text.encode("utf-8")
        compressed = zlib.compress(text_bytes, level=9)
        if len(compressed) == 0:
            return 1.0
        return len(text_bytes) / len(compressed)

    def _find_redundant_sentences(self, content: str) -> list[tuple[str, int]]:
        """Find near-duplicate sentences or paragraphs.

        Returns list of (sentence, count) tuples for sentences appearing
        multiple times.
        """
        # Split into sentences (simple approach)
        sentences = re.split(r"[.!?]\s+|\n\n+", content)
        # Normalize and filter short sentences
        normalized = []
        for s in sentences:
            s = s.strip()
            if len(s) > 20:  # Only consider meaningful sentences
                normalized.append(s.lower().strip())

        counter = Counter(normalized)
        return [(sent, count) for sent, count in counter.items() if count > 1]

    def _check_budget_overflow(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        total_tokens: int,
        budget: int,
    ) -> list[ScanFinding]:
        """Check if total tokens exceed the configured budget."""
        findings: list[ScanFinding] = []

        if total_tokens <= budget:
            return findings

        overflow_ratio = total_tokens / budget
        confidence = min(1.0, 0.95 + (overflow_ratio - 1.0) * 0.05)

        risk_id = self._get_budget_risk_id(artifact_type)
        risk_meta = self._get_risk_metadata(risk_id)

        findings.append(
            ScanFinding(
                id=risk_id,
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                severity_score=risk_meta["severity_score"],
                severity_label=risk_meta["severity_label"],
                priority=risk_meta["priority"],
                gate_action=risk_meta["gate_action"],
                category=RiskCategory.PERFORMANCE,
                title=risk_meta["title"],
                description=(
                    f"Artifact uses {total_tokens} tokens, exceeding budget of "
                    f"{budget} tokens ({overflow_ratio:.1f}x over budget)."
                ),
                location=FindingLocation(section="entire file"),
                evidence=f"Total tokens: {total_tokens}, Budget: {budget}",
                confidence=confidence,
                scanner_module=ScannerModule.TOKEN_ANALYZER,
                remediation="Compress content, remove redundancy, or increase token budget.",
                references=[],
                timestamp=datetime.now(timezone.utc),
            )
        )

        return findings

    def _check_section_disproportionality(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        sections: dict[str, str],
        total_tokens: int,
    ) -> list[ScanFinding]:
        """Check if any section uses a disproportionate share of tokens."""
        findings: list[ScanFinding] = []

        if total_tokens < 100 or len(sections) < 2:
            return findings

        for section_name, section_content in sections.items():
            section_tokens = self._count_tokens(section_content)
            ratio = section_tokens / total_tokens

            if ratio > SECTION_DISPROPORTIONATE_RATIO and section_tokens > 50:
                confidence = 0.80 + min(0.14, (ratio - SECTION_DISPROPORTIONATE_RATIO) * 0.5)
                risk_id = self._get_inefficiency_risk_id(artifact_type)
                risk_meta = self._get_risk_metadata(risk_id)

                findings.append(
                    ScanFinding(
                        id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        severity_score=risk_meta["severity_score"],
                        severity_label=risk_meta["severity_label"],
                        priority=risk_meta["priority"],
                        gate_action=risk_meta["gate_action"],
                        category=RiskCategory.PERFORMANCE,
                        title=risk_meta["title"],
                        description=(
                            f"Section '{section_name}' uses {section_tokens} tokens "
                            f"({ratio:.0%} of total), which is disproportionately large."
                        ),
                        location=FindingLocation(section=section_name),
                        evidence=f"Section tokens: {section_tokens}/{total_tokens} ({ratio:.0%})",
                        confidence=confidence,
                        scanner_module=ScannerModule.TOKEN_ANALYZER,
                        remediation="Consider splitting or summarizing the oversized section.",
                        references=[],
                        timestamp=datetime.now(timezone.utc),
                    )
                )
                break  # Only report the largest disproportionate section

        return findings

    def _check_compression_ratio(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check if content has a suspiciously high compression ratio."""
        findings: list[ScanFinding] = []

        if len(content) < 100:
            return findings

        ratio = self._compute_compression_ratio(content)

        if ratio > COMPRESSION_RATIO_THRESHOLD:
            confidence = 0.80 + min(0.14, (ratio - COMPRESSION_RATIO_THRESHOLD) * 0.05)
            risk_id = self._get_redundancy_risk_id(artifact_type)
            risk_meta = self._get_risk_metadata(risk_id)

            findings.append(
                ScanFinding(
                    id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    severity_score=risk_meta["severity_score"],
                    severity_label=risk_meta["severity_label"],
                    priority=risk_meta["priority"],
                    gate_action=risk_meta["gate_action"],
                    category=RiskCategory.PERFORMANCE,
                    title=risk_meta["title"],
                    description=(
                        f"Content has high compression ratio of {ratio:.2f} "
                        f"(threshold: {COMPRESSION_RATIO_THRESHOLD}), indicating "
                        "highly repetitive content."
                    ),
                    location=FindingLocation(section="entire file"),
                    evidence=f"Compression ratio: {ratio:.2f}",
                    confidence=confidence,
                    scanner_module=ScannerModule.TOKEN_ANALYZER,
                    remediation="Deduplicate content, remove repeated instructions or examples.",
                    references=[],
                    timestamp=datetime.now(timezone.utc),
                )
            )

        return findings

    def _check_redundancy(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect near-duplicate sentences or paragraphs."""
        findings: list[ScanFinding] = []

        redundant = self._find_redundant_sentences(content)
        if not redundant:
            return findings

        # Report the most repeated sentence
        most_repeated = max(redundant, key=lambda x: x[1])
        sentence, count = most_repeated

        confidence = 0.80 + min(0.14, (count - 1) * 0.05)
        risk_id = self._get_redundancy_risk_id(artifact_type)
        risk_meta = self._get_risk_metadata(risk_id)

        # Truncate evidence for display
        evidence_text = sentence[:100] + "..." if len(sentence) > 100 else sentence

        findings.append(
            ScanFinding(
                id=risk_id,
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                severity_score=risk_meta["severity_score"],
                severity_label=risk_meta["severity_label"],
                priority=risk_meta["priority"],
                gate_action=risk_meta["gate_action"],
                category=RiskCategory.PERFORMANCE,
                title=risk_meta["title"],
                description=(
                    f"Found {len(redundant)} redundant sentence(s). "
                    f"Most repeated appears {count} times."
                ),
                location=FindingLocation(section="entire file"),
                evidence=f"Repeated {count}x: '{evidence_text}'",
                confidence=confidence,
                scanner_module=ScannerModule.TOKEN_ANALYZER,
                remediation="Remove duplicate sentences and consolidate repeated instructions.",
                references=[],
                timestamp=datetime.now(timezone.utc),
            )
        )

        return findings

    def _check_context_saturation(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        total_tokens: int,
        budget: int,
    ) -> list[ScanFinding]:
        """Check if token usage saturates the context window."""
        findings: list[ScanFinding] = []

        utilization = total_tokens / budget if budget > 0 else 0

        if utilization < CONTEXT_WINDOW_SATURATION_RATIO or total_tokens > budget:
            # Skip if under threshold or already reported as overflow
            return findings

        confidence = 0.80 + min(0.14, (utilization - CONTEXT_WINDOW_SATURATION_RATIO) * 0.7)
        risk_id = self._get_saturation_risk_id(artifact_type)
        risk_meta = self._get_risk_metadata(risk_id)

        findings.append(
            ScanFinding(
                id=risk_id,
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                severity_score=risk_meta["severity_score"],
                severity_label=risk_meta["severity_label"],
                priority=risk_meta["priority"],
                gate_action=risk_meta["gate_action"],
                category=RiskCategory.PERFORMANCE,
                title=risk_meta["title"],
                description=(
                    f"Artifact uses {utilization:.0%} of available token budget "
                    f"({total_tokens}/{budget} tokens), leaving insufficient "
                    "space for user input and model output."
                ),
                location=FindingLocation(section="entire file"),
                evidence=f"Token utilization: {utilization:.0%} ({total_tokens}/{budget})",
                confidence=confidence,
                scanner_module=ScannerModule.TOKEN_ANALYZER,
                remediation=(
                    "Reserve space for user input and model output. "
                    "Consider dynamic prompt trimming or hierarchical structure."
                ),
                references=[],
                timestamp=datetime.now(timezone.utc),
            )
        )

        return findings

    def _check_verbosity(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        total_tokens: int,
    ) -> list[ScanFinding]:
        """Check for uncompressed verbose instructions."""
        findings: list[ScanFinding] = []

        if total_tokens < 200:
            return findings

        # Compute words-to-tokens ratio; very verbose text has more tokens per word
        words = content.split()
        word_count = len(words)
        if word_count == 0:
            return findings

        # Compute compression ratio for verbosity detection
        ratio = self._compute_compression_ratio(content)

        # Also check average sentence length
        sentences = re.split(r"[.!?]\s+|\n\n+", content)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 10]
        if not sentences:
            return findings

        avg_sentence_tokens = total_tokens / len(sentences) if sentences else 0

        # Flag if average sentence is very long AND compression is moderate
        # This means content is wordy but not outright repetitive
        if avg_sentence_tokens > 50 and ratio > 2.0 and ratio <= COMPRESSION_RATIO_THRESHOLD:
            confidence = 0.65 + min(0.14, (avg_sentence_tokens - 50) * 0.003)
            risk_id = self._get_verbosity_risk_id(artifact_type)
            risk_meta = self._get_risk_metadata(risk_id)

            findings.append(
                ScanFinding(
                    id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    severity_score=risk_meta["severity_score"],
                    severity_label=risk_meta["severity_label"],
                    priority=risk_meta["priority"],
                    gate_action=risk_meta["gate_action"],
                    category=RiskCategory.PERFORMANCE,
                    title=risk_meta["title"],
                    description=(
                        f"Content appears verbose with an average of "
                        f"{avg_sentence_tokens:.0f} tokens per sentence. "
                        "Could be compressed without losing meaning."
                    ),
                    location=FindingLocation(section="entire file"),
                    evidence=(
                        f"Avg tokens/sentence: {avg_sentence_tokens:.0f}, "
                        f"Compression ratio: {ratio:.2f}"
                    ),
                    confidence=confidence,
                    scanner_module=ScannerModule.TOKEN_ANALYZER,
                    remediation=(
                        "Use concise language, structured formats, "
                        "and prompt compression techniques."
                    ),
                    references=[],
                    timestamp=datetime.now(timezone.utc),
                )
            )

        return findings

    def _check_unbounded_dynamic(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for template variables with no length constraints."""
        findings: list[ScanFinding] = []

        # Look for template variables (common patterns)
        template_patterns = [
            r"\{\{(\w+)\}\}",  # Jinja2 style
            r"\{(\w+)\}",  # Python format style
            r"\$\{(\w+)\}",  # Shell/JS style
            r"<<(\w+)>>",  # Placeholder style
        ]

        # Keywords suggesting unbounded content
        unbounded_keywords = [
            "full_document",
            "document",
            "history",
            "conversation",
            "context",
            "full_text",
            "content",
            "input",
            "data",
            "messages",
            "chat_history",
            "user_history",
        ]

        found_vars: list[str] = []
        for pattern in template_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1).lower()
                if any(kw in var_name for kw in unbounded_keywords):
                    found_vars.append(match.group(0))

        if not found_vars:
            return findings

        # Check if there are length constraints mentioned nearby
        has_constraints = bool(
            re.search(
                r"(max_length|truncat|limit|max_tokens|[:]\s*\d+\s*(tokens?|chars?|words?))",
                content,
                re.IGNORECASE,
            )
        )

        if has_constraints:
            return findings

        confidence = 0.80 + min(0.14, len(found_vars) * 0.03)
        risk_id = self._get_unbounded_risk_id(artifact_type)
        risk_meta = self._get_risk_metadata(risk_id)

        findings.append(
            ScanFinding(
                id=risk_id,
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                severity_score=risk_meta["severity_score"],
                severity_label=risk_meta["severity_label"],
                priority=risk_meta["priority"],
                gate_action=risk_meta["gate_action"],
                category=RiskCategory.PERFORMANCE,
                title=risk_meta["title"],
                description=(
                    f"Found {len(found_vars)} template variable(s) that may inject "
                    "unbounded content without length constraints."
                ),
                location=FindingLocation(section="entire file"),
                evidence=f"Unbounded variables: {', '.join(found_vars[:5])}",
                confidence=confidence,
                scanner_module=ScannerModule.TOKEN_ANALYZER,
                remediation=(
                    "Set maximum length for dynamic content variables. "
                    "Implement truncation or budget guards."
                ),
                references=[],
                timestamp=datetime.now(timezone.utc),
            )
        )

        return findings

    # ========== Risk ID mapping helpers ==========

    def _get_budget_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate budget overflow risk ID for an artifact type."""
        mapping: dict[ArtifactType, str] = {
            ArtifactType.PROMPT: "P-P1",
            ArtifactType.SKILL: "SK-P1",
            ArtifactType.AGENT: "A-P2",
            ArtifactType.INSTRUCTION: "I-P1",
            ArtifactType.MEMORY: "M-P1",
            ArtifactType.MCP: "MCP-P3",
            ArtifactType.STEERING: "CMP-3",
            ArtifactType.RAG: "CMP-3",
        }
        return mapping.get(artifact_type, "P-P1")

    def _get_redundancy_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate redundancy risk ID for an artifact type."""
        mapping: dict[ArtifactType, str] = {
            ArtifactType.PROMPT: "P-P2",
            ArtifactType.SKILL: "SK-P1",
            ArtifactType.AGENT: "A-P3",
            ArtifactType.INSTRUCTION: "I-P3",
            ArtifactType.MEMORY: "M-P1",
            ArtifactType.MCP: "MCP-P3",
            ArtifactType.STEERING: "CMP-3",
            ArtifactType.RAG: "CMP-3",
        }
        return mapping.get(artifact_type, "P-P2")

    def _get_inefficiency_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate inefficiency risk ID for an artifact type."""
        mapping: dict[ArtifactType, str] = {
            ArtifactType.PROMPT: "P-P3",
            ArtifactType.SKILL: "SK-P1",
            ArtifactType.AGENT: "A-P3",
            ArtifactType.INSTRUCTION: "I-P4",
            ArtifactType.MEMORY: "M-P1",
            ArtifactType.MCP: "MCP-P3",
            ArtifactType.STEERING: "CMP-3",
            ArtifactType.RAG: "CMP-3",
        }
        return mapping.get(artifact_type, "P-P3")

    def _get_saturation_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate context saturation risk ID for an artifact type."""
        mapping: dict[ArtifactType, str] = {
            ArtifactType.PROMPT: "P-P4",
            ArtifactType.SKILL: "SK-P1",
            ArtifactType.AGENT: "A-P4",
            ArtifactType.INSTRUCTION: "I-P1",
            ArtifactType.MEMORY: "M-P1",
            ArtifactType.MCP: "MCP-P3",
            ArtifactType.STEERING: "MOD-2",
            ArtifactType.RAG: "CMP-3",
        }
        return mapping.get(artifact_type, "P-P4")

    def _get_verbosity_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate verbosity risk ID for an artifact type."""
        mapping: dict[ArtifactType, str] = {
            ArtifactType.PROMPT: "P-P5",
            ArtifactType.SKILL: "SK-P1",
            ArtifactType.AGENT: "A-P3",
            ArtifactType.INSTRUCTION: "I-P4",
            ArtifactType.MEMORY: "M-P1",
            ArtifactType.MCP: "MCP-P3",
            ArtifactType.STEERING: "CMP-3",
            ArtifactType.RAG: "CMP-3",
        }
        return mapping.get(artifact_type, "P-P5")

    def _get_unbounded_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate unbounded dynamic content risk ID."""
        mapping: dict[ArtifactType, str] = {
            ArtifactType.PROMPT: "P-P6",
            ArtifactType.SKILL: "SK-P1",
            ArtifactType.AGENT: "A-P4",
            ArtifactType.INSTRUCTION: "I-P1",
            ArtifactType.MEMORY: "M-P1",
            ArtifactType.MCP: "MCP-P3",
            ArtifactType.STEERING: "CMP-3",
            ArtifactType.RAG: "CMP-3",
        }
        return mapping.get(artifact_type, "P-P6")

    def _get_risk_metadata(self, risk_id: str) -> dict[str, Any]:
        """Get risk metadata (severity, priority, gate_action, title) by ID."""
        # Risk metadata lookup - derived from risk definitions
        metadata: dict[str, dict[str, Any]] = {
            "P-P1": {
                "severity_score": 6,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Token Budget Exceeded",
            },
            "P-P2": {
                "severity_score": 4,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P3,
                "gate_action": GateAction.INFO,
                "title": "Excessive Redundancy in Prompt",
            },
            "P-P3": {
                "severity_score": 3,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P4,
                "gate_action": GateAction.INFO,
                "title": "Inefficient Few-Shot Example Count",
            },
            "P-P4": {
                "severity_score": 5,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Context Window Saturation",
            },
            "P-P5": {
                "severity_score": 3,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P4,
                "gate_action": GateAction.INFO,
                "title": "Uncompressed Verbose Instructions",
            },
            "P-P6": {
                "severity_score": 5,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Unbounded Dynamic Content Insertion",
            },
            "SK-P1": {
                "severity_score": 4,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P3,
                "gate_action": GateAction.INFO,
                "title": "Excessive Skill Description Token Cost",
            },
            "A-P2": {
                "severity_score": 5,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Excessive Agent System Prompt Size",
            },
            "A-P3": {
                "severity_score": 4,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P3,
                "gate_action": GateAction.INFO,
                "title": "Tool Description Token Bloat",
            },
            "A-P4": {
                "severity_score": 5,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Unbounded Conversation History",
            },
            "I-P1": {
                "severity_score": 5,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Excessively Long Instructions",
            },
            "I-P3": {
                "severity_score": 4,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P3,
                "gate_action": GateAction.INFO,
                "title": "Redundant Instruction Content",
            },
            "I-P4": {
                "severity_score": 3,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P4,
                "gate_action": GateAction.INFO,
                "title": "Unnecessary Instruction Inclusion",
            },
            "M-P1": {
                "severity_score": 5,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Unbounded Memory Growth",
            },
            "CMP-3": {
                "severity_score": 6,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Context Budget Overflow from Composition",
            },
            "MCP-P3": {
                "severity_score": 4,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P3,
                "gate_action": GateAction.INFO,
                "title": "Missing Token Budget Awareness",
            },
            "MOD-2": {
                "severity_score": 5,
                "severity_label": SeverityLabel.MEDIUM,
                "priority": Priority.P2,
                "gate_action": GateAction.WARN,
                "title": "Model-Specific Token Limit Assumptions",
            },
        }
        return metadata.get(
            risk_id,
            {
                "severity_score": 4,
                "severity_label": SeverityLabel.LOW,
                "priority": Priority.P3,
                "gate_action": GateAction.INFO,
                "title": "Token Analysis Issue",
            },
        )
