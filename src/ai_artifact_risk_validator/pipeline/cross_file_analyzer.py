"""Cross-file semantic analysis for detecting inter-artifact risks.

Provides a post-scan analysis phase that examines relationships between
findings and directives across multiple files. Detects semantic
contradictions, redundant directives, and cross-file dependency issues
that single-file scanners cannot identify.

Gracefully degrades to no-ops when ``sentence-transformers`` is absent.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding

if TYPE_CHECKING:
    from pathlib import Path

    from ai_artifact_risk_validator.semantic.similarity import SimilarityScorer

logger = get_logger(__name__)

# Minimum similarity score to flag a semantic contradiction across files.
_CONTRADICTION_THRESHOLD: float = 0.70

# Minimum similarity score for semantic redundancy detection.
_REDUNDANCY_THRESHOLD: float = 0.85

# Negation markers used to detect directive polarity.
_NEGATION_MARKERS = frozenset(
    {
        "never",
        "not",
        "don't",
        "dont",
        "cannot",
        "must not",
        "shall not",
        "do not",
        "should not",
        "no",
        "shouldn't",
        "won't",
        "will not",
    }
)

# Pattern that extracts directive sentences (must/shall/always/never + rest).
_DIRECTIVE_RE = re.compile(
    r"^.*\b(must|shall|always|never|do\s+not|don'?t|cannot|should|will)\b.+$",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_directives(content: str) -> list[str]:
    """Extract directive sentences from artifact content.

    Returns sentences that contain modal verbs indicating instructions or
    constraints (must, shall, always, never, etc.).
    """
    return [m.group(0).strip() for m in _DIRECTIVE_RE.finditer(content)]


def _has_negation(text: str) -> bool:
    """Check whether *text* contains a negation marker."""
    lower = text.lower()
    return any(marker in lower for marker in _NEGATION_MARKERS)


class CrossFileAnalyzer:
    """Detects cross-file semantic contradictions and redundancies.

    After the per-file scanning phase completes, this analyzer compares
    directives extracted from different files to find contradictions
    (opposing polarity, high similarity) and redundancies (same polarity,
    very high similarity).

    When ``sentence-transformers`` is not installed the analyzer is a no-op.
    """

    def __init__(self) -> None:
        self._scorer: SimilarityScorer | None = None
        self._available: bool | None = None

    # ------------------------------------------------------------------
    # availability helpers
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """Return ``True`` if the semantic engine is available."""
        if self._available is None:
            try:
                from ai_artifact_risk_validator.semantic.embeddings import (
                    EmbeddingEngine,
                )

                self._available = EmbeddingEngine().is_available
            except Exception:
                self._available = False
        return self._available

    def _ensure_loaded(self) -> bool:
        """Lazily create the :class:`SimilarityScorer`."""
        if self._scorer is not None:
            return True
        if not self.is_available:
            return False
        try:
            from ai_artifact_risk_validator.semantic.similarity import (
                SimilarityScorer,
            )

            self._scorer = SimilarityScorer()
            return True
        except Exception:
            logger.debug("Failed to initialise SimilarityScorer", exc_info=True)
            self._available = False
            return False

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        file_contents: dict[Path, str],
        artifact_types: dict[Path, ArtifactType],
    ) -> list[ScanFinding]:
        """Run cross-file analysis over all scanned files.

        Parameters
        ----------
        file_contents:
            Mapping of file path → full text content.
        artifact_types:
            Mapping of file path → classified :class:`ArtifactType`.

        Returns
        -------
        list[ScanFinding]
            Findings for detected cross-file issues.
        """
        if not self._ensure_loaded() or self._scorer is None:
            return []

        # 1. Extract directives per file.
        directives_by_file: dict[Path, list[str]] = {}
        for fpath, content in file_contents.items():
            dirs = _extract_directives(content)
            if dirs:
                directives_by_file[fpath] = dirs

        if len(directives_by_file) < 2:
            return []

        findings: list[ScanFinding] = []

        # 2. Pair-wise comparison across files.
        file_list = list(directives_by_file.keys())
        for i in range(len(file_list)):
            for j in range(i + 1, len(file_list)):
                fa, fb = file_list[i], file_list[j]
                findings.extend(
                    self._compare_files(
                        fa,
                        directives_by_file[fa],
                        artifact_types.get(fa, ArtifactType.PROMPT),
                        fb,
                        directives_by_file[fb],
                        artifact_types.get(fb, ArtifactType.PROMPT),
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # internal comparison
    # ------------------------------------------------------------------

    def _compare_files(
        self,
        path_a: Path,
        directives_a: list[str],
        type_a: ArtifactType,
        path_b: Path,
        directives_b: list[str],
        type_b: ArtifactType,
    ) -> list[ScanFinding]:
        """Compare directives from two files for contradictions/redundancies."""
        if self._scorer is None:
            return []

        findings: list[ScanFinding] = []
        seen_pairs: set[tuple[str, str]] = set()

        for da in directives_a:
            for db in directives_b:
                key = (da, db) if da < db else (db, da)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)

                try:
                    score: float = self._scorer.score_pairwise(da, db)
                except Exception:
                    logger.debug("Pair scoring failed", exc_info=True)
                    continue

                neg_a = _has_negation(da)
                neg_b = _has_negation(db)
                opposing = neg_a != neg_b

                if opposing and score >= _CONTRADICTION_THRESHOLD:
                    findings.append(
                        self._make_finding(
                            risk_id="CMP-1",
                            path_a=path_a,
                            path_b=path_b,
                            dir_a=da,
                            dir_b=db,
                            score=score,
                            kind="Cross-File Semantic Contradiction",
                            description=(
                                "Semantically similar directives with opposing polarity "
                                f"detected across files (similarity {score:.2f}). "
                                "This may cause conflicting AI agent behaviour."
                            ),
                            severity_score=7,
                            severity_label=SeverityLabel.HIGH,
                            gate_action=GateAction.WARN,
                            confidence=min(score, 0.95),
                        )
                    )
                elif not opposing and score >= _REDUNDANCY_THRESHOLD:
                    findings.append(
                        self._make_finding(
                            risk_id="CMP-5",
                            path_a=path_a,
                            path_b=path_b,
                            dir_a=da,
                            dir_b=db,
                            score=score,
                            kind="Cross-File Redundant Directive",
                            description=(
                                "Nearly identical directives detected across files "
                                f"(similarity {score:.2f}). "
                                "Consider consolidating to avoid maintenance drift."
                            ),
                            severity_score=3,
                            severity_label=SeverityLabel.LOW,
                            gate_action=GateAction.WARN,
                            confidence=min(score, 0.90),
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # finding factory
    # ------------------------------------------------------------------

    @staticmethod
    def _make_finding(
        *,
        risk_id: str,
        path_a: Path,
        path_b: Path,
        dir_a: str,
        dir_b: str,
        score: float,
        kind: str,
        description: str,
        severity_score: int,
        severity_label: SeverityLabel,
        gate_action: GateAction,
        confidence: float,
    ) -> ScanFinding:
        evidence_text = f"[{path_a.name}] {dir_a[:80]} <-> [{path_b.name}] {dir_b[:80]}"
        return ScanFinding(
            id=risk_id,
            artifact_type=ArtifactType.PROMPT,
            artifact_path=str(path_a),
            severity_score=severity_score,
            severity_label=severity_label,
            priority=Priority.P1,
            gate_action=gate_action,
            category=RiskCategory.RELIABILITY,
            title=kind,
            description=description,
            location=FindingLocation(line=0, section=f"cross-file:{path_b.name}"),
            evidence=evidence_text[:200],
            confidence=confidence,
            scanner_module=ScannerModule.COMPOSE_ANALYZE,
            remediation=(
                "Review the directives in both files and reconcile conflicting "
                "or duplicated instructions."
            ),
        )
