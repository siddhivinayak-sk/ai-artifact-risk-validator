"""Finding aggregation and deduplication for the scan pipeline.

The Aggregator deduplicates findings with the same risk ID and location,
then applies suppression rules (config-based) to mark matching findings
as false positives.
"""

from __future__ import annotations

from fnmatch import fnmatch

from ai_artifact_risk_validator.models.config import SuppressionRule
from ai_artifact_risk_validator.models.findings import ScanFinding


class Aggregator:
    """Aggregates and deduplicates scan findings.

    Performs two-step post-processing on raw scanner output:
    1. Deduplication: removes findings with same (risk_id + artifact_path + location.line),
       keeping the one with highest confidence when duplicates exist.
    2. Suppression: applies suppression rules (risk_id + file_pattern via fnmatch) and
       marks matching findings with false_positive=True.
    """

    def aggregate(
        self,
        findings: list[ScanFinding],
        suppression_rules: list[SuppressionRule] | None = None,
    ) -> list[ScanFinding]:
        """Aggregate findings by deduplicating and applying suppression rules.

        Args:
            findings: Raw list of findings from scanner execution.
            suppression_rules: Optional list of suppression rules to apply.
                If None, no suppression is applied.

        Returns:
            Deduplicated list of findings with suppression rules applied.
        """
        calibrated = self._calibrate_confidence(findings)
        deduplicated = self._deduplicate(calibrated)
        if suppression_rules:
            deduplicated = self._apply_suppressions(deduplicated, suppression_rules)
        return deduplicated

    @staticmethod
    def _calibrate_confidence(findings: list[ScanFinding]) -> list[ScanFinding]:
        """Adjust confidence using semantic_score when present.

        Findings with a high ``semantic_score`` get a confidence boost
        (capped at 1.0).  Findings with a low ``semantic_score`` get a
        confidence penalty.  Findings without a ``semantic_score`` pass
        through unchanged.
        """
        result: list[ScanFinding] = []
        for f in findings:
            if f.semantic_score is None:
                result.append(f)
                continue
            # Blend original confidence with semantic_score (70/30 weight)
            blended = 0.7 * f.confidence + 0.3 * f.semantic_score
            result.append(f.model_copy(update={"confidence": min(blended, 1.0)}))
        return result

    def _deduplicate(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Remove duplicate findings, keeping the one with highest confidence.

        Duplicates are identified by the tuple (risk_id, artifact_path, location.line).
        When duplicates exist, the finding with the highest confidence score is kept.
        """
        best: dict[tuple[str, str, int | None], ScanFinding] = {}

        for finding in findings:
            key = (finding.id, finding.artifact_path, finding.location.line)
            existing = best.get(key)
            if existing is None or finding.confidence > existing.confidence:
                best[key] = finding

        return list(best.values())

    def _apply_suppressions(
        self,
        findings: list[ScanFinding],
        suppression_rules: list[SuppressionRule],
    ) -> list[ScanFinding]:
        """Apply suppression rules to findings, marking matches as false positives.

        A finding matches a suppression rule when:
        - The finding's risk ID matches the rule's risk_id
        - AND the finding's artifact_path matches the rule's file_pattern via fnmatch
          (if file_pattern is None, the rule matches ALL files for that risk_id)
        """
        result: list[ScanFinding] = []
        for finding in findings:
            suppressed = False
            for rule in suppression_rules:
                if self._matches_rule(finding, rule):
                    suppressed = True
                    break
            if suppressed:
                # Create a copy with false_positive=True
                result.append(finding.model_copy(update={"false_positive": True}))
            else:
                result.append(finding)
        return result

    def _matches_rule(self, finding: ScanFinding, rule: SuppressionRule) -> bool:
        """Check if a finding matches a suppression rule.

        Args:
            finding: The scan finding to check.
            rule: The suppression rule to match against.

        Returns:
            True if the finding matches the rule.
        """
        if finding.id != rule.risk_id:
            return False
        # If no file_pattern, the rule matches all files for that risk_id
        if rule.file_pattern is None:
            return True
        # Normalize path separators to forward slashes for consistent matching
        normalized_path = finding.artifact_path.replace("\\", "/")
        pattern = rule.file_pattern.replace("\\", "/")
        # Try matching against the full path
        if fnmatch(normalized_path, pattern):
            return True
        # Also try matching against just the filename or relative path segments
        # This handles the case where the pattern is relative (e.g., "tests/**")
        # but the artifact_path is absolute
        parts = normalized_path.split("/")
        for i in range(len(parts)):
            relative_segment = "/".join(parts[i:])
            if fnmatch(relative_segment, pattern):
                return True
        return False
