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
        deduplicated = self._deduplicate(findings)
        if suppression_rules:
            deduplicated = self._apply_suppressions(deduplicated, suppression_rules)
        return deduplicated

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
        # Use fnmatch for glob-style pattern matching
        return fnmatch(finding.artifact_path, rule.file_pattern)
