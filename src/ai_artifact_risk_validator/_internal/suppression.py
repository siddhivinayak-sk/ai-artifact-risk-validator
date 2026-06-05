"""False positive and suppression logic for the AI Artifact Risk Validator.

Provides inline suppression comment parsing and config-based suppression
matching. Inline comments suppress findings on the NEXT line after the comment.

Supported inline comment styles:
    - ``# aav-ignore: RISK-ID``
    - ``// aav-ignore: RISK-ID``
    - ``<!-- aav-ignore: RISK-ID -->``
    - ``/* aav-ignore: RISK-ID */``

Multiple risk IDs can be specified comma-separated:
    - ``# aav-ignore: P-S1, P-S3``
"""

from __future__ import annotations

import re
from fnmatch import fnmatch

from ai_artifact_risk_validator.models.config import SuppressionRule
from ai_artifact_risk_validator.models.findings import ScanFinding

# Regex patterns for extracting suppression directives from inline comments.
# Each pattern captures the comma-separated list of risk IDs.
_INLINE_PATTERNS: list[re.Pattern[str]] = [
    # Hash-style: # aav-ignore: RISK-ID, RISK-ID2
    re.compile(r"#\s*aav-ignore:\s*(.+?)$", re.IGNORECASE),
    # C-style single-line: // aav-ignore: RISK-ID
    re.compile(r"//\s*aav-ignore:\s*(.+?)$", re.IGNORECASE),
    # HTML comment: <!-- aav-ignore: RISK-ID -->
    re.compile(r"<!--\s*aav-ignore:\s*(.+?)\s*-->", re.IGNORECASE),
    # C-style block comment: /* aav-ignore: RISK-ID */
    re.compile(r"/\*\s*aav-ignore:\s*(.+?)\s*\*/", re.IGNORECASE),
]


def parse_inline_suppressions(content: str) -> dict[int, list[str]]:
    """Scan file content line by line for suppression comments.

    Suppression comments apply to the NEXT line (the line after the comment).
    Returns a dict mapping 1-based line numbers to lists of suppressed risk IDs.

    Args:
        content: The full text content of a file.

    Returns:
        Dict mapping line number (1-based) to list of suppressed risk IDs.
        The line number is the line that is suppressed (i.e., the line AFTER
        the comment containing the suppression directive).
    """
    suppressions: dict[int, list[str]] = {}
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        for pattern in _INLINE_PATTERNS:
            match = pattern.search(stripped)
            if match:
                raw_ids = match.group(1)
                # Parse comma-separated risk IDs, stripping whitespace
                risk_ids = [rid.strip() for rid in raw_ids.split(",") if rid.strip()]
                # Suppression applies to the NEXT line (i is 0-based, so next line is i+2 in 1-based)
                target_line = i + 2
                if target_line not in suppressions:
                    suppressions[target_line] = []
                suppressions[target_line].extend(risk_ids)
                break  # Only match the first pattern per line

    return suppressions


def apply_inline_suppressions(findings: list[ScanFinding], content: str) -> list[ScanFinding]:
    """Apply inline suppression comments to findings.

    Parses inline suppressions from content and marks matching findings
    (by risk_id and line number) as false positives.

    Args:
        findings: List of scan findings to process.
        content: The file content containing potential suppression comments.

    Returns:
        Modified list of findings with matching ones marked as false_positive=True.
    """
    suppressions = parse_inline_suppressions(content)
    if not suppressions:
        return findings

    result: list[ScanFinding] = []
    for finding in findings:
        finding_line = finding.location.line
        if finding_line is not None and finding_line in suppressions:
            suppressed_ids = suppressions[finding_line]
            if finding.id in suppressed_ids:
                result.append(finding.model_copy(update={"false_positive": True}))
                continue
        result.append(finding)
    return result


def apply_config_suppressions(
    findings: list[ScanFinding], rules: list[SuppressionRule]
) -> list[ScanFinding]:
    """Apply config-based suppression rules to findings.

    Matches finding.id against rule.risk_id AND finding.artifact_path against
    rule.file_pattern (using fnmatch glob matching). If file_pattern is None,
    the rule matches all files for that risk_id.

    Args:
        findings: List of scan findings to process.
        rules: List of suppression rules from configuration.

    Returns:
        Modified list of findings with matching ones marked as false_positive=True.
    """
    if not rules:
        return findings

    result: list[ScanFinding] = []
    for finding in findings:
        suppressed = False
        for rule in rules:
            if _matches_suppression_rule(finding, rule):
                suppressed = True
                break
        if suppressed:
            result.append(finding.model_copy(update={"false_positive": True}))
        else:
            result.append(finding)
    return result


def clear_suppressions(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Clear all suppression markings from findings (--no-ignore support).

    When the --no-ignore flag is active, all findings should have
    false_positive set to False regardless of suppression rules.

    Args:
        findings: List of scan findings to process.

    Returns:
        List of findings with all false_positive flags set to False.
    """
    return [
        finding.model_copy(update={"false_positive": False}) if finding.false_positive else finding
        for finding in findings
    ]


def _matches_suppression_rule(finding: ScanFinding, rule: SuppressionRule) -> bool:
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
