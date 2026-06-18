"""Aggregate risk scorer for the AI Artifact Risk Validator.

Computes a unified 0-100 risk score from weighted finding severities,
applies an executable-script multiplier, and maps the score to a human-readable
severity band and recommendation label.

Research basis: SkillSpector (Liu et al., 2026) found that artifacts containing
executable scripts are 2.12x more likely to be vulnerable; a 1.3x risk multiplier
captures this empirical observation.
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.enums import SeverityLabel
from ai_artifact_risk_validator.models.findings import ScanFinding

# Severity weights for the aggregate risk score.
_SEVERITY_WEIGHTS: dict[SeverityLabel, int] = {
    SeverityLabel.CRITICAL: 50,
    SeverityLabel.HIGH: 25,
    SeverityLabel.MEDIUM: 10,
    SeverityLabel.LOW: 5,
    SeverityLabel.INFORMATIONAL: 2,
}

# Executable file extensions that trigger the 1.3x risk multiplier.
EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".rb",
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".swift",
        ".php",
        ".pl",
        ".lua",
    }
)

_EXECUTABLE_MULTIPLIER: float = 1.3


def compute_risk_score(findings: list[ScanFinding], has_executable_scripts: bool) -> int:
    """Compute an aggregate 0-100 risk score from weighted finding severities.

    Non-false-positive findings are weighted by severity label. When the artifact
    contains executable scripts, the raw score is multiplied by 1.3 to account
    for the empirically higher vulnerability likelihood. The result is clamped
    to the [0, 100] range.

    Args:
        findings: All scan findings (false-positive findings are excluded from scoring).
        has_executable_scripts: Whether the scanned artifact includes executable files.

    Returns:
        Integer risk score in [0, 100].
    """
    raw = 0
    for finding in findings:
        if finding.false_positive:
            continue
        raw += _SEVERITY_WEIGHTS.get(finding.severity_label, 0)

    if has_executable_scripts:
        raw = int(raw * _EXECUTABLE_MULTIPLIER)

    return min(raw, 100)


def severity_band(score: int) -> tuple[str, str]:
    """Map a 0-100 risk score to a (severity_label, recommendation) pair.

    Bands match SkillSpector's thresholds:
        0-20  → LOW / SAFE
        21-50 → MEDIUM / CAUTION
        51-80 → HIGH / DO_NOT_INSTALL
        81-100 → CRITICAL / DO_NOT_INSTALL

    Args:
        score: An integer risk score in [0, 100].

    Returns:
        A 2-tuple of (risk_severity, risk_recommendation).
    """
    if score <= 20:
        return "LOW", "SAFE"
    elif score <= 50:
        return "MEDIUM", "CAUTION"
    elif score <= 80:
        return "HIGH", "DO_NOT_INSTALL"
    else:
        return "CRITICAL", "DO_NOT_INSTALL"


def detect_executable_scripts(file_paths: list[str]) -> bool:
    """Detect whether a list of file paths contains any executable scripts.

    Checks each path's suffix against the ``EXECUTABLE_EXTENSIONS`` set.

    Args:
        file_paths: List of file path strings (absolute or relative).

    Returns:
        True if at least one path has an executable extension.
    """
    from pathlib import Path

    return any(Path(p).suffix.lower() in EXECUTABLE_EXTENSIONS for p in file_paths)
