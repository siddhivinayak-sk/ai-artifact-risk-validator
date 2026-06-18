"""Risk definitions for dependency scanning (DEP-S1 and DEP-S2).

Contains risks for typosquatting detection and abandoned dependency detection
in AI artifact dependency manifests.
"""

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.risk import RiskDefinition

_DEP_TYPES: list[ArtifactType] = [
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.HOOK,
    ArtifactType.PLUGIN,
    ArtifactType.MCP,
    ArtifactType.ORCHESTRATION,
]

RISKS: list[RiskDefinition] = [
    RiskDefinition(
        id="DEP-S1",
        title="Typosquatting: Package Name Resembles Popular Package",
        artifact_types=_DEP_TYPES,
        category=RiskCategory.SECURITY,
        severity_score=7,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        description=(
            "A dependency name is suspiciously similar (Levenshtein distance ≤ 2) to a "
            "well-known popular package. This is the pattern used by typosquatting attacks, "
            "where an adversary publishes a malicious package under a misspelled name to "
            "capture mistaken installs. If installed, the package may contain credential "
            "harvesting, backdoors, or supply-chain malware."
        ),
        examples=[
            "requets (instead of requests) — one character omitted",
            "pydanctic (instead of pydantic) — transposed characters",
            "flask-secure (instead of flask-security) — truncated suffix",
            "nump (instead of numpy) — character removed",
        ],
        mitigation=[
            "Verify the exact package name on PyPI/npm before adding to requirements",
            "Use hash-pinning (requirements.txt with --hash) for all dependencies",
            "Enable dependency confusion protection in your package registry",
            "Review new dependencies in code review before merging",
            "Use a software composition analysis (SCA) tool on all PRs",
        ],
        detection_mechanisms=[
            "Levenshtein distance ≤ 2 comparison against the top-500 PyPI and top-200 npm package list",
            "Edit distance 1 (one insertion/deletion/substitution) triggers high confidence flag",
        ],
        scanner_modules=[ScannerModule.DEP_SCAN],
        owasp_refs=["LLM03:2025 Supply Chain Risks", "A06:2021 Vulnerable and Outdated Components"],
        cwe_refs=["CWE-1357", "CWE-829"],
    ),
    RiskDefinition(
        id="DEP-S2",
        title="Potentially Abandoned Dependency",
        artifact_types=_DEP_TYPES,
        category=RiskCategory.SECURITY,
        severity_score=5,
        severity_label=SeverityLabel.MEDIUM,
        priority=Priority.P2,
        gate_action=GateAction.WARN,
        description=(
            "A dependency has not received a release in an extended period and may be "
            "abandoned. Abandoned packages accumulate unpatched CVEs, may be taken over "
            "by malicious actors (dependency hijacking), and are not maintained against "
            "breaking changes in their transitive dependencies."
        ),
        examples=[
            "Package with last release >2 years ago and open security issues",
            "Package with 'deprecated' or 'archived' in its description",
            "Package whose maintainer transferred ownership to an unknown party",
        ],
        mitigation=[
            "Check the package's repository for activity and maintenance status",
            "Replace with an actively maintained alternative if one exists",
            "Fork and vendor the package internally if it is critical and unmaintained",
            "Subscribe to security advisories for all dependencies via OSV.dev or GitHub advisories",
        ],
        detection_mechanisms=[
            "OSV.dev API query for last-release date (requires allow_network_requests=true)",
            "Heuristic: packages matching known-abandoned patterns (version 0.x with no recent activity)",
        ],
        scanner_modules=[ScannerModule.DEP_SCAN],
        owasp_refs=["LLM03:2025 Supply Chain Risks", "A06:2021 Vulnerable and Outdated Components"],
        cwe_refs=["CWE-1357"],
    ),
]
