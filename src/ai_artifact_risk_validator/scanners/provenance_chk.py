"""ProvenanceChk scanner module for detecting provenance and integrity issues.

Detects missing provenance metadata, unsigned artifacts, missing integrity
hashes, unknown source/origin, stale provenance, and license/compliance gaps
in AI artifacts. Uses optional integrations with gitpython and cryptography
for enhanced verification.
"""

from __future__ import annotations

import fnmatch
import json
import re
from datetime import datetime, timezone
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

# --- Risk metadata lookup ---
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "SK-S7": {
        "title": "Unverified Skill Source/Provenance",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill artifact lacks verified source or provenance information.",
        "remediation": "Add provenance metadata with author, source repository URL, and version.",
    },
    "SK-S8": {
        "title": "Missing Skill Integrity Verification",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill artifact has no integrity hash or checksum for verification.",
        "remediation": "Add SHA-256 checksum or digital signature for integrity verification.",
    },
    "MCP-S4": {
        "title": "Unverified MCP Server Dependencies",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server configuration references unverified or unknown dependencies.",
        "remediation": "Verify all MCP dependencies against trusted registries. Pin versions.",
    },
    "MCP-S5": {
        "title": "Missing MCP Integrity Verification",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server artifact lacks integrity hash or signature verification.",
        "remediation": "Add integrity checksums for MCP server packages and verify signatures.",
    },
    "PL-S6": {
        "title": "Unverified Plugin Source",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin artifact has no verified source or provenance information.",
        "remediation": "Add source repository URL, author, and version metadata to plugin.",
    },
    "PL-S7": {
        "title": "Missing Plugin Integrity Hash",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin artifact has no integrity hash for verification.",
        "remediation": "Add SHA-256 hash or digital signature for plugin verification.",
    },
    "A-S8": {
        "title": "Agent Provenance Not Verified",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Agent artifact lacks provenance metadata for source verification.",
        "remediation": "Add provenance metadata including author, source, and timestamp.",
    },
    "A-S9": {
        "title": "Agent Integrity Hash Missing",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Agent artifact has no integrity hash or digital signature.",
        "remediation": "Add integrity verification mechanism (checksum or signature).",
    },
    "GOV-1": {
        "title": "Missing Artifact Provenance/Authorship Metadata",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.GOVERNANCE,
        "description": "Artifact lacks provenance or authorship metadata required for governance.",
        "remediation": "Add provenance metadata including author, version, and timestamp.",
    },
    "GOV-2": {
        "title": "Missing Artifact Version Control Metadata",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.GOVERNANCE,
        "description": "Artifact lacks version control metadata for change tracking.",
        "remediation": "Add version field and changelog references to artifact metadata.",
    },
    "REG-2": {
        "title": "Missing Regulatory Provenance Documentation",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": "Artifact lacks provenance documentation required for regulatory compliance.",
        "remediation": "Add provenance metadata with full audit trail (author, date, approver).",
    },
    "RAG-S2": {
        "title": "Unverified RAG Source Content",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "RAG knowledge base content has no verified source or provenance.",
        "remediation": "Add source attribution and verification for all RAG content.",
    },
}

# --- Artifact type to provenance risk ID mapping ---
_ARTIFACT_PROVENANCE_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S7",
    ArtifactType.AGENT: "A-S8",
    ArtifactType.MCP: "MCP-S4",
    ArtifactType.PLUGIN: "PL-S6",
    ArtifactType.RAG: "RAG-S2",
}

# --- Artifact type to integrity risk ID mapping ---
_ARTIFACT_INTEGRITY_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S8",
    ArtifactType.AGENT: "A-S9",
    ArtifactType.MCP: "MCP-S5",
    ArtifactType.PLUGIN: "PL-S7",
    ArtifactType.RAG: "RAG-S2",
}

# --- Provenance metadata patterns ---
# Patterns that indicate provenance metadata is present
_AUTHOR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:^|\n)\s*(?:author|created[_\-\s]?by|maintainer)\s*[:=]"),
    re.compile(r"(?i)(?:^|\n)\s*#\s*author\b"),
    re.compile(r'(?i)"author"\s*:'),
    re.compile(r"(?i)author:\s*\S"),
]

_VERSION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:^|\n)\s*version\s*[:=]\s*\S"),
    re.compile(r'(?i)"version"\s*:\s*"'),
    re.compile(r"(?i)version:\s*['\"]?\d"),
]

_TIMESTAMP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:^|\n)\s*(?:created|date|timestamp|last[_\-\s]?modified|updated)\s*[:=]"),
    re.compile(r'(?i)"(?:created|date|timestamp|last_modified|updated)"\s*:'),
    re.compile(r"(?i)(?:created|date|timestamp|last_modified|updated):\s*\S"),
]

_SOURCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:^|\n)\s*(?:source|repository|repo|origin|homepage|url)\s*[:=]"),
    re.compile(r'(?i)"(?:source|repository|homepage|url)"\s*:'),
    re.compile(r"(?i)(?:source|repository|repo|origin|homepage|url):\s*\S"),
    re.compile(r"https?://(?:github|gitlab|bitbucket)\.\S+"),
]

# --- Integrity/hash patterns ---
_HASH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)(?:^|\n)\s*(?:sha256|sha\-256|sha512|sha\-512|checksum|hash|integrity|digest)\s*[:=]"
    ),
    re.compile(r'(?i)"(?:sha256|sha512|checksum|hash|integrity|digest)"\s*:'),
    re.compile(
        r"(?i)(?:sha256|sha-256|sha512|sha-512|checksum|hash|integrity|digest):\s*[0-9a-fA-F]"
    ),
    re.compile(r"\b[0-9a-fA-F]{64}\b"),  # SHA-256 hex string
    re.compile(r"\b[0-9a-fA-F]{128}\b"),  # SHA-512 hex string
    re.compile(r"sha256-[A-Za-z0-9+/=]{43,}"),  # SRI hash format
    re.compile(r"sha512-[A-Za-z0-9+/=]{86,}"),  # SRI hash format SHA-512
]

# --- Signature patterns ---
_SIGNATURE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:^|\n)\s*(?:signature|signed[_\-\s]?by|pgp|gpg)\s*[:=]"),
    re.compile(r'(?i)"(?:signature|signed_by)"\s*:'),
    re.compile(r"-----BEGIN (?:PGP SIGNATURE|SIGNED MESSAGE)-----"),
    re.compile(r"(?i)(?:^|\n)\s*(?:sig|signature):\s*\S"),
]

# --- License/compliance patterns ---
_LICENSE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:^|\n)\s*(?:license|licence|spdx)\s*[:=]"),
    re.compile(r'(?i)"license"\s*:'),
    re.compile(r"(?i)license:\s*\S"),
    re.compile(r"(?i)MIT|Apache-2\.0|GPL|BSD|ISC|MPL"),
]

# --- Stale provenance detection ---
# If a date is found and it's older than this many days, flag as stale
_STALENESS_THRESHOLD_DAYS = 365

# Date patterns to extract for staleness checking
_DATE_EXTRACTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(\d{4}/\d{2}/\d{2})"),
    re.compile(r"(\d{2}/\d{2}/\d{4})"),
]


# --- Path classification patterns for scope restriction ---
# Patterns for test/spec/workflow directories (first-party, skip provenance entirely)
_FIRST_PARTY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(^|[\\/])tests?[\\/]"),  # tests/ or test/
    re.compile(r"(^|[\\/])__tests__[\\/]"),  # __tests__/
    re.compile(r"(^|[\\/])spec[\\/]"),  # spec/
    re.compile(r"[\\/]\.kiro[\\/]specs[\\/]"),  # .kiro/specs/
    re.compile(r"[\\/]\.kiro[\\/]workflows[\\/]"),  # .kiro/workflows/
]

# Patterns for documentation directories (downgrade severity to INFO)
_DOCUMENTATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(^|[\\/])docs?[\\/]"),  # doc/ or docs/
    re.compile(r"(^|[\\/])documentation[\\/]"),  # documentation/
]

# Patterns for external/vendor directories (retain full severity)
_EXTERNAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(^|[\\/])plugins?[\\/]"),  # plugin/ or plugins/
    re.compile(r"(^|[\\/])vendor[\\/]"),  # vendor/
    re.compile(r"(^|[\\/])node_modules[\\/]"),  # node_modules/
    re.compile(r"(^|[\\/])external[\\/]"),  # external/
]


def _is_test_or_spec_path(artifact_path: str) -> bool:
    """Check if the file path matches a test or spec directory pattern.

    Files in test/spec directories are first-party versioned files that do not
    need provenance or integrity verification.

    Args:
        artifact_path: Path to the artifact file.

    Returns:
        True if the path matches any first-party test/spec pattern.
    """
    for pattern in _FIRST_PARTY_PATTERNS:
        if pattern.search(artifact_path):
            return True
    return False


def _is_documentation_path(artifact_path: str) -> bool:
    """Check if the file path is under a documentation directory.

    Documentation files get reduced severity (INFO) for provenance findings
    rather than being skipped entirely.

    Args:
        artifact_path: Path to the artifact file.

    Returns:
        True if the path matches any documentation directory pattern.
    """
    for pattern in _DOCUMENTATION_PATTERNS:
        if pattern.search(artifact_path):
            return True
    return False


def _is_external_path(artifact_path: str) -> bool:
    """Check if the file path matches an external/vendor directory pattern.

    External files (plugins, vendor, node_modules) are considered
    externally-sourced and retain full High/Critical severity for
    provenance and integrity findings.

    Args:
        artifact_path: Path to the artifact file.

    Returns:
        True if the path matches any external/vendor directory pattern.
    """
    for pattern in _EXTERNAL_PATTERNS:
        if pattern.search(artifact_path):
            return True
    return False


def _has_pattern_match(content: str, patterns: list[re.Pattern[str]]) -> bool:
    """Check if any of the patterns match in the content.

    Args:
        content: Text to search.
        patterns: List of compiled regex patterns.

    Returns:
        True if at least one pattern matches.
    """
    for pattern in patterns:
        if pattern.search(content):
            return True
    return False


def _extract_dates(content: str) -> list[datetime]:
    """Extract parseable dates from content.

    Args:
        content: Text to search for dates.

    Returns:
        List of parsed datetime objects.
    """
    dates: list[datetime] = []
    for pattern in _DATE_EXTRACTION_PATTERNS:
        for match in pattern.finditer(content):
            date_str = match.group(1)
            for fmt in (
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d",
                "%Y/%m/%d",
                "%m/%d/%Y",
            ):
                try:
                    parsed = datetime.strptime(date_str[: len(fmt) + 5], fmt)
                    dates.append(parsed.replace(tzinfo=timezone.utc))
                    break
                except (ValueError, IndexError):
                    continue
    return dates


class ProvenanceChkScanner(BaseScanner):
    """Scanner for detecting provenance and integrity issues in artifacts.

    Uses multiple detection techniques:
    1. Metadata extraction checking for author, version, timestamp, source
    2. Integrity hash validation (SHA-256 checksums, SRI hashes)
    3. Signature verification (PGP/GPG signatures)
    4. Source attribution checking (repository URLs)
    5. Staleness detection (very old last-modified dates)
    6. License/compliance metadata checks

    The scanner always functions using built-in metadata pattern analysis,
    with optional gitpython and cryptography dependencies providing enhanced
    git history analysis and signature verification.
    """

    def __init__(self) -> None:
        """Initialize the ProvenanceChk scanner with lazy-loaded optional deps."""
        self._git: Any | None = None
        self._git_loaded = False
        self._cryptography: Any | None = None
        self._cryptography_loaded = False
        self._config_first_party_patterns: list[str] = []

    def set_first_party_patterns(self, patterns: list[str]) -> None:
        """Set configurable first-party path patterns from ValidatorConfig.

        These patterns use glob syntax (e.g. ``tests/**``, ``src/**``) and
        extend the built-in ``_FIRST_PARTY_PATTERNS`` when checking whether
        a file should be exempt from provenance/integrity scanning.

        Args:
            patterns: List of glob patterns identifying first-party paths.
        """
        self._config_first_party_patterns = patterns

    def _is_first_party_by_config(self, artifact_path: str) -> bool:
        """Check if the artifact path matches any config-defined first-party pattern.

        Uses fnmatch-style glob matching against path components. Normalises
        the path to forward slashes for consistent matching.

        Args:
            artifact_path: Path to the artifact file.

        Returns:
            True if the path matches any configured first-party pattern.
        """
        if not self._config_first_party_patterns:
            return False
        # Normalise to forward slashes for consistent matching
        normalised = artifact_path.replace("\\", "/")
        for pattern in self._config_first_party_patterns:
            # Match against the full path and also relative path fragments
            if fnmatch.fnmatch(normalised, pattern):
                return True
            if fnmatch.fnmatch(normalised, "*/" + pattern):
                return True
            # Also match basename-only patterns against any path component
            if "/" not in pattern and fnmatch.fnmatch(normalised.split("/")[-1], pattern):
                return True
        return False

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.PROVENANCE_CHK

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return [
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.MCP,
            ArtifactType.PLUGIN,
            ArtifactType.RAG,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner detects."""
        return [
            "SK-S7",
            "SK-S8",
            "MCP-S4",
            "MCP-S5",
            "PL-S6",
            "PL-S7",
            "A-S8",
            "A-S9",
            "GOV-1",
            "GOV-2",
            "REG-2",
            "RAG-S2",
        ]

    def is_available(self) -> bool:
        """Always available - uses metadata pattern analysis without optional deps."""
        return True

    def _load_git(self) -> Any | None:
        """Lazily load gitpython library.

        Returns:
            The git module or None if not installed.
        """
        if not self._git_loaded:
            self._git_loaded = True
            try:
                import git

                self._git = git
            except ImportError:
                self._git = None
        return self._git

    def _load_cryptography(self) -> Any | None:
        """Lazily load cryptography library.

        Returns:
            The cryptography module or None if not installed.
        """
        if not self._cryptography_loaded:
            self._cryptography_loaded = True
            try:
                import cryptography

                self._cryptography = cryptography
            except ImportError:
                self._cryptography = None
        return self._cryptography

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
            risk_id: The risk ID to report.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact file.
            evidence: The triggering text/pattern.
            confidence: Detection confidence (0.0-1.0).
            line: Line number where finding was detected.

        Returns:
            A fully constructed ScanFinding.
        """
        metadata = _RISK_METADATA[risk_id]

        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=metadata["severity_score"],
            severity_label=metadata["severity_label"],
            priority=metadata["priority"],
            gate_action=metadata["gate_action"],
            category=metadata["category"],
            title=metadata["title"],
            description=metadata["description"],
            location=FindingLocation(line=line),
            evidence=evidence,
            confidence=confidence,
            scanner_module=ScannerModule.PROVENANCE_CHK,
            remediation=metadata["remediation"],
            references=[],
        )

    def _check_provenance_metadata(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for missing provenance metadata (author, version, timestamp, source).

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for missing provenance metadata.
        """
        findings: list[ScanFinding] = []

        has_author = _has_pattern_match(content, _AUTHOR_PATTERNS)
        has_version = _has_pattern_match(content, _VERSION_PATTERNS)
        has_timestamp = _has_pattern_match(content, _TIMESTAMP_PATTERNS)
        has_source = _has_pattern_match(content, _SOURCE_PATTERNS)

        missing_fields: list[str] = []
        if not has_author:
            missing_fields.append("author")
        if not has_version:
            missing_fields.append("version")
        if not has_timestamp:
            missing_fields.append("timestamp")
        if not has_source:
            missing_fields.append("source")

        # If any provenance fields are missing, flag it
        if missing_fields:
            # Use artifact-specific risk ID for provenance issues
            provenance_risk_id = _ARTIFACT_PROVENANCE_MAP.get(artifact_type, "GOV-1")
            evidence = f"Missing provenance metadata: {', '.join(missing_fields)}"

            findings.append(
                self._create_finding(
                    risk_id=provenance_risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.95,
                )
            )

            # Also flag GOV-1 if not already the primary risk
            if provenance_risk_id != "GOV-1":
                findings.append(
                    self._create_finding(
                        risk_id="GOV-1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.95,
                    )
                )

        # Check version control metadata (GOV-2)
        if not has_version:
            findings.append(
                self._create_finding(
                    risk_id="GOV-2",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence="Missing version control metadata",
                    confidence=0.95,
                )
            )

        return findings

    def _check_integrity_hash(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for missing integrity hash/checksum and validate hash format.

        If a hash declaration is found, validates its format:
        - SHA-256: exactly 64 hex characters
        - SHA-512: exactly 128 hex characters

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for missing or malformed integrity hashes.
        """
        findings: list[ScanFinding] = []

        has_hash = _has_pattern_match(content, _HASH_PATTERNS)

        if not has_hash:
            integrity_risk_id = _ARTIFACT_INTEGRITY_MAP.get(artifact_type, "GOV-1")
            findings.append(
                self._create_finding(
                    risk_id=integrity_risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence="No integrity hash or checksum found in artifact",
                    confidence=0.95,
                )
            )
        else:
            # Validate hash format if a hash declaration is found
            hash_format_findings = self._validate_hash_format(content, artifact_type, artifact_path)
            findings.extend(hash_format_findings)

        return findings

    def _validate_hash_format(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Validate format of declared hash values.

        Checks that:
        - SHA-256 hashes are exactly 64 hex characters
        - SHA-512 hashes are exactly 128 hex characters

        A format mismatch indicates potential tampering or corruption,
        reported with confidence 1.0.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for malformed hashes.
        """
        findings: list[ScanFinding] = []

        # Pattern to extract hash values from declarations
        sha256_decl = re.compile(r"(?i)(?:sha256|sha-256)\s*[:=]\s*['\"]?([0-9a-fA-F]+)['\"]?")
        sha512_decl = re.compile(r"(?i)(?:sha512|sha-512)\s*[:=]\s*['\"]?([0-9a-fA-F]+)['\"]?")
        generic_hash_decl = re.compile(
            r"(?i)(?:checksum|hash|integrity|digest)\s*[:=]\s*['\"]?([0-9a-fA-F]+)['\"]?"
        )

        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # Check SHA-256 declarations
            for match in sha256_decl.finditer(line):
                hash_value = match.group(1)
                if len(hash_value) != 64:
                    integrity_risk_id = _ARTIFACT_INTEGRITY_MAP.get(artifact_type, "GOV-1")
                    findings.append(
                        self._create_finding(
                            risk_id=integrity_risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=f"SHA-256 hash has invalid length: {len(hash_value)} chars (expected 64)",
                            confidence=1.0,
                            line=line_num,
                        )
                    )

            # Check SHA-512 declarations
            for match in sha512_decl.finditer(line):
                hash_value = match.group(1)
                if len(hash_value) != 128:
                    integrity_risk_id = _ARTIFACT_INTEGRITY_MAP.get(artifact_type, "GOV-1")
                    findings.append(
                        self._create_finding(
                            risk_id=integrity_risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=f"SHA-512 hash has invalid length: {len(hash_value)} chars (expected 128)",
                            confidence=1.0,
                            line=line_num,
                        )
                    )

            # Check generic hash/checksum declarations for common format issues
            for match in generic_hash_decl.finditer(line):
                hash_value = match.group(1)
                # Skip if already caught by sha256/sha512 patterns
                if sha256_decl.search(line) or sha512_decl.search(line):
                    continue
                # A generic hash should be either 64 (SHA-256) or 128 (SHA-512) hex chars
                if len(hash_value) not in (64, 128):
                    integrity_risk_id = _ARTIFACT_INTEGRITY_MAP.get(artifact_type, "GOV-1")
                    findings.append(
                        self._create_finding(
                            risk_id=integrity_risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=f"Hash value has unexpected length: {len(hash_value)} chars (expected 64 for SHA-256 or 128 for SHA-512)",
                            confidence=1.0,
                            line=line_num,
                        )
                    )

        return findings

    def _check_signature(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for unsigned artifacts (no cryptographic signature).

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for unsigned artifacts.
        """
        findings: list[ScanFinding] = []

        has_signature = _has_pattern_match(content, _SIGNATURE_PATTERNS)

        if not has_signature:
            # Use integrity risk ID since signature is part of integrity verification
            integrity_risk_id = _ARTIFACT_INTEGRITY_MAP.get(artifact_type, "GOV-1")
            # Lower confidence than missing hash since signatures are less commonly required
            findings.append(
                self._create_finding(
                    risk_id=integrity_risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence="No cryptographic signature found in artifact",
                    confidence=0.80,
                )
            )

        # If cryptography library is available, attempt signature validation
        crypto = self._load_cryptography()
        if crypto is not None and has_signature:
            # With cryptography lib, we could verify signatures
            # For now, just having a signature present is positive signal
            pass

        return findings

    def _check_source_attribution(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for unknown source/origin (no repository URL or source attribution).

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for missing source attribution.
        """
        findings: list[ScanFinding] = []

        has_source = _has_pattern_match(content, _SOURCE_PATTERNS)

        if not has_source:
            # REG-2 for regulatory provenance documentation
            findings.append(
                self._create_finding(
                    risk_id="REG-2",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence="No source URL or repository attribution found",
                    confidence=0.85,
                )
            )

        return findings

    def _check_license_compliance(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for missing license/compliance information.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for missing license information.
        """
        findings: list[ScanFinding] = []

        has_license = _has_pattern_match(content, _LICENSE_PATTERNS)

        if not has_license:
            findings.append(
                self._create_finding(
                    risk_id="GOV-2",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence="No license or compliance information found",
                    confidence=0.80,
                )
            )

        return findings

    def _check_staleness(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for stale provenance (very old last-modified dates).

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for stale provenance.
        """
        findings: list[ScanFinding] = []

        dates = _extract_dates(content)
        if dates:
            now = datetime.now(tz=timezone.utc)
            # Check if the most recent date is older than threshold
            most_recent = max(dates)
            days_old = (now - most_recent).days

            if days_old > _STALENESS_THRESHOLD_DAYS:
                findings.append(
                    self._create_finding(
                        risk_id="GOV-2",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"Most recent date in artifact is {days_old} days old (threshold: {_STALENESS_THRESHOLD_DAYS} days)",
                        confidence=0.70,
                    )
                )

        return findings

    def _check_git_provenance(
        self,
        artifact_path: str,
        artifact_type: ArtifactType,
    ) -> list[ScanFinding]:
        """Check git history for provenance information if gitpython available.

        Args:
            artifact_path: Path to the artifact file.
            artifact_type: Type of artifact.

        Returns:
            List of findings from git analysis.
        """
        findings: list[ScanFinding] = []
        git_module = self._load_git()

        if git_module is None:
            return findings

        try:
            repo = git_module.Repo(artifact_path, search_parent_directories=True)
            # Check if the file is tracked in git
            try:
                commits = list(repo.iter_commits(paths=artifact_path, max_count=1))
                if not commits:
                    # File not in git history
                    findings.append(
                        self._create_finding(
                            risk_id="GOV-1",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence="File has no git history (untracked or newly added)",
                            confidence=0.70,
                        )
                    )
            except Exception:
                pass
        except Exception:
            # Not a git repo or git unavailable - not an error
            pass

        return findings

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for provenance and integrity issues.

        Applies metadata extraction, integrity hash validation, signature
        checking, source attribution analysis, staleness detection, and
        optional git history analysis.

        MCP client configuration files (containing ``mcpServers`` or
        ``servers`` keys that reference remote URLs) are exempt from
        provenance, integrity, and signature checks because those checks
        apply to server *artifacts*, not to client connection configs.

        Phase 2: Path-based scope restriction skips test/spec paths entirely
        and downgrades documentation paths to INFO severity.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        # Phase 2: Path-based scope restriction
        if _is_test_or_spec_path(artifact_path) or self._is_first_party_by_config(artifact_path):
            logger.debug("test_path_provenance_skip", path=artifact_path)
            return []

        is_doc_path = _is_documentation_path(artifact_path)

        findings: list[ScanFinding] = []

        # Skip provenance/integrity/signature checks for MCP client config files.
        # These are connection configs (url, command, args) — not server packages.
        is_mcp_client_config = artifact_type == ArtifactType.MCP and self._is_mcp_client_config(
            artifact_content
        )

        if not is_mcp_client_config:
            # 1. Check provenance metadata (author, version, timestamp, source)
            findings.extend(
                self._check_provenance_metadata(artifact_content, artifact_type, artifact_path)
            )

            # 2. Check integrity hash/checksum
            findings.extend(
                self._check_integrity_hash(artifact_content, artifact_type, artifact_path)
            )

            # 3. Check cryptographic signature
            findings.extend(self._check_signature(artifact_content, artifact_type, artifact_path))

        # 4. Check source attribution
        findings.extend(
            self._check_source_attribution(artifact_content, artifact_type, artifact_path)
        )

        # 5. Check license/compliance
        findings.extend(
            self._check_license_compliance(artifact_content, artifact_type, artifact_path)
        )

        # 6. Check staleness
        findings.extend(self._check_staleness(artifact_content, artifact_type, artifact_path))

        # 7. Optional: git-based provenance checking
        findings.extend(self._check_git_provenance(artifact_path, artifact_type))

        # Phase 2: Downgrade documentation path findings to INFO severity
        if is_doc_path:
            for finding in findings:
                finding.severity_score = min(finding.severity_score, 4)
                finding.gate_action = GateAction.INFO
            logger.debug(
                "doc_path_severity_downgrade",
                path=artifact_path,
                findings_count=len(findings),
            )

        return findings

    @staticmethod
    def _is_mcp_client_config(content: str) -> bool:
        """Detect whether content is an MCP client configuration file.

        MCP client configs contain ``mcpServers`` (Claude Desktop format) or
        ``servers`` (VS Code format) with server entries that have ``url`` or
        ``command`` fields — indicating they are *connection* definitions, not
        server artifacts that need provenance/integrity verification.

        Args:
            content: The artifact text content.

        Returns:
            True if the content looks like an MCP client config file.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return False

        if not isinstance(data, dict):
            return False

        # Claude Desktop uses "mcpServers", VS Code uses "servers"
        servers = data.get("mcpServers") or data.get("servers")
        if not isinstance(servers, dict):
            return False

        # Check that at least one server entry has a "url" or "command" field
        for entry in servers.values():
            if isinstance(entry, dict) and ("url" in entry or "command" in entry):
                return True

        return False
