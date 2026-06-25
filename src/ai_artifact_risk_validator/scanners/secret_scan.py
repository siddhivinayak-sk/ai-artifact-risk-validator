"""SecretScan scanner module for detecting embedded secrets and PII.

Detects hardcoded API keys, tokens, credentials, and personally identifiable
information in AI artifacts using regex patterns, Shannon entropy analysis,
and optional integrations with detect-secrets and presidio-analyzer.
"""

from __future__ import annotations

import math
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

# --- Risk metadata lookup ---
# Maps risk IDs to their metadata for finding construction
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "P-S3": {
        "title": "Hardcoded API Key in Prompt",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Prompt file contains a hardcoded API key, token, or secret.",
        "remediation": "Remove secrets from prompt files. Use environment variables or secret managers.",
    },
    "P-S4": {
        "title": "PII Exposure in Prompt Examples",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Prompt contains personally identifiable information in few-shot examples or instructions.",
        "remediation": "Replace real PII with synthetic data. Use placeholder tokens for examples.",
    },
    "P-S8": {
        "title": "Credential in Few-Shot Example",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Few-shot examples contain real credentials, tokens, or connection strings.",
        "remediation": "Replace credentials with dummy values. Use redacted examples.",
    },
    "SK-S5": {
        "title": "Embedded Secrets in Skill Configuration",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill configuration contains embedded API keys, tokens, or credentials.",
        "remediation": "Move secrets to environment variables. Use secret management service.",
    },
    "SOP-S1": {
        "title": "Hardcoded Credentials in SOP Steps",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "SOP contains hardcoded credentials, API keys, or tokens in procedural steps.",
        "remediation": "Replace with secret references. Use environment variables.",
    },
    "I-S3": {
        "title": "Secrets in Instruction Examples",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Instruction file contains real secrets or credentials in code examples.",
        "remediation": "Replace with placeholder credentials. Use synthetic examples.",
    },
    "M-S2": {
        "title": "Plaintext Secrets in Memory Storage",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Memory file contains plaintext API keys, tokens, or credentials.",
        "remediation": "Scrub secrets from memory before persistence. Encrypt sensitive entries.",
    },
    "M-S3": {
        "title": "PII Retention in Memory",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Memory file retains personally identifiable information.",
        "remediation": "Implement PII scrubbing. Set retention limits for PII.",
    },
    "M-S4": {
        "title": "Sensitive Context Leakage via Memory",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Memory entries from one security context are accessible in a different context.",
        "remediation": "Implement context isolation for memory. Enforce access boundaries.",
    },
    "EV-S2": {
        "title": "Credentials in Eval Configuration",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Evaluation harness configuration contains embedded API keys or credentials.",
        "remediation": "Use environment variables for credentials. Remove hardcoded keys.",
    },
    # Secondary risks
    "MCP-S3": {
        "title": "Credential Leakage in MCP Configuration",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server configuration contains embedded credentials.",
        "remediation": "Use environment variables or secret managers for MCP credentials.",
    },
    "H-S2": {
        "title": "Credential Exposure in Hook Configuration",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Hook configuration exposes credentials or tokens.",
        "remediation": "Remove credentials from hook configs. Use secret references.",
    },
    "RAG-S3": {
        "title": "Compliance-Sensitive Data in RAG",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "RAG knowledge base contains compliance-sensitive data or secrets.",
        "remediation": "Remove sensitive data from RAG sources. Apply data classification.",
    },
    "GOV-1": {
        "title": "Missing artifact provenance/authorship metadata",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.GOVERNANCE,
        "description": "Artifact lacks provenance or authorship metadata.",
        "remediation": "Add provenance metadata including author, version, and timestamp.",
    },
}

# --- Artifact type to risk ID mapping ---
# Maps each artifact type to the primary risk ID for secret/PII detection
_ARTIFACT_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "P-S3",
    ArtifactType.SKILL: "SK-S5",
    ArtifactType.AGENT: "P-S3",  # Uses P-S3 as generic secret risk
    ArtifactType.SOP: "SOP-S1",
    ArtifactType.STEERING: "P-S3",
    ArtifactType.MCP: "MCP-S3",
    ArtifactType.HOOK: "H-S2",
    ArtifactType.INSTRUCTION: "I-S3",
    ArtifactType.PLUGIN: "SK-S5",
    ArtifactType.MEMORY: "M-S2",
    ArtifactType.RAG: "RAG-S3",
    ArtifactType.EVAL_HARNESS: "EV-S2",
    ArtifactType.ORCHESTRATION: "P-S3",
    ArtifactType.API_SCHEMA: "P-S3",
}

# PII risk mapping for artifact types where PII is a distinct concern
_ARTIFACT_PII_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.PROMPT: "P-S4",
    ArtifactType.MEMORY: "M-S3",
    ArtifactType.INSTRUCTION: "I-S3",
    ArtifactType.SKILL: "SK-S5",
    ArtifactType.EVAL_HARNESS: "EV-S2",
}


# --- Secret detection patterns ---
# Each tuple: (pattern_name, compiled_regex, confidence)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # AWS Access Key ID
    (
        "AWS Access Key",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        0.98,
    ),
    # AWS Secret Access Key (40 chars base64-like following aws_secret or similar context)
    (
        "AWS Secret Key",
        re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        0.95,
    ),
    # GitHub Personal Access Token (classic & fine-grained)
    (
        "GitHub Token",
        re.compile(r"(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
        0.98,
    ),
    # GitHub OAuth / App tokens
    (
        "GitHub OAuth Token",
        re.compile(r"(gho_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}|ghr_[A-Za-z0-9]{36,})"),
        0.98,
    ),
    # Generic Bearer token
    (
        "Bearer Token",
        re.compile(
            r"(?i)(?:bearer|authorization)\s*[:=]\s*['\"]?Bearer\s+([A-Za-z0-9\-._~+/]+=*)['\"]?"
        ),
        0.90,
    ),
    # OpenAI API Key
    (
        "OpenAI API Key",
        re.compile(r"(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9\-_]{40,})"),
        0.98,
    ),
    # Generic API key patterns (key = value)
    (
        "Generic API Key",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9\-._]{20,})['\"]?"
        ),
        0.85,
    ),
    # Password in configuration
    (
        "Password in Config",
        re.compile(r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?"),
        0.80,
    ),
    # Connection strings with passwords
    (
        "Connection String",
        re.compile(r"(?i)(?:mongodb|mysql|postgres|postgresql|redis|amqp)://[^:]+:([^@\s]{4,})@"),
        0.95,
    ),
    # Private key markers
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        0.99,
    ),
    # Slack token
    (
        "Slack Token",
        re.compile(r"(xox[baprs]-[0-9A-Za-z\-]{10,})"),
        0.95,
    ),
    # Stripe API Key
    (
        "Stripe Key",
        re.compile(r"(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})"),
        0.98,
    ),
    # Google API Key
    (
        "Google API Key",
        re.compile(r"(AIza[0-9A-Za-z\-_]{35})"),
        0.95,
    ),
    # Azure/Microsoft Key
    (
        "Azure Key",
        re.compile(
            r"(?i)(?:azure|microsoft)[_-]?(?:key|secret|token)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{32,}=*)['\"]?"
        ),
        0.85,
    ),
    # JWT Token (long base64 dot-separated)
    (
        "JWT Token",
        re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
        0.90,
    ),
    # Hex-encoded secrets (32+ chars assigned to key-like variable)
    (
        "Hex Secret",
        re.compile(r"(?i)(?:secret|token|key|credential)\s*[=:]\s*['\"]?([0-9a-f]{32,})['\"]?"),
        0.80,
    ),
]

# --- PII detection patterns ---
_PII_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # Email address
    (
        "Email Address",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        0.75,
    ),
    # US Social Security Number
    (
        "SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        0.95,
    ),
    # US Phone Number
    (
        "Phone Number",
        re.compile(r"\b(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        0.70,
    ),
    # Credit Card Number (basic Luhn-eligible patterns)
    (
        "Credit Card",
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        0.85,
    ),
    # IP Address (non-localhost, non-example)
    (
        "IP Address",
        re.compile(r"\b(?!127\.0\.0\.|0\.0\.0\.|10\.0\.0\.|192\.168\.)(?:\d{1,3}\.){3}\d{1,3}\b"),
        0.60,
    ),
]

# Entropy threshold for high-entropy string detection
_ENTROPY_THRESHOLD = 4.5
# Minimum length for entropy analysis
_ENTROPY_MIN_LENGTH = 16

# --- Context-aware false-positive filters ---
# Patterns that look like high-entropy secrets but are benign.

# UUIDs (v4 with or without dashes)
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"
)

# Base64-encoded data URIs (images, fonts, etc.)
_DATA_URI_PATTERN = re.compile(r"^data:[a-zA-Z]+/[a-zA-Z0-9.+-]+;base64,")

# Lockfile / integrity hashes (sha256-xxx, sha384-xxx, sha512-xxx)
_INTEGRITY_HASH_PATTERN = re.compile(r"^sha(?:256|384|512)-[A-Za-z0-9+/=]+$")

# Well-known placeholder values
_PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)(?:REPLACE_ME|CHANGE_ME|TODO|FIXME|YOUR_.*_HERE|EXAMPLE|"
    r"user@example\.com|test@test\.com|xxx+|000+|placeholder)"
)

# --- Phase 2: Hardcoded allowlists (not configurable to prevent suppression attacks) ---
_RFC_2606_DOMAINS: frozenset[str] = frozenset(
    {"example.com", "example.org", "example.net", "example.edu"}
)

_PLACEHOLDER_IPS: frozenset[str] = frozenset(
    {
        "0.0.0.0",
        "1.2.3.4",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.0.1",
        "192.168.1.1",
        "255.255.255.255",
    }
)

# RFC 5737 documentation address ranges
_DOC_IP_PREFIXES: tuple[str, ...] = ("192.0.2.", "198.51.100.", "203.0.113.")

# Credential patterns found in URLs that indicate genuine secrets
_URL_CREDENTIAL_PATTERNS: re.Pattern[str] = re.compile(
    r"(?i)(?:token=|key=|secret=|password=|bearer|api_key)"
)


def _is_sequential_digits(s: str) -> bool:
    """Check if string contains ascending sequential or all-same digits.

    Extracts only digit characters from the input. Returns True if:
    - There are at least 6 digits, AND
    - The digits form an ascending sequence (substring of "0123456789" repeated), OR
    - All digits are the same character.

    Args:
        s: The string to check.

    Returns:
        True if the string is a sequential/repeating digit pattern.
    """
    digits = "".join(c for c in s if c.isdigit())
    if len(digits) < 6:
        return False
    # Check ascending: substring of "01234567890123456789"
    ascending = "0123456789" * 2
    if digits in ascending:
        return True
    # Check all same digit
    if len(set(digits)) == 1:
        return True
    return False


def _is_allowlisted_secret(match_value: str, match_type: str) -> bool:
    """Return True if the matched value is a known placeholder/documentation value.

    Checks the match against hardcoded allowlists based on the type of secret
    detected. These allowlists are intentionally not configurable to prevent
    suppression attacks via artifact content manipulation.

    Args:
        match_value: The matched secret value (e.g., email, IP, number).
        match_type: The type of match — one of "email", "ip_address",
            "numeric_secret".

    Returns:
        True if the value is a known placeholder that should be excluded
        from secret detection.
    """
    if match_type == "email":
        domain = match_value.split("@")[-1].lower()
        return any(domain == d or domain.endswith("." + d) for d in _RFC_2606_DOMAINS)
    if match_type == "ip_address":
        if match_value in _PLACEHOLDER_IPS:
            return True
        if any(match_value.startswith(p) for p in _DOC_IP_PREFIXES):
            return True
        return False
    if match_type == "numeric_secret":
        return _is_sequential_digits(match_value)
    return False


def _is_url_without_credentials(url: str) -> bool:
    """Check if a URL does NOT contain credential patterns.

    Returns True if the URL is just a plain service link without embedded
    tokens, keys, secrets, passwords, or bearer tokens — indicating it
    should not be flagged as an embedded secret.

    Args:
        url: The URL string to check.

    Returns:
        True if the URL has no credential patterns (safe to skip).
        False if credential patterns are found (should be flagged).
    """
    return _URL_CREDENTIAL_PATTERNS.search(url) is None


# --- Phase 2: ECR registry and test directory patterns ---
_ECR_PATTERN: re.Pattern[str] = re.compile(r"\d+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com")

_TEST_DIR_PATTERN: re.Pattern[str] = re.compile(r"(^|[\\/])tests?[\\/]|[\\/]\.qa[\\/]")

_DOC_OR_CI_PATH_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)(^|[\\/])(?:docs?|documentation|\.github|\.gitlab-ci|ci|\.circleci)[\\/]"
    r"|(?:README|CHANGELOG|CONTRIBUTING|\.ya?ml$|Dockerfile)"
)

# Key=value pattern for credential-like formats
_KEY_VALUE_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)(?:key|token|secret|password|credential|api_key|apikey|auth)\s*[=:]"
)


def _is_documentation_or_ci_path(artifact_path: str) -> bool:
    """Check if the file path is a documentation or CI/CD configuration file.

    Args:
        artifact_path: The file path to check.

    Returns:
        True if the path is under a documentation directory or is a CI config file.
    """
    return _DOC_OR_CI_PATH_PATTERN.search(artifact_path) is not None


def _looks_like_real_credential(match_value: str) -> bool:
    """Check if a match value looks like a real credential.

    Used for stricter validation in test directories — only flag matches
    that have high entropy or are in key=value format.

    Args:
        match_value: The matched secret value to validate.

    Returns:
        True if the value looks like a genuine credential.
    """
    # Check for key=value format in the surrounding context
    if _KEY_VALUE_PATTERN.search(match_value):
        return True
    # Check for high entropy (strong indicator of real secret)
    entropy = _calculate_shannon_entropy(match_value)
    if entropy >= _ENTROPY_THRESHOLD:
        return True
    return False


def _is_entropy_false_positive(candidate: str, line: str) -> bool:
    """Return True if the high-entropy *candidate* is a likely false positive.

    Checks common non-secret patterns that trigger high-entropy detection:
    UUIDs, data-URIs, integrity hashes, and placeholder values.
    """
    if _UUID_PATTERN.match(candidate):
        return True
    if _DATA_URI_PATTERN.search(line):
        return True
    if _INTEGRITY_HASH_PATTERN.match(candidate):
        return True
    if _PLACEHOLDER_PATTERNS.search(candidate):
        return True
    return False


def _calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Args:
        data: The string to analyze.

    Returns:
        Shannon entropy value (bits per character).
    """
    if not data:
        return 0.0

    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _find_high_entropy_strings(text: str) -> list[tuple[str, float, int]]:
    """Find high-entropy strings in text that might be secrets.

    Looks for quoted strings, assignment values, and contiguous alphanumeric
    sequences that have high Shannon entropy.

    Args:
        text: Content to analyze.

    Returns:
        List of (matched_string, entropy, line_number) tuples.
    """
    results: list[tuple[str, float, int]] = []

    # Pattern to find potential secret values: quoted strings or assignment values
    value_pattern = re.compile(
        r"""(?:['"]([A-Za-z0-9+/=\-_.]{""" + str(_ENTROPY_MIN_LENGTH) + r""",})['"])|"""
        r"""(?:[=:]\s*([A-Za-z0-9+/=\-_.]{""" + str(_ENTROPY_MIN_LENGTH) + r""",}))"""
    )

    for line_num, line in enumerate(text.splitlines(), start=1):
        for match in value_pattern.finditer(line):
            candidate = match.group(1) or match.group(2)
            if candidate:
                entropy = _calculate_shannon_entropy(candidate)
                if entropy > _ENTROPY_THRESHOLD:
                    if _is_entropy_false_positive(candidate, line):
                        continue
                    results.append((candidate, entropy, line_num))

    return results


class SecretScanScanner(BaseScanner):
    """Scanner for detecting embedded secrets, credentials, and PII in artifacts.

    Uses multiple detection techniques:
    1. Regex patterns for known secret formats (highest confidence)
    2. Shannon entropy analysis for high-entropy strings (moderate confidence)
    3. Optional detect-secrets integration for additional patterns
    4. Optional presidio-analyzer integration for PII detection

    The scanner always functions using built-in regex and entropy analysis,
    with optional dependencies providing enhanced coverage.
    """

    def __init__(self) -> None:
        """Initialize the SecretScan scanner with lazy-loaded optional deps."""
        self._detect_secrets: Any | None = None
        self._detect_secrets_loaded = False
        self._presidio: Any | None = None
        self._presidio_loaded = False

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.SECRET_SCAN

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """All 14 artifact types - secrets can appear anywhere."""
        return list(ArtifactType)

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner detects."""
        return [
            "P-S3",
            "P-S4",
            "P-S8",
            "SK-S5",
            "SOP-S1",
            "I-S3",
            "M-S2",
            "M-S3",
            "M-S4",
            "EV-S2",
            # Secondary risks
            "MCP-S3",
            "H-S2",
            "RAG-S3",
            "GOV-1",
        ]

    def is_available(self) -> bool:
        """Always available - uses regex fallback without optional deps."""
        return True

    def _load_detect_secrets(self) -> Any | None:
        """Lazily load detect-secrets library.

        Returns:
            The detect_secrets module or None if not installed.
        """
        if not self._detect_secrets_loaded:
            self._detect_secrets_loaded = True
            try:
                import detect_secrets  # noqa: F401
                from detect_secrets.core.scan import scan_line

                self._detect_secrets = scan_line
            except ImportError:
                self._detect_secrets = None
        return self._detect_secrets

    def _load_presidio(self) -> Any | None:
        """Lazily load presidio-analyzer library.

        Returns:
            The AnalyzerEngine instance or None if not installed.
        """
        if not self._presidio_loaded:
            self._presidio_loaded = True
            try:
                from presidio_analyzer import AnalyzerEngine

                self._presidio = AnalyzerEngine()
            except ImportError:
                self._presidio = None
        return self._presidio

    def _get_risk_id(self, artifact_type: ArtifactType, is_pii: bool = False) -> str:
        """Get the appropriate risk ID for the artifact type and detection type.

        Args:
            artifact_type: The type of artifact being scanned.
            is_pii: Whether this is a PII detection (vs secret/credential).

        Returns:
            The appropriate risk ID string.
        """
        if is_pii and artifact_type in _ARTIFACT_PII_RISK_MAP:
            return _ARTIFACT_PII_RISK_MAP[artifact_type]
        return _ARTIFACT_RISK_MAP.get(artifact_type, "P-S3")

    @staticmethod
    def _classify_pii_match_type(pattern_name: str) -> str:
        """Classify a PII pattern name into a match type for allowlist checks.

        Maps PII pattern names (e.g., "Email Address", "IP Address") to the
        match type strings expected by _is_allowlisted_secret().

        Args:
            pattern_name: The name from the PII patterns list.

        Returns:
            One of "email", "ip_address", "numeric_secret", or "other".
        """
        name_lower = pattern_name.lower()
        if "email" in name_lower:
            return "email"
        if "ip" in name_lower:
            return "ip_address"
        # SSNs, phone numbers, and credit cards are NOT numeric_secret —
        # they are distinct PII patterns that should not be filtered by
        # the sequential digit allowlist.
        return "other"

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        evidence: str,
        confidence: float,
        line: int | None = None,
        pattern_name: str = "",
    ) -> ScanFinding:
        """Create a ScanFinding from risk metadata.

        Args:
            risk_id: The risk ID to report.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact file.
            evidence: The triggering text/pattern.
            confidence: Detection confidence (0.0-1.0).
            line: Line number where finding was detected.
            pattern_name: Name of the pattern that matched.

        Returns:
            A fully constructed ScanFinding.
        """
        metadata = _RISK_METADATA.get(risk_id, _RISK_METADATA["P-S3"])

        # Truncate evidence to avoid leaking full secrets
        truncated_evidence = evidence[:60] + "..." if len(evidence) > 60 else evidence

        description = metadata["description"]
        if pattern_name:
            description = f"{description} Detected pattern: {pattern_name}."

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
            description=description,
            location=FindingLocation(line=line),
            evidence=truncated_evidence,
            confidence=confidence,
            scanner_module=ScannerModule.SECRET_SCAN,
            remediation=metadata["remediation"],
            references=[],
        )

    def _scan_regex_secrets(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan content using regex patterns for known secret formats.

        Applies Phase 2 allowlist filtering before emitting findings:
        - Allowlisted secrets (RFC 2606, placeholder IPs, sequential digits) skipped
        - URLs without credentials skipped
        - ECR registry URLs in doc/CI files get reduced confidence
        - Test directory matches require high-entropy or key=value format

        Args:
            content: Artifact content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from regex matches.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _SECRET_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    evidence = match.group(0)

                    # Phase 2: ECR registry URL check — reduce confidence in doc/CI
                    if _ECR_PATTERN.search(evidence):
                        if _is_documentation_or_ci_path(artifact_path):
                            confidence = 0.45
                            # ECR URLs in doc/CI without credentials: emit at
                            # reduced confidence rather than skipping entirely
                        elif _is_url_without_credentials(evidence):
                            logger.debug(
                                "allowlisted_secret_exclusion",
                                value=evidence[:40],
                                type="ecr_url_no_credentials",
                            )
                            continue

                    risk_id = self._get_risk_id(artifact_type, is_pii=False)
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=evidence,
                            confidence=confidence,
                            line=line_num,
                            pattern_name=pattern_name,
                        )
                    )

        return findings

    def _scan_entropy(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan content for high-entropy strings that may be secrets.

        Args:
            content: Artifact content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from entropy analysis.
        """
        findings: list[ScanFinding] = []
        high_entropy_strings = _find_high_entropy_strings(content)
        is_test_path = _TEST_DIR_PATTERN.search(artifact_path) is not None

        for candidate, entropy, line_num in high_entropy_strings:
            # Skip if already caught by regex patterns
            already_found = False
            for _, pattern, _ in _SECRET_PATTERNS:
                if pattern.search(candidate):
                    already_found = True
                    break
            if already_found:
                continue

            # Phase 2: Test directory stricter validation
            if is_test_path and not _looks_like_real_credential(candidate):
                logger.debug(
                    "allowlisted_secret_exclusion",
                    value=candidate[:40],
                    type="test_dir_low_confidence",
                )
                continue

            risk_id = self._get_risk_id(artifact_type, is_pii=False)
            # Confidence based on entropy: higher entropy = higher confidence
            # Entropy > 4.5 = 0.80, entropy > 5.0 = 0.85, entropy > 5.5 = 0.90
            confidence = min(0.80 + (entropy - _ENTROPY_THRESHOLD) * 0.05, 0.94)

            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=candidate,
                    confidence=confidence,
                    line=line_num,
                    pattern_name=f"High entropy ({entropy:.2f} bits)",
                )
            )

        return findings

    def _scan_pii(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan content for personally identifiable information.

        Uses built-in PII regex patterns and optionally presidio-analyzer.
        Applies Phase 2 allowlist filtering for known placeholder emails/IPs.

        Args:
            content: Artifact content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from PII detection.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()
        is_test_path = _TEST_DIR_PATTERN.search(artifact_path) is not None

        # Built-in PII regex detection
        for pattern_name, pattern, confidence in _PII_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    match_value = match.group(0)

                    # Phase 2: Determine match type and check allowlist
                    match_type = self._classify_pii_match_type(pattern_name)
                    if _is_allowlisted_secret(match_value, match_type):
                        logger.debug(
                            "allowlisted_secret_exclusion",
                            value=match_value[:40],
                            type=match_type,
                        )
                        continue

                    # Phase 2: Sequential digit check for purely numeric PII matches
                    # Patterns like Phone Number and Credit Card can match purely
                    # numeric sequential or repeating digits (e.g. "0123456789",
                    # "345678901234567", "1111111111") which are test/placeholder
                    # data, not genuine PII. Only apply to values that are purely
                    # digit characters (no dashes, spaces, or formatting — those
                    # indicate real formatted PII like SSNs).
                    if match_value.isdigit() and _is_sequential_digits(match_value):
                        logger.debug(
                            "allowlisted_secret_exclusion",
                            value=match_value[:40],
                            type="sequential_digits_pii",
                        )
                        continue

                    # Phase 2: Test directory stricter validation for emails/IPs
                    if is_test_path and match_type in ("email", "ip_address", "numeric_secret"):
                        if not _looks_like_real_credential(match_value):
                            logger.debug(
                                "allowlisted_secret_exclusion",
                                value=match_value[:40],
                                type="test_dir_low_confidence",
                            )
                            continue

                    risk_id = self._get_risk_id(artifact_type, is_pii=True)
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match_value,
                            confidence=confidence,
                            line=line_num,
                            pattern_name=f"PII: {pattern_name}",
                        )
                    )

        # Optional: enhanced PII detection with presidio
        presidio = self._load_presidio()
        if presidio is not None:
            # Entity types that are not actual PII/credential risks in config files
            _PRESIDIO_SKIP_ENTITIES: set[str] = {
                "URL",  # URLs are expected in MCP/API configs
                "DATE_TIME",  # Timestamps are not PII
                "NRP",  # Nationality/religious/political group — too noisy
                "LOCATION",  # Location names are not credential leaks
                "PERSON",  # Tech product names (Kafka, Helm, Docker) trigger spaCy NER; a person name is not a credential
            }
            try:
                results = presidio.analyze(text=content, language="en")
                for result in results:
                    if result.entity_type in _PRESIDIO_SKIP_ENTITIES:
                        continue
                    # Find line number for the match
                    offset = result.start
                    line_num = content[:offset].count("\n") + 1
                    evidence = content[result.start : result.end]
                    # Skip very short matches — too noisy (e.g. "K6" → US_DRIVER_LICENSE)
                    if len(evidence) < 4:
                        continue
                    # Skip EMAIL_ADDRESS matches that contain "/" — these are URL/path
                    # patterns such as GitLab CI component references, not real emails
                    if result.entity_type == "EMAIL_ADDRESS" and "/" in evidence:
                        continue
                    # Skip PHONE_NUMBER matches that are pure numeric constants without
                    # phone-like formatting — e.g. 2147483647 (INT_MAX), version numbers,
                    # or database IDs are not phone numbers.
                    if (
                        result.entity_type == "PHONE_NUMBER"
                        and evidence.strip().lstrip("+-").isdigit()
                    ):
                        continue
                    risk_id = self._get_risk_id(artifact_type, is_pii=True)

                    # Presidio confidence mapped to our bands
                    confidence = min(result.score * 0.95, 0.94)

                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=evidence,
                            confidence=confidence,
                            line=line_num,
                            pattern_name=f"PII: {result.entity_type} (presidio)",
                        )
                    )
            except Exception:
                # Presidio failure is non-fatal; regex fallback covers basics
                pass

        return findings

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for embedded secrets and PII.

        Applies regex pattern matching, Shannon entropy analysis, and optional
        detect-secrets/presidio integration.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        findings: list[ScanFinding] = []

        # 1. Regex-based secret detection (highest confidence)
        findings.extend(self._scan_regex_secrets(artifact_content, artifact_type, artifact_path))

        # 2. Entropy-based detection (moderate confidence)
        findings.extend(self._scan_entropy(artifact_content, artifact_type, artifact_path))

        # 3. PII detection (regex + optional presidio)
        findings.extend(self._scan_pii(artifact_content, artifact_type, artifact_path))

        # 4. Optional: detect-secrets integration
        scan_line = self._load_detect_secrets()
        if scan_line is not None:
            try:
                for line_num, line in enumerate(artifact_content.splitlines(), start=1):
                    secrets = scan_line(line)
                    if secrets:
                        for secret_type, secret in secrets:
                            risk_id = self._get_risk_id(artifact_type, is_pii=False)
                            findings.append(
                                self._create_finding(
                                    risk_id=risk_id,
                                    artifact_type=artifact_type,
                                    artifact_path=artifact_path,
                                    evidence=str(secret),
                                    confidence=0.85,
                                    line=line_num,
                                    pattern_name=f"detect-secrets: {secret_type}",
                                )
                            )
            except Exception:
                # detect-secrets failure is non-fatal
                pass

        return findings
