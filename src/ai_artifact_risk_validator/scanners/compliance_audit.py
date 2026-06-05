"""ComplianceAudit scanner module for regulatory and compliance risk detection.

Detects missing compliance/privacy declarations, cross-border data flow
references without residency controls, missing consent mechanisms, PII
handling without data classification, missing audit trails, and license
compliance gaps. Uses regex-based heuristics with optional presidio-analyzer
integration for enhanced PII detection.
"""

from __future__ import annotations

import re
from typing import Any

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

# --- Risk metadata lookup ---
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "REG-1": {
        "title": "Missing data residency declaration",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact processes or stores data without declaring where that "
            "data resides geographically. Missing data residency declarations "
            "can violate data sovereignty laws (GDPR, data localization requirements)."
        ),
        "remediation": (
            "Add a data_residency metadata field declaring processing and storage regions. "
            "Document data flow paths including all external service regions."
        ),
    },
    "REG-2": {
        "title": "License compliance violation",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact includes or references content, code, or models under "
            "licenses that are incompatible with the project's license or usage terms. "
            "This can expose the organization to legal risk."
        ),
        "remediation": (
            "Audit all referenced content for license compatibility. "
            "Maintain a license inventory for all third-party components used in artifacts."
        ),
    },
    "REG-3": {
        "title": "Missing data retention policy",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact handles user data (memory, context, logs) without "
            "specifying a data retention policy. This violates data minimization "
            "principles and may breach privacy regulations."
        ),
        "remediation": (
            "Define explicit retention periods for all stored data. "
            "Implement automated data expiry and deletion mechanisms."
        ),
    },
    "REG-4": {
        "title": "PII exposure without consent framework",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact processes personally identifiable information (PII) "
            "without referencing a consent framework or privacy policy. Processing "
            "PII without documented consent violates GDPR and similar regulations."
        ),
        "remediation": (
            "Reference the applicable privacy policy and consent mechanism in artifact metadata. "
            "Implement PII detection and redaction before storing data in artifacts."
        ),
    },
    "REG-5": {
        "title": "Missing AI regulation alignment (EU AI Act)",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact is part of an AI system that may fall under regulatory "
            "frameworks (EU AI Act, NIST AI RMF) but lacks the required transparency, "
            "risk classification, or documentation mandated by those regulations."
        ),
        "remediation": (
            "Classify the AI system's risk tier per applicable regulation. "
            "Document human oversight mechanisms and transparency requirements."
        ),
    },
    "RAG-S3": {
        "title": "Compliance-sensitive data in RAG",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": (
            "RAG knowledge base contains data subject to compliance regulations "
            "without proper handling controls."
        ),
        "remediation": (
            "Classify data in RAG sources. Implement compliance controls. "
            "Remove or encrypt regulated data."
        ),
    },
}

# --- Applicable artifact types (from design doc scanner-to-artifact matrix) ---
_COMPLIANCE_TYPES: list[ArtifactType] = [
    ArtifactType.AGENT,
    ArtifactType.SOP,
    ArtifactType.STEERING,
    ArtifactType.MCP,
    ArtifactType.PLUGIN,
    ArtifactType.MEMORY,
    ArtifactType.RAG,
]

# --- Cross-border data flow patterns (REG-1, REG-2) ---
_CROSS_BORDER_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "External API endpoint reference",
        re.compile(
            r"(?:https?://|endpoint[:\s]+|url[:\s]+|api[:\s]+|host[:\s]+)"
            r"[^\s\"']+\.(?:com|io|net|org|cloud|aws|azure|gcp)",
            re.IGNORECASE,
        ),
        0.70,
    ),
    (
        "Cross-region data transfer",
        re.compile(
            r"\b(?:cross[- ]?(?:border|region)|data\s+transfer|"
            r"international|offshore|foreign\s+(?:server|region|data\s*center))\b",
            re.IGNORECASE,
        ),
        0.80,
    ),
    (
        "Cloud region reference without controls",
        re.compile(
            r"\b(?:us-east|us-west|eu-west|eu-central|ap-southeast|"
            r"ap-northeast|sa-east|af-south|me-south|"
            r"eastus|westus|northeurope|westeurope|"
            r"asia-east|asia-south)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
]

# Patterns indicating data residency is properly declared
_RESIDENCY_DECLARATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bdata[_\s-]?residency\b", re.IGNORECASE),
    re.compile(r"\bdata[_\s-]?region\b", re.IGNORECASE),
    re.compile(r"\bprocessing[_\s-]?location\b", re.IGNORECASE),
    re.compile(r"\bstorage[_\s-]?region\b", re.IGNORECASE),
    re.compile(r"\bdata[_\s-]?sovereignty\b", re.IGNORECASE),
    re.compile(r"\bgeographic[_\s-]?(?:restriction|control|constraint)\b", re.IGNORECASE),
]

# --- License compliance patterns (REG-2) ---
_RESTRICTED_LICENSE_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "GPL family license (copyleft)",
        re.compile(
            r"\b(?:GPL|GNU\s+General\s+Public\s+License|GPLv[23]|AGPL|"
            r"GNU\s+Affero|LGPL)\b",
            re.IGNORECASE,
        ),
        0.95,
    ),
    (
        "Creative Commons restrictive license",
        re.compile(
            r"\bCC[- ](?:BY[- ](?:NC|SA|ND|NC-SA|NC-ND)|NC|SA|ND)\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
    (
        "SSPL license (Server Side Public License)",
        re.compile(r"\bSSPL\b", re.IGNORECASE),
        0.95,
    ),
    (
        "Proprietary/commercial license reference",
        re.compile(
            r"\b(?:proprietary|commercial\s+license|all\s+rights\s+reserved|"
            r"no\s+redistribution|restricted\s+use)\b",
            re.IGNORECASE,
        ),
        0.80,
    ),
    (
        "License file reference without compatibility check",
        re.compile(
            r"(?:license|LICENSE|LICENCE)(?:\.(?:md|txt|rst))?",
            re.IGNORECASE,
        ),
        0.60,
    ),
]

# --- Retention policy patterns (REG-3) ---
_DATA_HANDLING_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:store|persist|save|cache|log|record|retain|archive)\b", re.IGNORECASE),
    re.compile(r"\b(?:user\s+data|personal\s+data|conversation|history|session)\b", re.IGNORECASE),
    re.compile(r"\b(?:memory|context|state|storage)\b", re.IGNORECASE),
]

_RETENTION_POLICY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:retention[_\s-]?policy|ttl|time[_\s-]?to[_\s-]?live)\b", re.IGNORECASE),
    re.compile(r"\b(?:expir(?:y|ation|es)|auto[_\s-]?delete|purge|cleanup)\b", re.IGNORECASE),
    re.compile(r"\b(?:data[_\s-]?lifecycle|retention[_\s-]?period|max[_\s-]?age)\b", re.IGNORECASE),
    re.compile(r"\b(?:delete\s+after|remove\s+after|expire\s+after)\b", re.IGNORECASE),
]

# --- PII patterns (REG-4) ---
_PII_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "Email address",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        ),
        0.85,
    ),
    (
        "Phone number",
        re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        ),
        0.75,
    ),
    (
        "SSN-like pattern",
        re.compile(r"\b\d{3}[-]\d{2}[-]\d{4}\b"),
        0.90,
    ),
    (
        "Credit card number pattern",
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        0.85,
    ),
    (
        "PII field reference",
        re.compile(
            r"\b(?:social[_\s-]?security|ssn|date[_\s-]?of[_\s-]?birth|"
            r"dob|passport|national[_\s-]?id|driver[_\s-]?license|"
            r"bank[_\s-]?account|medical[_\s-]?record|health[_\s-]?data|"
            r"biometric|fingerprint|facial[_\s-]?recognition)\b",
            re.IGNORECASE,
        ),
        0.80,
    ),
    (
        "Personal data processing reference",
        re.compile(
            r"\b(?:collect(?:s|ing)?|process(?:es|ing)?|stor(?:es?|ing)|"
            r"transmit(?:s|ting)?)\s+(?:\w+\s+){0,3}"
            r"(?:personal|user|customer|patient|employee)\s+"
            r"(?:data|information|details|records)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
]

# Consent/privacy framework references
_CONSENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:consent[_\s-]?(?:framework|mechanism|management))\b", re.IGNORECASE),
    re.compile(r"\b(?:privacy[_\s-]?policy|data[_\s-]?protection)\b", re.IGNORECASE),
    re.compile(r"\b(?:gdpr|ccpa|hipaa|pipeda|lgpd)\b", re.IGNORECASE),
    re.compile(r"\b(?:opt[_\s-]?in|opt[_\s-]?out|user[_\s-]?consent)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:data[_\s-]?subject[_\s-]?rights|right\s+to\s+(?:erasure|forget))\b", re.IGNORECASE
    ),
]

# --- Audit trail / compliance documentation patterns (REG-5) ---
_HIGH_RISK_DOMAIN_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "Healthcare/medical domain",
        re.compile(
            r"\b(?:healthcare|medical|patient|diagnosis|treatment|"
            r"clinical|pharmaceutical|health[_\s-]?record)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "Financial domain",
        re.compile(
            r"\b(?:financial|banking|credit[_\s-]?(?:score|decision)|"
            r"loan|mortgage|insurance|trading|investment)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "HR/employment domain",
        re.compile(
            r"\b(?:hiring|recruitment|employment|resume|candidate[_\s-]?screen|"
            r"performance[_\s-]?review|termination|promotion)\b",
            re.IGNORECASE,
        ),
        0.70,
    ),
    (
        "Legal/judicial domain",
        re.compile(
            r"\b(?:legal|judicial|sentencing|parole|bail|law\s+enforcement|"
            r"criminal|prosecution|court)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "Education domain (automated decisions)",
        re.compile(
            r"\b(?:grading|admission|student[_\s-]?evaluation|"
            r"academic[_\s-]?decision|expulsion)\b",
            re.IGNORECASE,
        ),
        0.70,
    ),
]

_REGULATION_ALIGNMENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:ai[_\s-]?risk[_\s-]?classification|risk[_\s-]?tier)\b", re.IGNORECASE),
    re.compile(r"\b(?:eu[_\s-]?ai[_\s-]?act|nist[_\s-]?ai[_\s-]?rmf)\b", re.IGNORECASE),
    re.compile(r"\b(?:human[_\s-]?oversight|human[_\s-]?in[_\s-]?the[_\s-]?loop)\b", re.IGNORECASE),
    re.compile(r"\b(?:transparency[_\s-]?requirement|explainability)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:regulatory[_\s-]?alignment|compliance[_\s-]?classification)\b", re.IGNORECASE
    ),
]

# --- Audit trail patterns (REG-5 secondary) ---
_AUDIT_TRAIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:audit[_\s-]?(?:log|trail|record))\b", re.IGNORECASE),
    re.compile(r"\b(?:compliance[_\s-]?log(?:ging)?)\b", re.IGNORECASE),
    re.compile(r"\b(?:accountability|traceability)\b", re.IGNORECASE),
]

# --- RAG compliance-sensitive data patterns (RAG-S3) ---
_COMPLIANCE_SENSITIVE_DATA_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "GDPR-protected data reference",
        re.compile(
            r"\b(?:gdpr|personal\s+data|data\s+subject|"
            r"right\s+to\s+be\s+forgotten|erasure\s+request)\b",
            re.IGNORECASE,
        ),
        0.80,
    ),
    (
        "HIPAA-covered information",
        re.compile(
            r"\b(?:hipaa|phi|protected\s+health\s+information|"
            r"patient\s+(?:data|record|information)|"
            r"medical\s+(?:record|history|diagnosis))\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
    (
        "Financial regulation data (PCI-DSS, SOX)",
        re.compile(
            r"\b(?:pci[- ]?dss|sox|sarbanes|cardholder\s+data|"
            r"payment\s+card|account\s+number)\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
]


class ComplianceAuditScanner(BaseScanner):
    """Scanner for detecting regulatory compliance and privacy risks.

    Detects:
    - REG-1: Missing data residency declarations
    - REG-2: License compliance violations (copyleft, restricted licenses)
    - REG-3: Missing data retention policies
    - REG-4: PII processing without consent frameworks
    - REG-5: Missing AI regulation alignment for high-risk domains
    - RAG-S3: Compliance-sensitive data in RAG sources

    Uses regex-based heuristics by default. Optionally integrates with
    the `presidio-analyzer` library for enhanced PII detection when available.
    """

    def __init__(self) -> None:
        """Initialize the ComplianceAudit scanner with lazy-loaded optional deps."""
        self._presidio: Any | None = None
        self._presidio_loaded = False

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.COMPLIANCE_AUDIT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return list(_COMPLIANCE_TYPES)

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner detects."""
        return ["REG-1", "REG-2", "REG-3", "REG-4", "REG-5", "RAG-S3"]

    def is_available(self) -> bool:
        """Always available - uses regex fallback without optional deps."""
        return True

    def _load_presidio(self) -> Any | None:
        """Lazily load the presidio-analyzer library for enhanced PII detection.

        Returns:
            The AnalyzerEngine class, or None if not installed.
        """
        if not self._presidio_loaded:
            self._presidio_loaded = True
            try:
                from presidio_analyzer import AnalyzerEngine

                self._presidio = AnalyzerEngine
            except ImportError:
                self._presidio = None
        return self._presidio

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        evidence: str,
        confidence: float,
        line: int | None = None,
        detail: str = "",
    ) -> ScanFinding:
        """Create a ScanFinding from risk metadata.

        Args:
            risk_id: The risk ID to report.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact file.
            evidence: The triggering text/pattern.
            confidence: Detection confidence (0.0-1.0).
            line: Line number where finding was detected.
            detail: Additional detail to append to description.

        Returns:
            A fully constructed ScanFinding.
        """
        metadata = _RISK_METADATA[risk_id]

        # Truncate evidence to avoid overly long findings
        truncated_evidence = evidence[:80] + "..." if len(evidence) > 80 else evidence

        description = metadata["description"]
        if detail:
            description = f"{description} {detail}"

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
            scanner_module=ScannerModule.COMPLIANCE_AUDIT,
            remediation=metadata["remediation"],
            references=[],
        )

    def _detect_missing_residency(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect missing data residency declarations (REG-1).

        Looks for cross-border data flow references without corresponding
        data residency declarations.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of REG-1 findings.
        """
        findings: list[ScanFinding] = []

        # Check if there are data flow references
        has_data_flow = False
        data_flow_evidence: list[tuple[str, int, float]] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _CROSS_BORDER_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    has_data_flow = True
                    data_flow_evidence.append((match.group(0), line_num, confidence))

        if not has_data_flow:
            return findings

        # Check if data residency is declared
        has_residency = any(p.search(content) for p in _RESIDENCY_DECLARATION_PATTERNS)

        if not has_residency:
            # Report the first data flow reference as evidence
            evidence_text, line_num, confidence = data_flow_evidence[0]
            findings.append(
                self._create_finding(
                    risk_id="REG-1",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=f"Data flow detected: {evidence_text}",
                    confidence=confidence,
                    line=line_num,
                    detail="Cross-border data flow detected without residency declaration.",
                )
            )

        return findings

    def _detect_license_violations(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect license compliance issues (REG-2).

        Scans for references to restrictive or copyleft licenses without
        compatibility documentation.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of REG-2 findings.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _RESTRICTED_LICENSE_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    # Skip the generic LICENSE file reference pattern if it has
                    # low confidence and no strong surrounding context
                    if confidence < 0.65:
                        continue

                    findings.append(
                        self._create_finding(
                            risk_id="REG-2",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            detail=f"Detected: {pattern_name}.",
                        )
                    )
                    break  # One finding per pattern per line is enough

        return findings

    def _detect_missing_retention(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect missing data retention policy (REG-3).

        Checks if the artifact handles data (stores, persists, caches)
        without specifying a retention policy.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of REG-3 findings.
        """
        findings: list[ScanFinding] = []

        # Check if artifact handles data
        has_data_handling = any(p.search(content) for p in _DATA_HANDLING_KEYWORDS)

        if not has_data_handling:
            return findings

        # Check if retention policy is specified
        has_retention = any(p.search(content) for p in _RETENTION_POLICY_PATTERNS)

        if not has_retention:
            # Find the first data handling keyword for evidence
            evidence_line = None
            evidence_text = "Data handling detected without retention policy"
            lines = content.splitlines()
            for pattern in _DATA_HANDLING_KEYWORDS:
                for line_num, line in enumerate(lines, start=1):
                    match = pattern.search(line)
                    if match:
                        evidence_text = match.group(0)
                        evidence_line = line_num
                        break
                if evidence_line is not None:
                    break

            findings.append(
                self._create_finding(
                    risk_id="REG-3",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=f"Data handling: '{evidence_text}'",
                    confidence=0.75,
                    line=evidence_line,
                    detail="Artifact handles data without specifying retention policy.",
                )
            )

        return findings

    def _detect_pii_without_consent(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect PII processing without consent framework (REG-4).

        Looks for PII patterns in the content and checks whether a consent
        mechanism or privacy policy is referenced.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of REG-4 findings.
        """
        findings: list[ScanFinding] = []

        # First check if content has PII indicators
        pii_evidence: list[tuple[str, int, float]] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _PII_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if match:
                    pii_evidence.append(
                        (
                            f"{pattern_name}: {match.group(0)}",
                            line_num,
                            confidence,
                        )
                    )
                    break  # One match per pattern type is enough

        if not pii_evidence:
            return findings

        # Check if consent framework is referenced
        has_consent = any(p.search(content) for p in _CONSENT_PATTERNS)

        if not has_consent:
            # Report the highest confidence PII finding
            pii_evidence.sort(key=lambda x: x[2], reverse=True)
            evidence_text, line_num, confidence = pii_evidence[0]

            findings.append(
                self._create_finding(
                    risk_id="REG-4",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence_text,
                    confidence=confidence,
                    line=line_num,
                    detail="PII detected without consent framework reference.",
                )
            )

        # Also try presidio if available for enhanced PII detection
        self._load_presidio()

        return findings

    def _detect_missing_regulation_alignment(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect missing AI regulation alignment (REG-5).

        Checks if the artifact operates in a high-risk domain without
        the required regulatory compliance documentation.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of REG-5 findings.
        """
        findings: list[ScanFinding] = []

        # Check if the artifact operates in a high-risk domain
        high_risk_evidence: list[tuple[str, int, float]] = []
        lines = content.splitlines()

        for domain_name, pattern, confidence in _HIGH_RISK_DOMAIN_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if match:
                    high_risk_evidence.append(
                        (
                            f"{domain_name}: {match.group(0)}",
                            line_num,
                            confidence,
                        )
                    )
                    break  # One match per domain

        if not high_risk_evidence:
            return findings

        # Check if regulation alignment is declared
        has_alignment = any(p.search(content) for p in _REGULATION_ALIGNMENT_PATTERNS)

        # Also check for audit trail
        has_audit_trail = any(p.search(content) for p in _AUDIT_TRAIL_PATTERNS)

        if not has_alignment:
            # Report the highest confidence domain match
            high_risk_evidence.sort(key=lambda x: x[2], reverse=True)
            evidence_text, line_num, confidence = high_risk_evidence[0]

            findings.append(
                self._create_finding(
                    risk_id="REG-5",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence_text,
                    confidence=confidence,
                    line=line_num,
                    detail="High-risk domain artifact without AI regulation alignment.",
                )
            )

            # Report missing audit trail as secondary signal (only if alignment also missing)
            if not has_audit_trail:
                findings.append(
                    self._create_finding(
                        risk_id="REG-5",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"Missing audit trail for: {evidence_text}",
                        confidence=confidence * 0.9,  # Slightly lower for secondary signal
                        line=line_num,
                        detail="High-risk domain lacks compliance audit trail/logging.",
                    )
                )

        return findings

    def _detect_rag_compliance_data(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect compliance-sensitive data in RAG sources (RAG-S3).

        Only applies to RAG artifact types. Looks for regulated data
        patterns (GDPR, HIPAA, PCI-DSS).

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of RAG-S3 findings.
        """
        findings: list[ScanFinding] = []

        # Only apply to RAG artifacts
        if artifact_type != ArtifactType.RAG:
            return findings

        lines = content.splitlines()

        for pattern_name, pattern, confidence in _COMPLIANCE_SENSITIVE_DATA_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if match:
                    findings.append(
                        self._create_finding(
                            risk_id="RAG-S3",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            detail=f"Detected: {pattern_name}.",
                        )
                    )
                    break  # One finding per pattern type

        return findings

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for compliance and regulatory risks.

        Applies license scanning, data residency flow mapping, retention
        policy checking, PII detection, and AI regulation alignment checking.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        if artifact_type not in _COMPLIANCE_TYPES:
            return []

        findings: list[ScanFinding] = []

        # 1. Missing data residency declaration (REG-1)
        findings.extend(
            self._detect_missing_residency(artifact_content, artifact_type, artifact_path)
        )

        # 2. License compliance violations (REG-2)
        findings.extend(
            self._detect_license_violations(artifact_content, artifact_type, artifact_path)
        )

        # 3. Missing data retention policy (REG-3)
        findings.extend(
            self._detect_missing_retention(artifact_content, artifact_type, artifact_path)
        )

        # 4. PII without consent framework (REG-4)
        findings.extend(
            self._detect_pii_without_consent(artifact_content, artifact_type, artifact_path)
        )

        # 5. Missing AI regulation alignment (REG-5)
        findings.extend(
            self._detect_missing_regulation_alignment(
                artifact_content, artifact_type, artifact_path
            )
        )

        # 6. Compliance-sensitive data in RAG (RAG-S3)
        findings.extend(
            self._detect_rag_compliance_data(artifact_content, artifact_type, artifact_path)
        )

        return findings
