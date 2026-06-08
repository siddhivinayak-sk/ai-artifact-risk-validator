"""ComplianceAudit scanner for detecting regulatory compliance risks.

Detects missing data retention policies, cross-region data transfer without
compliance safeguards, license violations, PII handling without consent,
and missing regulatory compliance markers.

Operates primarily via regex-based detection. The optional `presidio-analyzer`
dependency is lazy-loaded for enhanced PII detection when available.
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

# ============================================================
# License Detection Patterns (REG-2)
# ============================================================

# Copyleft/restrictive license identifiers
_COPYLEFT_LICENSE_PATTERN = re.compile(
    r"\b(?:"
    r"GPL(?:-?[23](?:\.\d)?)?(?:\s*(?:or\s+later|only|\+))?|"
    r"AGPL(?:-?[23](?:\.\d)?)?|"
    r"LGPL(?:-?[23](?:\.\d)?)?|"
    r"SSPL|"
    r"CC-?BY-?(?:NC|SA|ND|NC-SA|NC-ND)|"
    r"copyleft|"
    r"GNU\s+(?:General|Affero|Lesser)\s+Public\s+License|"
    r"Server\s+Side\s+Public\s+License"
    r")\b",
    re.IGNORECASE,
)

# License declarations (general - indicates awareness)
_LICENSE_DECLARATION_PATTERN = re.compile(
    r"\b(?:"
    r"licen[sc]e[d]?\s*(?:[:=]|under)|"
    r"SPDX-License-Identifier\s*:|"
    r"(?:MIT|Apache|BSD|ISC|MPL|Unlicense)\s+[Ll]icen[sc]e|"
    r"licen[sc]ed?\s+(?:under|as)|"
    r"(?:under|subject\s+to)\s+(?:the\s+)?(?:terms\s+of\s+)?(?:the\s+)?\w+\s+licen[sc]e"
    r")\b",
    re.IGNORECASE,
)

# License file references
_LICENSE_FILE_PATTERN = re.compile(
    r"\b(?:LICENSE|LICENCE|COPYING|NOTICE)(?:\.\w+)?\b",
)

# ============================================================
# Data Residency / Region Patterns (REG-1)
# ============================================================

# Cloud provider region references
_REGION_PATTERN = re.compile(
    r"\b(?:"
    r"us-(?:east|west|central|north|south)-\d|"
    r"eu-(?:west|central|north|south)-\d|"
    r"ap-(?:southeast|northeast|south|east)-\d|"
    r"sa-east-\d|"
    r"af-south-\d|"
    r"me-(?:south|central)-\d|"
    r"ca-central-\d|"
    r"(?:us|eu|asia|global)(?:[-_](?:east|west|central|multi))?(?:\d)?|"
    r"(?:east|west|north|south)\s*(?:us|europe|asia)|"
    r"(?:northeurope|westeurope|eastus|westus|centralus|uksouth|ukwest|"
    r"germanywestcentral|francecentral|japaneast|australiaeast|"
    r"southeastasia|eastasia|brazilsouth|canadacentral|"
    r"koreacentral|southafricanorth)"
    r")\b",
    re.IGNORECASE,
)

# Cross-region/cross-border data transfer keywords
_DATA_TRANSFER_PATTERN = re.compile(
    r"\b(?:"
    r"cross[_\-\s]?(?:region|border|boundary)|"
    r"data[_\-\s]?(?:transfer|replication|migration|sync|export)|"
    r"replicate[sd]?\s+(?:to|across|between)|"
    r"transfer[s]?\s+(?:to|across|between|from)\s+(?:\w+\s+)?(?:region|zone|country|jurisdiction)|"
    r"multi[_\-\s]?region|"
    r"geo[_\-\s]?(?:replication|distributed|redundan)"
    r")\b",
    re.IGNORECASE,
)

# Data residency declaration keywords (positive signal - these indicate compliance)
_RESIDENCY_DECLARATION_PATTERN = re.compile(
    r"\b(?:"
    r"data[_\-\s]?residency|"
    r"data[_\-\s]?sovereignty|"
    r"data[_\-\s]?localization|"
    r"processing[_\-\s]?region|"
    r"storage[_\-\s]?region|"
    r"data[_\-\s]?jurisdiction"
    r")\s*(?:[:=]|is|declaration|policy)",
    re.IGNORECASE,
)

# ============================================================
# Retention / TTL Patterns (REG-3)
# ============================================================

# Data retention policy keywords (positive signals - indicate compliance)
_RETENTION_POLICY_PATTERN = re.compile(
    r"\b(?:"
    r"retention[_\-\s]?policy|"
    r"data[_\-\s]?retention|"
    r"retention[_\-\s]?period|"
    r"(?:ttl|time[_\-\s]?to[_\-\s]?live)\s*(?:[:=]|is)|"
    r"expir(?:ation|es?|y)[_\-\s]?(?:policy|period|time|after)|"
    r"auto[_\-\s]?(?:delete|purge|expire|cleanup)|"
    r"data[_\-\s]?lifecycle|"
    r"retention[_\-\s]?(?:days?|hours?|months?|years?)"
    r")\b",
    re.IGNORECASE,
)

# Data storage/persistence keywords (indicate need for retention policy)
_DATA_STORAGE_PATTERN = re.compile(
    r"\b(?:"
    r"(?:store|persist|save|log|record|cache|retain)[s]?\s+(?:\w+\s+)?(?:data|information|messages?|history|context|conversations?|interactions?|logs?|events?)|"
    r"(?:conversation|chat|message|interaction|session)[_\-\s]?(?:history|log|store|memory|storage)|"
    r"(?:user|customer|client)[_\-\s]?(?:data|information|records?|profiles?)|"
    r"(?:database|storage|datastore|cache|bucket|collection|table)\b"
    r")\b",
    re.IGNORECASE,
)

# ============================================================
# PII Detection Patterns (REG-4)
# ============================================================

# Common PII patterns (regex fallback when presidio unavailable)
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Email addresses
    (re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"), "email address"),
    # Phone numbers (international formats)
    (re.compile(r"(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"), "phone number"),
    # SSN (US)
    (re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"), "SSN-like number"),
    # Credit card numbers
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "credit card-like number"),
    # IP addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "IP address"),
]

# PII handling keywords that indicate processing of personal data
_PII_HANDLING_PATTERN = re.compile(
    r"\b(?:"
    r"(?:personal|sensitive|private)[_\-\s]?(?:data|information|details)|"
    r"PII|PHI|PCI|"
    r"(?:collect|process|handle|store|gather)[s]?\s+(?:\w+\s+)?(?:personal|user|customer)\s+(?:data|information)|"
    r"(?:name|email|phone|address|ssn|social[_\-\s]security|date[_\-\s]of[_\-\s]birth|dob)\s+(?:field|column|attribute|input)"
    r")\b",
    re.IGNORECASE,
)

# Consent/privacy policy references (positive signals)
_CONSENT_FRAMEWORK_PATTERN = re.compile(
    r"\b(?:"
    r"consent[_\-\s]?(?:framework|mechanism|management|form|policy)|"
    r"privacy[_\-\s]?(?:policy|notice|statement|framework)|"
    r"data[_\-\s]?(?:protection|processing)[_\-\s]?(?:agreement|policy|notice)|"
    r"GDPR[_\-\s]?(?:complian|consent)|"
    r"(?:opt[_\-\s]?in|opt[_\-\s]?out)\s+(?:mechanism|option|consent)|"
    r"data[_\-\s]?subject[_\-\s]?(?:rights?|consent|access)"
    r")\b",
    re.IGNORECASE,
)

# ============================================================
# Regulatory Compliance Markers (REG-5)
# ============================================================

# Known regulatory frameworks
_REGULATORY_FRAMEWORK_PATTERN = re.compile(
    r"\b(?:"
    r"GDPR|"
    r"HIPAA|"
    r"SOC[_\-\s]?2|SOC2|"
    r"PCI[_\-\s]?DSS|"
    r"CCPA|CPRA|"
    r"FERPA|"
    r"COPPA|"
    r"EU\s+AI\s+Act|"
    r"NIST\s+AI\s+RMF|"
    r"ISO\s+27001|"
    r"FedRAMP|"
    r"FISMA"
    r")\b",
    re.IGNORECASE,
)

# High-risk domain keywords that suggest regulatory compliance needed
_HIGH_RISK_DOMAIN_PATTERN = re.compile(
    r"\b(?:"
    r"(?:patient|medical|health|clinical|diagnostic|treatment)[_\-\s]?(?:data|records?|information)|"
    r"(?:financial|banking|credit|loan|insurance)[_\-\s]?(?:data|records?|information|transactions?|decisions?)|"
    r"(?:hire|hiring|recruit|employment|HR|human\s+resources)[_\-\s]?(?:decisions?|process|screening)|"
    r"(?:criminal|law\s+enforcement|surveillance|biometric)[_\-\s]?(?:data|records?|screening|identification)|"
    r"(?:child|minor|student|education)[_\-\s]?(?:data|records?|information|protection)"
    r")\b",
    re.IGNORECASE,
)

# Risk classification metadata (positive signals)
_RISK_CLASSIFICATION_PATTERN = re.compile(
    r"\b(?:"
    r"(?:ai|risk)[_\-\s]?(?:classification|tier|level|category)|"
    r"human[_\-\s]?(?:oversight|in[_\-\s]the[_\-\s]loop|review)|"
    r"transparency[_\-\s]?(?:requirement|declaration|notice)|"
    r"regulatory[_\-\s]?(?:alignment|compliance|framework)"
    r")\b",
    re.IGNORECASE,
)

# ============================================================
# Compliance-Sensitive Data in RAG (RAG-S3)
# ============================================================

_COMPLIANCE_SENSITIVE_DATA_PATTERN = re.compile(
    r"\b(?:"
    r"(?:patient|medical|health|clinical)\s+(?:record|data|information|history)|"
    r"(?:protected\s+health\s+information|PHI)|"
    r"(?:personally\s+identifiable|PII)|"
    r"(?:financial|banking|credit)\s+(?:record|data|account)|"
    r"(?:social\s+security|SSN|tax\s+(?:id|identification))|"
    r"(?:biometric|genetic)\s+(?:data|information|sample)"
    r")\b",
    re.IGNORECASE,
)

# ============================================================
# Risk Metadata
# ============================================================

_RISK_METADATA: dict[str, dict[str, Any]] = {
    "REG-1": {
        "title": "Missing data residency declaration",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact references cross-region data transfer or cloud regions "
            "without declaring data residency requirements. This may violate "
            "data sovereignty laws (GDPR, data localization requirements)."
        ),
        "remediation": (
            "Add a data_residency metadata field declaring processing and storage "
            "regions. Document data flow paths including all external service regions."
        ),
        "confidence": 0.75,
    },
    "REG-2": {
        "title": "License compliance violation",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact includes or references content under copyleft or "
            "restrictive licenses that may be incompatible with the project's "
            "license or usage terms."
        ),
        "remediation": (
            "Audit all referenced content for license compatibility. Maintain a "
            "license inventory for all third-party components used in artifacts."
        ),
        "confidence": 0.95,
    },
    "REG-3": {
        "title": "Missing data retention policy",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact handles user data without specifying a data retention "
            "policy. This violates data minimization principles and may breach "
            "privacy regulations."
        ),
        "remediation": (
            "Define explicit retention periods for all stored data. Implement "
            "automated data expiry and deletion mechanisms (TTL, auto-purge)."
        ),
        "confidence": 0.70,
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
            "Reference the applicable privacy policy and consent mechanism in "
            "artifact metadata. Implement PII detection and redaction before "
            "storing data in artifacts."
        ),
        "confidence": 0.80,
    },
    "REG-5": {
        "title": "Missing AI regulation alignment (EU AI Act)",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.COMPLIANCE,
        "description": (
            "The artifact is part of an AI system in a high-risk domain but "
            "lacks required transparency, risk classification, or documentation "
            "mandated by regulatory frameworks (EU AI Act, NIST AI RMF)."
        ),
        "remediation": (
            "Classify the AI system's risk tier per applicable regulation. "
            "Document human oversight mechanisms and transparency requirements."
        ),
        "confidence": 0.70,
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
            "(GDPR, HIPAA, PCI-DSS) without proper handling controls."
        ),
        "remediation": (
            "Classify data in RAG sources. Implement compliance controls. "
            "Remove or encrypt regulated data."
        ),
        "confidence": 0.80,
    },
}


class ComplianceAuditScanner(BaseScanner):
    """Scanner for detecting regulatory compliance risks in AI artifacts.

    Detects:
    - Missing data residency declarations (REG-1)
    - License compliance violations (REG-2)
    - Missing data retention policies (REG-3)
    - PII exposure without consent framework (REG-4)
    - Missing regulatory compliance markers (REG-5)
    - Compliance-sensitive data in RAG sources (RAG-S3)

    Always available via regex-based detection. Enhanced PII detection
    available when `presidio-analyzer` is installed.
    """

    def __init__(self) -> None:
        """Initialize the ComplianceAudit scanner."""
        self._presidio_available: bool | None = None

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.COMPLIANCE_AUDIT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze.

        Applicable to: Agent, SOP, Steering, MCP, Plugin, Memory, RAG.
        NOT applicable to: Prompt, Skill, Hook, Instruction, Eval Harness,
        Orchestration, API Schema.
        """
        return [
            ArtifactType.AGENT,
            ArtifactType.SOP,
            ArtifactType.STEERING,
            ArtifactType.MCP,
            ArtifactType.PLUGIN,
            ArtifactType.MEMORY,
            ArtifactType.RAG,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        return ["REG-1", "REG-2", "REG-3", "REG-4", "REG-5", "RAG-S3"]

    def is_available(self) -> bool:
        """Always available via regex-based detection."""
        return True

    def _check_presidio_available(self) -> bool:
        """Lazy check for optional presidio-analyzer dependency."""
        if self._presidio_available is None:
            try:
                import presidio_analyzer  # noqa: F401

                self._presidio_available = True
            except ImportError:
                self._presidio_available = False
        return self._presidio_available

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for regulatory compliance risks.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        findings: list[ScanFinding] = []

        if artifact_type not in self.applicable_artifact_types:
            return findings

        # Run all detection methods
        findings.extend(
            self._detect_license_violations(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_data_residency_issues(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_missing_retention_policy(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_pii_without_consent(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_missing_regulatory_markers(artifact_content, artifact_type, artifact_path)
        )

        # RAG-specific: compliance-sensitive data
        if artifact_type == ArtifactType.RAG:
            findings.extend(
                self._detect_compliance_sensitive_data(
                    artifact_content, artifact_type, artifact_path
                )
            )

        return findings

    def _find_line_number(self, content: str, match_start: int) -> int:
        """Find the 1-based line number for a character offset."""
        return content[:match_start].count("\n") + 1

    def _create_finding(
        self,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        evidence: str,
        confidence: float | None = None,
        line: int | None = None,
    ) -> ScanFinding:
        """Create a ScanFinding from risk metadata.

        Args:
            risk_id: The risk ID for this finding.
            artifact_type: The artifact type being scanned.
            artifact_path: Path to the artifact file.
            evidence: The text/pattern that triggered the finding.
            confidence: Confidence score override (uses metadata default if None).
            line: Optional line number where finding was detected.

        Returns:
            A complete ScanFinding object.
        """
        meta = _RISK_METADATA[risk_id]
        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=meta["severity_score"],
            severity_label=meta["severity_label"],
            priority=meta["priority"],
            gate_action=meta["gate_action"],
            category=meta["category"],
            title=meta["title"],
            description=meta["description"],
            location=FindingLocation(line=line),
            evidence=evidence[:200],
            confidence=confidence if confidence is not None else meta["confidence"],
            scanner_module=ScannerModule.COMPLIANCE_AUDIT,
            remediation=meta["remediation"],
            references=[],
        )

    def _detect_license_violations(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect license compliance violations (REG-2).

        Looks for copyleft/restrictive license references and missing
        license declarations in artifacts.
        """
        findings: list[ScanFinding] = []

        # Check for copyleft/restrictive license references
        copyleft_match = _COPYLEFT_LICENSE_PATTERN.search(content)
        if copyleft_match:
            line = self._find_line_number(content, copyleft_match.start())
            evidence = (
                f"Copyleft/restrictive license reference detected: "
                f"'{copyleft_match.group(0)}'. Verify compatibility with project license."
            )
            findings.append(
                self._create_finding(
                    risk_id="REG-2",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=0.95,
                    line=line,
                )
            )

        return findings

    def _detect_data_residency_issues(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect cross-region data transfer without residency declarations (REG-1).

        Looks for region references and data transfer patterns without
        corresponding data residency declarations.
        """
        findings: list[ScanFinding] = []

        # Check if there are region references or data transfer patterns
        has_region_ref = _REGION_PATTERN.search(content)
        has_data_transfer = _DATA_TRANSFER_PATTERN.search(content)

        if not has_region_ref and not has_data_transfer:
            return findings

        # Check if there's a data residency declaration (positive signal)
        has_residency_declaration = _RESIDENCY_DECLARATION_PATTERN.search(content)

        if has_residency_declaration:
            # Residency is declared, no issue
            return findings

        # Found region/transfer references without residency declaration
        match = has_region_ref or has_data_transfer
        if match:
            line = self._find_line_number(content, match.start())
            if has_data_transfer:
                evidence = (
                    f"Cross-region data transfer reference without data residency "
                    f"declaration: '{match.group(0)}'"
                )
                confidence = 0.80
            else:
                evidence = (
                    f"Cloud region reference without data residency declaration: '{match.group(0)}'"
                )
                confidence = 0.70
            findings.append(
                self._create_finding(
                    risk_id="REG-1",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=confidence,
                    line=line,
                )
            )

        return findings

    def _detect_missing_retention_policy(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect missing data retention/expiration policies (REG-3).

        Looks for data storage/persistence patterns without corresponding
        retention policy declarations.
        """
        findings: list[ScanFinding] = []

        # Check if artifact stores/persists data
        storage_match = _DATA_STORAGE_PATTERN.search(content)
        if not storage_match:
            return findings

        # Check if there's a retention policy declared
        has_retention_policy = _RETENTION_POLICY_PATTERN.search(content)
        if has_retention_policy:
            return findings

        # Data storage without retention policy
        line = self._find_line_number(content, storage_match.start())
        evidence = (
            f"Data storage/persistence without retention policy: "
            f"'{storage_match.group(0).strip()}'. No TTL, expiration, or "
            f"retention period defined."
        )
        findings.append(
            self._create_finding(
                risk_id="REG-3",
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                evidence=evidence,
                confidence=0.70,
                line=line,
            )
        )

        return findings

    def _detect_pii_without_consent(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect PII handling without consent framework (REG-4).

        Looks for PII patterns or PII handling keywords without
        corresponding consent/privacy policy references.
        """
        findings: list[ScanFinding] = []

        # Check for PII indicators
        has_pii_handling = _PII_HANDLING_PATTERN.search(content)
        has_pii_data = False
        pii_evidence = ""

        # Check for actual PII data patterns
        for pattern, pii_type in _PII_PATTERNS:
            match = pattern.search(content)
            if match:
                has_pii_data = True
                pii_evidence = f"{pii_type}: '{match.group(0)}'"
                break

        if not has_pii_handling and not has_pii_data:
            return findings

        # Check for consent/privacy framework references
        has_consent = _CONSENT_FRAMEWORK_PATTERN.search(content)
        if has_consent:
            return findings

        # PII detected without consent framework
        if has_pii_handling:
            line = self._find_line_number(content, has_pii_handling.start())
            evidence = (
                f"PII handling without consent framework reference: "
                f"'{has_pii_handling.group(0).strip()}'"
            )
            confidence = 0.80
        elif has_pii_data:
            # Find the first PII match again for line number
            for pat, pii_type in _PII_PATTERNS:
                m = pat.search(content)
                if m:
                    line = self._find_line_number(content, m.start())
                    evidence = f"PII data detected without consent framework: {pii_evidence}"
                    confidence = 0.75
                    break
            else:
                return findings
        else:
            return findings

        findings.append(
            self._create_finding(
                risk_id="REG-4",
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                evidence=evidence,
                confidence=confidence,
                line=line,
            )
        )

        return findings

    def _detect_missing_regulatory_markers(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect missing regulatory compliance markers (REG-5).

        Looks for high-risk domain keywords without corresponding
        regulatory framework references or risk classification.
        """
        findings: list[ScanFinding] = []

        # Check if content operates in a high-risk domain
        domain_match = _HIGH_RISK_DOMAIN_PATTERN.search(content)
        if not domain_match:
            return findings

        # Check for regulatory framework references
        has_regulatory_ref = _REGULATORY_FRAMEWORK_PATTERN.search(content)
        has_risk_classification = _RISK_CLASSIFICATION_PATTERN.search(content)

        if has_regulatory_ref or has_risk_classification:
            return findings

        # High-risk domain without regulatory markers
        line = self._find_line_number(content, domain_match.start())
        evidence = (
            f"High-risk domain reference without regulatory compliance markers: "
            f"'{domain_match.group(0).strip()}'. No GDPR, HIPAA, SOC2, or "
            f"risk classification declaration found."
        )
        findings.append(
            self._create_finding(
                risk_id="REG-5",
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                evidence=evidence,
                confidence=0.70,
                line=line,
            )
        )

        return findings

    def _detect_compliance_sensitive_data(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect compliance-sensitive data in RAG sources (RAG-S3).

        Specifically for RAG artifacts: looks for references to regulated
        data types (PHI, PII, financial data) without compliance controls.
        """
        findings: list[ScanFinding] = []

        sensitive_match = _COMPLIANCE_SENSITIVE_DATA_PATTERN.search(content)
        if not sensitive_match:
            return findings

        # Check if compliance controls are mentioned
        has_controls = _REGULATORY_FRAMEWORK_PATTERN.search(content)
        has_consent = _CONSENT_FRAMEWORK_PATTERN.search(content)

        if has_controls or has_consent:
            return findings

        # Compliance-sensitive data without controls
        line = self._find_line_number(content, sensitive_match.start())
        evidence = (
            f"Compliance-sensitive data in RAG without proper controls: "
            f"'{sensitive_match.group(0).strip()}'"
        )
        findings.append(
            self._create_finding(
                risk_id="RAG-S3",
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                evidence=evidence,
                confidence=0.80,
                line=line,
            )
        )

        return findings
