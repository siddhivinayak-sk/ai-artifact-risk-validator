"""BiasDetector scanner for detecting bias and non-inclusive language.

Detects gendered language used generically, cultural/racial bias in examples,
stereotyped persona definitions, and non-inclusive terminology (blacklist/whitelist,
master/slave, grandfathered, etc.).

Operates primarily via regex-based detection. The optional `transformers` dependency
is lazy-loaded for enhanced name diversity analysis when available.
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
# Non-inclusive terminology mappings (term -> suggested replacement)
# ============================================================

_NON_INCLUSIVE_TERMS: dict[str, str] = {
    "blacklist": "blocklist",
    "whitelist": "allowlist",
    "black-list": "blocklist",
    "white-list": "allowlist",
    "master": "main/primary",
    "slave": "replica/secondary",
    "master/slave": "primary/replica",
    "grandfathered": "legacy/exempted",
    "grandfather clause": "legacy clause",
    "sanity check": "confidence check/validation",
    "sanity-check": "confidence check/validation",
    "dummy": "placeholder/sample",
    "cripple": "disable/degrade",
    "crippled": "disabled/degraded",
}

# Compile patterns for non-inclusive terms (word boundary matching)
_NON_INCLUSIVE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE),
        term,
        replacement,
    )
    for term, replacement in _NON_INCLUSIVE_TERMS.items()
]

# ============================================================
# Gendered language patterns
# ============================================================

# Gendered pronouns used generically (he/him/his as default, she/her as default)
_GENDERED_PRONOUN_PATTERNS: list[re.Pattern[str]] = [
    # "he should", "he will", "he can", "he must" (generic usage)
    re.compile(
        r"\b(when|if|once)\s+(the\s+)?(user|developer|employee|worker|manager|customer|client|person|engineer|programmer|admin|administrator)\s+(asks?|requests?|needs?|wants?)\b[^.]{0,50}\b(he|his|him)\b",
        re.IGNORECASE,
    ),
    # "he or she" is somewhat inclusive but still binary
    re.compile(r"\bhe\s+or\s+she\b", re.IGNORECASE),
    re.compile(r"\bhis\s+or\s+her\b", re.IGNORECASE),
    re.compile(r"\bhim\s+or\s+her\b", re.IGNORECASE),
    # Generic "he" as subject in instructions/prompts
    re.compile(
        r"\bthe\s+(user|developer|employee|worker|manager|customer|client|person|engineer|programmer|admin|administrator)\s+.*?\b(he|his|him)\s+(should|will|can|must|may|shall|would|could|needs?|wants?|receives?|gets?)\b",
        re.IGNORECASE,
    ),
    # Standalone generic male pronoun patterns in instruction context
    re.compile(
        r"\b(each|every|any)\s+(user|developer|employee|worker|person|engineer|programmer)\s+.*?\b(he|his|him)\b",
        re.IGNORECASE,
    ),
]

# Gendered job titles / role descriptions
_GENDERED_TITLE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bbusinessman\b", re.IGNORECASE), "business professional"),
    (re.compile(r"\bbusinessmen\b", re.IGNORECASE), "business professionals"),
    (re.compile(r"\bchairman\b", re.IGNORECASE), "chairperson/chair"),
    (re.compile(r"\bchairmen\b", re.IGNORECASE), "chairpersons"),
    (re.compile(r"\bfireman\b", re.IGNORECASE), "firefighter"),
    (re.compile(r"\bfiremen\b", re.IGNORECASE), "firefighters"),
    (re.compile(r"\bpoliceman\b", re.IGNORECASE), "police officer"),
    (re.compile(r"\bpolicemen\b", re.IGNORECASE), "police officers"),
    (re.compile(r"\bstewardess\b", re.IGNORECASE), "flight attendant"),
    (re.compile(r"\bstewardesses\b", re.IGNORECASE), "flight attendants"),
    (re.compile(r"\bmailman\b", re.IGNORECASE), "mail carrier"),
    (re.compile(r"\bmanpower\b", re.IGNORECASE), "workforce/personnel"),
    (re.compile(r"\bman-hours?\b", re.IGNORECASE), "person-hours"),
    (re.compile(r"\bworkman\b", re.IGNORECASE), "worker"),
    (re.compile(r"\bworkmen\b", re.IGNORECASE), "workers"),
    (re.compile(r"\bsalesman\b", re.IGNORECASE), "salesperson"),
    (re.compile(r"\bsalesmen\b", re.IGNORECASE), "salespeople"),
    (re.compile(r"\bforeman\b", re.IGNORECASE), "supervisor"),
    (re.compile(r"\blandlord\b", re.IGNORECASE), "property owner"),
]

# ============================================================
# Stereotyping language patterns
# ============================================================

_STEREOTYPE_PATTERNS: list[re.Pattern[str]] = [
    # Trait-gender associations
    re.compile(
        r"\b(nurturing|emotional|submissive|bossy|aggressive)\s+(female|male|woman|man|girl|boy)\b",
        re.IGNORECASE,
    ),
    # Demographic-attribute stereotypes
    re.compile(
        r"\b(all|every|most)\s+(women|men|girls|boys|asians?|africans?|latinos?|latinas?|hispanics?)\s+(are|tend\s+to\s+be|usually)\b",
        re.IGNORECASE,
    ),
    # Role-gender stereotypes in persona definitions
    re.compile(
        r"\b(a|the)\s+(nurturing|caring|gentle|soft|maternal)\s+(female|woman)\s+(assistant|helper|agent)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(a|the)\s+(strong|assertive|dominant|authoritative)\s+(male|man)\s+(leader|boss|manager|executive)\b",
        re.IGNORECASE,
    ),
]

# ============================================================
# Name diversity analysis
# ============================================================

# Common names grouped by cultural origin (for diversity detection)
_WESTERN_NAMES: set[str] = {
    "john",
    "james",
    "robert",
    "michael",
    "william",
    "david",
    "richard",
    "joseph",
    "thomas",
    "charles",
    "mary",
    "patricia",
    "jennifer",
    "linda",
    "elizabeth",
    "barbara",
    "susan",
    "jessica",
    "sarah",
    "alice",
    "bob",
    "charlie",
    "dave",
    "steve",
    "mike",
    "tom",
    "jack",
    "jane",
    "emily",
    "emma",
    "olivia",
    "matt",
    "chris",
    "daniel",
    "kevin",
    "brian",
    "jason",
    "andrew",
    "ryan",
    "mark",
    "peter",
    "paul",
    "george",
    "henry",
    "sam",
    "kate",
    "anna",
    "rachel",
    "lisa",
    "laura",
    "nancy",
    "helen",
    "karen",
    "betty",
    "dorothy",
    "margaret",
}

_DIVERSE_NAMES: set[str] = {
    # South Asian
    "priya",
    "rahul",
    "ananya",
    "arjun",
    "deepa",
    "vikram",
    "sunita",
    "ravi",
    "aisha",
    "fatima",
    "sandeep",
    "lakshmi",
    "krishna",
    "sanjay",
    "meera",
    # East Asian
    "wei",
    "chen",
    "yuki",
    "sakura",
    "hiroshi",
    "mei",
    "jin",
    "li",
    "akira",
    "haruki",
    "kenji",
    "sato",
    "tanaka",
    "park",
    "kim",
    # African / African-American
    "amara",
    "kwame",
    "nia",
    "jabari",
    "zara",
    "kofi",
    "imani",
    "adaeze",
    "chidi",
    "olumide",
    "abena",
    "malik",
    # Middle Eastern
    "ahmed",
    "layla",
    "omar",
    "nadia",
    "khalid",
    "yasmin",
    "tariq",
    "hassan",
    "leila",
    "karim",
    # Latin American
    "carlos",
    "maria",
    "jose",
    "carmen",
    "alejandro",
    "sofia",
    "diego",
    "valentina",
    "miguel",
    "lucia",
    "pablo",
    "rosa",
    "gabriel",
    "isabella",
}

# Pattern to extract names from examples (quoted names, names in sentences)
_NAME_PATTERN = re.compile(
    r"""(?:
        (?:name\s*(?:is|:)\s*["\']?)(\w+)|   # name is/: "X"
        (?:user\s*(?:is|:)\s*["\']?)(\w+)|   # user is/: "X"
        (?:example|e\.g\.?|e\.g)\s*.*?\b([A-Z][a-z]+)\b|  # Example: Name
        (?:^|\n)\s*[-*]\s*(?:User:\s*)?([A-Z][a-z]+)\b|   # - User: Name
        ["\']([A-Z][a-z]+)["\']                            # "Name"
    )""",
    re.VERBOSE | re.MULTILINE,
)


# ============================================================
# Risk metadata
# ============================================================

_RISK_METADATA: dict[str, dict[str, Any]] = {
    "ETH-1": {
        "title": "Gendered language bias in prompts/instructions",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "description": (
            "The artifact contains gendered language (e.g., he/him as default pronouns, "
            "gendered job titles) that may produce biased or exclusionary outputs."
        ),
        "remediation": ("Use gender-neutral language (they/them, 'the user', role-based titles)."),
    },
    "ETH-2": {
        "title": "Cultural/racial bias in examples",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "description": (
            "The artifact contains examples or sample data that reflect cultural bias, "
            "potentially causing the AI to perpetuate stereotypes."
        ),
        "remediation": ("Ensure diverse representation in all examples and sample data."),
    },
    "ETH-3": {
        "title": "Stereotyped persona definitions",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "description": (
            "The artifact defines AI personas or roles using stereotypical attributes "
            "that reinforce harmful social biases."
        ),
        "remediation": (
            "Define personas based on functional capabilities rather than demographic attributes."
        ),
    },
    "ETH-4": {
        "title": "Missing inclusivity considerations",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P3,
        "gate_action": GateAction.WARN,
        "description": (
            "The artifact uses non-inclusive terminology that should be replaced "
            "with modern inclusive alternatives."
        ),
        "remediation": (
            "Replace non-inclusive terms: blacklist→blocklist, whitelist→allowlist, "
            "master→main/primary, slave→replica/secondary, grandfathered→legacy."
        ),
    },
}


class BiasDetectorScanner(BaseScanner):
    """Scanner for detecting bias and non-inclusive language in AI artifacts.

    Detects:
    - Gendered language used generically (ETH-1)
    - Cultural/racial bias in examples (ETH-2)
    - Stereotyped persona definitions (ETH-3)
    - Non-inclusive terminology (ETH-4)

    Always available via regex-based detection. Enhanced name diversity
    analysis available when `transformers` is installed.
    """

    def __init__(self) -> None:
        """Initialize the BiasDetector scanner."""
        self._transformers_available: bool | None = None

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.BIAS_DETECTOR

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze.

        NOT applicable to: SOP, MCP, Hook, Plugin, Memory.
        """
        return [
            ArtifactType.PROMPT,
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.STEERING,
            ArtifactType.INSTRUCTION,
            ArtifactType.RAG,
            ArtifactType.EVAL_HARNESS,
            ArtifactType.ORCHESTRATION,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        return ["ETH-1", "ETH-2", "ETH-3", "ETH-4"]

    def is_available(self) -> bool:
        """Always available via regex-based detection."""
        return True

    def _check_transformers_available(self) -> bool:
        """Lazy check for optional transformers dependency."""
        if self._transformers_available is None:
            try:
                import transformers  # noqa: F401

                self._transformers_available = True
            except ImportError:
                self._transformers_available = False
        return self._transformers_available

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for bias and non-inclusive language.

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
            self._detect_non_inclusive_terms(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(
            self._detect_gendered_language(artifact_content, artifact_type, artifact_path)
        )
        findings.extend(self._detect_stereotyping(artifact_content, artifact_type, artifact_path))
        findings.extend(self._detect_cultural_bias(artifact_content, artifact_type, artifact_path))

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
        confidence: float,
        line: int | None = None,
    ) -> ScanFinding:
        """Create a ScanFinding from risk metadata.

        Args:
            risk_id: The risk ID for this finding.
            artifact_type: The artifact type being scanned.
            artifact_path: Path to the artifact file.
            evidence: The text/pattern that triggered the finding.
            confidence: Confidence score (0.0-1.0).
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
            category=RiskCategory.ETHICS,
            title=meta["title"],
            description=meta["description"],
            location=FindingLocation(line=line),
            evidence=evidence[:200],
            confidence=confidence,
            scanner_module=ScannerModule.BIAS_DETECTOR,
            remediation=meta["remediation"],
            references=[],
        )

    def _detect_non_inclusive_terms(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect non-inclusive terminology (blacklist, whitelist, master/slave, etc.)."""
        findings: list[ScanFinding] = []
        seen_terms: set[str] = set()

        for pattern, term, replacement in _NON_INCLUSIVE_PATTERNS:
            for match in pattern.finditer(content):
                # Only report each term once per artifact
                term_lower = term.lower()
                if term_lower in seen_terms:
                    continue
                seen_terms.add(term_lower)

                line = self._find_line_number(content, match.start())
                evidence = (
                    f"Non-inclusive term '{match.group(0)}' found. "
                    f"Suggested replacement: '{replacement}'"
                )
                findings.append(
                    self._create_finding(
                        risk_id="ETH-4",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.90,
                        line=line,
                    )
                )
                break  # Only first occurrence per pattern

        return findings

    def _detect_gendered_language(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect gendered language used generically."""
        findings: list[ScanFinding] = []

        # Check gendered pronouns used generically
        for pattern in _GENDERED_PRONOUN_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                evidence = f"Gendered pronoun in generic context: '{match.group(0).strip()}'"
                findings.append(
                    self._create_finding(
                        risk_id="ETH-1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.90,
                        line=line,
                    )
                )
                # Report only first match per pattern
                break

        # Check gendered job titles
        for pattern, replacement in _GENDERED_TITLE_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                evidence = f"Gendered title '{match.group(0)}' found. Suggested: '{replacement}'"
                findings.append(
                    self._create_finding(
                        risk_id="ETH-1",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.90,
                        line=line,
                    )
                )
                break  # Only first occurrence per pattern

        return findings

    def _detect_stereotyping(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect stereotyping language patterns in persona definitions."""
        findings: list[ScanFinding] = []

        for pattern in _STEREOTYPE_PATTERNS:
            for match in pattern.finditer(content):
                line = self._find_line_number(content, match.start())
                evidence = f"Stereotyping language: '{match.group(0).strip()}'"
                findings.append(
                    self._create_finding(
                        risk_id="ETH-3",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=0.75,
                        line=line,
                    )
                )
                break  # Only first match per pattern

        return findings

    def _detect_cultural_bias(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect potential cultural bias in examples by analyzing name diversity."""
        findings: list[ScanFinding] = []

        # Extract names from the content
        extracted_names: list[str] = []
        for match in _NAME_PATTERN.finditer(content):
            # Get the first non-None group
            for group in match.groups():
                if group:
                    extracted_names.append(group.lower())
                    break

        if len(extracted_names) < 2:
            # Not enough names to assess diversity
            return findings

        # Classify names
        western_count = 0
        diverse_count = 0
        unknown_count = 0

        for name in extracted_names:
            if name in _WESTERN_NAMES:
                western_count += 1
            elif name in _DIVERSE_NAMES:
                diverse_count += 1
            else:
                unknown_count += 1

        total_classified = western_count + diverse_count
        if total_classified == 0:
            return findings

        # Flag if all classified names are from one cultural group
        western_ratio = western_count / total_classified if total_classified > 0 else 0

        if western_ratio >= 1.0 and western_count >= 3:
            # All names are Western and there are at least 3
            confidence = min(0.60 + (western_count - 3) * 0.05, 0.79)
            western_found = list(set(n for n in extracted_names if n in _WESTERN_NAMES))[:5]
            evidence = (
                f"Examples use only Western-origin names ({western_count} found: "
                f"{', '.join(western_found)}). "
                f"Consider diversifying with names from multiple cultural backgrounds."
            )
            findings.append(
                self._create_finding(
                    risk_id="ETH-2",
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=evidence,
                    confidence=confidence,
                )
            )

        return findings
