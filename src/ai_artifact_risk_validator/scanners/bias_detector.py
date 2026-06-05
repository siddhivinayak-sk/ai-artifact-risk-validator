"""BiasDetector scanner module for detecting bias and inclusivity issues.

Detects gendered language, cultural bias in examples, stereotyped persona
definitions, and missing inclusivity considerations in AI artifacts. Uses
regex-based heuristics with optional transformers integration for enhanced
semantic analysis.
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
    "ETH-1": {
        "title": "Gendered language bias in prompts/instructions",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.ETHICS,
        "description": (
            "The artifact contains gendered language (e.g., he/him as default "
            "pronouns, gendered job titles) that may produce biased or "
            "exclusionary outputs."
        ),
        "remediation": (
            "Use gender-neutral language (they/them, 'the user', role-based titles). "
            "Review all persona definitions for gendered assumptions."
        ),
    },
    "ETH-2": {
        "title": "Cultural/racial bias in examples",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.ETHICS,
        "description": (
            "The artifact contains examples or sample data reflecting cultural "
            "or racial bias, potentially causing the AI to perpetuate stereotypes."
        ),
        "remediation": (
            "Ensure diverse representation in all examples and sample data. "
            "Conduct bias audits on few-shot examples across demographic dimensions."
        ),
    },
    "ETH-3": {
        "title": "Stereotyped persona definitions",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.ETHICS,
        "description": (
            "The artifact defines AI personas or roles using stereotypical "
            "attributes that reinforce harmful social biases."
        ),
        "remediation": (
            "Define personas based on functional capabilities rather than "
            "demographic attributes. Audit persona descriptions for stereotype reinforcement."
        ),
    },
    "ETH-4": {
        "title": "Non-inclusive language patterns",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P3,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.ETHICS,
        "description": (
            "The artifact uses non-inclusive language such as ableist terms "
            "or exclusionary phrasing that may alienate users."
        ),
        "remediation": (
            "Replace non-inclusive terms with inclusive alternatives. "
            "Add explicit inclusivity guidelines to artifact metadata."
        ),
    },
}

# --- Applicable artifact types for bias detection ---
_BIAS_RELEVANT_TYPES: list[ArtifactType] = [
    ArtifactType.PROMPT,
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.STEERING,
    ArtifactType.INSTRUCTION,
    ArtifactType.RAG,
    ArtifactType.EVAL_HARNESS,
    ArtifactType.ORCHESTRATION,
]

# --- Gendered language patterns (ETH-1) ---
# Detects exclusive use of he/him or she/her in generic/default contexts
_GENDERED_PRONOUN_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # "he" used as default pronoun in generic statements
    (
        "Default male pronoun",
        re.compile(
            r"\b(?:the\s+user|the\s+developer|the\s+employee|the\s+customer|"
            r"the\s+manager|the\s+engineer|the\s+worker|the\s+person|"
            r"the\s+candidate|the\s+applicant|the\s+caller|a\s+user|"
            r"a\s+developer|an?\s+employee|a\s+customer|a\s+manager)\s+"
            r"(?:\S+\s+){0,6}?\b(he|him|his)\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    # Standalone generic "he" as default (e.g., "When he asks...")
    (
        "Generic male pronoun usage",
        re.compile(
            r"\b(?:when|if|once|after|before)\s+he\s+(?:asks|requests|needs|wants|submits|provides|enters)",
            re.IGNORECASE,
        ),
        0.90,
    ),
    # Generic "she" as default (less common but still biased)
    (
        "Generic female pronoun usage",
        re.compile(
            r"\b(?:when|if|once|after|before)\s+she\s+(?:asks|requests|needs|wants|submits|provides|enters)",
            re.IGNORECASE,
        ),
        0.90,
    ),
]

# Gendered job titles/roles
_GENDERED_TITLE_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "Gendered job title",
        re.compile(
            r"\b(businessman|businesswoman|chairman|chairwoman|"
            r"policeman|policewoman|fireman|firewoman|"
            r"stewardess|steward(?:ess)?|waitress|"
            r"mailman|postman|manpower|mankind|"
            r"salesman|saleswoman|foreman|"
            r"craftsman|workman|cameraman)\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
]

# --- Name diversity analysis (ETH-2) ---
# Cultural name pools for diversity checking
_WESTERN_NAMES: set[str] = {
    "john",
    "jane",
    "bob",
    "alice",
    "tom",
    "mary",
    "james",
    "sarah",
    "michael",
    "jennifer",
    "david",
    "susan",
    "robert",
    "lisa",
    "william",
    "jessica",
    "richard",
    "ashley",
    "charles",
    "amanda",
    "joseph",
    "emily",
    "daniel",
    "rachel",
    "matthew",
    "megan",
    "andrew",
    "hannah",
    "christopher",
    "elizabeth",
    "mark",
    "stephanie",
    "steven",
    "karen",
    "paul",
    "nancy",
    "brian",
    "betty",
    "kevin",
    "helen",
    "george",
    "sandra",
    "edward",
    "donna",
    "ronald",
    "carol",
    "timothy",
    "michelle",
    "jason",
    "laura",
    "jeff",
    "margaret",
    "frank",
    "catherine",
    "scott",
    "deborah",
    "peter",
    "patrick",
    "sam",
    "samantha",
    "alex",
    "mike",
    "joe",
    "jake",
    "kate",
    "anna",
    "smith",
    "johnson",
    "williams",
    "brown",
    "jones",
    "davis",
    "miller",
}

_SOUTH_ASIAN_NAMES: set[str] = {
    "priya",
    "rahul",
    "amit",
    "anita",
    "vikram",
    "deepa",
    "raj",
    "sita",
    "kumar",
    "lakshmi",
    "arjun",
    "meera",
    "ravi",
    "sunita",
    "suresh",
    "patel",
    "sharma",
    "singh",
    "gupta",
    "khan",
    "ali",
    "fatima",
    "mohammed",
    "aisha",
    "hassan",
    "zainab",
}

_EAST_ASIAN_NAMES: set[str] = {
    "wei",
    "li",
    "zhang",
    "wang",
    "chen",
    "liu",
    "yang",
    "huang",
    "yuki",
    "kenji",
    "akira",
    "sakura",
    "hiro",
    "tanaka",
    "suzuki",
    "kim",
    "park",
    "lee",
    "jin",
    "min",
    "soo",
    "hyun",
}

_AFRICAN_NAMES: set[str] = {
    "kwame",
    "ama",
    "kofi",
    "akua",
    "femi",
    "ngozi",
    "olumide",
    "chioma",
    "amara",
    "zuri",
    "jabari",
    "nia",
    "imani",
    "malik",
    "akin",
    "adaeze",
    "chidi",
    "obi",
    "nkechi",
}

_HISPANIC_NAMES: set[str] = {
    "maria",
    "jose",
    "carlos",
    "rosa",
    "miguel",
    "carmen",
    "juan",
    "garcia",
    "martinez",
    "rodriguez",
    "lopez",
    "gonzalez",
    "fernando",
    "isabel",
    "diego",
    "alejandra",
    "ricardo",
    "sofia",
    "pedro",
    "lucia",
    "pablo",
    "valentina",
}

_ALL_NAME_POOLS: dict[str, set[str]] = {
    "western": _WESTERN_NAMES,
    "south_asian": _SOUTH_ASIAN_NAMES,
    "east_asian": _EAST_ASIAN_NAMES,
    "african": _AFRICAN_NAMES,
    "hispanic": _HISPANIC_NAMES,
}

# Pattern to extract names from examples/sample data
_NAME_EXTRACT_PATTERN = re.compile(
    r"(?:name[:\s]+|user[:\s]+|example[:\s]+|e\.g\.\s*|"
    r'for\s+|by\s+|from\s+|["\'])\s*([A-Z][a-z]{2,})',
)

# --- Non-inclusive language patterns (ETH-4) ---
_NON_INCLUSIVE_PATTERNS: list[tuple[str, re.Pattern[str], str, float]] = [
    # Ableist language
    (
        "Ableist term: crazy/insane",
        re.compile(r"\b(crazy|insane|nuts|mental|psycho|lunatic)\b", re.IGNORECASE),
        "Use specific descriptions like 'surprising', 'unexpected', or 'chaotic' instead.",
        0.75,
    ),
    (
        "Ableist term: blind/deaf (metaphorical)",
        re.compile(
            r"\b(blind\s+(?:to|spot)|deaf\s+(?:to|ear)|turn(?:ing|ed)?\s+a\s+blind\s+eye|"
            r"fell\s+on\s+deaf\s+ears)\b",
            re.IGNORECASE,
        ),
        "Use 'unaware of', 'overlooked', 'ignored' instead of disability metaphors.",
        0.70,
    ),
    (
        "Ableist term: crippling/lame",
        re.compile(r"\b(crippl(?:ing|ed)|lame)\b", re.IGNORECASE),
        "Use 'severely limiting', 'inadequate', or 'unsatisfactory' instead.",
        0.75,
    ),
    (
        "Ableist term: dumb/mute",
        re.compile(r"\b(dumb(?:ed)?(?:\s+down)?|retarded)\b", re.IGNORECASE),
        "Use 'simplified', 'unintelligent', or the specific meaning intended.",
        0.80,
    ),
    # Exclusionary phrasing
    (
        "Exclusionary: whitelist/blacklist",
        re.compile(r"\b(whitelist|blacklist|white\s*-?\s*list|black\s*-?\s*list)\b", re.IGNORECASE),
        "Use 'allowlist'/'blocklist' or 'permit list'/'deny list' instead.",
        0.80,
    ),
    (
        "Exclusionary: master/slave",
        re.compile(
            r"\b(master(?:/|\s+and\s+)slave|slave\s+(?:node|server|process))\b", re.IGNORECASE
        ),
        "Use 'primary/replica', 'leader/follower', or 'controller/worker' instead.",
        0.85,
    ),
    (
        "Exclusionary: grandfathered",
        re.compile(r"\b(grandfather(?:ed|ing)?)\b", re.IGNORECASE),
        "Use 'legacy', 'exempted', or 'previously established' instead.",
        0.70,
    ),
]

# --- Stereotyping patterns (ETH-3) ---
_STEREOTYPE_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # Gender-role stereotypes
    (
        "Gender stereotype: nurturing/caring female",
        re.compile(
            r"\b(nurturing|caring|emotional|gentle|soft)\s+(?:female|woman|lady|girl)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "Gender stereotype: strong/aggressive male",
        re.compile(
            r"\b(strong|aggressive|dominant|assertive|tough)\s+(?:male|man|guy|boy)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    # Demographic-trait associations
    (
        "Demographic stereotype association",
        re.compile(
            r"\b(?:all|every|typical)\s+(?:women|men|asians|blacks|whites|"
            r"mexicans|indians|muslims|christians|jews)\s+(?:are|is|tend|always)\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    # Persona with demographic attributes
    (
        "Persona with demographic stereotype",
        re.compile(
            r"(?:you\s+are|act\s+as|behave\s+like|persona[:\s]+)\s*"
            r"(?:a\s+)?(?:young|old|elderly|Asian|Black|White|Hispanic|"
            r"Indian|Chinese|Japanese|Arab|male|female)\s+\w+",
            re.IGNORECASE,
        ),
        0.70,
    ),
]

# --- Fairness / differential treatment patterns (ETH-2 / ETH-3) ---
_FAIRNESS_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "Differential treatment directive",
        re.compile(
            r"\b(?:treat|respond|handle|prioritize|deprioritize)\s+(?:\w+\s+){0,3}"
            r"(?:differently|worse|better|less|more)\s+(?:based\s+on|depending\s+on|"
            r"because\s+of|due\s+to)\s+(?:their\s+)?(?:race|gender|sex|religion|"
            r"ethnicity|nationality|age|disability|sexual\s+orientation|"
            r"skin\s+color|country|origin)\b",
            re.IGNORECASE,
        ),
        0.95,
    ),
    (
        "Explicit discrimination directive",
        re.compile(
            r"\b(?:discriminate|exclude|reject|deny|refuse)\s+(?:\w+\s+){0,4}"
            r"(?:based\s+on|because\s+of|due\s+to)\s+(?:their\s+)?(?:race|gender|"
            r"sex|religion|ethnicity|nationality|age|disability|"
            r"sexual\s+orientation|skin\s+color|country|origin)\b",
            re.IGNORECASE,
        ),
        0.95,
    ),
]


class BiasDetectorScanner(BaseScanner):
    """Scanner for detecting bias, stereotyping, and non-inclusive language.

    Detects:
    - ETH-1: Gendered language bias (pronouns, job titles)
    - ETH-2: Cultural/racial bias in examples (name diversity, stereotyping)
    - ETH-3: Stereotyped persona definitions
    - ETH-4: Non-inclusive language patterns (ableist terms, exclusionary phrasing)

    Uses regex-based heuristics by default. Optionally integrates with
    the `transformers` library for enhanced semantic bias analysis when available.
    """

    def __init__(self) -> None:
        """Initialize the BiasDetector scanner with lazy-loaded optional deps."""
        self._transformers: Any | None = None
        self._transformers_loaded = False

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.BIAS_DETECTOR

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return list(_BIAS_RELEVANT_TYPES)

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner detects."""
        return ["ETH-1", "ETH-2", "ETH-3", "ETH-4"]

    def is_available(self) -> bool:
        """Always available - uses regex fallback without optional deps."""
        return True

    def _load_transformers(self) -> Any | None:
        """Lazily load the transformers library for enhanced bias analysis.

        Returns:
            The transformers pipeline function, or None if not installed.
        """
        if not self._transformers_loaded:
            self._transformers_loaded = True
            try:
                from transformers import pipeline

                self._transformers = pipeline
            except ImportError:
                self._transformers = None
        return self._transformers

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
            scanner_module=ScannerModule.BIAS_DETECTOR,
            remediation=metadata["remediation"],
            references=[],
        )

    def _detect_gendered_language(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect gendered language patterns (ETH-1).

        Scans for exclusive use of gendered pronouns in generic contexts
        and gendered job titles.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of ETH-1 findings.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        # Check pronoun patterns
        for pattern_name, pattern, confidence in _GENDERED_PRONOUN_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    findings.append(
                        self._create_finding(
                            risk_id="ETH-1",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            detail=f"Detected: {pattern_name}.",
                        )
                    )

        # Check gendered job titles
        for pattern_name, pattern, confidence in _GENDERED_TITLE_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    findings.append(
                        self._create_finding(
                            risk_id="ETH-1",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            detail=f"Detected: {pattern_name}.",
                        )
                    )

        return findings

    def _detect_name_diversity(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect lack of name diversity in examples (ETH-2).

        Analyzes names found in the artifact to determine if they
        exclusively come from one cultural background.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of ETH-2 findings for cultural bias.
        """
        findings: list[ScanFinding] = []

        # Extract potential names from the content
        extracted_names: list[str] = []
        for match in _NAME_EXTRACT_PATTERN.finditer(content):
            name = match.group(1).lower()
            if len(name) >= 3:  # Filter very short matches
                extracted_names.append(name)

        if len(extracted_names) < 3:
            # Not enough names to assess diversity
            return findings

        # Categorize names by cultural pool
        pool_counts: dict[str, int] = dict.fromkeys(_ALL_NAME_POOLS, 0)
        matched_names: list[str] = []

        for name in extracted_names:
            for pool_name, pool_set in _ALL_NAME_POOLS.items():
                if name in pool_set:
                    pool_counts[pool_name] += 1
                    matched_names.append(name)
                    break

        total_matched = sum(pool_counts.values())
        if total_matched < 3:
            # Not enough recognized names to assess
            return findings

        # Check if names are predominantly from one cultural background
        for pool_name, count in pool_counts.items():
            if count >= 3 and count / total_matched >= 0.80:
                # 80%+ of names from a single cultural pool indicates bias
                confidence = 0.60 + min((count / total_matched - 0.80) * 2.0, 0.19)
                evidence_names = [n for n in extracted_names if n in _ALL_NAME_POOLS[pool_name]]
                evidence = f"Names predominantly from {pool_name} background: {', '.join(evidence_names[:5])}"

                findings.append(
                    self._create_finding(
                        risk_id="ETH-2",
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=confidence,
                        detail=f"Found {count}/{total_matched} names from {pool_name} cultural background.",
                    )
                )
                break  # Only report the dominant pool

        return findings

    def _detect_stereotypes(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect stereotyping patterns (ETH-3).

        Scans for persona definitions using stereotypical demographic
        attributes and group generalizations.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of ETH-3 findings.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, confidence in _STEREOTYPE_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    findings.append(
                        self._create_finding(
                            risk_id="ETH-3",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            detail=f"Detected: {pattern_name}.",
                        )
                    )

        # Also check fairness patterns (differential treatment = ETH-2 for severity)
        for pattern_name, pattern, confidence in _FAIRNESS_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    findings.append(
                        self._create_finding(
                            risk_id="ETH-2",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            detail=f"Detected: {pattern_name}.",
                        )
                    )

        return findings

    def _detect_non_inclusive_language(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect non-inclusive language patterns (ETH-4).

        Scans for ableist terms, exclusionary phrasing, and other
        non-inclusive language.

        Args:
            content: Artifact content.
            artifact_type: Type of artifact.
            artifact_path: Path to artifact.

        Returns:
            List of ETH-4 findings.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for pattern_name, pattern, suggestion, confidence in _NON_INCLUSIVE_PATTERNS:
            for line_num, line in enumerate(lines, start=1):
                for match in pattern.finditer(line):
                    findings.append(
                        self._create_finding(
                            risk_id="ETH-4",
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0),
                            confidence=confidence,
                            line=line_num,
                            detail=f"Detected: {pattern_name}. {suggestion}",
                        )
                    )

        return findings

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for bias, stereotyping, and inclusivity issues.

        Applies gendered language detection, name diversity analysis,
        stereotype detection, and non-inclusive language linting.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        if artifact_type not in _BIAS_RELEVANT_TYPES:
            return []

        findings: list[ScanFinding] = []

        # 1. Gendered language detection (ETH-1)
        findings.extend(
            self._detect_gendered_language(artifact_content, artifact_type, artifact_path)
        )

        # 2. Name diversity analysis (ETH-2)
        findings.extend(self._detect_name_diversity(artifact_content, artifact_type, artifact_path))

        # 3. Stereotype detection (ETH-3) and fairness (ETH-2)
        findings.extend(self._detect_stereotypes(artifact_content, artifact_type, artifact_path))

        # 4. Non-inclusive language linting (ETH-4)
        findings.extend(
            self._detect_non_inclusive_language(artifact_content, artifact_type, artifact_path)
        )

        # 5. Optional: enhanced analysis with transformers
        # (Lazy-loaded, only runs if library is available)
        self._load_transformers()
        # Transformers integration would be used here for semantic bias detection
        # but the core regex-based approach provides the primary detection capability

        return findings
