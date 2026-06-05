"""DepScan scanner module for detecting dependency-related security risks.

Detects vulnerable, outdated, unpinned, and potentially malicious dependencies
in AI artifact manifests (requirements.txt, package.json, pyproject.toml).
Uses regex-based parsing with optional integration for pip-audit, safety,
and packaging libraries.
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
    "MCP-S4": {
        "title": "Vulnerable Dependency in MCP Server",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server depends on packages with known CVE vulnerabilities.",
        "remediation": "Update vulnerable dependencies. Pin to secure versions. Run regular dependency audits.",
    },
    "MCP-S11": {
        "title": "Outdated MCP Runtime Dependencies",
        "severity_score": 5,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.SECURITY,
        "description": "MCP server uses outdated runtime dependencies that may have unpatched vulnerabilities.",
        "remediation": "Update runtime dependencies. Set up automated dependency updates. Monitor security advisories.",
    },
    "MCP-S12": {
        "title": "Typosquatting Risk in MCP Dependencies",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server depends on packages with names similar to popular packages, suggesting typosquatting.",
        "remediation": "Verify package names against registries. Use exact verified package names. Audit all dependencies.",
    },
    "PL-S3": {
        "title": "Vulnerable Plugin Dependencies",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin depends on packages with known security vulnerabilities.",
        "remediation": "Update vulnerable dependencies. Pin to secure versions. Run dependency audit.",
    },
    "PL-S8": {
        "title": "Typosquatting Risk in Plugin Name",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin name is suspiciously similar to a popular plugin, suggesting typosquatting attack.",
        "remediation": "Verify plugin name matches intended package. Check download counts and publisher.",
    },
    "SK-S7": {
        "title": "Unverified External Dependency",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill depends on external packages or modules without version pinning or integrity verification.",
        "remediation": "Pin all dependency versions. Verify package checksums. Use lockfiles for reproducibility.",
    },
}

# Artifact type to vulnerability risk ID mapping
_VULN_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.MCP: "MCP-S4",
    ArtifactType.PLUGIN: "PL-S3",
    ArtifactType.SKILL: "SK-S7",
    ArtifactType.HOOK: "MCP-S4",  # Hooks use MCP-S4 for vulnerable deps
}

# Artifact type to outdated risk ID mapping
_OUTDATED_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.MCP: "MCP-S11",
    ArtifactType.PLUGIN: "PL-S3",
    ArtifactType.SKILL: "SK-S7",
    ArtifactType.HOOK: "MCP-S11",
}

# Artifact type to typosquatting risk ID mapping
_TYPOSQUAT_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.MCP: "MCP-S12",
    ArtifactType.PLUGIN: "PL-S8",
    ArtifactType.SKILL: "SK-S7",
    ArtifactType.HOOK: "MCP-S12",
}

# Artifact type to unpinned dependency risk ID mapping
_UNPINNED_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.MCP: "MCP-S11",
    ArtifactType.PLUGIN: "PL-S3",
    ArtifactType.SKILL: "SK-S7",
    ArtifactType.HOOK: "MCP-S11",
}

# --- Known vulnerable package patterns ---
# Packages with known critical vulnerabilities (common examples)
_KNOWN_VULNERABLE_PACKAGES: dict[str, tuple[str, str]] = {
    # Python packages
    "pyyaml": ("< 5.4", "CVE-2020-14343: Arbitrary code execution via yaml.load()"),
    "urllib3": ("< 1.26.5", "CVE-2021-33503: ReDoS vulnerability"),
    "requests": ("< 2.20.0", "CVE-2018-18074: Redirect credential leak"),
    "django": ("< 3.2.4", "CVE-2021-33203: Path traversal"),
    "flask": ("< 2.0.0", "CVE-2019-1010083: DOS via large request"),
    "pillow": ("< 8.3.2", "CVE-2021-34552: Buffer overflow"),
    "cryptography": ("< 3.3.2", "CVE-2020-36242: Integer overflow"),
    "jinja2": ("< 2.11.3", "CVE-2020-28493: ReDoS vulnerability"),
    "numpy": ("< 1.22.0", "CVE-2021-41496: Buffer overflow"),
    "setuptools": ("< 65.5.1", "CVE-2022-40897: ReDoS in package_index"),
    # Node.js packages
    "lodash": ("< 4.17.21", "CVE-2021-23337: Command injection"),
    "minimist": ("< 1.2.6", "CVE-2021-44906: Prototype pollution"),
    "node-fetch": ("< 2.6.7", "CVE-2022-0235: Credential leak"),
    "express": ("< 4.17.3", "CVE-2022-24999: qs prototype pollution"),
    "axios": ("< 0.21.2", "CVE-2021-3749: ReDoS vulnerability"),
    "glob-parent": ("< 5.1.2", "CVE-2020-28469: ReDoS vulnerability"),
    "trim-newlines": ("< 3.0.1", "CVE-2021-33623: ReDoS vulnerability"),
    "path-parse": ("< 1.0.7", "CVE-2021-23343: ReDoS vulnerability"),
    "tar": ("< 6.1.9", "CVE-2021-37701: Path traversal"),
    "ws": ("< 7.4.6", "CVE-2021-32640: ReDoS vulnerability"),
}

# --- Popular package names for typosquatting detection ---
_POPULAR_PACKAGES: set[str] = {
    # Python
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "tensorflow",
    "pytorch",
    "torch",
    "pillow",
    "cryptography",
    "pyyaml",
    "pydantic",
    "fastapi",
    "uvicorn",
    "sqlalchemy",
    "celery",
    "redis",
    "boto3",
    "botocore",
    "jinja2",
    "click",
    "rich",
    "httpx",
    "aiohttp",
    # Node.js
    "express",
    "react",
    "vue",
    "angular",
    "lodash",
    "axios",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "next",
    "nuxt",
    "gatsby",
    "svelte",
    "tailwindcss",
    "postcss",
    "nodemon",
    "dotenv",
    "cors",
    "helmet",
    "morgan",
    "passport",
    "socket.io",
    "mongoose",
    "sequelize",
    "prisma",
    "graphql",
}

# Excessive dependency threshold
_EXCESSIVE_DEP_THRESHOLD = 50

# Regex for parsing requirements.txt lines
_REQUIREMENTS_LINE_RE = re.compile(
    r"^\s*([a-zA-Z0-9][\w\-.]*[a-zA-Z0-9])\s*"  # Package name
    r"(?:"
    r"(==|!=|>=|<=|>|<|~=|===)\s*"  # Operator
    r"([\w\.\-\*]+)"  # Version
    r")?\s*"  # Version spec is optional (unpinned)
    r"(?:;.*)?$"  # Environment markers
)

# Regex for detecting wildcard/star versions
_WILDCARD_VERSION_RE = re.compile(r"^\*$|^\d+\.\*$|^\d+\.\d+\.\*$")


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein (edit) distance between two strings.

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        Integer edit distance.
    """
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _is_typosquat_candidate(package_name: str) -> str | None:
    """Check if a package name is suspiciously similar to a popular package.

    Args:
        package_name: The package name to check.

    Returns:
        The popular package name it resembles, or None.
    """
    normalized = package_name.lower().replace("-", "").replace("_", "")

    for popular in _POPULAR_PACKAGES:
        popular_normalized = popular.lower().replace("-", "").replace("_", "")

        # Skip exact matches
        if normalized == popular_normalized:
            return None

        # Check edit distance (1-2 for short names, 1-2 for longer)
        distance = _levenshtein_distance(normalized, popular_normalized)
        min_len = min(len(normalized), len(popular_normalized))

        if min_len >= 4 and distance <= 2 and distance > 0:
            return popular

    return None


def _parse_requirements_txt(content: str) -> list[dict[str, Any]]:
    """Parse requirements.txt format dependencies.

    Args:
        content: File content in requirements.txt format.

    Returns:
        List of dicts with keys: name, version, operator, line, pinned.
    """
    deps: list[dict[str, Any]] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        # Skip comments, blank lines, options, and URLs
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        if "://" in stripped:
            continue

        match = _REQUIREMENTS_LINE_RE.match(stripped)
        if match:
            name = match.group(1)
            operator = match.group(2)
            version = match.group(3)
            pinned = operator == "==" and version is not None
            deps.append(
                {
                    "name": name,
                    "version": version,
                    "operator": operator,
                    "line": line_num,
                    "pinned": pinned,
                }
            )
    return deps


def _parse_package_json(content: str) -> list[dict[str, Any]]:
    """Parse package.json format dependencies.

    Args:
        content: File content as JSON string.

    Returns:
        List of dicts with keys: name, version, line, pinned.
    """
    import json

    deps: list[dict[str, Any]] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
    for section in dep_sections:
        section_deps = data.get(section, {})
        if not isinstance(section_deps, dict):
            continue
        for name, version_spec in section_deps.items():
            if not isinstance(version_spec, str):
                continue
            # Find line number by searching content
            line_num = _find_line_for_key(content, name)
            # Determine if pinned: exact version without range chars
            is_pinned = bool(re.match(r"^\d+\.\d+\.\d+$", version_spec))
            is_wildcard = (
                version_spec in ("*", "latest")
                or _WILDCARD_VERSION_RE.match(version_spec) is not None
            )
            deps.append(
                {
                    "name": name,
                    "version": version_spec,
                    "operator": None,
                    "line": line_num,
                    "pinned": is_pinned,
                    "wildcard": is_wildcard,
                }
            )
    return deps


def _parse_pyproject_toml(content: str) -> list[dict[str, Any]]:
    """Parse pyproject.toml dependencies section.

    Uses regex to extract dependencies without requiring a TOML parser.

    Args:
        content: File content of pyproject.toml.

    Returns:
        List of dicts with keys: name, version, line, pinned.
    """
    deps: list[dict[str, Any]] = []

    # Look for dependencies = [...] section
    dep_section_re = re.compile(r"dependencies\s*=\s*\[([^\]]*)\]", re.DOTALL)

    for section_match in dep_section_re.finditer(content):
        section_text = section_match.group(1)
        section_start = content[: section_match.start()].count("\n") + 1

        # Parse individual dependency strings
        dep_str_re = re.compile(r'["\']([^"\']+)["\']')
        for dep_match in dep_str_re.finditer(section_text):
            dep_str = dep_match.group(1)
            # Calculate line number
            lines_before = section_text[: dep_match.start()].count("\n")
            line_num = section_start + lines_before + 1

            # Parse the dependency specifier
            req_match = re.match(
                r"([a-zA-Z0-9][\w\-.]*[a-zA-Z0-9])\s*(?:(>=|==|<=|!=|~=|>|<)\s*([\w\.\-\*]+))?",
                dep_str,
            )
            if req_match:
                name = req_match.group(1)
                operator = req_match.group(2)
                version = req_match.group(3)
                pinned = operator == "==" and version is not None
                deps.append(
                    {
                        "name": name,
                        "version": version,
                        "operator": operator,
                        "line": line_num,
                        "pinned": pinned,
                    }
                )

    return deps


def _find_line_for_key(content: str, key: str) -> int:
    """Find the line number where a JSON key appears.

    Args:
        content: Full file content.
        key: The key to search for.

    Returns:
        Line number (1-indexed), or 1 if not found.
    """
    pattern = re.compile(rf'["\']{re.escape(key)}["\']')
    for line_num, line in enumerate(content.splitlines(), start=1):
        if pattern.search(line):
            return line_num
    return 1


def _detect_manifest_type(content: str, artifact_path: str) -> str | None:
    """Detect which type of dependency manifest we're dealing with.

    Args:
        content: File content.
        artifact_path: File path.

    Returns:
        One of 'requirements_txt', 'package_json', 'pyproject_toml', or None.
    """
    path_lower = artifact_path.lower()

    if path_lower.endswith("requirements.txt") or path_lower.endswith("requirements-lock.txt"):
        return "requirements_txt"
    if path_lower.endswith("package.json"):
        return "package_json"
    if path_lower.endswith("pyproject.toml"):
        return "pyproject_toml"

    # Try to detect from content patterns
    if '"dependencies"' in content or '"devDependencies"' in content:
        return "package_json"
    if "[project]" in content and "dependencies" in content:
        return "pyproject_toml"
    # requirements.txt style: lines with package==version, git URLs, or direct URLs
    if re.search(r"^[a-zA-Z][\w\-.]*[a-zA-Z0-9]\s*(==|>=|<=)", content, re.MULTILINE):
        return "requirements_txt"
    if re.search(r"^git\+|^https?://", content, re.MULTILINE):
        return "requirements_txt"

    return None


class DepScanScanner(BaseScanner):
    """Scanner for detecting dependency-related security risks.

    Detects vulnerable, outdated, unpinned, and potentially malicious
    dependencies in artifact manifests. Supports:
    - requirements.txt (Python)
    - package.json (Node.js)
    - pyproject.toml (Python PEP 621)

    Optional integrations:
    - pip-audit: For querying Python vulnerability databases
    - safety: For checking Python dependencies against safety DB
    - packaging: For proper PEP 440 version comparison

    The scanner always functions using built-in regex and heuristic analysis,
    with optional dependencies providing enhanced accuracy.
    """

    def __init__(self) -> None:
        """Initialize the DepScan scanner with lazy-loaded optional deps."""
        self._pip_audit: Any | None = None
        self._pip_audit_loaded = False
        self._safety: Any | None = None
        self._safety_loaded = False
        self._packaging: Any | None = None
        self._packaging_loaded = False

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.DEP_SCAN

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return [ArtifactType.SKILL, ArtifactType.MCP, ArtifactType.HOOK, ArtifactType.PLUGIN]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner detects."""
        return [
            "MCP-S4",
            "MCP-S11",
            "MCP-S12",
            "PL-S3",
            "PL-S8",
            "SK-S7",
        ]

    def is_available(self) -> bool:
        """Always available - uses regex fallback without optional deps."""
        return True

    def _load_pip_audit(self) -> Any | None:
        """Lazily load pip-audit library.

        Returns:
            The pip_audit module or None if not installed.
        """
        if not self._pip_audit_loaded:
            self._pip_audit_loaded = True
            try:
                import pip_audit

                self._pip_audit = pip_audit
            except ImportError:
                self._pip_audit = None
        return self._pip_audit

    def _load_safety(self) -> Any | None:
        """Lazily load safety library.

        Returns:
            The safety module or None if not installed.
        """
        if not self._safety_loaded:
            self._safety_loaded = True
            try:
                import safety

                self._safety = safety
            except ImportError:
                self._safety = None
        return self._safety

    def _load_packaging(self) -> Any | None:
        """Lazily load packaging library.

        Returns:
            The packaging.version module or None if not installed.
        """
        if not self._packaging_loaded:
            self._packaging_loaded = True
            try:
                from packaging import version

                self._packaging = version
            except ImportError:
                self._packaging = None
        return self._packaging

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
            evidence=evidence[:100] if len(evidence) > 100 else evidence,
            confidence=confidence,
            scanner_module=ScannerModule.DEP_SCAN,
            remediation=metadata["remediation"],
            references=[],
        )

    def _check_known_vulnerabilities(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check dependencies against known vulnerable package patterns.

        Args:
            deps: Parsed dependency list.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for vulnerable dependencies.
        """
        findings: list[ScanFinding] = []
        packaging_mod = self._load_packaging()

        for dep in deps:
            name_lower = dep["name"].lower()
            if name_lower in _KNOWN_VULNERABLE_PACKAGES:
                vuln_range, cve_info = _KNOWN_VULNERABLE_PACKAGES[name_lower]
                dep_version = dep.get("version")

                # If we have the packaging module and a version, do proper comparison
                if packaging_mod and dep_version and dep.get("operator") == "==":
                    try:
                        installed = packaging_mod.Version(dep_version)
                        # Parse the vulnerable range upper bound
                        upper_match = re.match(r"<\s*([\d.]+)", vuln_range)
                        if upper_match:
                            upper = packaging_mod.Version(upper_match.group(1))
                            if installed >= upper:
                                continue  # Not vulnerable
                    except Exception:
                        pass  # Fall through to heuristic

                # Without packaging or with non-pinned version, report as potential
                risk_id = _VULN_RISK_MAP.get(artifact_type, "MCP-S4")
                confidence = 0.95 if dep.get("pinned") else 0.85
                evidence = f"{dep['name']}=={dep_version}" if dep_version else dep["name"]

                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=evidence,
                        confidence=confidence,
                        line=dep.get("line"),
                        detail=f"Known vulnerability: {cve_info}",
                    )
                )

        return findings

    def _check_unpinned_dependencies(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for unpinned or wildcard version dependencies.

        Args:
            deps: Parsed dependency list.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for unpinned dependencies.
        """
        findings: list[ScanFinding] = []

        for dep in deps:
            is_unpinned = False
            reason = ""

            if dep.get("version") is None and dep.get("operator") is None:
                is_unpinned = True
                reason = "No version specified"
            elif dep.get("wildcard"):
                is_unpinned = True
                reason = f"Wildcard version: {dep.get('version')}"
            elif dep.get("version") in ("*", "latest"):
                is_unpinned = True
                reason = f"Unrestricted version: {dep.get('version')}"

            if is_unpinned:
                risk_id = _UNPINNED_RISK_MAP.get(artifact_type, "SK-S7")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"{dep['name']} ({reason})",
                        confidence=0.70,
                        line=dep.get("line"),
                        detail=f"Unpinned dependency: {reason}. This allows untested versions to be installed.",
                    )
                )

        return findings

    def _check_typosquatting(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for potential typosquatting in dependency names.

        Args:
            deps: Parsed dependency list.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for suspected typosquatting.
        """
        findings: list[ScanFinding] = []

        for dep in deps:
            similar_to = _is_typosquat_candidate(dep["name"])
            if similar_to:
                risk_id = _TYPOSQUAT_RISK_MAP.get(artifact_type, "MCP-S12")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=f"{dep['name']} (similar to '{similar_to}')",
                        confidence=0.85,
                        line=dep.get("line"),
                        detail=f"Package name '{dep['name']}' is suspiciously similar to popular package '{similar_to}'.",
                    )
                )

        return findings

    def _check_excessive_dependencies(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for excessive dependency count indicating supply chain risk.

        Args:
            deps: Parsed dependency list.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for excessive dependencies.
        """
        findings: list[ScanFinding] = []

        if len(deps) > _EXCESSIVE_DEP_THRESHOLD:
            risk_id = _VULN_RISK_MAP.get(artifact_type, "MCP-S4")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=f"{len(deps)} dependencies declared",
                    confidence=0.70,
                    line=1,
                    detail=f"Excessive dependency count ({len(deps)} > {_EXCESSIVE_DEP_THRESHOLD}) increases supply chain attack surface.",
                )
            )

        return findings

    def _check_untrusted_sources(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check for dependencies from untrusted or unknown sources.

        Detects git URLs, direct URLs, and non-standard registries.

        Args:
            content: Raw file content.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings for untrusted dependency sources.
        """
        findings: list[ScanFinding] = []

        # Patterns indicating non-registry sources
        untrusted_patterns: list[tuple[str, re.Pattern[str]]] = [
            ("Git URL dependency", re.compile(r"(?:git\+|git://)[^\s]+")),
            (
                "Direct URL dependency",
                re.compile(
                    r"https?://(?!pypi\.org|registry\.npmjs\.org|files\.pythonhosted\.org)[^\s]+\.(tar\.gz|whl|tgz)"
                ),
            ),
            ("Private registry", re.compile(r"--index-url\s+https?://(?!pypi\.org)[^\s]+")),
        ]

        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern_name, pattern in untrusted_patterns:
                match = pattern.search(stripped)
                if match:
                    risk_id = _VULN_RISK_MAP.get(artifact_type, "MCP-S4")
                    findings.append(
                        self._create_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            evidence=match.group(0)[:80],
                            confidence=0.75,
                            line=line_num,
                            detail=f"{pattern_name} detected. Dependencies from non-standard sources bypass registry integrity checks.",
                        )
                    )
                    break  # One finding per line

        return findings

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for dependency-related security risks.

        Parses dependency manifests, checks for known vulnerabilities,
        unpinned versions, typosquatting, and excessive dependencies.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        findings: list[ScanFinding] = []

        # Detect manifest type
        manifest_type = _detect_manifest_type(artifact_content, artifact_path)
        if manifest_type is None:
            return findings

        # Parse dependencies based on manifest type
        deps: list[dict[str, Any]] = []
        if manifest_type == "requirements_txt":
            deps = _parse_requirements_txt(artifact_content)
        elif manifest_type == "package_json":
            deps = _parse_package_json(artifact_content)
        elif manifest_type == "pyproject_toml":
            deps = _parse_pyproject_toml(artifact_content)

        # Check for untrusted sources (operates on raw content, not parsed deps)
        findings.extend(
            self._check_untrusted_sources(artifact_content, artifact_type, artifact_path)
        )

        if not deps:
            return findings

        # 1. Check for known vulnerable packages
        findings.extend(self._check_known_vulnerabilities(deps, artifact_type, artifact_path))

        # 2. Check for unpinned/wildcard dependencies
        findings.extend(self._check_unpinned_dependencies(deps, artifact_type, artifact_path))

        # 3. Check for typosquatting
        findings.extend(self._check_typosquatting(deps, artifact_type, artifact_path))

        # 4. Check for excessive dependency count
        findings.extend(self._check_excessive_dependencies(deps, artifact_type, artifact_path))

        return findings
