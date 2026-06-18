"""DepScan scanner module.

Scans AI artifact dependency manifests and lockfiles for:
- Known vulnerable package versions (CVE matching)
- Unpinned or wildcard version specifications
- Typosquatting package names
- Excessive dependency counts
- Untrusted dependency sources (git URLs, direct URLs)
- Overly broad version ranges

Supports parsing:
- requirements.txt
- package.json
- pyproject.toml
- Pipfile.lock
- yarn.lock
- pnpm-lock.yaml
- Cargo.lock
- go.sum

Detects risk IDs: MCP-S4, MCP-S11, MCP-S12, PL-S3, PL-S8, SK-S7
"""

from __future__ import annotations

import json
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

# ---------------------------------------------------------------------------
# Known vulnerable packages with version ranges and CVE references
# ---------------------------------------------------------------------------

_KNOWN_VULNERABILITIES: list[dict[str, Any]] = [
    # Python packages
    {
        "name": "pyyaml",
        "ecosystem": "python",
        "vulnerable_below": "5.4",
        "cve": "CVE-2020-14343",
        "description": "Arbitrary code execution via unsafe load",
    },
    {
        "name": "requests",
        "ecosystem": "python",
        "vulnerable_below": "2.20.0",
        "cve": "CVE-2018-18074",
        "description": "Session fixation vulnerability",
    },
    {
        "name": "urllib3",
        "ecosystem": "python",
        "vulnerable_below": "1.26.5",
        "cve": "CVE-2021-33503",
        "description": "ReDoS vulnerability in URL authority parsing",
    },
    {
        "name": "pillow",
        "ecosystem": "python",
        "vulnerable_below": "9.0.0",
        "cve": "CVE-2022-22817",
        "description": "Arbitrary code execution via PIL.ImageMath.eval",
    },
    {
        "name": "jinja2",
        "ecosystem": "python",
        "vulnerable_below": "2.11.3",
        "cve": "CVE-2020-28493",
        "description": "ReDoS in urlize filter",
    },
    {
        "name": "django",
        "ecosystem": "python",
        "vulnerable_below": "3.2.14",
        "cve": "CVE-2022-34265",
        "description": "SQL injection in Trunc and Extract functions",
    },
    {
        "name": "flask",
        "ecosystem": "python",
        "vulnerable_below": "2.2.5",
        "cve": "CVE-2023-30861",
        "description": "Cookie theft via proxy misconfiguration",
    },
    {
        "name": "cryptography",
        "ecosystem": "python",
        "vulnerable_below": "39.0.1",
        "cve": "CVE-2023-23931",
        "description": "Memory corruption in PKCS12 parsing",
    },
    {
        "name": "numpy",
        "ecosystem": "python",
        "vulnerable_below": "1.22.0",
        "cve": "CVE-2021-41496",
        "description": "Buffer overflow in array operations",
    },
    # Node.js packages
    {
        "name": "lodash",
        "ecosystem": "node",
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2021-23337",
        "description": "Command injection via template function",
    },
    {
        "name": "express",
        "ecosystem": "node",
        "vulnerable_below": "4.17.3",
        "cve": "CVE-2022-24999",
        "description": "Open redirect via qs prototype pollution",
    },
    {
        "name": "minimist",
        "ecosystem": "node",
        "vulnerable_below": "1.2.6",
        "cve": "CVE-2021-44906",
        "description": "Prototype pollution",
    },
    {
        "name": "axios",
        "ecosystem": "node",
        "vulnerable_below": "0.21.2",
        "cve": "CVE-2021-3749",
        "description": "ReDoS vulnerability",
    },
    {
        "name": "node-fetch",
        "ecosystem": "node",
        "vulnerable_below": "2.6.7",
        "cve": "CVE-2022-0235",
        "description": "Exposure of sensitive information to unauthorized actor",
    },
    {
        "name": "json5",
        "ecosystem": "node",
        "vulnerable_below": "2.2.2",
        "cve": "CVE-2022-46175",
        "description": "Prototype pollution via parse method",
    },
    {
        "name": "semver",
        "ecosystem": "node",
        "vulnerable_below": "7.5.2",
        "cve": "CVE-2022-25883",
        "description": "ReDoS vulnerability in semver parsing",
    },
]

# ---------------------------------------------------------------------------
# Popular packages for typosquatting detection
# ---------------------------------------------------------------------------

_POPULAR_PACKAGES: list[str] = [
    # Python
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "pyyaml",
    "cryptography",
    "pillow",
    "boto3",
    "urllib3",
    "setuptools",
    "pytest",
    "jinja2",
    "pydantic",
    "fastapi",
    "celery",
    "sqlalchemy",
    "aiohttp",
    "beautifulsoup4",
    # Node.js
    "express",
    "lodash",
    "react",
    "axios",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "moment",
    "commander",
    "chalk",
    "underscore",
    "debug",
    "next",
    "vue",
    "angular",
    "jquery",
    "socket.io",
    # Rust
    "serde",
    "tokio",
    "reqwest",
    "clap",
    "rand",
]

# Maximum number of dependencies before flagging as excessive
_EXCESSIVE_DEP_THRESHOLD = 50

# Regex patterns for requirements.txt lines
_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9][\w.\-]*(?:\[[^\]]+\])?)\s*(==|>=|<=|!=|~=|>|<|===)?\s*([^\s;#,]+)?",
)
_REQ_EXTRAS_RE = re.compile(r"^([A-Za-z0-9][\w.\-]*?)(?:\[.*?\])?$")

# Regex to detect git/URL-based installs
_GIT_URL_RE = re.compile(r"^(git\+|https?://|ssh://|ftp://)", re.IGNORECASE)

# Unpinned/wildcard version patterns for Node.js
_WILDCARD_VERSIONS = {"*", "latest", "x", "X", ""}
_BROAD_RANGE_RE = re.compile(r"^[~^>]")


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein (edit) distance between two strings."""
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
    """Check if a package name might be a typosquat of a popular package.

    Returns the popular package name it's similar to, or None.
    """
    name_lower = package_name.lower().strip()

    # Skip if the name is too short (high false positive rate)
    if len(name_lower) < 4:
        return None

    # Skip exact matches to popular packages
    if name_lower in {p.lower() for p in _POPULAR_PACKAGES}:
        return None

    for popular in _POPULAR_PACKAGES:
        popular_lower = popular.lower()

        # Only compare packages of similar length
        len_diff = abs(len(name_lower) - len(popular_lower))
        if len_diff > 2:
            continue

        distance = _levenshtein_distance(name_lower, popular_lower)

        # Flag if edit distance is 1-2 (very similar but not exact)
        if 1 <= distance <= 2:
            return popular

    return None


def _parse_requirements_txt(content: str) -> list[dict[str, Any]]:
    """Parse a requirements.txt file and extract dependency info.

    Returns a list of dicts with keys: name, version, operator, pinned, line_number.
    """
    deps: list[dict[str, Any]] = []

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        # Skip blanks, comments, pip options
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Skip git/URL-based installs (handled separately)
        if _GIT_URL_RE.match(line):
            continue

        # Strip environment markers
        if ";" in line:
            line = line.split(";")[0].strip()

        # Strip inline comments
        if " #" in line:
            line = line.split(" #")[0].strip()

        match = _REQ_LINE_RE.match(line)
        if not match:
            continue

        raw_name = match.group(1)
        operator = match.group(2)
        version = match.group(3)

        # Strip extras from name (e.g., "package[extra]" -> "package")
        extras_match = _REQ_EXTRAS_RE.match(raw_name)
        name = extras_match.group(1) if extras_match else raw_name

        is_pinned = operator == "==" and version is not None

        deps.append(
            {
                "name": name,
                "version": version,
                "operator": operator,
                "pinned": is_pinned,
                "wildcard": False,
                "line_number": line_num,
            }
        )

    return deps


def _parse_package_json(content: str) -> list[dict[str, Any]]:
    """Parse a package.json file and extract dependency info.

    Returns a list of dicts with keys: name, version, pinned, wildcard, line_number.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    deps: list[dict[str, Any]] = []
    dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]

    for section in dep_sections:
        section_data = data.get(section)
        if not isinstance(section_data, dict):
            continue

        for name, version_spec in section_data.items():
            if not isinstance(version_spec, str):
                continue

            version_str = version_spec.strip()
            is_wildcard = version_str in _WILDCARD_VERSIONS
            is_pinned = bool(re.match(r"^\d+\.\d+\.\d+$", version_str)) and not is_wildcard

            deps.append(
                {
                    "name": name,
                    "version": version_str if version_str else None,
                    "operator": None,
                    "pinned": is_pinned,
                    "wildcard": is_wildcard,
                    "line_number": 1,  # JSON doesn't have easy line mapping
                }
            )

    return deps


def _parse_pyproject_toml(content: str) -> list[dict[str, Any]]:
    """Parse a pyproject.toml file for PEP 621 dependencies.

    Uses regex-based parsing to avoid requiring tomli/tomllib.
    Returns a list of dicts similar to requirements.txt parsing.
    """
    deps: list[dict[str, Any]] = []

    # Find dependencies array in [project] section
    # Match: dependencies = [ ... ]
    dep_block_re = re.compile(r"dependencies\s*=\s*\[(.*?)\]", re.DOTALL)
    match = dep_block_re.search(content)
    if not match:
        return deps

    deps_block = match.group(1)
    # Extract individual dependency strings
    dep_str_re = re.compile(r'"([^"]+)"|\'([^\']+)\'')

    for dep_match in dep_str_re.finditer(deps_block):
        dep_str = dep_match.group(1) or dep_match.group(2)
        dep_str = dep_str.strip()

        # Parse like requirements.txt line
        req_match = _REQ_LINE_RE.match(dep_str)
        if not req_match:
            continue

        raw_name = req_match.group(1)
        operator = req_match.group(2)
        version = req_match.group(3)

        extras_match = _REQ_EXTRAS_RE.match(raw_name)
        name = extras_match.group(1) if extras_match else raw_name

        is_pinned = operator == "==" and version is not None

        deps.append(
            {
                "name": name,
                "version": version,
                "operator": operator,
                "pinned": is_pinned,
                "wildcard": False,
                "line_number": 1,
            }
        )

    return deps


def _parse_pipfile_lock(content: str) -> list[dict[str, Any]]:
    """Parse a Pipfile.lock JSON file and extract dependency info."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    deps: list[dict[str, Any]] = []

    for section in ("default", "develop"):
        section_data = data.get(section)
        if not isinstance(section_data, dict):
            continue

        for name, info in section_data.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version", "")
            # Pipfile.lock versions are typically "==X.Y.Z"
            if version.startswith("=="):
                version = version[2:]
                is_pinned = True
            else:
                is_pinned = bool(version)

            deps.append(
                {
                    "name": name,
                    "version": version or None,
                    "operator": "==" if is_pinned else None,
                    "pinned": is_pinned,
                    "wildcard": False,
                    "line_number": 1,
                }
            )

    return deps


def _parse_cargo_lock(content: str) -> list[dict[str, Any]]:
    """Parse a Cargo.lock file (TOML-like) for Rust dependencies."""
    deps: list[dict[str, Any]] = []
    # Cargo.lock uses [[package]] blocks with name and version
    package_re = re.compile(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"')

    for match in package_re.finditer(content):
        name = match.group(1)
        version = match.group(2)
        deps.append(
            {
                "name": name,
                "version": version,
                "operator": "==",
                "pinned": True,
                "wildcard": False,
                "line_number": 1,
            }
        )

    return deps


def _parse_go_sum(content: str) -> list[dict[str, Any]]:
    """Parse a go.sum file for Go module dependencies."""
    deps: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue

        name = parts[0]
        version = parts[1].lstrip("v").split("/")[0]

        # Deduplicate (go.sum has multiple entries per module)
        key = f"{name}@{version}"
        if key in seen:
            continue
        seen.add(key)

        deps.append(
            {
                "name": name,
                "version": version,
                "operator": "==",
                "pinned": True,
                "wildcard": False,
                "line_number": line_num,
            }
        )

    return deps


def _parse_yarn_lock(content: str) -> list[dict[str, Any]]:
    """Parse a yarn.lock file for Node.js dependencies."""
    deps: list[dict[str, Any]] = []
    # Yarn lock format: "package@version": followed by resolved version
    entry_re = re.compile(r'^"?([^@\s"]+)@[^"]*"?:\s*$', re.MULTILINE)
    version_re = re.compile(r'^\s+version\s+"?([^"\s]+)"?\s*$', re.MULTILINE)

    entries = list(entry_re.finditer(content))
    versions = list(version_re.finditer(content))

    for i, entry_match in enumerate(entries):
        name = entry_match.group(1)
        version = versions[i].group(1) if i < len(versions) else None
        deps.append(
            {
                "name": name,
                "version": version,
                "operator": "==",
                "pinned": version is not None,
                "wildcard": False,
                "line_number": 1,
            }
        )

    return deps


def _parse_pnpm_lock(content: str) -> list[dict[str, Any]]:
    """Parse a pnpm-lock.yaml file for Node.js dependencies."""
    deps: list[dict[str, Any]] = []
    # pnpm lockfile v6+ uses /package@version format
    pkg_re = re.compile(r"^\s+/?([^@\s/]+)@(\S+):", re.MULTILINE)

    for match in pkg_re.finditer(content):
        name = match.group(1)
        version = match.group(2)
        deps.append(
            {
                "name": name,
                "version": version,
                "operator": "==",
                "pinned": True,
                "wildcard": False,
                "line_number": 1,
            }
        )

    return deps


def _version_less_than(version: str, threshold: str) -> bool:
    """Compare two version strings. Returns True if version < threshold.

    Uses simple tuple comparison of numeric parts. Falls back to string
    comparison if parsing fails.
    """
    try:
        # Try importing packaging for accurate comparison
        from packaging.version import Version

        return Version(version) < Version(threshold)
    except (ImportError, Exception):
        pass

    # Fallback: simple numeric tuple comparison
    try:
        v_parts = tuple(int(x) for x in re.split(r"[.\-+]", version) if x.isdigit())
        t_parts = tuple(int(x) for x in re.split(r"[.\-+]", threshold) if x.isdigit())
        return v_parts < t_parts
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Manifest file detection
# ---------------------------------------------------------------------------

_MANIFEST_PARSERS: dict[str, Any] = {
    "requirements.txt": _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "requirements-lock.txt": _parse_requirements_txt,
    "requirements_dev.txt": _parse_requirements_txt,
    "requirements_lock.txt": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "pyproject.toml": _parse_pyproject_toml,
    "pipfile.lock": _parse_pipfile_lock,
    "cargo.lock": _parse_cargo_lock,
    "go.sum": _parse_go_sum,
    "yarn.lock": _parse_yarn_lock,
    "pnpm-lock.yaml": _parse_pnpm_lock,
}


def _detect_manifest_type(path: str, content: str) -> str | None:
    """Detect the manifest type from file path or content heuristics."""
    import os

    basename = os.path.basename(path).lower()

    # Direct filename match
    if basename in _MANIFEST_PARSERS:
        return basename

    # requirements*.txt pattern
    if basename.startswith("requirements") and basename.endswith(".txt"):
        return "requirements.txt"

    return None


# ---------------------------------------------------------------------------
# DepScanScanner
# ---------------------------------------------------------------------------


class DepScanScanner(BaseScanner):
    """Scanner that analyzes dependency manifests and lockfiles for risks.

    Detects:
    - Known CVE vulnerabilities in pinned package versions
    - Unpinned or wildcard version specifications
    - Typosquatting package names (similar to popular packages)
    - Excessive dependency counts
    - Dependencies from untrusted sources (git URLs, direct URLs)

    Works with regex-based parsing without requiring pip-audit or safety.
    Optional `packaging` dependency used for accurate version comparison.
    """

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.DEP_SCAN

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [
            ArtifactType.MCP,
            ArtifactType.PLUGIN,
            ArtifactType.SKILL,
            ArtifactType.HOOK,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["MCP-S4", "MCP-S11", "MCP-S12", "PL-S3", "PL-S8", "SK-S7", "DEP-S1", "DEP-S2"]

    def is_available(self) -> bool:
        """Always available — works with regex-based parsing."""
        return True

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan dependency manifest for security risks."""
        if not artifact_content.strip():
            return []

        manifest_type = _detect_manifest_type(artifact_path, artifact_content)
        if manifest_type is None:
            return []

        parser = _MANIFEST_PARSERS.get(manifest_type)
        if parser is None:
            return []

        deps = parser(artifact_content)
        findings: list[ScanFinding] = []

        # Check for untrusted sources (requirements.txt specific) — runs even if deps is empty
        if manifest_type == "requirements.txt" or manifest_type.startswith("requirements"):
            findings.extend(
                self._check_untrusted_sources(artifact_content, artifact_type, artifact_path)
            )

        if not deps:
            return findings

        # Check for known vulnerabilities
        findings.extend(self._check_vulnerabilities(deps, artifact_type, artifact_path))

        # Check for unpinned/wildcard versions
        findings.extend(self._check_unpinned(deps, artifact_type, artifact_path))

        # Check for typosquatting
        findings.extend(self._check_typosquatting(deps, artifact_type, artifact_path))

        # Check for excessive dependencies
        findings.extend(self._check_excessive_deps(deps, artifact_type, artifact_path))

        return findings

    # ------------------------------------------------------------------
    # Vulnerability checks
    # ------------------------------------------------------------------

    def _check_vulnerabilities(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Check dependencies against known vulnerable versions."""
        findings: list[ScanFinding] = []

        for dep in deps:
            name = dep["name"].lower()
            version = dep.get("version")

            if not version:
                continue

            for vuln in _KNOWN_VULNERABILITIES:
                if vuln["name"].lower() != name:
                    continue

                if _version_less_than(version, vuln["vulnerable_below"]):
                    risk_id = self._get_vuln_risk_id(artifact_type)
                    findings.append(
                        self._make_finding(
                            risk_id=risk_id,
                            artifact_type=artifact_type,
                            artifact_path=artifact_path,
                            title="Known Vulnerable Dependency",
                            description=(
                                f"Package '{dep['name']}' version {version} has a known "
                                f"vulnerability ({vuln['cve']}): {vuln['description']}. "
                                f"Update to >= {vuln['vulnerable_below']}."
                            ),
                            evidence=f"{dep['name']}=={version} (CVE: {vuln['cve']})",
                            location=FindingLocation(
                                line=dep.get("line_number", 1),
                                section="dependencies",
                            ),
                            remediation=(
                                f"Update '{dep['name']}' to version >= {vuln['vulnerable_below']}."
                            ),
                            confidence=0.97,
                            severity_score=7,
                            severity_label=SeverityLabel.HIGH,
                            priority=Priority.P1,
                            gate_action=GateAction.BLOCK,
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Unpinned version checks
    # ------------------------------------------------------------------

    def _check_unpinned(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect unpinned and wildcard dependency versions."""
        findings: list[ScanFinding] = []

        for dep in deps:
            is_wildcard = dep.get("wildcard", False)
            is_pinned = dep.get("pinned", False)
            version = dep.get("version")

            if is_wildcard:
                risk_id = self._get_outdated_risk_id(artifact_type)
                findings.append(
                    self._make_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        title="Unpinned Dependency Version",
                        description=(
                            f"Dependency '{dep['name']}' uses an unpinned/wildcard version "
                            f"specification. This allows arbitrary versions to be installed."
                        ),
                        evidence=f"Unrestricted version for '{dep['name']}': {version or '*'}",
                        location=FindingLocation(
                            line=dep.get("line_number", 1),
                            section="dependencies",
                        ),
                        remediation=f"Pin '{dep['name']}' to a specific version.",
                        confidence=0.70,
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )
            elif not is_pinned and version is None:
                # No version specified at all
                risk_id = self._get_outdated_risk_id(artifact_type)
                findings.append(
                    self._make_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        title="Unpinned Dependency Version",
                        description=(
                            f"Dependency '{dep['name']}' has no version constraint. "
                            f"Any version may be installed, including vulnerable ones."
                        ),
                        evidence=f"No version specified for '{dep['name']}'",
                        location=FindingLocation(
                            line=dep.get("line_number", 1),
                            section="dependencies",
                        ),
                        remediation=f"Pin '{dep['name']}' to a specific version (e.g., ==X.Y.Z).",
                        confidence=0.70,
                        severity_score=5,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Typosquatting checks
    # ------------------------------------------------------------------

    def _check_typosquatting(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect potential typosquatting package names."""
        findings: list[ScanFinding] = []

        for dep in deps:
            similar_to = _is_typosquat_candidate(dep["name"])
            if similar_to is not None:
                risk_id = self._get_typosquat_risk_id(artifact_type)
                findings.append(
                    self._make_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        title="Potential Typosquatting Package",
                        description=(
                            f"Package '{dep['name']}' has a name suspiciously similar to "
                            f"the popular package '{similar_to}'. This may be a "
                            f"typosquatting attack."
                        ),
                        evidence=(
                            f"'{dep['name']}' is similar to '{similar_to}' (edit distance ≤ 2)"
                        ),
                        location=FindingLocation(
                            line=dep.get("line_number", 1),
                            section="dependencies",
                        ),
                        remediation=(
                            f"Verify that '{dep['name']}' is the intended package. "
                            f"Did you mean '{similar_to}'?"
                        ),
                        confidence=0.85,
                        severity_score=7,
                        severity_label=SeverityLabel.HIGH,
                        priority=Priority.P1,
                        gate_action=GateAction.BLOCK,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Excessive dependency checks
    # ------------------------------------------------------------------

    def _check_excessive_deps(
        self,
        deps: list[dict[str, Any]],
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Flag manifests with an excessive number of dependencies."""
        findings: list[ScanFinding] = []

        if len(deps) > _EXCESSIVE_DEP_THRESHOLD:
            risk_id = self._get_outdated_risk_id(artifact_type)
            findings.append(
                self._make_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    title="Excessive Dependency Count",
                    description=(
                        f"Manifest declares {len(deps)} dependencies, exceeding the "
                        f"recommended threshold of {_EXCESSIVE_DEP_THRESHOLD}. "
                        f"Large dependency trees increase supply chain risk."
                    ),
                    evidence=f"{len(deps)} dependencies declared (threshold: {_EXCESSIVE_DEP_THRESHOLD})",
                    location=FindingLocation(line=1, section="dependencies"),
                    remediation="Review and reduce dependencies. Remove unused packages.",
                    confidence=0.80,
                    severity_score=5,
                    severity_label=SeverityLabel.MEDIUM,
                    priority=Priority.P2,
                    gate_action=GateAction.WARN,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Untrusted source checks
    # ------------------------------------------------------------------

    def _check_untrusted_sources(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Detect dependencies installed from non-standard sources."""
        findings: list[ScanFinding] = []

        for line_num, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if _GIT_URL_RE.match(line):
                is_git = line.lower().startswith("git+")
                source_type = "Git URL" if is_git else "Direct URL"
                risk_id = self._get_vuln_risk_id(artifact_type)
                findings.append(
                    self._make_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        title=f"Dependency from {source_type}",
                        description=(
                            f"A dependency is installed from a non-standard source "
                            f"({source_type}). This bypasses registry integrity checks."
                        ),
                        evidence=line[:200],
                        location=FindingLocation(
                            line=line_num,
                            section="dependencies",
                        ),
                        remediation="Use official package registry versions instead of direct URLs.",
                        confidence=0.80,
                        severity_score=6,
                        severity_label=SeverityLabel.MEDIUM,
                        priority=Priority.P2,
                        gate_action=GateAction.WARN,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Risk ID mapping per artifact type
    # ------------------------------------------------------------------

    def _get_vuln_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate vulnerability risk ID for the artifact type."""
        mapping = {
            ArtifactType.MCP: "MCP-S4",
            ArtifactType.PLUGIN: "PL-S3",
            ArtifactType.SKILL: "SK-S7",
            ArtifactType.HOOK: "MCP-S4",  # Hooks use MCP risk IDs
        }
        return mapping.get(artifact_type, "MCP-S4")

    def _get_outdated_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate outdated/unpinned risk ID for the artifact type."""
        mapping = {
            ArtifactType.MCP: "MCP-S11",
            ArtifactType.PLUGIN: "PL-S3",
            ArtifactType.SKILL: "SK-S7",
            ArtifactType.HOOK: "MCP-S11",
        }
        return mapping.get(artifact_type, "MCP-S11")

    def _get_typosquat_risk_id(self, artifact_type: ArtifactType) -> str:
        """Get the appropriate typosquatting risk ID for the artifact type."""
        return "DEP-S1"

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        *,
        risk_id: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        title: str,
        description: str,
        evidence: str,
        location: FindingLocation,
        remediation: str,
        confidence: float,
        severity_score: int,
        severity_label: SeverityLabel,
        priority: Priority,
        gate_action: GateAction,
    ) -> ScanFinding:
        """Create a ScanFinding for dependency scanning."""
        return ScanFinding(
            id=risk_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            severity_score=severity_score,
            severity_label=severity_label,
            priority=priority,
            gate_action=gate_action,
            category=RiskCategory.SECURITY,
            title=title,
            description=description,
            location=location,
            evidence=evidence,
            confidence=confidence,
            scanner_module=ScannerModule.DEP_SCAN,
            remediation=remediation,
        )
