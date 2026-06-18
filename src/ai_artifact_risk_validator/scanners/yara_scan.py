"""YaraScan scanner for AI artifact YARA signature matching.

Scans artifact content against bundled YARA rule sets to detect malware
indicators, webshell patterns, crypto-mining code, and hack tools.

Gracefully degrades when ``yara-python`` is not installed — logs a warning
and returns no findings rather than raising an error.

Install optional dependency:
    pip install ai-artifact-risk-validator[security]
    # or directly: pip install yara-python>=4.3
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ai_artifact_risk_validator._internal.logging import get_logger
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

logger = get_logger(__name__)

# Path to bundled YARA rule files
_RULES_DIR: Path = Path(__file__).parent.parent / "yara_rules"

# Risk metadata for each YARA category
_YARA_RISK_META: dict[str, dict[str, object]] = {
    "Y-S1": {
        "title": "Malware Signature Match",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": (
            "YARA signature match for known malware patterns including droppers, "
            "obfuscated payloads, C2 beacons, and credential-harvesting code."
        ),
        "remediation": (
            "Remove or quarantine the matched file. Review the matched evidence and "
            "investigate the artifact's origin and intent."
        ),
    },
    "Y-S2": {
        "title": "Webshell Pattern Match",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": (
            "YARA signature match for webshell patterns — scripts that accept HTTP "
            "requests to execute OS commands on the server."
        ),
        "remediation": (
            "Immediately remove the matched script. Webshells represent a full "
            "remote code execution backdoor."
        ),
    },
    "Y-S3": {
        "title": "Cryptominer Signature Match",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": (
            "YARA signature match for crypto-mining indicators including Stratum protocol "
            "strings, XMR wallet addresses, and known mining pool domains."
        ),
        "remediation": (
            "Remove the matched file. Crypto-mining code consumes resources without "
            "consent and indicates malicious intent."
        ),
    },
    "Y-S4": {
        "title": "Hack Tool / Exploit Match",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": (
            "YARA signature match for hack tool indicators including reverse shell stagers, "
            "Metasploit payload markers, PowerShell download-and-execute chains, and "
            "SQL injection tool signatures."
        ),
        "remediation": (
            "Remove the matched file and investigate the artifact's origin. "
            "Hack tools have no legitimate place in AI skill bundles."
        ),
    },
}

# Map YARA file → default risk_id (overridden per-rule by meta.risk_id)
_RULE_FILE_RISK_MAP: dict[str, str] = {
    "malware.yar": "Y-S1",
    "webshell.yar": "Y-S2",
    "cryptominer.yar": "Y-S3",
    "hacktool.yar": "Y-S4",
}


def _load_compiled_rules() -> Any | None:
    """Compile all bundled YARA rule files into a single Rules object.

    Returns:
        A compiled ``yara.Rules`` object, or None if yara-python is unavailable
        or no rule files exist.
    """
    try:
        import yara
    except ImportError:
        return None

    rule_files: dict[str, str] = {}
    for yar_file in _RULES_DIR.glob("*.yar"):
        rule_files[yar_file.stem] = str(yar_file)

    if not rule_files:
        logger.warning("YaraScan: no .yar rule files found in %s", _RULES_DIR)
        return None

    try:
        return yara.compile(filepaths=rule_files)
    except Exception as exc:
        logger.error("YaraScan: failed to compile YARA rules: %s", exc)
        return None


# Module-level compiled rules (loaded once at first is_available() / scan() call)
_compiled_rules: Any | None = None
_rules_loaded: bool = False


def _get_rules() -> Any | None:
    """Return the module-level compiled YARA rules, loading them if needed."""
    global _compiled_rules, _rules_loaded
    if not _rules_loaded:
        _compiled_rules = _load_compiled_rules()
        _rules_loaded = True
    return _compiled_rules


class YaraScanScanner(BaseScanner):
    """YARA signature scanner for malware, webshells, cryptominers, and hack tools.

    Uses bundled YARA rule files from the ``yara_rules/`` package directory.
    Requires ``yara-python>=4.3`` (install with ``pip install .[security]``).

    When yara-python is not installed, ``is_available()`` returns False and
    ``scan()`` returns an empty list rather than raising an error.
    """

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.YARA_SCAN

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """YARA scans all artifact types — any bundled file can carry malware."""
        return list(ArtifactType)

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs detected by this scanner."""
        return ["Y-S1", "Y-S2", "Y-S3", "Y-S4"]

    def is_available(self) -> bool:
        """Check if yara-python is installed and rules compiled successfully."""
        return _get_rules() is not None

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan artifact content against bundled YARA rules.

        Args:
            artifact_content: Full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path for the artifact.

        Returns:
            List of ScanFinding objects for any YARA rule matches.
            Empty list if yara-python is unavailable or no rules match.
        """
        rules = _get_rules()
        if rules is None:
            return []

        findings: list[ScanFinding] = []

        try:
            from datetime import datetime, timezone

            matches: list[object] = rules.match(
                data=artifact_content.encode("utf-8", errors="replace")
            )

            for match in matches:
                risk_id = _resolve_risk_id(match)
                meta = _YARA_RISK_META.get(risk_id)
                if meta is None:
                    continue

                # Extract matched string evidence (first match, truncated)
                evidence = _extract_evidence(match)

                findings.append(
                    ScanFinding(
                        id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        severity_score=int(str(meta["severity_score"])),
                        severity_label=meta["severity_label"],  # type: ignore[arg-type]
                        priority=meta["priority"],  # type: ignore[arg-type]
                        gate_action=meta["gate_action"],  # type: ignore[arg-type]
                        category=RiskCategory.SECURITY,
                        title=str(meta["title"]),
                        description=str(meta["description"]),
                        location=FindingLocation(line=None),
                        evidence=evidence,
                        confidence=0.92,
                        scanner_module=ScannerModule.YARA_SCAN,
                        remediation=str(meta["remediation"]),
                        references=["YARA signature match"],
                        timestamp=datetime.now(tz=timezone.utc),
                    )
                )
        except Exception as exc:
            logger.warning("YaraScan: error during scan of %s: %s", artifact_path, exc)

        return findings


def _resolve_risk_id(match: object) -> str:
    """Extract the risk_id from a YARA match's meta block, or fall back to Y-S1."""
    meta: dict[str, object] = getattr(match, "meta", {})
    risk_id = meta.get("risk_id", "Y-S1")
    return str(risk_id) if risk_id in _YARA_RISK_META else "Y-S1"


def _extract_evidence(match: object) -> str:
    """Extract a short evidence string from the first YARA string match."""
    strings: list[object] = getattr(match, "strings", [])
    if not strings:
        rule_name: str = getattr(match, "rule", "unknown_rule")
        return f"YARA rule matched: {rule_name}"

    # strings is a list of StringMatch objects; get the first instance
    first = strings[0]
    instances: list[object] = getattr(first, "instances", [])
    if instances:
        raw: bytes = getattr(instances[0], "matched_data", b"")
        try:
            return raw.decode("utf-8", errors="replace")[:200]
        except Exception:
            pass

    rule_name = getattr(match, "rule", "unknown_rule")
    identifier: str = getattr(first, "identifier", "")
    return f"YARA rule '{rule_name}' matched string '{identifier}'"
