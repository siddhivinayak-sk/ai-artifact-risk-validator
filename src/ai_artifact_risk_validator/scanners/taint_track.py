"""TaintTrack scanner for data-flow / taint analysis.

Detects dangerous data flows where tainted data from external sources
reaches code execution or network transmission sinks without sanitization.

Detection approach:
  - **Python files**: Full AST-based assignment chain tracking
    (source → variable → sink co-occurrence within function scope)
  - **Other languages**: 10-line proximity regex window detecting
    source patterns followed by the same variable name at a sink

Risk IDs detected:
  TT-S1  Direct Taint Flow                  (HIGH)
  TT-S2  Variable-Mediated Taint Flow       (MEDIUM)
  TT-S3  Credential Exfiltration Chain      (CRITICAL)
  TT-S4  File Read to Network Exfiltration  (HIGH)
  TT-S5  External Input to Code Execution   (CRITICAL)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Risk metadata
# ---------------------------------------------------------------------------

_RISK_META: dict[str, dict[str, object]] = {
    "TT-S1": {
        "title": "Direct Taint Flow",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "description": "Data flows directly from an external source to a dangerous sink without sanitization.",
        "remediation": "Validate and sanitize all external input before passing to command execution or network sinks.",
    },
    "TT-S2": {
        "title": "Variable-Mediated Taint Flow",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "description": "Data flows from an external source through intermediate variables to a dangerous sink.",
        "remediation": "Apply input validation at the source and sanitize before the sink.",
    },
    "TT-S3": {
        "title": "Credential Exfiltration Chain",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Credentials or secrets (environment variables, config keys) flow to network output sinks.",
        "remediation": "Never transmit credentials to external endpoints. Use a secrets manager.",
    },
    "TT-S4": {
        "title": "File Read to Network Exfiltration",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "File contents are read and then transmitted to an external network endpoint.",
        "remediation": "Restrict file read permissions and remove unauthorized network transmissions.",
    },
    "TT-S5": {
        "title": "External Input to Code Execution",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "description": "Network or user input flows directly to exec/eval/subprocess sinks enabling remote code execution.",
        "remediation": "Never pass external input to code execution functions. Use strict allowlists.",
    },
}

# ---------------------------------------------------------------------------
# Source and sink patterns for AST analysis
# ---------------------------------------------------------------------------

# Source call signatures — (module_or_None, function_name) or attribute chains
_CRED_SOURCE_CALLS: frozenset[str] = frozenset(
    {
        "os.environ.get",
        "os.getenv",
        "os.environ.__getitem__",
    }
)

_FILE_SOURCE_CALLS: frozenset[str] = frozenset(
    {
        "open",
        "pathlib.Path.read_text",
        "pathlib.Path.read_bytes",
    }
)

_NETWORK_SOURCE_CALLS: frozenset[str] = frozenset(
    {
        "requests.get",
        "requests.post",
        "urllib.request.urlopen",
        "urllib.urlopen",
        "httpx.get",
        "httpx.post",
    }
)

_USER_SOURCE_CALLS: frozenset[str] = frozenset({"input", "sys.stdin.read", "sys.stdin.readline"})

_ALL_SOURCES: frozenset[str] = (
    _CRED_SOURCE_CALLS | _FILE_SOURCE_CALLS | _NETWORK_SOURCE_CALLS | _USER_SOURCE_CALLS
)

# Sink call signatures
_CODE_EXEC_SINKS: frozenset[str] = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execvp",
    }
)

_NETWORK_SINKS: frozenset[str] = frozenset(
    {
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "urllib.request.urlopen",
        "socket.send",
        "socket.sendall",
        "socket.sendto",
        "smtplib.SMTP.sendmail",
        "httpx.post",
        "httpx.put",
    }
)

# Method names (attribute part only) that are network sinks regardless of object name
_NETWORK_SINK_METHODS: frozenset[str] = frozenset({"send", "sendall", "sendto", "sendmail"})

_ALL_SINKS: frozenset[str] = _CODE_EXEC_SINKS | _NETWORK_SINKS

# ---------------------------------------------------------------------------
# Regex patterns for non-Python proximity analysis
# ---------------------------------------------------------------------------

_RE_CRED_SOURCE = re.compile(
    r"(?:os\.environ|getenv|ENV\[|process\.env(?:\.\w+|\[['\"]?\w+['\"]?\])?|System\.getenv)"
    r"(?:\s*[\[\(]['\"]?\w+['\"]?[\]\)])?",
    re.IGNORECASE,
)
_RE_FILE_SOURCE = re.compile(
    r"(?:open|readFile|read_text|File\.read)\s*\((['\"]?[\w./\\-]+['\"]?)",
    re.IGNORECASE,
)
_RE_NETWORK_SOURCE = re.compile(
    r"(?:requests?\.|urllib|http|fetch|axios)\.\s*(?:get|post)\s*\(",
    re.IGNORECASE,
)
_RE_CODE_SINK = re.compile(
    r"(?:exec|eval|subprocess\.|os\.system|Runtime\.exec|shell_exec|system)\s*\(",
    re.IGNORECASE,
)
_RE_NETWORK_SINK = re.compile(
    r"(?:requests?\.|urllib|http|fetch|axios)\.\s*(?:post|put|patch|delete)\s*\(",
    re.IGNORECASE,
)
# ---------------------------------------------------------------------------


def _call_name(node: ast.expr) -> str:
    """Return a dotted string representation of a call target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_source(name: str) -> tuple[bool, str]:
    """Check if a call name is a known taint source and return source category."""
    if name in _CRED_SOURCE_CALLS or "environ" in name:
        return True, "cred"
    if name in _FILE_SOURCE_CALLS or name in ("open",):
        return True, "file"
    if name in _NETWORK_SOURCE_CALLS:
        return True, "network"
    if name in _USER_SOURCE_CALLS:
        return True, "user"
    return False, ""


def _is_sink(name: str) -> tuple[bool, str]:
    """Check if a call name is a known dangerous sink and return sink category."""
    if name in _CODE_EXEC_SINKS:
        return True, "code_exec"
    if name in _NETWORK_SINKS:
        return True, "network"
    # Also match bare method names like s.sendall() → attr='sendall'
    method_part = name.rsplit(".", 1)[-1]
    if method_part in _NETWORK_SINK_METHODS:
        return True, "network"
    return False, ""


def _choose_risk_id(source_cat: str, sink_cat: str, *, direct: bool) -> str:
    """Choose the most specific risk ID given source and sink categories."""
    if source_cat == "cred" and sink_cat == "network":
        return "TT-S3"
    if source_cat == "file" and sink_cat == "network":
        return "TT-S4"
    if (source_cat in ("network", "user")) and sink_cat == "code_exec":
        return "TT-S5"
    if direct:
        return "TT-S1"
    return "TT-S2"


# ---------------------------------------------------------------------------
# AST-based taint analysis for Python files
# ---------------------------------------------------------------------------


class _TaintVisitor(ast.NodeVisitor):
    """AST visitor that tracks taint flow within a function scope."""

    def __init__(self) -> None:
        # Maps variable name → source category
        self._tainted: dict[str, str] = {}
        # Collected (risk_id, line, evidence) tuples
        self.hits: list[tuple[str, int, str]] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments from taint sources."""
        rhs = node.value
        src_cat = self._get_source_category(rhs)
        if src_cat:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted[target.id] = src_cat
        self.generic_visit(node)

    def _get_source_category(self, node: ast.expr) -> str:
        """Return source category if node is a taint source, else ''."""
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            is_src, src_cat = _is_source(call_name)
            if is_src:
                return src_cat
        # Handle: source_call().attr  (e.g. requests.get(url).text)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
            call_name = _call_name(node.value.func)
            is_src, src_cat = _is_source(call_name)
            if is_src:
                return src_cat
        # Handle: source_call().method()  (e.g. urlopen(url).read())
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Call)
        ):
            call_name = _call_name(node.func.value.func)
            is_src, src_cat = _is_source(call_name)
            if is_src:
                return src_cat
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        """Detect when a tainted variable reaches a dangerous sink."""
        sink_name = _call_name(node.func)
        is_snk, snk_cat = _is_sink(sink_name)
        if is_snk:
            # Check all positional and keyword args for tainted variables
            all_args: list[ast.expr] = list(node.args)
            all_args += [kw.value for kw in node.keywords]
            # Also descend into dict literal values (e.g. requests.post(data={"k": tainted}))
            expanded: list[ast.expr] = []
            for arg in all_args:
                expanded.append(arg)
                if isinstance(arg, ast.Dict):
                    expanded.extend(v for v in arg.values if v is not None)
            for arg in expanded:
                tainted_var, src_cat = self._find_tainted_name(arg)
                if tainted_var:
                    risk_id = _choose_risk_id(src_cat, snk_cat, direct=False)
                    evidence = (
                        f"Tainted '{tainted_var}' (from {src_cat} source) reaches {sink_name}()"
                    )
                    self.hits.append((risk_id, node.lineno, evidence))
        # Also check for direct taint: source call result passed directly to sink
        # Handles: exec(requests.get(url).text), exec(open(path).read())
        if is_snk:
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                src_call, src_cat = self._find_chained_source(arg)
                if src_call:
                    risk_id = _choose_risk_id(src_cat, snk_cat, direct=True)
                    evidence = f"Direct taint: {src_call} result passed to {sink_name}()"
                    self.hits.append((risk_id, node.lineno, evidence))
                elif isinstance(arg, ast.Call):
                    inner_name = _call_name(arg.func)
                    is_src, src_cat = _is_source(inner_name)
                    if is_src:
                        risk_id = _choose_risk_id(src_cat, snk_cat, direct=True)
                        evidence = f"Direct taint: {inner_name}() result passed to {sink_name}()"
                        self.hits.append((risk_id, node.lineno, evidence))
        self.generic_visit(node)

    def _find_chained_source(self, node: ast.expr) -> tuple[str, str]:
        """Check if node is a chained attribute access on a source call (e.g. requests.get(url).text)."""
        if isinstance(node, ast.Attribute):
            # e.g. requests.get(url).text, open(path).read()
            inner = node.value
            if isinstance(inner, ast.Call):
                call_name_str = _call_name(inner.func)
                is_src, src_cat = _is_source(call_name_str)
                if is_src:
                    return call_name_str, src_cat
        if isinstance(node, ast.Call):
            # e.g. open(path).read() — the outer call is .read()
            inner_attr = node.func
            if isinstance(inner_attr, ast.Attribute) and isinstance(inner_attr.value, ast.Call):
                call_name_str = _call_name(inner_attr.value.func)
                is_src, src_cat = _is_source(call_name_str)
                if is_src:
                    return call_name_str, src_cat
        return "", ""

    def _find_tainted_name(self, node: ast.expr) -> tuple[str, str]:
        """Return (var_name, src_cat) if node is a tainted Name (or method call on it), else ('', '')."""
        if isinstance(node, ast.Name) and node.id in self._tainted:
            return node.id, self._tainted[node.id]
        # Handle: tainted_var.encode() or tainted_var.method(...)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self._tainted
        ):
            return node.func.value.id, self._tainted[node.func.value.id]
        return "", ""


def _analyze_python_ast(content: str, artifact_path: str) -> list[tuple[str, int, str]]:
    """Parse Python source and run taint visitor across all function bodies.

    Returns list of (risk_id, line_number, evidence) tuples.
    """
    try:
        tree = ast.parse(content, filename=artifact_path)
    except SyntaxError:
        return []

    hits: list[tuple[str, int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            visitor = _TaintVisitor()
            visitor.visit(node)
            hits.extend(visitor.hits)

    # Also run at module level for top-level script taint
    module_visitor = _TaintVisitor()
    for child in ast.iter_child_nodes(tree):
        module_visitor.visit(child)
    hits.extend(module_visitor.hits)

    return hits


# ---------------------------------------------------------------------------
# Proximity-based analysis for non-Python files
# ---------------------------------------------------------------------------


def _analyze_proximity(lines: list[str]) -> list[tuple[str, int, str]]:
    """10-line proximity analysis: source pattern followed by sink within 10 lines."""
    hits: list[tuple[str, int, str]] = []
    window = 10

    for i, line in enumerate(lines):
        src_match = _RE_CRED_SOURCE.search(line) or _RE_FILE_SOURCE.search(line)
        net_src = _RE_NETWORK_SOURCE.search(line)

        if src_match or net_src:
            src_cat = (
                "cred"
                if (_RE_CRED_SOURCE.search(line))
                else ("file" if (_RE_FILE_SOURCE.search(line)) else "network")
            )
            # Look ahead within window lines for a sink
            for j in range(i + 1, min(i + window + 1, len(lines))):
                if _RE_CODE_SINK.search(lines[j]):
                    evidence = f"Proximity: source at line {i + 1}, exec sink at line {j + 1}"
                    risk_id = _choose_risk_id(src_cat, "code_exec", direct=False)
                    hits.append((risk_id, i + 1, evidence))
                    break
                if _RE_NETWORK_SINK.search(lines[j]):
                    evidence = f"Proximity: source at line {i + 1}, network sink at line {j + 1}"
                    risk_id = _choose_risk_id(src_cat, "network", direct=False)
                    hits.append((risk_id, i + 1, evidence))
                    break

    return hits


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

_APPLICABLE_TYPES: list[ArtifactType] = [
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.HOOK,
    ArtifactType.PLUGIN,
    ArtifactType.MCP,
    ArtifactType.ORCHESTRATION,
]


class TaintTrackScanner(BaseScanner):
    """Data-flow taint tracking scanner.

    For Python files: uses AST to trace source→sink assignment chains.
    For other languages: uses 10-line proximity regex windows.

    Detects credential exfiltration, file-to-network leaks, and
    remote-input-to-exec chains that single-pattern regex misses.
    """

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.TAINT_TRACK

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types containing executable code."""
        return _APPLICABLE_TYPES

    @property
    def detected_risk_ids(self) -> list[str]:
        """Taint tracking risk IDs."""
        return ["TT-S1", "TT-S2", "TT-S3", "TT-S4", "TT-S5"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan artifact for taint-flow vulnerabilities.

        Args:
            artifact_content: Full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects for detected taint flows.
        """
        suffix = Path(artifact_path).suffix.lower()
        raw_hits: list[tuple[str, int, str]]

        if suffix == ".py":
            raw_hits = _analyze_python_ast(artifact_content, artifact_path)
        else:
            raw_hits = _analyze_proximity(artifact_content.splitlines())

        if not raw_hits:
            return []

        from datetime import datetime, timezone

        findings: list[ScanFinding] = []
        seen: set[tuple[str, int]] = set()

        for risk_id, line_num, evidence in raw_hits:
            key = (risk_id, line_num)
            if key in seen:
                continue
            seen.add(key)

            meta = _RISK_META[risk_id]
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
                    location=FindingLocation(line=line_num),
                    evidence=evidence,
                    confidence=0.80,
                    scanner_module=ScannerModule.TAINT_TRACK,
                    remediation=str(meta["remediation"]),
                    references=["CWE-829", "CWE-78", "CWE-319"],
                    timestamp=datetime.now(tz=timezone.utc),
                )
            )

        return findings
