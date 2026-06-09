"""CodeAudit scanner module for detecting code security risks in AI artifacts.

Detects dangerous function calls, subprocess usage, SSRF patterns, path traversal,
unsafe deserialization, code injection, and dynamic imports using Python AST analysis
and regex-based pattern matching for non-Python artifacts.

Uses optional `bandit` dependency for enhanced security linting when available.
"""

from __future__ import annotations

import ast
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
from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.scanners.generic_language_scanner import GenericLanguageScanner
from ai_artifact_risk_validator.scanners.java_analyzer import JavaAnalyzer
from ai_artifact_risk_validator.scanners.language_detector import LanguageDetector
from ai_artifact_risk_validator.scanners.rust_analyzer import RustAnalyzer
from ai_artifact_risk_validator.scanners.tsjs_enhanced import TSJSEnhancedPatterns

# --- Risk metadata lookup ---
_RISK_METADATA: dict[str, dict[str, Any]] = {
    "SK-S2": {
        "title": "Unsafe Code Execution in Skill Logic",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Skill implementation uses dangerous code execution functions like eval(), exec(), or subprocess with unsanitized input.",
        "remediation": "Remove dynamic code execution. Use parameterized commands. Implement input validation.",
    },
    "MCP-S1": {
        "title": "Remote Code Execution via MCP Tool",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server exposes a tool that allows arbitrary remote code execution without sandboxing.",
        "remediation": "Sandbox all code execution. Remove arbitrary execution capabilities. Implement strict input validation.",
    },
    "MCP-S2": {
        "title": "Server-Side Request Forgery (SSRF) in MCP Tool",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP tool accepts URLs or network addresses that could be used to probe internal services.",
        "remediation": "Validate and restrict URLs. Implement URL allowlists. Block internal network ranges.",
    },
    "MCP-S8": {
        "title": "Unsafe Deserialization in MCP Transport",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP server uses unsafe deserialization that could allow code execution via crafted payloads.",
        "remediation": "Use safe deserialization methods. Validate input schemas. Avoid pickle for untrusted data.",
    },
    "MCP-S9": {
        "title": "Path Traversal in MCP File Tool",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "MCP file access tool does not properly sanitize paths, allowing directory traversal attacks.",
        "remediation": "Canonicalize all file paths. Implement path allowlists. Validate paths stay within sandbox.",
    },
    "H-S1": {
        "title": "Arbitrary Command Execution in Hook",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Hook executes arbitrary shell commands that could be exploited for code execution attacks.",
        "remediation": "Restrict allowed commands. Validate and sanitize all inputs. Use allowlisted command patterns.",
    },
    "H-S4": {
        "title": "Unsafe External Script Execution",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Hook invokes external scripts from unverified sources without integrity checking.",
        "remediation": "Verify script integrity via checksums. Use local scripts only. Implement script allowlists.",
    },
    "H-S5": {
        "title": "Privilege Escalation via Hook Actions",
        "severity_score": 7,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Hook actions execute with elevated privileges beyond what the triggering event requires.",
        "remediation": "Run hooks with minimal required privileges. Implement privilege separation. Validate permission levels.",
    },
    "PL-S1": {
        "title": "Arbitrary Code Execution in Plugin",
        "severity_score": 10,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin executes arbitrary code without sandboxing, enabling full system compromise.",
        "remediation": "Sandbox plugin execution. Remove arbitrary code execution. Implement strict input validation.",
    },
    "PL-S4": {
        "title": "Insecure Data Storage in Plugin",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.SECURITY,
        "description": "Plugin stores sensitive data without encryption or proper access controls.",
        "remediation": "Encrypt sensitive data at rest. Use secure credential storage. Implement proper access controls.",
    },
    "PL-S5": {
        "title": "Network Exfiltration Risk in Plugin",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Plugin makes network requests that could exfiltrate workspace data to external servers.",
        "remediation": "Audit all network requests. Implement data egress controls. Require user consent for data transmission.",
    },
    "PL-S9": {
        "title": "Insecure Plugin Communication",
        "severity_score": 6,
        "severity_label": SeverityLabel.MEDIUM,
        "priority": Priority.P2,
        "gate_action": GateAction.WARN,
        "category": RiskCategory.SECURITY,
        "description": "Plugin communicates with external services over insecure channels.",
        "remediation": "Use HTTPS for all communications. Implement TLS for all connections. Validate server certificates.",
    },
    "A-S3": {
        "title": "Unsafe Code Execution Capability",
        "severity_score": 9,
        "severity_label": SeverityLabel.CRITICAL,
        "priority": Priority.P0,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Agent has capability to execute arbitrary code without sandboxing or safety controls.",
        "remediation": "Sandbox code execution. Implement allowlisted commands. Add output filtering.",
    },
    "A-S7": {
        "title": "Dangerous Tool Combination",
        "severity_score": 8,
        "severity_label": SeverityLabel.HIGH,
        "priority": Priority.P1,
        "gate_action": GateAction.BLOCK,
        "category": RiskCategory.SECURITY,
        "description": "Agent has access to a combination of tools that together enable dangerous operations not intended individually.",
        "remediation": "Audit tool combinations for emergent risks. Implement tool interaction policies. Restrict dangerous combinations.",
    },
}

# --- Artifact type to risk ID mappings ---

# Dangerous function (eval/exec/compile/__import__) risk mapping
_DANGEROUS_FUNC_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S1",
    ArtifactType.HOOK: "H-S1",
    ArtifactType.PLUGIN: "PL-S1",
    ArtifactType.AGENT: "A-S3",
}

# Subprocess/command execution risk mapping
_SUBPROCESS_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S1",
    ArtifactType.HOOK: "H-S1",
    ArtifactType.PLUGIN: "PL-S1",
    ArtifactType.AGENT: "A-S3",
}

# SSRF risk mapping
_SSRF_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S2",
    ArtifactType.HOOK: "H-S4",
    ArtifactType.PLUGIN: "PL-S5",
    ArtifactType.AGENT: "A-S7",
}

# Path traversal risk mapping
_PATH_TRAVERSAL_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S9",
    ArtifactType.HOOK: "H-S5",
    ArtifactType.PLUGIN: "PL-S4",
    ArtifactType.AGENT: "A-S7",
}

# Deserialization risk mapping
_DESERIALIZATION_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S8",
    ArtifactType.HOOK: "H-S4",
    ArtifactType.PLUGIN: "PL-S1",
    ArtifactType.AGENT: "A-S3",
}

# Code injection (f-strings in SQL, shell formatting) risk mapping
_CODE_INJECTION_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S1",
    ArtifactType.HOOK: "H-S1",
    ArtifactType.PLUGIN: "PL-S1",
    ArtifactType.AGENT: "A-S3",
}

# Dynamic imports risk mapping
_DYNAMIC_IMPORT_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S1",
    ArtifactType.HOOK: "H-S4",
    ArtifactType.PLUGIN: "PL-S1",
    ArtifactType.AGENT: "A-S3",
}

# External script execution risk mapping
_EXTERNAL_SCRIPT_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S1",
    ArtifactType.HOOK: "H-S4",
    ArtifactType.PLUGIN: "PL-S5",
    ArtifactType.AGENT: "A-S7",
}

# Insecure communication risk mapping
_INSECURE_COMM_RISK_MAP: dict[ArtifactType, str] = {
    ArtifactType.SKILL: "SK-S2",
    ArtifactType.MCP: "MCP-S2",
    ArtifactType.HOOK: "H-S5",
    ArtifactType.PLUGIN: "PL-S9",
    ArtifactType.AGENT: "A-S7",
}

# --- Dangerous function names ---
_DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__"}

# Dangerous module.function patterns for subprocess/os calls
_DANGEROUS_SUBPROCESS_CALLS: set[tuple[str, str]] = {
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "exec"),
    ("os", "execl"),
    ("os", "execle"),
    ("os", "execlp"),
    ("os", "execlpe"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "execvpe"),
    ("os", "spawn"),
    ("os", "spawnl"),
    ("os", "spawnle"),
}

# Unsafe deserialization functions
_UNSAFE_DESERIALIZATION: set[tuple[str, str]] = {
    ("pickle", "loads"),
    ("pickle", "load"),
    ("pickle", "Unpickler"),
    ("cPickle", "loads"),
    ("cPickle", "load"),
    ("marshal", "loads"),
    ("marshal", "load"),
    ("shelve", "open"),
}

# yaml.load without Loader is unsafe
_YAML_UNSAFE_LOAD = ("yaml", "load")

# --- Regex patterns for non-Python (regex-based) detection ---

# Dangerous function call patterns (generic)
_RE_DANGEROUS_FUNCS = re.compile(r"\b(eval|exec|compile|__import__)\s*\(", re.IGNORECASE)

# Subprocess / shell command patterns
_RE_SUBPROCESS = re.compile(
    r"\b(subprocess\.(call|Popen|run|check_output|check_call)"
    r"|os\.(system|popen|exec\w*|spawn\w*))\s*\(",
    re.IGNORECASE,
)

# SSRF patterns: unvalidated URL construction with variables
_RE_SSRF_PATTERNS = re.compile(
    r"(requests\.(get|post|put|delete|patch|head)\s*\(\s*(f['\"]|[a-zA-Z_]\w*\s*[\+\.])"
    r"|urllib\.request\.urlopen\s*\(\s*(f['\"]|[a-zA-Z_]\w*)"
    r"|fetch\s*\(\s*(f['\"]|[a-zA-Z_]\w*\s*[\+\.]|`\$\{)"
    r"|httpx\.\w+\s*\(\s*(f['\"]|[a-zA-Z_]\w*\s*[\+\.])"
    r"|aiohttp\.ClientSession\(\)\.(?:get|post)\s*\(\s*(f['\"]|[a-zA-Z_]\w*\s*[\+\.]))",
)

# Path traversal patterns
_RE_PATH_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|os\.path\.join\s*\(\s*[^)]*\b(user|input|param|arg|request)"
    r"|Path\s*\(\s*[^)]*\b(user|input|param|arg|request)"
    r"|open\s*\(\s*(f['\"]|[a-zA-Z_]\w*\s*[\+\.]))",
)

# Unsafe deserialization patterns
_RE_DESERIALIZATION = re.compile(
    r"\b(pickle\.(loads?|Unpickler)|cPickle\.(loads?)"
    r"|marshal\.(loads?)|shelve\.open"
    r"|yaml\.load\s*\([^)]*(?!Loader|SafeLoader|FullLoader))"
    r"\s*\(",
    re.IGNORECASE,
)

# Code injection: f-strings in SQL or shell commands
_RE_CODE_INJECTION = re.compile(
    r"(f['\"].*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s"
    r"|f['\"].*?(sh|bash|cmd|powershell)\s"
    r"|\.format\s*\([^)]*\).*?(SELECT|INSERT|UPDATE|DELETE|DROP)"
    r"|%\s*\([^)]*\).*?(SELECT|INSERT|UPDATE|DELETE|DROP))",
    re.IGNORECASE,
)

# Dynamic import patterns
_RE_DYNAMIC_IMPORTS = re.compile(
    r"\b(importlib\.import_module\s*\(\s*(f['\"]|[a-zA-Z_]\w*)"
    r"|__import__\s*\(\s*(f['\"]|[a-zA-Z_]\w*))",
)

# Insecure HTTP patterns
_RE_INSECURE_HTTP = re.compile(r"(http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s'\"]+)")

# Privilege escalation patterns
_RE_PRIVILEGE_ESCALATION = re.compile(
    r"\b(sudo|runas|chmod\s+[0-7]*7[0-7]*|setuid|setgid|os\.setuid|os\.setgid"
    r"|ctypes\.windll|win32api\.AdjustTokenPrivileges)\b",
    re.IGNORECASE,
)


class _ASTDangerousCallVisitor(ast.NodeVisitor):
    """AST visitor that detects dangerous function calls in Python source."""

    def __init__(self) -> None:
        """Initialize the visitor with empty findings lists."""
        self.dangerous_calls: list[tuple[int, str, str]] = []  # (line, func_name, category)
        self.subprocess_calls: list[tuple[int, str, str]] = []
        self.ssrf_patterns: list[tuple[int, str, str]] = []
        self.path_traversal: list[tuple[int, str, str]] = []
        self.deserialization: list[tuple[int, str, str]] = []
        self.code_injection: list[tuple[int, str, str]] = []
        self.dynamic_imports: list[tuple[int, str, str]] = []
        self.privilege_escalation: list[tuple[int, str, str]] = []
        self.insecure_comms: list[tuple[int, str, str]] = []
        self._imports: dict[str, str] = {}  # alias -> module name

    def visit_Import(self, node: ast.Import) -> None:
        """Track imports for module resolution."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self._imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-imports for module resolution."""
        module = node.module or ""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self._imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for dangerous patterns."""
        self._check_dangerous_builtins(node)
        self._check_subprocess_calls(node)
        self._check_ssrf_patterns(node)
        self._check_deserialization(node)
        self._check_dynamic_imports(node)
        self._check_code_injection(node)
        self._check_path_traversal(node)
        self._check_privilege_escalation(node)
        self._check_insecure_comms(node)
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> tuple[str | None, str | None]:
        """Extract module and function name from a call node.

        Returns:
            Tuple of (module_name, function_name) or (None, function_name) for builtins.
        """
        if isinstance(node.func, ast.Name):
            return None, node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                # Resolve import aliases
                resolved = self._imports.get(module, module)
                return resolved, node.func.attr
            if isinstance(node.func.value, ast.Attribute):
                # Handle chained attributes like urllib.request.urlopen
                if isinstance(node.func.value.value, ast.Name):
                    module = f"{node.func.value.value.id}.{node.func.value.attr}"
                    return module, node.func.attr
        return None, None

    def _check_dangerous_builtins(self, node: ast.Call) -> None:
        """Check for dangerous built-in function calls."""
        _, func_name = self._get_call_name(node)
        if func_name in _DANGEROUS_BUILTINS:
            self.dangerous_calls.append(
                (node.lineno, func_name, f"Dangerous function call: {func_name}()")
            )

    def _check_subprocess_calls(self, node: ast.Call) -> None:
        """Check for subprocess and os command execution calls."""
        module, func_name = self._get_call_name(node)
        if module and func_name:
            # Normalize module name for alias resolution
            base_module = module.split(".")[-1] if "." in module else module
            for target_mod, target_func in _DANGEROUS_SUBPROCESS_CALLS:
                if (base_module == target_mod or module == target_mod) and func_name == target_func:
                    # Check for shell=True which is even more dangerous
                    has_shell_true = any(
                        isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                        and kw.arg == "shell"
                        for kw in node.keywords
                    )
                    detail = f"{module}.{func_name}()"
                    if has_shell_true:
                        detail += " with shell=True"
                    self.subprocess_calls.append(
                        (node.lineno, detail, f"Command execution: {detail}")
                    )
                    return

    def _check_ssrf_patterns(self, node: ast.Call) -> None:
        """Check for potential SSRF patterns (requests to dynamic URLs)."""
        module, func_name = self._get_call_name(node)
        if module and func_name:
            # Check for requests.get/post/etc with variable URL
            http_modules = {"requests", "httpx", "urllib.request", "aiohttp"}
            http_methods = {"get", "post", "put", "delete", "patch", "head", "urlopen", "request"}
            base_module = module.split(".")[-1] if "." in module else module

            if (
                base_module in http_modules or module in http_modules
            ) and func_name in http_methods:
                # Check if the first argument is a variable (not a string literal)
                if node.args and not isinstance(node.args[0], ast.Constant):
                    url_source = ast.dump(node.args[0])[:50]
                    self.ssrf_patterns.append(
                        (
                            node.lineno,
                            f"{module}.{func_name}({url_source})",
                            f"Potential SSRF: {module}.{func_name}() with dynamic URL",
                        )
                    )

    def _check_deserialization(self, node: ast.Call) -> None:
        """Check for unsafe deserialization function calls."""
        module, func_name = self._get_call_name(node)
        if module and func_name:
            base_module = module.split(".")[-1] if "." in module else module
            for target_mod, target_func in _UNSAFE_DESERIALIZATION:
                if (base_module == target_mod or module == target_mod) and func_name == target_func:
                    self.deserialization.append(
                        (
                            node.lineno,
                            f"{module}.{func_name}()",
                            f"Unsafe deserialization: {module}.{func_name}()",
                        )
                    )
                    return

            # Special case: yaml.load without safe Loader
            if (base_module == "yaml" or module == "yaml") and func_name == "load":
                has_safe_loader = any(
                    (
                        kw.arg == "Loader"
                        and isinstance(kw.value, ast.Attribute)
                        and kw.value.attr in ("SafeLoader", "FullLoader", "BaseLoader")
                    )
                    or (
                        kw.arg == "Loader"
                        and isinstance(kw.value, ast.Name)
                        and kw.value.id in ("SafeLoader", "FullLoader", "BaseLoader")
                    )
                    for kw in node.keywords
                )
                if not has_safe_loader:
                    # Check positional arg for Loader
                    if len(node.args) < 2:
                        self.deserialization.append(
                            (
                                node.lineno,
                                "yaml.load() without SafeLoader",
                                "Unsafe deserialization: yaml.load() without explicit Loader",
                            )
                        )

    def _check_dynamic_imports(self, node: ast.Call) -> None:
        """Check for dynamic imports with user-controlled inputs."""
        module, func_name = self._get_call_name(node)
        if module and func_name:
            base_module = module.split(".")[-1] if "." in module else module
            if base_module == "importlib" and func_name == "import_module":
                # Flag if the argument is not a string literal
                if node.args and not isinstance(node.args[0], ast.Constant):
                    self.dynamic_imports.append(
                        (
                            node.lineno,
                            "importlib.import_module() with dynamic input",
                            "Dynamic import with user-controlled module name",
                        )
                    )

        # __import__ with variable
        _, builtin_name = self._get_call_name(node)
        if builtin_name == "__import__" and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self.dynamic_imports.append(
                    (
                        node.lineno,
                        "__import__() with dynamic input",
                        "Dynamic import with user-controlled module name",
                    )
                )

    def _check_code_injection(self, node: ast.Call) -> None:
        """Check for code injection via string formatting in SQL/shell."""
        # Check for cursor.execute() with format string
        module, func_name = self._get_call_name(node)
        if func_name == "execute" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                # f-string in SQL execute
                self.code_injection.append(
                    (
                        node.lineno,
                        "SQL query with f-string",
                        "Potential SQL injection: f-string used in query execution",
                    )
                )
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                # % formatting in SQL
                self.code_injection.append(
                    (
                        node.lineno,
                        "SQL query with % formatting",
                        "Potential SQL injection: %-formatting used in query execution",
                    )
                )
            elif isinstance(first_arg, ast.Call):
                # .format() in SQL
                if isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    self.code_injection.append(
                        (
                            node.lineno,
                            "SQL query with .format()",
                            "Potential SQL injection: .format() used in query execution",
                        )
                    )

    def _check_path_traversal(self, node: ast.Call) -> None:
        """Check for path traversal patterns."""
        module, func_name = self._get_call_name(node)
        if module and func_name:
            base_module = module.split(".")[-1] if "." in module else module
            # os.path.join with a variable that might be user input
            if base_module == "path" and func_name == "join":
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id.lower() in (
                        "user_input",
                        "input",
                        "param",
                        "filename",
                        "filepath",
                        "path",
                        "user_path",
                        "file_path",
                        "request_path",
                    ):
                        self.path_traversal.append(
                            (
                                node.lineno,
                                f"os.path.join() with {arg.id}",
                                f"Potential path traversal: os.path.join() with user-controlled '{arg.id}'",
                            )
                        )
                        break

            # open() with variable path (heuristic)
            if func_name == "open" and module is None:
                pass  # too noisy without context

    def _check_privilege_escalation(self, node: ast.Call) -> None:
        """Check for privilege escalation patterns."""
        module, func_name = self._get_call_name(node)
        if module and func_name:
            base_module = module.split(".")[-1] if "." in module else module
            if base_module == "os" and func_name in ("setuid", "setgid", "seteuid", "setegid"):
                self.privilege_escalation.append(
                    (node.lineno, f"os.{func_name}()", f"Privilege escalation: os.{func_name}()")
                )

    def _check_insecure_comms(self, node: ast.Call) -> None:
        """Check for insecure HTTP communication patterns."""
        module, func_name = self._get_call_name(node)
        if module and func_name:
            http_methods = {"get", "post", "put", "delete", "patch", "head"}
            base_module = module.split(".")[-1] if "." in module else module
            if base_module in ("requests", "httpx") and func_name in http_methods:
                # Check if URL starts with http://
                if node.args and isinstance(node.args[0], ast.Constant):
                    url = str(node.args[0].value)
                    if url.startswith("http://") and not any(
                        local in url for local in ("localhost", "127.0.0.1", "0.0.0.0")
                    ):
                        self.insecure_comms.append(
                            (
                                node.lineno,
                                f"HTTP request to {url[:50]}",
                                "Insecure communication: HTTP used instead of HTTPS",
                            )
                        )


def _is_python_content(content: str, artifact_path: str) -> bool:
    """Determine if content is Python source code.

    Args:
        content: File content.
        artifact_path: File path.

    Returns:
        True if content appears to be Python.
    """
    if artifact_path.lower().endswith(".py"):
        return True
    # Try to detect Python via content heuristics
    python_indicators = [
        "import ",
        "from ",
        "def ",
        "class ",
        "if __name__",
    ]
    indicator_count = sum(1 for ind in python_indicators if ind in content[:500])
    return indicator_count >= 2


class CodeAuditScanner(BaseScanner):
    """Scanner for detecting code security risks in AI artifacts.

    Analyzes Python source code using AST-based analysis and applies regex-based
    pattern matching for non-Python artifacts. Detects:

    - Dangerous function calls: eval(), exec(), compile(), __import__()
    - Subprocess usage: subprocess.call, subprocess.Popen, os.system, os.popen
    - SSRF patterns: unvalidated URL construction, requests to user-supplied URLs
    - Path traversal: os.path.join with user input, unvalidated file paths
    - Deserialization: pickle.loads, yaml.load (without safe_load), marshal.loads
    - Code injection: f-strings in SQL queries, string formatting in shell commands
    - Dynamic imports: importlib usage with user-controlled inputs

    Optional integration with `bandit` for enhanced security linting.
    """

    def __init__(self) -> None:
        """Initialize the CodeAudit scanner with lazy-loaded optional deps."""
        self._bandit: Any | None = None
        self._bandit_loaded = False
        self._language_detector = LanguageDetector()
        self._ts_js_patterns = TSJSEnhancedPatterns()
        self._rust_analyzer = RustAnalyzer()
        self._java_analyzer = JavaAnalyzer()
        self._generic_scanner = GenericLanguageScanner()

    @property
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        return ScannerModule.CODE_AUDIT

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        return [
            ArtifactType.SKILL,
            ArtifactType.AGENT,
            ArtifactType.MCP,
            ArtifactType.HOOK,
            ArtifactType.PLUGIN,
        ]

    @property
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner detects."""
        return [
            "SK-S2",
            "MCP-S1",
            "MCP-S2",
            "MCP-S8",
            "MCP-S9",
            "H-S1",
            "H-S4",
            "H-S5",
            "PL-S1",
            "PL-S4",
            "PL-S5",
            "PL-S9",
            "A-S3",
            "A-S7",
        ]

    def is_available(self) -> bool:
        """Always available - uses AST + regex fallback without optional deps."""
        return True

    def _load_bandit(self) -> Any | None:
        """Lazily load the bandit library.

        Returns:
            The bandit module or None if not installed.
        """
        if not self._bandit_loaded:
            self._bandit_loaded = True
            try:
                import bandit

                self._bandit = bandit
            except ImportError:
                self._bandit = None
        return self._bandit

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
            evidence=evidence[:200] if len(evidence) > 200 else evidence,
            confidence=confidence,
            scanner_module=ScannerModule.CODE_AUDIT,
            remediation=metadata["remediation"],
            references=[],
        )

    def _scan_python_ast(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Perform AST-based analysis on Python source code.

        Args:
            content: Python source code.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from AST analysis.
        """
        findings: list[ScanFinding] = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            # If we can't parse, fall through to regex-based detection
            return findings

        visitor = _ASTDangerousCallVisitor()
        visitor.visit(tree)

        # Process dangerous function calls
        for line, func_name, detail in visitor.dangerous_calls:
            risk_id = _DANGEROUS_FUNC_RISK_MAP.get(artifact_type, "SK-S2")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.90,
                    line=line,
                    detail=detail,
                )
            )

        # Process subprocess calls
        for line, func_name, detail in visitor.subprocess_calls:
            risk_id = _SUBPROCESS_RISK_MAP.get(artifact_type, "SK-S2")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.88,
                    line=line,
                    detail=detail,
                )
            )

        # Process SSRF patterns
        for line, func_name, detail in visitor.ssrf_patterns:
            risk_id = _SSRF_RISK_MAP.get(artifact_type, "MCP-S2")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.82,
                    line=line,
                    detail=detail,
                )
            )

        # Process path traversal
        for line, func_name, detail in visitor.path_traversal:
            risk_id = _PATH_TRAVERSAL_RISK_MAP.get(artifact_type, "MCP-S9")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.80,
                    line=line,
                    detail=detail,
                )
            )

        # Process deserialization
        for line, func_name, detail in visitor.deserialization:
            risk_id = _DESERIALIZATION_RISK_MAP.get(artifact_type, "MCP-S8")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.90,
                    line=line,
                    detail=detail,
                )
            )

        # Process code injection
        for line, func_name, detail in visitor.code_injection:
            risk_id = _CODE_INJECTION_RISK_MAP.get(artifact_type, "MCP-S1")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.85,
                    line=line,
                    detail=detail,
                )
            )

        # Process dynamic imports
        for line, func_name, detail in visitor.dynamic_imports:
            risk_id = _DYNAMIC_IMPORT_RISK_MAP.get(artifact_type, "MCP-S1")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.80,
                    line=line,
                    detail=detail,
                )
            )

        # Process privilege escalation
        for line, func_name, detail in visitor.privilege_escalation:
            risk_id = _PATH_TRAVERSAL_RISK_MAP.get(artifact_type, "H-S5")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.85,
                    line=line,
                    detail=detail,
                )
            )

        # Process insecure communications
        for line, func_name, detail in visitor.insecure_comms:
            risk_id = _INSECURE_COMM_RISK_MAP.get(artifact_type, "PL-S9")
            findings.append(
                self._create_finding(
                    risk_id=risk_id,
                    artifact_type=artifact_type,
                    artifact_path=artifact_path,
                    evidence=func_name,
                    confidence=0.85,
                    line=line,
                    detail=detail,
                )
            )

        return findings

    def _scan_regex(
        self,
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Perform regex-based analysis on non-Python content.

        Used as fallback for non-Python artifacts or when AST parsing fails.

        Args:
            content: File content to scan.
            artifact_type: Type of artifact.
            artifact_path: Path to the artifact.

        Returns:
            List of findings from regex analysis.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # Dangerous function calls
            for match in _RE_DANGEROUS_FUNCS.finditer(line):
                risk_id = _DANGEROUS_FUNC_RISK_MAP.get(artifact_type, "SK-S2")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip(),
                        confidence=0.85,
                        line=line_num,
                        detail=f"Dangerous function detected: {match.group(1)}()",
                    )
                )

            # Subprocess/os command execution
            for match in _RE_SUBPROCESS.finditer(line):
                risk_id = _SUBPROCESS_RISK_MAP.get(artifact_type, "SK-S2")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip(),
                        confidence=0.85,
                        line=line_num,
                        detail=f"Command execution detected: {match.group(0).strip()}",
                    )
                )

            # SSRF patterns
            for match in _RE_SSRF_PATTERNS.finditer(line):
                risk_id = _SSRF_RISK_MAP.get(artifact_type, "MCP-S2")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip()[:100],
                        confidence=0.80,
                        line=line_num,
                        detail="Potential SSRF: HTTP request with dynamic URL",
                    )
                )

            # Unsafe deserialization
            for match in _RE_DESERIALIZATION.finditer(line):
                risk_id = _DESERIALIZATION_RISK_MAP.get(artifact_type, "MCP-S8")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip(),
                        confidence=0.85,
                        line=line_num,
                        detail=f"Unsafe deserialization: {match.group(0).strip()}",
                    )
                )

            # Path traversal
            for match in _RE_PATH_TRAVERSAL.finditer(line):
                risk_id = _PATH_TRAVERSAL_RISK_MAP.get(artifact_type, "MCP-S9")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip()[:100],
                        confidence=0.80,
                        line=line_num,
                        detail="Potential path traversal vulnerability",
                    )
                )

            # Code injection
            for match in _RE_CODE_INJECTION.finditer(line):
                risk_id = _CODE_INJECTION_RISK_MAP.get(artifact_type, "MCP-S1")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip()[:100],
                        confidence=0.82,
                        line=line_num,
                        detail="Potential code injection via string formatting",
                    )
                )

            # Dynamic imports
            for match in _RE_DYNAMIC_IMPORTS.finditer(line):
                risk_id = _DYNAMIC_IMPORT_RISK_MAP.get(artifact_type, "MCP-S1")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip()[:100],
                        confidence=0.80,
                        line=line_num,
                        detail="Dynamic import with potentially user-controlled input",
                    )
                )

            # Insecure HTTP
            for match in _RE_INSECURE_HTTP.finditer(line):
                risk_id = _INSECURE_COMM_RISK_MAP.get(artifact_type, "PL-S9")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip()[:100],
                        confidence=0.80,
                        line=line_num,
                        detail="Insecure HTTP communication detected",
                    )
                )

            # Privilege escalation
            for match in _RE_PRIVILEGE_ESCALATION.finditer(line):
                risk_id = _PATH_TRAVERSAL_RISK_MAP.get(artifact_type, "H-S5")
                findings.append(
                    self._create_finding(
                        risk_id=risk_id,
                        artifact_type=artifact_type,
                        artifact_path=artifact_path,
                        evidence=match.group(0).strip(),
                        confidence=0.82,
                        line=line_num,
                        detail=f"Privilege escalation: {match.group(0).strip()}",
                    )
                )

        return findings

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for code security risks.

        Uses LanguageDetector to determine the file's programming language and
        routes to the appropriate analyzer. Python files use AST analysis,
        TypeScript/JavaScript get both enhanced patterns and regex, Rust/Java/Kotlin
        use dedicated analyzers, and other supported languages use the generic scanner.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        findings: list[ScanFinding] = []

        if not artifact_content.strip():
            return findings

        language = self._language_detector.detect(artifact_path, artifact_content)

        match language:
            case DetectedLanguage.PYTHON:
                ast_findings = self._scan_python_ast(artifact_content, artifact_type, artifact_path)
                findings.extend(ast_findings)
                if not ast_findings:
                    findings.extend(
                        self._scan_regex(artifact_content, artifact_type, artifact_path)
                    )
            case DetectedLanguage.TYPESCRIPT | DetectedLanguage.JAVASCRIPT:
                findings.extend(
                    self._ts_js_patterns.scan(artifact_content, artifact_type, artifact_path)
                )
                findings.extend(self._scan_regex(artifact_content, artifact_type, artifact_path))
            case DetectedLanguage.RUST:
                findings.extend(
                    self._rust_analyzer.scan(artifact_content, artifact_type, artifact_path)
                )
            case DetectedLanguage.JAVA | DetectedLanguage.KOTLIN:
                findings.extend(
                    self._java_analyzer.scan(artifact_content, artifact_type, artifact_path)
                )
            case (
                DetectedLanguage.GO
                | DetectedLanguage.RUBY
                | DetectedLanguage.CSHARP
                | DetectedLanguage.PHP
            ):
                findings.extend(
                    self._generic_scanner.scan(
                        artifact_content, language, artifact_type, artifact_path
                    )
                )
            case _:
                # UNKNOWN language: apply regex patterns with confidence forced to 0.60
                regex_findings = self._scan_regex(artifact_content, artifact_type, artifact_path)
                for f in regex_findings:
                    f.confidence = 0.60
                findings.extend(regex_findings)

        return findings
