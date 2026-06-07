# AI Artifact Risk Validator

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A comprehensive Python package that validates AI artifacts for security, performance, quality, compliance, and operational risks before peer sharing. It implements a risk framework covering **190 risks** across **14 artifact types** and **13 scanner modules**.

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Scanner Modules](#scanner-modules)
- [Risk Framework Reference](#risk-framework-reference)
- [Contributing](#contributing)

---

## Overview

The AI Artifact Risk Validator scans directories containing AI artifacts (prompts, skills, agents, MCP server configs, steering files, hooks, plugins, and more) and produces a structured report identifying security vulnerabilities, performance concerns, quality issues, and compliance gaps.

Key features:

- **190 risk definitions** across 14 artifact types and 6 cross-cutting dimensions
- **13 scanner modules** covering secrets, injection, permissions, tokens, schema, dependencies, quality, provenance, bias, composability, portability, compliance, and code security
- **Plugin architecture** — extend with custom scanners via entry points or plugin directories
- **Parallel execution** — concurrent file and scanner processing for fast scans
- **Configurable gates** — BLOCK/WARN/INFO decisions with confidence-based downgrade
- **Multiple output formats** — JSON, rich terminal text, and HTML reports
- **CI/CD integration** — exit codes map to gate decisions (0=PASS, 1=BLOCK, 2=WARN)
- **False positive management** — inline suppression comments and config-based rules

---

## Installation

### Basic installation (core scanners)

```bash
pip install ai-artifact-risk-validator
```

### With optional scanner dependencies

```bash
# ML-based scanners (injection detection, bias detection)
pip install ai-artifact-risk-validator[ml]

# Secret detection (detect-secrets, presidio)
pip install ai-artifact-risk-validator[secrets]

# Security scanning (bandit, pip-audit, safety)
pip install ai-artifact-risk-validator[security]

# Provenance checking (gitpython, cryptography)
pip install ai-artifact-risk-validator[provenance]

# Quality analysis (nltk, networkx)
pip install ai-artifact-risk-validator[quality]

# All optional dependencies
pip install ai-artifact-risk-validator[all]
```

### Development installation

```bash
git clone https://github.com/ai-artifact-validator/ai-artifact-risk-validator.git
cd ai-artifact-risk-validator
pip install -e ".[dev,test]"
```

### Requirements

- Python 3.11 or 3.12
- Core dependencies: pydantic, pyyaml, jsonschema, tiktoken, click, rich, structlog

---

## Quick Start

### Python API

```python
from ai_artifact_risk_validator import Validator
from ai_artifact_risk_validator.models import ValidatorConfig

# Basic usage with defaults
validator = Validator()
report = validator.verify("path/to/artifacts")

# Print summary
print(f"Gate decision: {report.summary.gate_decision.value}")
print(f"Total findings: {report.summary.total_findings}")
print(f"Blocking: {report.summary.blocking_findings}")
print(f"Warnings: {report.summary.warning_findings}")

# Iterate over findings
for finding in report.findings:
    print(f"[{finding.severity_label.value}] {finding.id}: {finding.title}")
    print(f"  File: {finding.artifact_path}:{finding.location.line}")
    print(f"  Remediation: {finding.remediation}")
```

### With custom configuration

```python
from ai_artifact_risk_validator import Validator
from ai_artifact_risk_validator.models import ValidatorConfig, ScannerModule

config = ValidatorConfig(
    log_level="WARNING",
    enabled_scanners=[
        ScannerModule.SECRET_SCAN,
        ScannerModule.INJECTION_DET,
        ScannerModule.CODE_AUDIT,
    ],
    severity_threshold=5,  # Only report Medium and above
    file_exclude_patterns=["*.test.*", "node_modules/**"],
    parallel_files=8,
)

validator = Validator(config=config)
report = validator.verify("/my/project/ai-artifacts")

# Check if the scan should block a CI pipeline
if report.summary.gate_decision.value == "BLOCK":
    print("Blocking findings detected — review required!")
    for f in report.findings:
        if f.gate_action.value == "BLOCK":
            print(f"  BLOCK: {f.id} - {f.title} ({f.artifact_path})")
```

### CLI usage

```bash
# Scan a directory and output JSON report
ai-artifact-validator verify ./my-artifacts

# Output as formatted text
ai-artifact-validator verify ./my-artifacts --format text

# Save report to file
ai-artifact-validator verify ./my-artifacts --output report.json

# Use specific scanners only
ai-artifact-validator verify ./my-artifacts --scanners SecretScan,InjectionDet,CodeAudit

# Set severity threshold (only show Medium+ findings)
ai-artifact-validator verify ./my-artifacts --severity-threshold 5

# Use a config file
ai-artifact-validator verify ./my-artifacts --config .aav.yaml

# Ignore all suppression rules
ai-artifact-validator verify ./my-artifacts --no-ignore

# Control parallelism
ai-artifact-validator verify ./my-artifacts --parallel 8

# Output as standalone HTML report
ai-artifact-validator verify ./my-artifacts --format html

# Save HTML report to file
ai-artifact-validator verify ./my-artifacts --format html --output report.html
```

### JSON report output examples

#### Clean scan (no findings)

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "artifact_path": "./my-artifacts",
  "artifact_type": null,
  "scan_timestamp": "2025-06-05T14:30:00.000000Z",
  "scanner_version": "0.2.0",
  "findings": [],
  "summary": {
    "total_findings": 0,
    "by_severity": {},
    "by_category": {},
    "gate_decision": "INFO",
    "blocking_findings": 0,
    "warning_findings": 0,
    "info_findings": 0
  },
  "errors": []
}
```

#### Scan with findings at different severity levels

```json
{
  "scan_id": "f8e7d6c5-b4a3-2190-fedc-ba9876543210",
  "artifact_path": "./my-artifacts",
  "artifact_type": null,
  "scan_timestamp": "2025-06-05T14:32:15.123456Z",
  "scanner_version": "0.2.0",
  "findings": [
    {
      "id": "P-S1",
      "artifact_type": "prompt",
      "artifact_path": "./my-artifacts/prompts/system.prompt.md",
      "severity_score": 9,
      "severity_label": "Critical",
      "priority": "P0",
      "gate_action": "BLOCK",
      "category": "Security",
      "title": "Prompt Injection Vulnerability",
      "description": "Direct prompt injection pattern detected that could allow unauthorized instruction override.",
      "location": {
        "line": 12,
        "end_line": 14,
        "section": "system",
        "offset": null
      },
      "evidence": "ignore previous instructions and",
      "confidence": 0.95,
      "scanner_module": "InjectionDet",
      "remediation": "Remove or sanitize injection patterns. Use structured prompt templates with clear boundaries.",
      "references": ["OWASP-LLM01"],
      "false_positive": false,
      "timestamp": "2025-06-05T14:32:15.100000Z"
    },
    {
      "id": "P-P1",
      "artifact_type": "prompt",
      "artifact_path": "./my-artifacts/prompts/system.prompt.md",
      "severity_score": 6,
      "severity_label": "Medium",
      "priority": "P2",
      "gate_action": "WARN",
      "category": "Performance",
      "title": "Token Budget Exceeded",
      "description": "Prompt content exceeds recommended token budget for the target model context window.",
      "location": {
        "line": 1,
        "end_line": 250,
        "section": null,
        "offset": null
      },
      "evidence": "Token count: 8500 (budget: 4096)",
      "confidence": 0.98,
      "scanner_module": "TokenAnalyzer",
      "remediation": "Reduce prompt length or split into multiple sections. Consider using prompt compression techniques.",
      "references": [],
      "false_positive": false,
      "timestamp": "2025-06-05T14:32:15.110000Z"
    },
    {
      "id": "SK-Q1",
      "artifact_type": "skill",
      "artifact_path": "./my-artifacts/skills/data-fetch/SKILL.md",
      "severity_score": 3,
      "severity_label": "Low",
      "priority": "P4",
      "gate_action": "INFO",
      "category": "Quality",
      "title": "Missing Skill Metadata",
      "description": "Skill definition is missing recommended metadata fields for discoverability.",
      "location": {
        "line": 1,
        "end_line": 5,
        "section": "frontmatter",
        "offset": null
      },
      "evidence": "Missing fields: version, author, tags",
      "confidence": 0.92,
      "scanner_module": "QualityLint",
      "remediation": "Add version, author, and tags metadata to the skill definition frontmatter.",
      "references": [],
      "false_positive": false,
      "timestamp": "2025-06-05T14:32:15.120000Z"
    }
  ],
  "summary": {
    "total_findings": 3,
    "by_severity": {
      "Critical": 1,
      "Medium": 1,
      "Low": 1
    },
    "by_category": {
      "Security": 1,
      "Performance": 1,
      "Quality": 1
    },
    "gate_decision": "BLOCK",
    "blocking_findings": 1,
    "warning_findings": 1,
    "info_findings": 1
  },
  "errors": []
}
```

---

## Configuration

### Configuration file (`.aav.yaml`)

Create a `.aav.yaml` file in your project root:

```yaml
# Logging
log_level: INFO

# Scanner selection
enabled_scanners:
  - SecretScan
  - InjectionDet
  - PermAudit
  - TokenAnalyzer
  - SchemaValid
  - DepScan
  - QualityLint
  - CodeAudit

disabled_scanners: []

# Severity filtering
severity_threshold: 3  # Report Low and above (1-10)

# File patterns
file_include_patterns:
  - "**/*.md"
  - "**/*.yaml"
  - "**/*.json"
  - "**/*.py"
  - "**/*.ts"

file_exclude_patterns:
  - "node_modules/**"
  - ".git/**"
  - "**/*.test.*"
  - "dist/**"

# Performance
max_file_size_bytes: 10485760  # 10 MB
parallel_files: 4
parallel_scanners: 4

# Caching
cache_dir: .aav-cache

# Token budget
token_budget_limit: 8192

# Gate action overrides (risk_id -> action)
gate_overrides:
  P-P1: WARN   # Downgrade token budget from default
  SK-Q1: INFO  # Informational only

# Suppression rules
suppression_rules:
  - risk_id: P-S3
    file_pattern: "tests/**"
    reason: "Test fixtures contain intentional secrets"
  - risk_id: SK-Q1
    reason: "Accepted missing metadata for internal skills"

# Custom artifact patterns
custom_artifact_patterns:
  prompt:
    - "*.prompt.txt"
    - "prompt-templates/**"
  agent:
    - "my-agents/**/*.yaml"

# Custom plugin directories
custom_plugin_dirs:
  - ./custom-scanners

# HTML report output path (generates an HTML report as a side effect)
html_report_path: ./reports/scan-report.html
```

### Configuration precedence

Configuration is merged with the following precedence (highest to lowest):

1. **CLI arguments** (`--log-level`, `--scanners`, etc.)
2. **Environment variables** (prefix `AAV_`, e.g., `AAV_LOG_LEVEL=DEBUG`)
3. **Configuration file** (`.aav.yaml` or `--config` path)
4. **Built-in defaults**

### Environment variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AAV_LOG_LEVEL` | Logging level | `DEBUG` |
| `AAV_SEVERITY_THRESHOLD` | Minimum severity to report | `5` |
| `AAV_PARALLEL_FILES` | Parallel file workers | `8` |
| `AAV_CACHE_DIR` | Cache directory path | `.aav-cache` |
| `AAV_HTML_REPORT_PATH` | Write an HTML report to this path as a side effect (in addition to primary output) | `/tmp/report.html` |

### Inline suppression

Suppress specific findings in artifact files using comments:

```markdown
<!-- aav-ignore: P-S3 -->
This line contains an API key for testing: sk-test-1234567890
```

```python
# aav-ignore: MCP-S1
eval(user_input)  # Intentional for plugin system
```

```yaml
# aav-ignore: H-S2
api_key: ${SECRET_KEY}  # Loaded from vault at runtime
```

---

## API Reference

### `Validator` class

```python
from ai_artifact_risk_validator import Validator
```

#### Constructor

```python
Validator(config: ValidatorConfig | None = None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | `ValidatorConfig \| None` | `None` | Configuration object. Uses built-in defaults if not provided. |

#### `verify(path)` method

```python
def verify(self, path: str | Path) -> ScanReport
```

Scans the given path for AI artifact risks. Handles directories (recursive scan), single files, and non-existent paths gracefully.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `str \| Path` | Directory or file path to scan |

**Returns:** `ScanReport` — Never raises exceptions to calling code.

#### `version` property

```python
@property
def version(self) -> str
```

Returns the package version string.

### `ValidatorConfig` model

```python
from ai_artifact_risk_validator.models import ValidatorConfig
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_level` | `Literal["DEBUG","INFO","WARNING","ERROR","CRITICAL"]` | `"INFO"` | Logging verbosity |
| `enabled_scanners` | `list[ScannerModule] \| None` | `None` (all) | Scanners to enable |
| `disabled_scanners` | `list[ScannerModule]` | `[]` | Scanners to disable |
| `severity_threshold` | `int` (1-10) | `1` | Minimum severity to report |
| `file_include_patterns` | `list[str]` | `[]` | Glob patterns to include |
| `file_exclude_patterns` | `list[str]` | `[]` | Glob patterns to exclude |
| `max_file_size_bytes` | `int` | `10485760` | Max file size (10 MB) |
| `parallel_files` | `int` (1-32) | `4` | Parallel file workers |
| `parallel_scanners` | `int` (1-16) | `4` | Parallel scanners per file |
| `cache_dir` | `str \| None` | `None` | Cache directory for results |
| `suppression_rules` | `list[SuppressionRule]` | `[]` | False positive suppressions |
| `token_budget_limit` | `int \| None` | `None` | Token budget for analysis |
| `gate_overrides` | `dict[str, GateAction]` | `{}` | Override gate actions by risk ID |
| `custom_artifact_patterns` | `dict[str, list[str]]` | `{}` | Custom classification patterns |
| `custom_plugin_dirs` | `list[str]` | `[]` | Directories for custom scanners |
| `html_report_path` | `str \| None` | `None` | Path to write an HTML report as a side effect |

### `ScanReport` model

```python
from ai_artifact_risk_validator.models import ScanReport
```

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | `str` | Unique scan identifier (UUID) |
| `artifact_path` | `str` | Path that was scanned |
| `artifact_type` | `ArtifactType \| None` | Artifact type (None for directory scans) |
| `scan_timestamp` | `datetime` | When the scan was performed (ISO 8601) |
| `scanner_version` | `str` | Package version |
| `findings` | `list[ScanFinding]` | All detected risk findings |
| `summary` | `ScanSummary` | Aggregated metrics and gate decision |
| `errors` | `list[str]` | Diagnostic error messages |

### `ScanFinding` model

```python
from ai_artifact_risk_validator.models import ScanFinding
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Risk ID (e.g., `P-S1`, `MCP-S3`) |
| `artifact_type` | `ArtifactType` | Type of artifact |
| `artifact_path` | `str` | File path |
| `severity_score` | `int` (1-10) | Severity score |
| `severity_label` | `SeverityLabel` | Human-readable severity |
| `priority` | `Priority` | Implementation priority (P0-P5) |
| `gate_action` | `GateAction` | BLOCK, WARN, or INFO |
| `category` | `RiskCategory` | Risk category |
| `title` | `str` | Short description |
| `description` | `str` | Detailed description |
| `location` | `FindingLocation` | Where in the file |
| `evidence` | `str` | Triggering text/pattern |
| `confidence` | `float` (0.0-1.0) | Detection confidence |
| `scanner_module` | `ScannerModule` | Which scanner found it |
| `remediation` | `str` | How to fix |
| `references` | `list[str]` | OWASP, CWE references |
| `false_positive` | `bool` | Whether suppressed |
| `timestamp` | `datetime` | Detection timestamp |

### `ScanSummary` model

| Field | Type | Description |
|-------|------|-------------|
| `total_findings` | `int` | Total number of findings |
| `by_severity` | `dict[str, int]` | Counts by severity label |
| `by_category` | `dict[str, int]` | Counts by risk category |
| `gate_decision` | `GateAction` | Overall gate (BLOCK > WARN > INFO) |
| `blocking_findings` | `int` | Count of BLOCK findings |
| `warning_findings` | `int` | Count of WARN findings |
| `info_findings` | `int` | Count of INFO findings |

### `format_html` function

```python
from ai_artifact_risk_validator.reporting.formatters.html_formatter import format_html
```

Generates a standalone HTML report from a `ScanReport`. The output is a self-contained HTML5 document with all CSS inline — no external dependencies required.

```python
from ai_artifact_risk_validator import Validator
from ai_artifact_risk_validator.reporting.formatters.html_formatter import format_html
from pathlib import Path

validator = Validator()
report = validator.verify("path/to/artifacts")

# Generate HTML string
html = format_html(report)

# Write to file
Path("report.html").write_text(html, encoding="utf-8")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `report` | `ScanReport` | The scan report to format |

**Returns:** `str` — A complete standalone HTML document.

---

## Scanner Modules

The validator includes 13 scanner modules, each specializing in a category of risk detection:

| Scanner | Description | Optional Dependencies |
|---------|-------------|----------------------|
| **SecretScan** | Detects API keys, tokens, PII via regex and entropy analysis | `detect-secrets`, `presidio-analyzer` |
| **InjectionDet** | Identifies prompt injection and jailbreak patterns | `transformers`, `sentence-transformers` |
| **PermAudit** | Audits tool permissions, file access, and network patterns | — |
| **TokenAnalyzer** | Token counting, budget analysis, redundancy detection | — (uses `tiktoken`) |
| **SchemaValid** | YAML/JSON schema validation, OpenAPI checks | — |
| **DepScan** | Dependency vulnerability scanning | `pip-audit`, `safety` |
| **QualityLint** | Ambiguity, staleness, metadata, and quality checks | `nltk` |
| **ProvenanceChk** | Provenance metadata and integrity verification | `gitpython`, `cryptography` |
| **BiasDetector** | Gendered language, inclusive language analysis | `transformers` |
| **ComposeAnalyze** | Cross-artifact contradiction and composition analysis | `networkx`, `sentence-transformers` |
| **PortabilityChk** | Model-specific syntax and portability concerns | — |
| **ComplianceAudit** | License, data residency, and regulatory compliance | `presidio-analyzer` |
| **CodeAudit** | Dangerous function detection, AST analysis | `bandit` |

### Scanner-to-artifact-type coverage

Each scanner applies to specific artifact types. For example:

- **SecretScan** applies to all 14 artifact types
- **InjectionDet** applies to prompts, skills, agents, steering, MCP, instructions, memory, RAG, orchestration, API schemas
- **CodeAudit** applies to skills, agents, MCP, hooks, plugins

When a scanner's optional dependencies are not installed, it gracefully degrades — logging a warning and skipping execution rather than raising errors.

### Writing custom scanners

Extend the validator with custom scanners by inheriting from `BaseScanner`:

```python
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.models import (
    ArtifactType, ScanFinding, ScannerModule, FindingLocation,
    SeverityLabel, GateAction, Priority, RiskCategory,
)

class MyCustomScanner(BaseScanner):
    @property
    def name(self) -> ScannerModule:
        return ScannerModule.QUALITY_LINT  # or register a custom name

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT, ArtifactType.SKILL]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["CUSTOM-1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        findings = []
        if "TODO" in artifact_content:
            findings.append(ScanFinding(
                id="CUSTOM-1",
                artifact_type=artifact_type,
                artifact_path=artifact_path,
                severity_score=3,
                severity_label=SeverityLabel.LOW,
                priority=Priority.P4,
                gate_action=GateAction.INFO,
                category=RiskCategory.QUALITY,
                title="TODO found in artifact",
                description="Artifact contains TODO markers indicating incomplete work.",
                location=FindingLocation(line=1),
                evidence="TODO",
                confidence=0.95,
                scanner_module=self.name,
                remediation="Resolve all TODO items before sharing.",
            ))
        return findings
```

Register via entry points in `pyproject.toml`:

```toml
[project.entry-points."ai_artifact_validator.scanners"]
my_scanner = "my_package.scanners:MyCustomScanner"
```

Or load from a plugin directory:

```python
config = ValidatorConfig(custom_plugin_dirs=["./my-scanners"])
```

---

## Risk Framework Reference

### Artifact types (14)

| Type | Description |
|------|-------------|
| `prompt` | Prompt templates and system prompts |
| `skill` | AI skill definitions with invocation criteria |
| `agent` | Agent configurations with tool/capability declarations |
| `sop` | Standard operating procedures with step-based structure |
| `steering` | Priority/scope steering files (e.g., `.kiro/steering/`) |
| `mcp` | MCP server configurations and tool definitions |
| `hook` | Event-driven hook definitions |
| `instruction` | Instruction files (e.g., `copilot-instructions.md`) |
| `plugin` | Plugin manifests and extensions |
| `memory` | Memory/session storage files |
| `rag` | Knowledge base and RAG source files |
| `eval_harness` | Evaluation harness and benchmark configs |
| `orchestration` | Workflow/pipeline orchestration definitions |
| `api_schema` | OpenAPI and tool schema definitions |

### Risk categories (10)

| Category | Description |
|----------|-------------|
| Security | Authentication, injection, secrets, code execution risks |
| Performance | Token budget, latency, redundancy issues |
| Quality | Ambiguity, staleness, missing metadata, conflicts |
| Reliability | Fault tolerance, error handling, resilience |
| Compliance | License, data residency, regulatory alignment |
| Ethics | Bias, fairness, inclusive language |
| Composability | Cross-artifact conflicts, priority resolution |
| Observability | Logging, monitoring, traceability gaps |
| Governance | Provenance, versioning, ownership |
| ModelPortability | Model-specific syntax, portability concerns |

### Severity scale

| Score | Label | Gate Action | Description |
|-------|-------|-------------|-------------|
| S9-S10 | Critical | BLOCK | Immediate security threat or data exposure |
| S7-S8 | High | BLOCK | Significant risk requiring remediation |
| S5-S6 | Medium | WARN | Moderate concern requiring review |
| S3-S4 | Low | INFO | Minor issue, best practice violation |
| S1-S2 | Informational | INFO | Advisory, no action required |

### Gate decision logic

- **BLOCK** — At least one finding has severity ≥ 7 (with confidence ≥ 0.60)
- **WARN** — At least one finding has severity 5-6 (no blocking findings)
- **INFO** — All findings are severity ≤ 4 or confidence < 0.60

Findings with confidence below 0.60 are automatically downgraded to INFO regardless of severity. Findings with confidence below 0.40 are suppressed from the report (unless `DEBUG` log level is enabled).

### Risk ID format

Risk IDs follow the pattern `{PREFIX}-{CATEGORY_CODE}{NUMBER}`:

- **Prefix**: Artifact type abbreviation (P=Prompt, SK=Skill, A=Agent, SOP, ST=Steering, MCP, H=Hook, I=Instruction, PL=Plugin, M=Memory, RAG, EV=EvalHarness, OW=Orchestration, API)
- **Category code**: S=Security, P=Performance, Q=Quality, R=Reliability
- **Cross-cutting prefixes**: GOV, ETH, CMP, REG, MOD, OBS

Examples: `P-S1` (Prompt Security #1), `MCP-Q3` (MCP Quality #3), `GOV-2` (Governance #2)

---

## Contributing

### Development setup

```bash
# Clone the repository
git clone https://github.com/ai-artifact-validator/ai-artifact-risk-validator.git
cd ai-artifact-risk-validator

# Install in development mode with all extras
pip install -e ".[dev,test,all]"

# Install pre-commit hooks
pre-commit install
```

### Running tests

```bash
# Run all tests
make test

# Run with coverage
pytest --cov=src/ai_artifact_risk_validator --cov-report=term-missing

# Run specific test file
pytest tests/test_validator.py

# Run property-based tests only
pytest tests/ -k "property" -v
```

### Code quality

```bash
# Lint
make lint

# Format
make format

# Type check
make type-check

# All checks
make lint type-check test
```

### Project structure

```
src/ai_artifact_risk_validator/
├── __init__.py          # Package entry, exports Validator, __version__
├── validator.py         # Validator class (main entry point)
├── models/             # Pydantic data models and enums
├── scanners/           # BaseScanner and 13 scanner implementations
├── classifiers/        # Artifact type detection
├── risks/              # Risk registry and 190 risk definitions
├── reporting/          # Report generation, serialization, formatters
├── config/             # Configuration management
├── cli/                # Click CLI application
├── pipeline/           # File discovery, parallel execution, aggregation
└── _internal/          # Hashing, suppression, caching utilities
```

### Coding standards

- **Type annotations** on all public functions and methods
- **Pydantic models** for all data structures
- **Structured logging** via structlog (no print statements)
- **ruff** for linting and formatting
- **mypy** with strict mode for type checking
- Minimum **90% test coverage**

### Adding a new scanner

1. Create a new file in `src/ai_artifact_risk_validator/scanners/`
2. Implement the `BaseScanner` interface
3. Register in the scanner registry or via entry points
4. Add risk definitions to `src/ai_artifact_risk_validator/risks/definitions/`
5. Write unit tests covering detection logic
6. Update the scanner-to-artifact-type matrix

### Submitting changes

1. Create a feature branch from `main`
2. Make your changes with appropriate tests
3. Ensure all checks pass: `make lint type-check test`
4. Submit a pull request with a clear description

---

## License

MIT License. See [LICENSE](LICENSE) for details.
