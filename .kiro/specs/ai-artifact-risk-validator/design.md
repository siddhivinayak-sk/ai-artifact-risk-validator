# Design Document: AI Artifact Risk Validator

## Overview

The AI Artifact Risk Validator (`ai-artifact-risk-validator`) is a Python package that validates AI artifacts for security, performance, quality, compliance, and operational risks before peer sharing. It implements a comprehensive risk framework covering 190 risks (163 artifact-specific + 27 cross-cutting) across 14 artifact types, 6 cross-cutting dimensions, and 13 scanner modules.

The system follows a pipeline architecture: files are discovered, classified by artifact type, routed to applicable scanners, and findings are aggregated into a structured report with gate decisions (BLOCK/WARN/PASS). The package is distributed via Nexus, installed via pip, and exposes both a programmatic API (`Validator.verify(path)`) and a CLI (`ai-artifact-validator verify <path>`).

### Design Principles

- **Plugin-first**: All scanners are pluggable modules conforming to `BaseScanner`
- **Fail-safe**: Scanner failures are isolated; no uncaught exceptions propagate to callers
- **Lazy loading**: Heavy dependencies (ML models) load only when their scanner is invoked
- **Parallel execution**: File scanning and scanner execution leverage `concurrent.futures`
- **Configuration cascade**: CLI args > environment variables > config file > built-in defaults

---

## Architecture

### High-Level Component Diagram

```mermaid
graph TD
    subgraph "User Interface Layer"
        CLI[CLI - click/rich]
        API[Python API - Validator class]
    end

    subgraph "Core Engine"
        VE[Validator Engine]
        CM[Configuration Manager]
        AC[Artifact Classifier]
        SR[Scanner Registry]
        RR[Risk Registry]
        RG[Report Generator]
        GD[Gate Decision Engine]
    end

    subgraph "Scanner Modules"
        SS[SecretScan]
        ID[InjectionDet]
        PA[PermAudit]
        TA[TokenAnalyzer]
        SV[SchemaValid]
        DS[DepScan]
        QL[QualityLint]
        PC[ProvenanceChk]
        BD[BiasDetector]
        CA_S[ComposeAnalyze]
        PK[PortabilityChk]
        CO[ComplianceAudit]
        CD[CodeAudit]
    end

    CLI --> VE
    API --> VE
    VE --> CM
    VE --> AC
    VE --> SR
    VE --> RR
    VE --> RG
    VE --> GD

    SR --> SS
    SR --> ID
    SR --> PA
    SR --> TA
    SR --> SV
    SR --> DS
    SR --> QL
    SR --> PC
    SR --> BD
    SR --> CA_S
    SR --> PK
    SR --> CO
    SR --> CD
```

### Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| **Validator Engine** | Orchestrates the full scan pipeline: discovery → classification → scanning → aggregation → reporting |
| **Configuration Manager** | Loads/merges config from YAML files, env vars, CLI args; validates against schema |
| **Artifact Classifier** | Determines artifact type from file extension, path, content markers, directory context |
| **Scanner Registry** | Discovers, registers, and manages scanner module lifecycle; routes artifacts to applicable scanners |
| **Risk Registry** | Catalog of all 190 risk definitions with metadata; queryable by ID, type, category, scanner |
| **Report Generator** | Serializes ScanReport to JSON/text/HTML; deserializes JSON back to ScanReport |
| **Gate Decision Engine** | Computes per-finding gate_action and overall gate_decision from severity + confidence |
| **CLI** | Command-line interface using click with rich output formatting |

---

## Components and Interfaces

### Package Structure

```
src/
└── ai_artifact_risk_validator/
    ├── __init__.py                    # Package entry, exports Validator, __version__
    ├── py.typed                       # PEP 561 marker
    ├── validator.py                   # Validator class (main entry point)
    │
    ├── models/
    │   ├── __init__.py                # Re-exports all models
    │   ├── enums.py                   # ArtifactType, RiskCategory, SeverityLabel, GateAction, Priority, ScannerModule
    │   ├── findings.py                # FindingLocation, ScanFinding
    │   ├── report.py                  # ScanReport, ScanSummary
    │   ├── risk.py                    # RiskDefinition
    │   └── config.py                  # ValidatorConfig
    │
    ├── scanners/
    │   ├── __init__.py                # Re-exports BaseScanner
    │   ├── base.py                    # BaseScanner abstract class
    │   ├── registry.py                # ScannerRegistry
    │   ├── secret_scan.py             # SecretScan scanner
    │   ├── injection_det.py           # InjectionDet scanner
    │   ├── perm_audit.py              # PermAudit scanner
    │   ├── token_analyzer.py          # TokenAnalyzer scanner
    │   ├── schema_valid.py            # SchemaValid scanner
    │   ├── dep_scan.py                # DepScan scanner
    │   ├── quality_lint.py            # QualityLint scanner
    │   ├── provenance_chk.py          # ProvenanceChk scanner
    │   ├── bias_detector.py           # BiasDetector scanner
    │   ├── compose_analyze.py         # ComposeAnalyze scanner
    │   ├── portability_chk.py         # PortabilityChk scanner
    │   ├── compliance_audit.py        # ComplianceAudit scanner
    │   └── code_audit.py              # CodeAudit scanner
    │
    ├── classifiers/
    │   ├── __init__.py                # Re-exports ArtifactClassifier
    │   ├── classifier.py              # ArtifactClassifier class
    │   └── patterns.py                # Detection patterns per artifact type
    │
    ├── risks/
    │   ├── __init__.py                # Re-exports RiskRegistry
    │   ├── registry.py                # RiskRegistry class
    │   └── definitions/
    │       ├── __init__.py            # Risk loading utilities
    │       ├── prompts.py             # P-S1..P-Q7 risk definitions
    │       ├── skills.py              # SK-S1..SK-Q3 risk definitions
    │       ├── agents.py              # A-S1..A-R3 risk definitions
    │       ├── sops.py                # SOP-S1..SOP-Q5 risk definitions
    │       ├── steering.py            # ST-S1..ST-P3 risk definitions
    │       ├── mcp.py                 # MCP-S1..MCP-Q3 risk definitions
    │       ├── hooks.py               # H-S1..H-Q3 risk definitions
    │       ├── instructions.py        # I-S1..I-Q3 risk definitions
    │       ├── plugins.py             # PL-S1..PL-Q3 risk definitions
    │       ├── memory.py              # M-S1..M-Q1 risk definitions
    │       ├── rag.py                 # RAG-S1..RAG-Q1 risk definitions
    │       ├── eval_harness.py        # EV-S1..EV-Q2 risk definitions
    │       ├── orchestration.py       # OW-S1..OW-P2 risk definitions
    │       ├── api_schema.py          # API-S1..API-Q1 risk definitions
    │       └── cross_cutting.py       # GOV-1..OBS-4 cross-cutting definitions
    │
    ├── reporting/
    │   ├── __init__.py                # Re-exports ReportGenerator
    │   ├── generator.py               # ReportGenerator class
    │   ├── serializer.py              # JSON serialization (ScanReport → JSON string)
    │   ├── parser.py                  # JSON deserialization (JSON string → ScanReport)
    │   └── formatters/
    │       ├── __init__.py
    │       ├── json_formatter.py      # JSON output formatter
    │       ├── text_formatter.py      # Plain text / rich terminal output
    │       └── html_formatter.py      # HTML report formatter
    │
    ├── config/
    │   ├── __init__.py                # Re-exports ConfigManager
    │   ├── manager.py                 # ConfigManager (load, merge, validate)
    │   ├── schema.py                  # JSON Schema for .aav.yaml validation
    │   └── defaults.py                # Built-in default configuration values
    │
    ├── cli/
    │   ├── __init__.py
    │   ├── main.py                    # Click CLI application entry point
    │   ├── commands/
    │   │   ├── __init__.py
    │   │   ├── verify.py              # `verify` command implementation
    │   │   ├── list_risks.py          # `list-risks` command implementation
    │   │   └── init.py                # `init` command (generate .aav.yaml)
    │   └── formatters.py              # CLI-specific output formatters using rich
    │
    ├── pipeline/
    │   ├── __init__.py
    │   ├── discovery.py               # File discovery and filtering
    │   ├── executor.py                # Parallel scanner execution engine
    │   └── aggregator.py              # Finding aggregation and deduplication
    │
    └── _internal/
        ├── __init__.py
        ├── hashing.py                 # Content hashing for caching
        ├── suppression.py             # False positive / suppression logic
        └── cache.py                   # Scan result caching
```

### Validator Class (Entry Point)

```python
class Validator:
    """Main entry point for AI artifact risk validation."""

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        """Initialize the Validator with optional configuration.
        
        Args:
            config: Optional ValidatorConfig. Defaults are used if None.
        """
        ...

    def verify(self, path: str | Path) -> ScanReport:
        """Scan the given path for AI artifact risks.
        
        Args:
            path: Directory or file path to scan.
            
        Returns:
            ScanReport containing all findings and summary.
            Never raises exceptions to calling code.
        """
        ...

    @property
    def version(self) -> str:
        """Return the validator package version."""
        ...
```

### ValidatorConfig (Pydantic Model)

```python
class ValidatorConfig(BaseModel):
    """Configuration for the Validator engine."""
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    enabled_scanners: list[ScannerModule] | None = None  # None = all
    disabled_scanners: list[ScannerModule] = Field(default_factory=list)
    severity_threshold: int = Field(default=1, ge=1, le=10)  # Min severity to report
    file_include_patterns: list[str] = Field(default_factory=list)
    file_exclude_patterns: list[str] = Field(default_factory=list)
    max_file_size_bytes: int = Field(default=10_485_760)  # 10 MB
    parallel_files: int = Field(default=4, ge=1, le=32)
    parallel_scanners: int = Field(default=4, ge=1, le=16)
    cache_dir: str | None = None
    config_path: str | None = None
    custom_plugin_dirs: list[str] = Field(default_factory=list)
    suppression_rules: list[SuppressionRule] = Field(default_factory=list)
    token_budget_limit: int | None = None
    gate_overrides: dict[str, GateAction] = Field(default_factory=dict)
    custom_artifact_patterns: dict[str, list[str]] = Field(default_factory=dict)

class SuppressionRule(BaseModel):
    """Rule for suppressing specific findings."""
    risk_id: str
    file_pattern: str | None = None
    reason: str | None = None
```

### ArtifactClassifier

```python
class ArtifactClassifier:
    """Classifies files into artifact types based on multiple signals."""

    def __init__(self, custom_patterns: dict[str, list[str]] | None = None) -> None:
        ...

    def classify(self, file_path: Path, content: str | None = None) -> ClassificationResult | None:
        """Classify a file into an artifact type.
        
        Args:
            file_path: Path to the file being classified.
            content: Optional file content (read if not provided).
            
        Returns:
            ClassificationResult with artifact_type and confidence, or None.
        """
        ...

class ClassificationResult(BaseModel):
    """Result of artifact type classification."""
    artifact_type: ArtifactType
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[str]  # Which detection signals matched
```

### ScannerRegistry

```python
class ScannerRegistry:
    """Manages scanner module discovery, registration, and lifecycle."""

    def __init__(self) -> None:
        ...

    def register(self, scanner: type[BaseScanner]) -> None:
        """Register a scanner class."""
        ...

    def discover_entry_points(self) -> None:
        """Discover scanners via Python entry points."""
        ...

    def discover_plugin_dir(self, path: Path) -> None:
        """Discover scanners from a plugin directory."""
        ...

    def get_scanners_for_artifact(self, artifact_type: ArtifactType) -> list[BaseScanner]:
        """Return scanner instances applicable to the given artifact type."""
        ...

    def get_scanner_by_name(self, name: ScannerModule) -> BaseScanner | None:
        """Retrieve a specific scanner by its module name."""
        ...
```

### BaseScanner (Abstract Class)

```python
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    """Abstract base class for all scanner modules."""

    @property
    @abstractmethod
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        ...

    @property
    @abstractmethod
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        ...

    @property
    @abstractmethod
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        ...

    @abstractmethod
    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for risks.
        
        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.
            
        Returns:
            List of ScanFinding objects (may be empty).
        """
        ...

    def is_available(self) -> bool:
        """Check if required dependencies for this scanner are installed.
        
        Returns True by default. Override for scanners with optional deps.
        """
        return True
```

### ReportGenerator

```python
class ReportGenerator:
    """Generates scan reports in various formats."""

    def generate(self, findings: list[ScanFinding], scan_context: ScanContext) -> ScanReport:
        """Generate a complete ScanReport from findings and context."""
        ...

    def serialize_json(self, report: ScanReport) -> str:
        """Serialize a ScanReport to a JSON string."""
        ...

    def parse_json(self, json_str: str) -> ScanReport:
        """Parse a JSON string into a ScanReport object."""
        ...

    def format_text(self, report: ScanReport) -> str:
        """Format a report for terminal output."""
        ...

    def format_html(self, report: ScanReport) -> str:
        """Format a report as an HTML page."""
        ...
```

---

## Data Models

### Enums

```python
from enum import Enum

class ArtifactType(str, Enum):
    PROMPT = "prompt"
    SKILL = "skill"
    AGENT = "agent"
    SOP = "sop"
    STEERING = "steering"
    MCP = "mcp"
    HOOK = "hook"
    INSTRUCTION = "instruction"
    PLUGIN = "plugin"
    MEMORY = "memory"
    RAG = "rag"
    EVAL_HARNESS = "eval_harness"
    ORCHESTRATION = "orchestration"
    API_SCHEMA = "api_schema"


class RiskCategory(str, Enum):
    SECURITY = "Security"
    PERFORMANCE = "Performance"
    QUALITY = "Quality"
    RELIABILITY = "Reliability"
    COMPLIANCE = "Compliance"
    ETHICS = "Ethics"
    COMPOSABILITY = "Composability"
    OBSERVABILITY = "Observability"
    GOVERNANCE = "Governance"
    MODEL_PORTABILITY = "ModelPortability"


class SeverityLabel(str, Enum):
    CRITICAL = "Critical"       # S9-S10
    HIGH = "High"               # S7-S8
    MEDIUM = "Medium"           # S5-S6
    LOW = "Low"                 # S3-S4
    INFORMATIONAL = "Informational"  # S1-S2


class GateAction(str, Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    INFO = "INFO"


class Priority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class ScannerModule(str, Enum):
    SECRET_SCAN = "SecretScan"
    INJECTION_DET = "InjectionDet"
    PERM_AUDIT = "PermAudit"
    TOKEN_ANALYZER = "TokenAnalyzer"
    SCHEMA_VALID = "SchemaValid"
    DEP_SCAN = "DepScan"
    QUALITY_LINT = "QualityLint"
    PROVENANCE_CHK = "ProvenanceChk"
    BIAS_DETECTOR = "BiasDetector"
    COMPOSE_ANALYZE = "ComposeAnalyze"
    PORTABILITY_CHK = "PortabilityChk"
    COMPLIANCE_AUDIT = "ComplianceAudit"
    CODE_AUDIT = "CodeAudit"
```

### Finding Models

```python
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class FindingLocation(BaseModel):
    """Specifies where in a file a finding was detected."""
    line: Optional[int] = None
    end_line: Optional[int] = None
    section: Optional[str] = None
    offset: Optional[int] = None


class ScanFinding(BaseModel):
    """A single detected risk instance produced by a scanner."""
    id: str = Field(..., pattern=r"^[A-Z]+-[A-Z]?[0-9]+$", description="Risk ID (e.g. P-S1, MCP-S3)")
    artifact_type: ArtifactType
    artifact_path: str
    severity_score: int = Field(..., ge=1, le=10)
    severity_label: SeverityLabel
    priority: Priority
    gate_action: GateAction
    category: RiskCategory
    title: str
    description: str
    location: FindingLocation
    evidence: str = Field(..., description="Text/pattern that triggered the finding")
    confidence: float = Field(..., ge=0.0, le=1.0)
    scanner_module: ScannerModule
    remediation: str
    references: list[str] = Field(default_factory=list)
    false_positive: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)
```

### Report Models

```python
class ScanSummary(BaseModel):
    """Aggregated metrics for a scan report."""
    total_findings: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    gate_decision: GateAction
    blocking_findings: int
    warning_findings: int
    info_findings: int


class ScanReport(BaseModel):
    """Complete scan report for a validation run."""
    scan_id: str
    artifact_path: str
    artifact_type: Optional[ArtifactType] = None  # None for directory scans
    scan_timestamp: datetime
    scanner_version: str
    findings: list[ScanFinding]
    summary: ScanSummary
    errors: list[str] = Field(default_factory=list)  # Diagnostic messages
```

### Risk Definition Model

```python
class RiskDefinition(BaseModel):
    """Schema for a risk definition in the taxonomy."""
    id: str = Field(..., description="Unique risk ID, e.g. P-S1, MCP-S3")
    title: str
    artifact_types: list[ArtifactType]
    category: RiskCategory
    severity_score: int = Field(..., ge=1, le=10)
    severity_label: SeverityLabel
    priority: Priority
    gate_action: GateAction
    description: str
    examples: list[str] = Field(..., min_length=1)
    mitigation: list[str] = Field(..., min_length=1)
    detection_mechanisms: list[str] = Field(..., min_length=1)
    scanner_modules: list[ScannerModule] = Field(..., min_length=1)
    owasp_refs: list[str] = Field(default_factory=list)
    cwe_refs: list[str] = Field(default_factory=list)
```

---

## Scanner Module Architecture

### Scanner-to-Artifact-Type Matrix

This defines which scanners execute for each artifact type:

| Scanner | Prompt | Skill | Agent | SOP | Steering | MCP | Hook | Instruction | Plugin | Memory | RAG | Eval | Orch | API |
|---------|:------:|:-----:|:-----:|:---:|:--------:|:---:|:----:|:-----------:|:------:|:------:|:---:|:----:|:----:|:---:|
| SecretScan | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| InjectionDet | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | ✓ | ✓ | — | ✓ | ✓ |
| PermAudit | — | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| TokenAnalyzer | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ | — | ✓ | ✓ | — | — | — |
| SchemaValid | — | — | — | — | ✓ | ✓ | — | ✓ | ✓ | — | — | — | — | ✓ |
| DepScan | — | ✓ | — | — | — | ✓ | ✓ | — | ✓ | — | — | — | — | — |
| QualityLint | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ProvenanceChk | — | ✓ | ✓ | — | — | ✓ | — | — | ✓ | — | ✓ | — | — | — |
| BiasDetector | ✓ | ✓ | ✓ | — | ✓ | — | — | ✓ | — | — | ✓ | ✓ | ✓ | — |
| ComposeAnalyze | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | — | ✓ | — |
| PortabilityChk | ✓ | ✓ | ✓ | — | ✓ | — | — | ✓ | — | — | — | ✓ | — | — |
| ComplianceAudit | — | — | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | ✓ | — | — | — |
| CodeAudit | — | ✓ | ✓ | — | — | ✓ | ✓ | — | ✓ | — | — | — | — | — |

### Scanner-to-Risk ID Mapping (Complete 190 Risks)

#### SecretScan (Primary: 15 risks)
- **Prompts**: P-S3, P-S4, P-S8
- **Skills**: SK-S5
- **SOPs**: SOP-S1
- **Instructions**: I-S3
- **Memory**: M-S2, M-S3, M-S4
- **Eval Harness**: EV-S2
- **Secondary**: MCP-S3 (s), H-S2 (s), RAG-S3 (s), GOV-1 (s)

#### InjectionDet (Primary: 22 risks)
- **Prompts**: P-S1, P-S2, P-S6, P-S7, P-S9, P-S10
- **Instructions**: I-S1, I-S2
- **Steering**: ST-S1, ST-S2, ST-S5
- **MCP**: MCP-S3, MCP-S6
- **API Schema**: API-S1
- **Memory**: M-S1
- **RAG**: RAG-S1
- **Orchestration**: OW-S1
- **Agents**: A-S4, A-S5
- **Secondary**: SK-S4 (s), P-S5 (s)

#### PermAudit (Primary: 20 risks)
- **Skills**: SK-S1, SK-S3, SK-S6
- **Agents**: A-S1, A-S2, A-S6
- **Steering**: ST-S3, ST-S4
- **MCP**: MCP-S7, MCP-S10
- **Hooks**: H-S3, H-S6
- **Instructions**: I-S4, I-S5
- **API Schema**: API-S2
- **Orchestration**: OW-S2
- **Memory**: M-S5
- **Plugins**: PL-S2, PL-S6

#### TokenAnalyzer (Primary: 16 risks)
- **Prompts**: P-P1, P-P2, P-P3, P-P4, P-P5, P-P6
- **Skills**: SK-P1
- **Agents**: A-P2, A-P3, A-P4
- **Instructions**: I-P1, I-P3, I-P4
- **Memory**: M-P1
- **Composability**: CMP-3
- **MCP**: MCP-P3
- **Model Portability**: MOD-2

#### SchemaValid (Primary: 5 risks)
- **Instructions**: I-Q1
- **Steering**: ST-Q1
- **MCP**: MCP-Q1
- **API Schema**: API-Q1
- **Plugins**: PL-Q1

#### DepScan (Primary: 7 risks)
- **MCP**: MCP-S4, MCP-S11, MCP-S12
- **Plugins**: PL-S3, PL-S8
- **Skills**: SK-S7
- **Secondary**: H-S3 (s)

#### QualityLint (Primary: 38 risks)
- **Prompts**: P-Q1, P-Q2, P-Q3, P-Q4, P-Q5, P-Q6, P-Q7
- **Skills**: SK-Q1, SK-Q2, SK-Q3
- **SOPs**: SOP-Q1, SOP-Q2, SOP-Q3, SOP-Q4, SOP-Q5
- **Instructions**: I-Q2, I-Q3
- **Steering**: ST-Q2
- **MCP**: MCP-Q2, MCP-Q3
- **Hooks**: H-Q1, H-Q2, H-Q3
- **Eval Harness**: EV-Q1, EV-Q2
- **Memory**: M-Q1
- **RAG**: RAG-Q1
- **Plugins**: PL-Q2, PL-Q3
- **Governance**: GOV-3, GOV-4, GOV-5
- **Agents**: A-R1, A-R2, A-R3
- **MCP Performance**: MCP-P1, MCP-P2, MCP-P4

#### ProvenanceChk (Primary: 14 risks)
- **Skills**: SK-S7, SK-S8
- **MCP**: MCP-S4, MCP-S5
- **Plugins**: PL-S6, PL-S7
- **Agents**: A-S8, A-S9
- **Governance**: GOV-1, GOV-2
- **Regulatory**: REG-2
- **RAG**: RAG-S2
- **Secondary**: SK-S7 shared with DepScan

#### BiasDetector (Primary: 5 risks)
- **Ethics**: ETH-1, ETH-2, ETH-3, ETH-4
- **Secondary**: P-S10 (s)

#### ComposeAnalyze (Primary: 12 risks)
- **Composability**: CMP-1, CMP-2, CMP-3, CMP-4, CMP-5
- **Instructions**: I-P2
- **Steering**: ST-P2
- **Agents**: A-P5
- **Orchestration**: OW-P1, OW-P2
- **Steering Performance**: ST-P3
- **Skills Performance**: SK-P2, SK-P3, SK-P4

#### PortabilityChk (Primary: 4 risks)
- **Model Portability**: MOD-1, MOD-2, MOD-3, MOD-4

#### ComplianceAudit (Primary: 8 risks)
- **Regulatory**: REG-1, REG-2, REG-3, REG-4, REG-5
- **RAG**: RAG-S3
- **Secondary**: SOP-S3 (s), SOP-S5 (s)

#### CodeAudit (Primary: 14 risks)
- **Skills**: SK-S2
- **MCP**: MCP-S1, MCP-S2, MCP-S8
- **Hooks**: H-S1, H-S4
- **Plugins**: PL-S1, PL-S5, PL-S9
- **Agents**: A-S3, A-S7
- **Hooks additional**: H-S5
- **MCP Security**: MCP-S9
- **Plugins**: PL-S4

### Individual Scanner Designs

#### SecretScan
- **Dependencies**: `detect-secrets`, `presidio-analyzer` (optional PII)
- **Technique**: Regex patterns for API key formats, entropy analysis (Shannon entropy > 4.5), `detect-secrets` plugin pipeline, Presidio NER for PII
- **Confidence bands**: Exact regex match = 0.95–1.0, High entropy string = 0.80–0.94, Partial pattern = 0.60–0.79

#### InjectionDet
- **Dependencies**: `transformers`, `sentence-transformers` (optional ML)
- **Technique**: Regex for known injection phrases, TF-IDF cosine similarity against jailbreak corpus, zero-shot classification, unicode anomaly detection
- **Confidence bands**: Known pattern exact match = 0.95, Semantic similarity > 0.85 = 0.80–0.94, Heuristic match = 0.60–0.79
- **Fallback**: Without ML deps, uses regex-only mode (lower recall, same precision)

#### PermAudit
- **Dependencies**: `jsonschema` (core)
- **Technique**: Policy engine checking tool permissions against allowlists, file path pattern analysis, network access audit, destructive action detection
- **Confidence bands**: Policy violation = 0.95–1.0, Pattern-based detection = 0.80–0.94

#### TokenAnalyzer
- **Dependencies**: `tiktoken`, `sentence-transformers` (optional)
- **Technique**: Token counting per section via tiktoken, compression ratio analysis, sentence-level redundancy detection, caching efficiency estimation
- **Confidence bands**: Exceeds budget = 0.95–1.0, Redundancy detected = 0.80–0.94

#### SchemaValid
- **Dependencies**: `jsonschema`, `pyyaml`, `pydantic`
- **Technique**: YAML/JSON schema validation, OpenAPI spec validation, frontmatter structure checking
- **Confidence bands**: Schema violation = 0.99–1.0 (deterministic)

#### DepScan
- **Dependencies**: `pip-audit`, `safety`, `packaging`
- **Technique**: Parse lockfiles/manifests, query CVE databases, version comparison
- **Confidence bands**: Known CVE match = 0.95–1.0, Outdated version = 0.80–0.94

#### QualityLint
- **Dependencies**: `nltk` (optional)
- **Technique**: Ambiguity detection via linguistic patterns, conflict detection via NLI, staleness heuristics, metadata presence checks
- **Confidence bands**: Missing metadata = 0.95, Ambiguity detected = 0.70–0.85

#### ProvenanceChk
- **Dependencies**: `gitpython`, `cryptography`
- **Technique**: Git history analysis, signature verification, metadata extraction, integrity hash validation
- **Confidence bands**: Missing provenance = 0.95, Signature mismatch = 1.0

#### BiasDetector
- **Dependencies**: `transformers` (optional ML)
- **Technique**: Gendered language detection, name diversity analysis, inclusive language linting, fairness evaluation
- **Confidence bands**: Gendered pronoun = 0.90, Cultural bias = 0.60–0.79

#### ComposeAnalyze
- **Dependencies**: `networkx`, `sentence-transformers` (optional)
- **Technique**: Cross-artifact NLI contradiction detection, priority resolution simulation, dependency graph analysis, context budget computation
- **Confidence bands**: Direct contradiction = 0.90–0.95, Potential conflict = 0.60–0.79

#### PortabilityChk
- **Dependencies**: `tiktoken`
- **Technique**: Model-specific token/tag detection via regex, token limit analysis, capability requirement extraction
- **Confidence bands**: Model-specific syntax = 0.95–1.0, Token limit assumption = 0.80

#### ComplianceAudit
- **Dependencies**: `presidio-analyzer` (optional)
- **Technique**: License scanning, data residency flow mapping, retention policy checking, AI regulation alignment
- **Confidence bands**: License violation = 0.95, Residency concern = 0.70–0.85

#### CodeAudit
- **Dependencies**: `bandit`
- **Technique**: Python AST analysis via `ast` module, bandit security linting, pattern matching for dangerous functions (eval, exec, subprocess), SSRF detection
- **Confidence bands**: Bandit finding = 0.85–0.95, Pattern match = 0.80–0.90

---

## Artifact Classification Logic

The `ArtifactClassifier` uses a weighted signal system to determine artifact type. Each signal contributes to a confidence score for one or more artifact types.

### Detection Patterns by Artifact Type

| Artifact Type | File Extensions | Path Patterns | Content Markers | Directory Context |
|---------------|----------------|---------------|-----------------|-------------------|
| **Prompt** | `.prompt.md`, `.prompt` | `prompts/`, `prompt-templates/` | Role/system/user markers, `## System Prompt` | Parent dir named `prompts` |
| **Skill** | `.md` (with SKILL markers) | `skills/` | `SKILL.md`, invocation criteria, skill metadata YAML | `SKILL.md` in same dir |
| **Agent** | `.md`, `.yaml`, `.json` | `agents/` | `AGENT.md`, tool/capability declarations | `AGENT.md` in same dir |
| **SOP** | `.md`, `.sop.md` | `sops/`, `procedures/` | Step-based structures, `SOP` in filename, numbered steps | Parent dir named `sops` |
| **Steering** | `.md` | `.kiro/steering/` | Priority/scope declarations, `inclusion:` YAML frontmatter | Path contains `.kiro/steering` |
| **MCP** | `.json`, `.ts`, `.py` | `mcp-servers/`, `mcp/` | `mcp.json`, tool definitions, `transport` declarations | `mcp.json` in same dir |
| **Hook** | `.yaml`, `.json`, `.md` | `.hooks/`, `.kiro/hooks/` | Event/action definitions, `hook` in filename, `eventType` | Path contains `.hooks` |
| **Instruction** | `.instructions.md`, `.md` | Root or `.github/` | `copilot-instructions.md`, YAML `applyTo` frontmatter | Filename contains `instructions` |
| **Plugin** | `.json`, `.ts`, `.vsix` | `extensions/`, `plugins/` | `package.json` with plugin manifest, activation events | `contributes` in package.json |
| **Memory** | `.md`, `.json` | `.memory/`, `memory/` | Session/context storage markers, memory metadata | Path contains `.memory` |
| **RAG** | `.md`, `.txt`, `.pdf`, `.json` | `knowledge/`, `context/`, `rag/` | Embedding index files, knowledge base markers | Parent dir named `knowledge` |
| **Eval Harness** | `.yaml`, `.json`, `.py` | `evals/`, `benchmarks/` | Benchmark config, expected outputs, evaluation metrics | Parent dir named `evals` |
| **Orchestration** | `.yaml`, `.json` | `workflows/`, `pipelines/` | Pipeline/workflow definitions, step/stage declarations, DAG patterns | Parent dir named `workflows` |
| **API Schema** | `.yaml`, `.json` | `schemas/`, `api/` | `openapi.yaml`, `$schema` references, JSON Schema `type`/`properties` | OpenAPI version marker |

### Classification Algorithm

```python
def classify(self, file_path: Path, content: str | None = None) -> ClassificationResult | None:
    scores: dict[ArtifactType, float] = {}
    signals: dict[ArtifactType, list[str]] = {}

    # 1. Extension matching (weight: 0.3)
    for artifact_type, patterns in EXTENSION_PATTERNS.items():
        if any(file_path.name.endswith(ext) for ext in patterns):
            scores[artifact_type] = scores.get(artifact_type, 0) + 0.3
            signals.setdefault(artifact_type, []).append(f"extension:{file_path.suffix}")

    # 2. Path pattern matching (weight: 0.35)
    for artifact_type, path_patterns in PATH_PATTERNS.items():
        if any(pattern in str(file_path) for pattern in path_patterns):
            scores[artifact_type] = scores.get(artifact_type, 0) + 0.35
            signals.setdefault(artifact_type, []).append(f"path:{matched_pattern}")

    # 3. Content marker matching (weight: 0.25)
    if content:
        for artifact_type, markers in CONTENT_MARKERS.items():
            if any(marker in content for marker in markers):
                scores[artifact_type] = scores.get(artifact_type, 0) + 0.25
                signals.setdefault(artifact_type, []).append(f"content:{matched_marker}")

    # 4. Directory context (weight: 0.10)
    for artifact_type, dir_patterns in DIR_CONTEXT_PATTERNS.items():
        if any(pattern == file_path.parent.name for pattern in dir_patterns):
            scores[artifact_type] = scores.get(artifact_type, 0) + 0.10
            signals.setdefault(artifact_type, []).append(f"dir_context:{file_path.parent.name}")

    # Select highest-scoring type above threshold (0.3)
    if not scores:
        return None
    best_type = max(scores, key=scores.get)
    if scores[best_type] < 0.3:
        return None
    return ClassificationResult(
        artifact_type=best_type,
        confidence=min(scores[best_type], 1.0),
        signals=signals.get(best_type, []),
    )
```

---

## Scanning Pipeline

### End-to-End `verify(path)` Flow

```mermaid
sequenceDiagram
    participant User
    participant Validator
    participant ConfigMgr as Config Manager
    participant Discovery
    participant Classifier as Artifact Classifier
    participant Registry as Scanner Registry
    participant Executor as Pipeline Executor
    participant Aggregator
    participant GateEngine as Gate Decision Engine
    participant Reporter as Report Generator

    User->>Validator: verify(path)
    Validator->>ConfigMgr: load_config()
    Validator->>Discovery: discover_files(path, config)
    Discovery-->>Validator: list[Path]
    
    par For each file (parallel)
        Validator->>Classifier: classify(file_path, content)
        Classifier-->>Validator: ClassificationResult | None
        Validator->>Registry: get_scanners_for_artifact(artifact_type)
        Registry-->>Validator: list[BaseScanner]
        Validator->>Executor: execute_scanners(scanners, content, type, path)
        par For each scanner (parallel)
            Executor->>Executor: scanner.scan(content, type, path)
        end
        Executor-->>Validator: list[ScanFinding]
    end
    
    Validator->>Aggregator: aggregate(all_findings)
    Aggregator-->>Validator: deduplicated_findings
    Validator->>GateEngine: compute_gate_decision(findings, config)
    GateEngine-->>Validator: gate_decision + adjusted findings
    Validator->>Reporter: generate(findings, context)
    Reporter-->>Validator: ScanReport
    Validator-->>User: ScanReport
```

### Pipeline Stages

#### 1. File Discovery and Filtering

```python
class FileDiscovery:
    def discover(self, path: Path, config: ValidatorConfig) -> list[Path]:
        """Recursively discover files, applying include/exclude filters."""
        files = []
        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.stat().st_size > config.max_file_size_bytes:
                continue
            if self._is_excluded(file_path, config.file_exclude_patterns):
                continue
            if config.file_include_patterns and not self._is_included(file_path, config.file_include_patterns):
                continue
            files.append(file_path)
        return files
```

#### 2. Artifact Classification

For each discovered file, the `ArtifactClassifier.classify()` method determines the artifact type. Files that cannot be classified (return `None`) are skipped.

#### 3. Scanner Selection

The `ScannerRegistry` maps artifact types to applicable scanners. Only enabled and available scanners are returned:

```python
def get_scanners_for_artifact(self, artifact_type: ArtifactType) -> list[BaseScanner]:
    applicable = [
        scanner for scanner in self._scanners.values()
        if artifact_type in scanner.applicable_artifact_types
        and scanner.name not in self._disabled
        and scanner.is_available()
    ]
    return applicable
```

#### 4. Parallel Scanner Execution

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

class PipelineExecutor:
    def execute_scanners(
        self,
        scanners: list[BaseScanner],
        content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
        max_workers: int = 4,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scanner.scan, content, artifact_type, artifact_path): scanner
                for scanner in scanners
            }
            for future in as_completed(futures):
                scanner = futures[future]
                try:
                    result = future.result(timeout=30)
                    findings.extend(result)
                except Exception as e:
                    logger.error("scanner_failure", scanner=scanner.name, error=str(e))
        return findings
```

#### 5. Finding Aggregation

Deduplicates findings (same risk ID + same location), applies suppression rules, and marks false positives.

#### 6. Gate Decision Computation

```python
class GateDecisionEngine:
    def compute(self, findings: list[ScanFinding], config: ValidatorConfig) -> GateAction:
        active_findings = [f for f in findings if not f.false_positive]
        
        for finding in active_findings:
            # Low confidence downgrade
            if finding.confidence < 0.60:
                finding.gate_action = GateAction.INFO
            # Custom gate overrides
            if finding.id in config.gate_overrides:
                finding.gate_action = config.gate_overrides[finding.id]
        
        if any(f.gate_action == GateAction.BLOCK for f in active_findings):
            return GateAction.BLOCK
        elif any(f.gate_action == GateAction.WARN for f in active_findings):
            return GateAction.WARN
        else:
            return GateAction.INFO
```

#### 7. Report Generation

The `ReportGenerator` assembles the final `ScanReport` with all findings, computes the `ScanSummary`, and serializes to the requested format.

---

## Configuration System

### YAML Config Schema (`.aav.yaml`)

```yaml
# .aav.yaml - AI Artifact Validator Configuration
version: "1.0"

# Scanner control
scanners:
  enabled:
    - SecretScan
    - InjectionDet
    - PermAudit
    - TokenAnalyzer
    - SchemaValid
    - DepScan
    - QualityLint
    - ProvenanceChk
    - CodeAudit
  disabled:
    - BiasDetector  # Requires ML dependencies

# Severity and gate configuration
severity:
  threshold: 3                    # Minimum severity to report (1-10)
  gate_overrides:
    P-P5: INFO                   # Downgrade caching warning

# File filtering
files:
  include:
    - "**/*.md"
    - "**/*.yaml"
    - "**/*.json"
    - "**/*.py"
    - "**/*.ts"
  exclude:
    - "node_modules/**"
    - ".git/**"
    - "__pycache__/**"
    - "*.pyc"
  max_size_bytes: 10485760       # 10 MB

# Performance
performance:
  parallel_files: 4
  parallel_scanners: 4
  cache_dir: ".aav_cache"

# Token budgets (for TokenAnalyzer)
token_budgets:
  system_prompt: 2000
  few_shot_examples: 1500
  total_artifact: 8000

# Suppressions
suppressions:
  - risk_id: P-S3
    file_pattern: "tests/fixtures/**"
    reason: "Test fixtures intentionally contain mock secrets"
  - risk_id: P-P1
    file_pattern: "docs/**"
    reason: "Documentation prompts are verbose by design"

# Custom artifact classification
custom_patterns:
  prompt:
    - "*.prompt.txt"
    - "templates/*.md"
  instruction:
    - ".cursor/*.md"

# Plugin directories
plugins:
  directories:
    - "./custom-scanners/"
```

### Configuration Precedence

1. **CLI arguments** (highest priority)
2. **Environment variables** (`AAV_LOG_LEVEL`, `AAV_CACHE_DIR`, etc.)
3. **Config file** (`.aav.yaml` / `.aav.yml`)
4. **Built-in defaults** (lowest priority)

### Environment Variable Mapping

| Env Variable | Config Path | Example |
|-------------|-------------|---------|
| `AAV_LOG_LEVEL` | `log_level` | `AAV_LOG_LEVEL=DEBUG` |
| `AAV_CACHE_DIR` | `performance.cache_dir` | `AAV_CACHE_DIR=/tmp/.aav_cache` |
| `AAV_PARALLEL_FILES` | `performance.parallel_files` | `AAV_PARALLEL_FILES=8` |
| `AAV_SEVERITY_THRESHOLD` | `severity.threshold` | `AAV_SEVERITY_THRESHOLD=5` |
| `AAV_DISABLED_SCANNERS` | `scanners.disabled` | `AAV_DISABLED_SCANNERS=BiasDetector,ComposeAnalyze` |
| `AAV_CONFIG_PATH` | config file path | `AAV_CONFIG_PATH=./custom.aav.yaml` |

---

## Error Handling Strategy

### Exception Hierarchy

```python
class AAVError(Exception):
    """Base exception for AI Artifact Validator."""
    pass

class ConfigurationError(AAVError):
    """Invalid configuration (schema validation failure, missing required field)."""
    pass

class ClassificationError(AAVError):
    """Artifact classification failure (internal, never propagated to user)."""
    pass

class ScannerError(AAVError):
    """Scanner execution failure (caught and logged, never propagated)."""
    scanner_name: str
    artifact_path: str

class ReportSerializationError(AAVError):
    """Report serialization or deserialization failure."""
    pass

class FileAccessError(AAVError):
    """File read/permission error (logged, file skipped)."""
    pass
```

### Isolation Strategy

| Component | Failure Mode | Handling |
|-----------|-------------|----------|
| **File read** | Permission denied, encoding error | Log WARNING, skip file, add to `errors` list |
| **Classifier** | Cannot determine type | Log INFO, skip file |
| **Scanner** | Unhandled exception | Log ERROR with scanner name + path, continue other scanners |
| **All scanners fail** | All scanners error for a file | Include file in report with zero findings, note failures |
| **Config file** | Invalid YAML, schema violation | Raise `ConfigurationError` with descriptive message |
| **Report serialization** | Invalid data | Raise `ReportSerializationError` |
| **Validator.verify()** | Any internal error | Catch all, return ScanReport with error status |

### Graceful Degradation

```python
def verify(self, path: str | Path) -> ScanReport:
    try:
        # ... pipeline execution ...
        return report
    except ConfigurationError:
        raise  # Only exception type that propagates
    except Exception as e:
        logger.critical("unrecoverable_error", error=str(e))
        return ScanReport(
            scan_id=str(uuid4()),
            artifact_path=str(path),
            scan_timestamp=datetime.utcnow(),
            scanner_version=self.version,
            findings=[],
            summary=ScanSummary(
                total_findings=0,
                gate_decision=GateAction.INFO,
                blocking_findings=0,
                warning_findings=0,
                info_findings=0,
            ),
            errors=[f"Scan failed: {e}"],
        )
```

---

## CLI Design

### Commands

```
ai-artifact-validator <command> [options]

Commands:
  verify       Scan a path for AI artifact risks
  list-risks   Display the risk catalog
  init         Generate a default .aav.yaml config file
```

### `verify` Command

```
ai-artifact-validator verify <path> [OPTIONS]

Arguments:
  PATH    Directory or file path to scan

Options:
  --output, -o FILE         Write report to file (default: stdout)
  --format, -f [json|text]  Output format (default: json)
  --config, -c FILE         Configuration file path
  --scanners TEXT           Comma-separated scanner names to enable
  --severity-threshold INT  Minimum severity to include (1-10)
  --log-level TEXT          Log level: DEBUG|INFO|WARNING|ERROR|CRITICAL
  --no-ignore              Disable all suppressions
  --no-cache               Disable result caching
  --parallel INT           Max parallel workers (default: 4)
```

### `list-risks` Command

```
ai-artifact-validator list-risks [OPTIONS]

Options:
  --category TEXT          Filter by risk category
  --artifact-type TEXT     Filter by artifact type
  --severity INT           Filter by minimum severity
  --scanner TEXT           Filter by scanner module
  --format [json|text]     Output format
```

### `init` Command

```
ai-artifact-validator init [OPTIONS]

Options:
  --path, -p DIRECTORY     Target directory (default: current)
  --force                  Overwrite existing .aav.yaml
```

### Exit Codes

| Code | Meaning | CI/CD Usage |
|------|---------|-------------|
| 0 | PASS (INFO only) | Pipeline continues |
| 1 | BLOCK (critical/high findings) | Pipeline fails |
| 2 | WARN (medium findings, no blocking) | Pipeline warns / soft gate |

---

## Testing Strategy

### Directory Structure

```
tests/
├── conftest.py                      # Shared fixtures, sample data generators
├── unit/
│   ├── test_models/
│   │   ├── test_enums.py
│   │   ├── test_findings.py
│   │   ├── test_report.py
│   │   ├── test_config.py
│   │   └── test_risk_definition.py
│   ├── test_classifiers/
│   │   ├── test_classifier.py       # All 14 artifact types
│   │   └── test_patterns.py
│   ├── test_scanners/
│   │   ├── test_base_scanner.py
│   │   ├── test_registry.py
│   │   ├── test_secret_scan.py
│   │   ├── test_injection_det.py
│   │   ├── test_perm_audit.py
│   │   ├── test_token_analyzer.py
│   │   ├── test_schema_valid.py
│   │   ├── test_dep_scan.py
│   │   ├── test_quality_lint.py
│   │   ├── test_provenance_chk.py
│   │   ├── test_bias_detector.py
│   │   ├── test_compose_analyze.py
│   │   ├── test_portability_chk.py
│   │   ├── test_compliance_audit.py
│   │   └── test_code_audit.py
│   ├── test_risks/
│   │   └── test_registry.py
│   ├── test_reporting/
│   │   ├── test_serializer.py
│   │   ├── test_parser.py
│   │   └── test_formatters.py
│   ├── test_config/
│   │   └── test_manager.py
│   ├── test_pipeline/
│   │   ├── test_discovery.py
│   │   ├── test_executor.py
│   │   └── test_aggregator.py
│   ├── test_gate_decision.py
│   └── test_validator.py
├── integration/
│   ├── test_verify_pipeline.py      # End-to-end verify() tests
│   ├── test_cli.py                  # CLI command tests
│   └── test_plugin_loading.py       # Entry point discovery tests
├── property/
│   ├── test_report_roundtrip.py     # Hypothesis: serialize/deserialize
│   ├── test_model_validation.py     # Hypothesis: valid/invalid data
│   ├── test_gate_decision.py        # Hypothesis: severity-to-gate consistency
│   └── test_confidence_bounds.py    # Hypothesis: confidence score invariants
└── fixtures/
    ├── artifacts/                   # 28+ sample artifacts (2 per type)
    │   ├── prompts/
    │   ├── skills/
    │   ├── agents/
    │   ├── sops/
    │   ├── steering/
    │   ├── mcp/
    │   ├── hooks/
    │   ├── instructions/
    │   ├── plugins/
    │   ├── memory/
    │   ├── rag/
    │   ├── eval_harness/
    │   ├── orchestration/
    │   └── api_schema/
    ├── configs/                     # Sample .aav.yaml configurations
    ├── reports/                     # Golden report outputs
    └── malicious/                   # Artifacts with known risks for scanner testing
```

### Property-Based Testing (Hypothesis)

The project uses `hypothesis` for property-based testing. Each property test runs a minimum of 100 iterations.

**Library**: `hypothesis` (Python's standard PBT library)

**Configuration**: Each test uses `@settings(max_examples=200)` to ensure comprehensive input coverage.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Report Serialization Round-Trip

*For any* valid `ScanReport` object, serializing it to JSON via `ReportSerializer` and then parsing it back via `ReportParser` SHALL produce an object equivalent to the original.

**Validates: Requirements 13.1, 13.2, 13.3**

### Property 2: Model Validation Consistency

*For any* data used to construct a `ScanFinding`, if `severity_score` is in [1, 10], `confidence` is in [0.0, 1.0], and `id` matches the pattern `^[A-Z]+-[A-Z]?[0-9]+$`, construction SHALL succeed; if any constraint is violated, construction SHALL raise `ValidationError`.

**Validates: Requirements 10.2, 10.6**

### Property 3: Verify Never Raises

*For any* input path (valid directory, valid file, non-existent path, empty string, path to unreadable file), calling `Validator.verify(path)` SHALL return a `ScanReport` object and SHALL NOT propagate any exception to the caller.

**Validates: Requirements 4.2, 4.4, 7.1, 7.4**

### Property 4: Severity-to-Gate Mapping Consistency

*For any* severity score in [1, 10], the assigned `gate_action` SHALL follow: S9-S10 → BLOCK, S7-S8 → BLOCK, S5-S6 → WARN, S3-S4 → INFO, S1-S2 → INFO. *For any* list of findings, the overall `gate_decision` SHALL equal the most severe individual `gate_action` (BLOCK > WARN > INFO).

**Validates: Requirements 12.4, 14.1, 14.2, 14.3**

### Property 5: Low Confidence Downgrade

*For any* `ScanFinding` with `confidence < 0.60`, the effective `gate_action` used in gate decision computation SHALL be `INFO`, regardless of the finding's `severity_score`.

**Validates: Requirements 14.4**

### Property 6: False Positive Exclusion from Counts

*For any* `ScanReport`, the `blocking_findings`, `warning_findings`, and `info_findings` counts in the summary SHALL exclude all findings where `false_positive == True`. The `total_findings` count SHALL include all findings.

**Validates: Requirements 14.5**

### Property 7: Risk Registry Completeness and Consistency

*For any* risk ID in the complete set of 190 defined risks, the `RiskRegistry` SHALL contain a `RiskDefinition` with valid `severity_score` (1-10), a `severity_label` consistent with the score, at least one `scanner_module`, and at least one `artifact_type`.

**Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5**

### Property 8: Suppression Rule Application

*For any* `ScanFinding` and *for any* `SuppressionRule` where the finding's `risk_id` matches the rule's `risk_id` and the finding's `artifact_path` matches the rule's `file_pattern` (or `file_pattern` is None), the finding SHALL have `false_positive` set to `True` in the output report.

**Validates: Requirements 18.1, 18.2, 18.3**

---

## Dependency Architecture

### Core Dependencies (Required)

| Package | Version | Purpose |
|---------|---------|---------|
| `pydantic` | >=2.0,<3.0 | Data models, validation, serialization |
| `pyyaml` | >=6.0 | YAML config parsing |
| `jsonschema` | >=4.17 | JSON Schema validation (config, schemas) |
| `tiktoken` | >=0.5 | OpenAI token counting |
| `click` | >=8.0 | CLI framework |
| `rich` | >=13.0 | Terminal output formatting |
| `structlog` | >=23.0 | Structured logging |

### Optional Dependencies by Extra

#### `[ml]` — ML-based scanners (InjectionDet, BiasDetector, ComposeAnalyze)
| Package | Version | Purpose |
|---------|---------|---------|
| `transformers` | >=4.30 | Zero-shot classification, NLI models |
| `sentence-transformers` | >=2.2 | Semantic similarity matching |
| `torch` | >=2.0 | PyTorch backend |
| `spacy` | >=3.5 | NLP pipeline for NER |

#### `[secrets]` — Enhanced secret/PII scanning
| Package | Version | Purpose |
|---------|---------|---------|
| `detect-secrets` | >=1.4 | Multi-pattern secret detection |
| `presidio-analyzer` | >=2.2 | Microsoft PII detection |
| `presidio-anonymizer` | >=2.2 | PII redaction |

#### `[security]` — Code audit and dependency scanning
| Package | Version | Purpose |
|---------|---------|---------|
| `bandit` | >=1.7 | Python security linter |
| `pip-audit` | >=2.6 | Python dependency CVE scanning |
| `safety` | >=2.3 | Alternative CVE database |
| `packaging` | >=23.0 | Version parsing |

#### `[provenance]` — Provenance and signing
| Package | Version | Purpose |
|---------|---------|---------|
| `gitpython` | >=3.1 | Git history analysis |
| `cryptography` | >=41.0 | Signature verification |

#### `[quality]` — Quality and bias analysis
| Package | Version | Purpose |
|---------|---------|---------|
| `nltk` | >=3.8 | Text analysis utilities |
| `textblob` | >=0.17 | Sentiment/language analysis |
| `networkx` | >=3.0 | Graph analysis for dependencies |

#### `[dev]` — Development tools
| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | >=7.0 | Test runner |
| `pytest-cov` | >=4.0 | Coverage reporting |
| `hypothesis` | >=6.0 | Property-based testing |
| `pytest-asyncio` | >=0.21 | Async test support |
| `ruff` | >=0.1.0 | Linting and formatting |
| `mypy` | >=1.5 | Static type checking |
| `pre-commit` | >=3.0 | Git hooks |

#### `[all]` — Everything
Installs all optional extras.

### Lazy Loading Strategy

Scanners with optional dependencies implement `is_available()` and use deferred imports:

```python
class InjectionDetScanner(BaseScanner):
    def is_available(self) -> bool:
        try:
            import transformers  # noqa: F401
            return True
        except ImportError:
            return False

    def scan(self, artifact_content: str, artifact_type: ArtifactType, artifact_path: str) -> list[ScanFinding]:
        if not self._ml_available:
            return self._regex_only_scan(artifact_content, artifact_type, artifact_path)
        # Full ML-based scanning
        from transformers import pipeline
        ...
```

When a scanner's optional dependencies are missing:
1. `is_available()` returns `False`
2. `ScannerRegistry` logs a WARNING
3. Scanner is excluded from applicable scanner list
4. Scanning continues with remaining available scanners

---

## Performance Design

### Parallel Execution Model

```
┌─────────────────────────────────────────────────────────────┐
│              File-Level Parallelism (ThreadPool)             │
│                                                             │
│   File 1 ──┐                                               │
│   File 2 ──┤── ThreadPoolExecutor(max_workers=parallel_files)│
│   File 3 ──┤                                               │
│   File N ──┘                                               │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │       Scanner-Level Parallelism (per file)          │   │
│   │                                                     │   │
│   │  Scanner A ──┐                                      │   │
│   │  Scanner B ──┤── ThreadPoolExecutor(parallel_scanners)│  │
│   │  Scanner C ──┘                                      │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

- **File-level**: `concurrent.futures.ThreadPoolExecutor` with configurable `parallel_files` workers (default: 4)
- **Scanner-level**: Nested `ThreadPoolExecutor` with `parallel_scanners` workers (default: 4)
- **GIL consideration**: Scanners are primarily I/O-bound (regex, file reads) and CPU-bound with C extensions (tiktoken, transformers). ThreadPoolExecutor is appropriate. ProcessPoolExecutor available as future optimization.

### Caching Strategy

```python
class ScanCache:
    """Content-hash based scan result caching."""
    
    def __init__(self, cache_dir: Path):
        self._cache_dir = cache_dir
    
    def get(self, file_path: Path, content_hash: str, scanner_names: list[str]) -> list[ScanFinding] | None:
        """Return cached findings if file content hasn't changed."""
        cache_key = self._compute_key(content_hash, scanner_names)
        cache_file = self._cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            return self._load(cache_file)
        return None
    
    def put(self, content_hash: str, scanner_names: list[str], findings: list[ScanFinding]) -> None:
        """Store scan results for a file."""
        cache_key = self._compute_key(content_hash, scanner_names)
        cache_file = self._cache_dir / f"{cache_key}.json"
        self._save(cache_file, findings)
    
    def _compute_key(self, content_hash: str, scanner_names: list[str]) -> str:
        """Cache key = hash(file_content_hash + sorted_scanner_names + scanner_version)."""
        combined = f"{content_hash}:{'|'.join(sorted(scanner_names))}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
```

- **Cache invalidation**: Content hash (SHA-256 of file content) changes → cache miss
- **Scanner version**: Cache includes scanner version in key; version bump invalidates
- **Storage**: JSON files in configurable cache directory (default: `.aav_cache/`)
- **Cleanup**: Cache entries older than configurable TTL are pruned on startup

### Lazy Scanner Loading

Scanners are instantiated only when needed:

```python
class ScannerRegistry:
    def __init__(self):
        self._scanner_classes: dict[ScannerModule, type[BaseScanner]] = {}
        self._scanner_instances: dict[ScannerModule, BaseScanner] = {}  # Lazy

    def get_scanner_instance(self, name: ScannerModule) -> BaseScanner | None:
        if name not in self._scanner_instances:
            cls = self._scanner_classes.get(name)
            if cls and cls.is_available():
                self._scanner_instances[name] = cls()
        return self._scanner_instances.get(name)
```

---

## Report Schema

### Complete JSON Report Structure

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "artifact_path": "/path/to/scanned/directory",
  "artifact_type": null,
  "scan_timestamp": "2026-06-05T14:30:00.000Z",
  "scanner_version": "0.1.0",
  "findings": [
    {
      "id": "P-S3",
      "artifact_type": "prompt",
      "artifact_path": "/path/to/scanned/directory/prompts/system.prompt.md",
      "severity_score": 10,
      "severity_label": "Critical",
      "priority": "P0",
      "gate_action": "BLOCK",
      "category": "Security",
      "title": "Secrets / Credentials Hardcoded",
      "description": "AWS access key detected in prompt template",
      "location": {
        "line": 42,
        "end_line": 42,
        "section": "examples",
        "offset": 15
      },
      "evidence": "AKIA...[REDACTED]",
      "confidence": 0.98,
      "scanner_module": "SecretScan",
      "remediation": "Replace hardcoded key with environment variable reference: {{AWS_ACCESS_KEY}}",
      "references": [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "CWE-798"
      ],
      "false_positive": false,
      "timestamp": "2026-06-05T14:30:01.234Z"
    }
  ],
  "summary": {
    "total_findings": 5,
    "by_severity": {
      "Critical": 1,
      "High": 2,
      "Medium": 1,
      "Low": 1,
      "Informational": 0
    },
    "by_category": {
      "Security": 3,
      "Performance": 1,
      "Quality": 1
    },
    "gate_decision": "BLOCK",
    "blocking_findings": 3,
    "warning_findings": 1,
    "info_findings": 1
  },
  "errors": []
}
```

### JSON Schema Validation

The report format is validated against a JSON Schema stored in `src/ai_artifact_risk_validator/config/schema.py`. Key validation rules:

- `id` must match `^[A-Z]+-[A-Z]?[0-9]+$`
- `severity_score` must be integer 1–10
- `confidence` must be float 0.0–1.0
- `gate_action` must be one of `BLOCK`, `WARN`, `INFO`
- `scan_timestamp` must be ISO 8601 format
- `artifact_type` must be one of the 14 defined enum values (or null for directory scans)

---

## Gate Decision Logic

### Per-Finding Gate Action Assignment

```python
def assign_gate_action(severity_score: int, confidence: float, overrides: dict[str, GateAction], risk_id: str) -> GateAction:
    """Determine gate action for a single finding."""
    # 1. Check for explicit override
    if risk_id in overrides:
        return overrides[risk_id]
    
    # 2. Low confidence downgrade
    if confidence < 0.60:
        return GateAction.INFO
    
    # 3. Severity-based assignment
    if severity_score >= 9:
        return GateAction.BLOCK
    elif severity_score >= 7:
        return GateAction.BLOCK  # Overridable via config
    elif severity_score >= 5:
        return GateAction.WARN
    else:
        return GateAction.INFO
```

### Overall Gate Decision

```python
def compute_overall_gate(findings: list[ScanFinding]) -> GateAction:
    """Compute the most severe gate action across all non-FP findings."""
    active = [f for f in findings if not f.false_positive]
    
    if any(f.gate_action == GateAction.BLOCK for f in active):
        return GateAction.BLOCK
    elif any(f.gate_action == GateAction.WARN for f in active):
        return GateAction.WARN
    else:
        return GateAction.INFO
```

### Confidence-Based Suppression

| Confidence Range | Behavior |
|:----------------:|----------|
| 0.95–1.00 | Auto-apply gate action |
| 0.80–0.94 | Auto-apply gate action |
| 0.60–0.79 | Apply gate action, flag for human review |
| 0.40–0.59 | Report as INFO regardless of severity |
| 0.00–0.39 | Suppress from report (unless DEBUG mode) |

---

## False Positive Management

### Inline Suppressions

Artifact files can contain inline comments to suppress specific findings:

```markdown
<!-- aav-ignore: P-S3 -->
Authorization: Bearer sk-example-key-for-documentation
```

```python
# aav-ignore: SK-S2
subprocess.run(user_command, shell=True)  # Intentional for this tool
```

```yaml
# aav-ignore: I-Q1
invalid_frontmatter: [unclosed bracket
```

### Suppression Detection Logic

```python
SUPPRESSION_PATTERN = re.compile(
    r'(?:#|//|<!--|/\*)\s*aav-ignore:\s*([\w\-,\s]+?)(?:\s*-->|\s*\*/|\s*$)',
    re.MULTILINE
)

def extract_suppressions(content: str) -> dict[int, list[str]]:
    """Extract line-level suppression comments.
    
    Returns mapping of line_number -> list of suppressed risk_ids.
    """
    suppressions = {}
    for i, line in enumerate(content.splitlines(), start=1):
        match = SUPPRESSION_PATTERN.search(line)
        if match:
            risk_ids = [r.strip() for r in match.group(1).split(",")]
            suppressions[i + 1] = risk_ids  # Suppresses the NEXT line
    return suppressions
```

### Config-Based Suppressions

Via `.aav.yaml`:
```yaml
suppressions:
  - risk_id: P-S3
    file_pattern: "tests/**"
    reason: "Test fixtures contain intentional mock secrets"
  - risk_id: P-P1
    file_pattern: "docs/prompts/**"
    reason: "Documentation prompts are verbose by design"
```

### Override Flag

The CLI `--no-ignore` flag disables all suppressions:
- Inline suppressions are ignored
- Config-based suppressions are ignored
- All findings report `false_positive: false`

---

## Extensibility

### Custom Scanner Plugins

#### Via Entry Points

```toml
# In the custom scanner's pyproject.toml
[project.entry-points."ai_artifact_validator.scanners"]
my_custom_scanner = "my_package.scanner:MyCustomScanner"
```

```python
# my_package/scanner.py
from ai_artifact_risk_validator.scanners.base import BaseScanner
from ai_artifact_risk_validator.models.enums import ScannerModule, ArtifactType
from ai_artifact_risk_validator.models.findings import ScanFinding

class MyCustomScanner(BaseScanner):
    @property
    def name(self) -> ScannerModule:
        return "CustomScanner"  # Custom name

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT, ArtifactType.INSTRUCTION]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["CUSTOM-1", "CUSTOM-2"]

    def scan(self, artifact_content: str, artifact_type: ArtifactType, artifact_path: str) -> list[ScanFinding]:
        findings = []
        # Custom detection logic
        return findings
```

#### Via Plugin Directory

```yaml
# .aav.yaml
plugins:
  directories:
    - "./custom-scanners/"
```

The registry loads all Python files in the directory that export a class inheriting from `BaseScanner`.

### Custom Risk Definitions

```yaml
# .aav.yaml
custom_risks:
  - id: "ORG-S1"
    title: "Internal API Reference"
    artifact_types: [prompt, instruction]
    category: Security
    severity_score: 7
    severity_label: High
    priority: P1
    gate_action: BLOCK
    description: "References to internal APIs that should not be shared"
    scanner_modules: [SecretScan]
```

### Custom Artifact Types

```yaml
# .aav.yaml
custom_patterns:
  prompt:
    - "*.prompt.txt"
    - "prompt-templates/**/*.md"
  instruction:
    - ".cursor/**/*.md"
    - ".windsurf/**/*.md"
```

---

## Risk Registry Implementation

### Storage Format

Risk definitions are stored as Python objects in the `risks/definitions/` sub-package, organized by artifact type. Each file exports a list of `RiskDefinition` objects:

```python
# src/ai_artifact_risk_validator/risks/definitions/prompts.py
from ai_artifact_risk_validator.models.risk import RiskDefinition
from ai_artifact_risk_validator.models.enums import *

PROMPT_RISKS: list[RiskDefinition] = [
    RiskDefinition(
        id="P-S1",
        title="Prompt Injection",
        artifact_types=[ArtifactType.PROMPT],
        category=RiskCategory.SECURITY,
        severity_score=10,
        severity_label=SeverityLabel.CRITICAL,
        priority=Priority.P0,
        gate_action=GateAction.BLOCK,
        description="Malicious instructions embedded in user-facing or data-sourced content that hijack model behavior",
        examples=["Ignore all previous instructions...", "[SYSTEM OVERRIDE]..."],
        mitigation=["Input/output sanitization", "Clear delimiters", "Instruction hierarchy enforcement"],
        detection_mechanisms=["Regex for injection phrases", "NLP classifier", "Entropy analysis"],
        scanner_modules=[ScannerModule.INJECTION_DET],
        owasp_refs=["LLM01"],
        cwe_refs=[],
    ),
    # ... 22 more prompt risks
]
```

### Registry Class

```python
class RiskRegistry:
    """Catalog of all 190 risk definitions."""

    def __init__(self) -> None:
        self._risks: dict[str, RiskDefinition] = {}
        self._load_builtin_risks()

    def _load_builtin_risks(self) -> None:
        """Load all built-in risk definitions from definitions sub-package."""
        from .definitions import prompts, skills, agents, sops, steering, mcp
        from .definitions import hooks, instructions, plugins, memory, rag
        from .definitions import eval_harness, orchestration, api_schema, cross_cutting
        # Register all
        for module in [prompts, skills, agents, ...]:
            for risk in module.RISKS:
                self._risks[risk.id] = risk

    def get(self, risk_id: str) -> RiskDefinition | None:
        return self._risks.get(risk_id)

    def query(
        self,
        artifact_type: ArtifactType | None = None,
        category: RiskCategory | None = None,
        severity_min: int | None = None,
        priority: Priority | None = None,
        scanner: ScannerModule | None = None,
    ) -> list[RiskDefinition]:
        """Query risks by various filters."""
        results = list(self._risks.values())
        if artifact_type:
            results = [r for r in results if artifact_type in r.artifact_types]
        if category:
            results = [r for r in results if r.category == category]
        if severity_min:
            results = [r for r in results if r.severity_score >= severity_min]
        if priority:
            results = [r for r in results if r.priority == priority]
        if scanner:
            results = [r for r in results if scanner in r.scanner_modules]
        return results

    def add_custom(self, risk: RiskDefinition) -> None:
        """Add a custom risk definition."""
        self._risks[risk.id] = risk

    @property
    def total_count(self) -> int:
        return len(self._risks)
```

### Complete Risk ID Inventory (190 Risks)

| Prefix | Artifact Type | Count | Risk IDs |
|--------|---------------|:-----:|----------|
| P- | Prompts | 23 | P-S1, P-S2, P-S3, P-S4, P-S5, P-S6, P-S7, P-S8, P-S9, P-S10, P-P1, P-P2, P-P3, P-P4, P-P5, P-P6, P-Q1, P-Q2, P-Q3, P-Q4, P-Q5, P-Q6, P-Q7 |
| SK- | Skills | 15 | SK-S1, SK-S2, SK-S3, SK-S4, SK-S5, SK-S6, SK-S7, SK-S8, SK-P1, SK-P2, SK-P3, SK-P4, SK-Q1, SK-Q2, SK-Q3 |
| A- | Agents | 17 | A-S1, A-S2, A-S3, A-S4, A-S5, A-S6, A-S7, A-S8, A-S9, A-P1, A-P2, A-P3, A-P4, A-P5, A-R1, A-R2, A-R3 |
| SOP- | SOPs | 10 | SOP-S1, SOP-S2, SOP-S3, SOP-S4, SOP-S5, SOP-Q1, SOP-Q2, SOP-Q3, SOP-Q4, SOP-Q5 |
| ST- | Steering | 10 | ST-S1, ST-S2, ST-S3, ST-S4, ST-S5, ST-P2, ST-P3, ST-Q1, ST-Q2 |
| MCP- | MCP Servers | 20 | MCP-S1, MCP-S2, MCP-S3, MCP-S4, MCP-S5, MCP-S6, MCP-S7, MCP-S8, MCP-S9, MCP-S10, MCP-S11, MCP-S12, MCP-P1, MCP-P2, MCP-P3, MCP-P4, MCP-Q1, MCP-Q2, MCP-Q3 |
| H- | Hooks | 12 | H-S1, H-S2, H-S3, H-S4, H-S5, H-S6, H-P1, H-P2, H-P3, H-Q1, H-Q2, H-Q3 |
| I- | Instructions | 13 | I-S1, I-S2, I-S3, I-S4, I-S5, I-S6, I-P1, I-P2, I-P3, I-P4, I-Q1, I-Q2, I-Q3 |
| PL- | Plugins | 17 | PL-S1, PL-S2, PL-S3, PL-S4, PL-S5, PL-S6, PL-S7, PL-S8, PL-S9, PL-P1, PL-P2, PL-P3, PL-P4, PL-P5, PL-Q1, PL-Q2, PL-Q3 |
| M- | Memory | 7 | M-S1, M-S2, M-S3, M-S4, M-S5, M-P1, M-Q1 |
| RAG- | RAG/Context | 7 | RAG-S1, RAG-S2, RAG-S3, RAG-S4, RAG-P1, RAG-P2, RAG-Q1 |
| EV- | Eval Harness | 4 | EV-S1, EV-S2, EV-Q1, EV-Q2 |
| OW- | Orchestration | 5 | OW-S1, OW-S2, OW-P1, OW-P2 |
| API- | API Schemas | 3 | API-S1, API-S2, API-Q1 |
| GOV- | Governance | 5 | GOV-1, GOV-2, GOV-3, GOV-4, GOV-5 |
| ETH- | Ethics/Bias | 4 | ETH-1, ETH-2, ETH-3, ETH-4 |
| CMP- | Composability | 5 | CMP-1, CMP-2, CMP-3, CMP-4, CMP-5 |
| REG- | Regulatory | 5 | REG-1, REG-2, REG-3, REG-4, REG-5 |
| MOD- | Model Portability | 4 | MOD-1, MOD-2, MOD-3, MOD-4 |
| OBS- | Observability | 4 | OBS-1, OBS-2, OBS-3, OBS-4 |
| **Total** | | **190** | |

---

## Error Handling

### Error Handling by Component

| Component | Error Type | Action | Log Level |
|-----------|-----------|--------|-----------|
| File discovery | Permission denied | Skip file, add to errors | WARNING |
| File discovery | Encoding error | Skip file, add to errors | WARNING |
| File discovery | Symlink loop | Skip, add to errors | WARNING |
| Classifier | Unknown type | Skip file, continue | INFO |
| Classifier | Parse failure | Skip file, log error | ERROR |
| Scanner | Any exception | Catch, log, continue other scanners | ERROR |
| Scanner | Timeout (30s) | Cancel, log, continue | WARNING |
| Scanner | Missing dependency | Log once, exclude scanner | WARNING |
| Report generator | Serialization failure | Raise ReportSerializationError | ERROR |
| Config manager | Invalid YAML | Raise ConfigurationError | CRITICAL |
| Config manager | Schema violation | Raise ConfigurationError with details | CRITICAL |
| Gate engine | No findings | Return INFO gate decision | INFO |
| Cache | Read failure | Skip cache, scan normally | WARNING |
| Cache | Write failure | Log, continue without caching | WARNING |

---

## Testing Strategy

### Property-Based Testing Configuration

**Library**: `hypothesis` >=6.0
**Minimum iterations**: 200 per property (configured via `@settings(max_examples=200)`)
**Tag format**: Comments reference design properties

```python
# Feature: ai-artifact-risk-validator, Property 1: Report Serialization Round-Trip
@given(report=scan_report_strategy())
@settings(max_examples=200)
def test_report_serialization_roundtrip(report: ScanReport):
    serializer = ReportSerializer()
    parser = ReportParser()
    json_str = serializer.serialize(report)
    restored = parser.parse(json_str)
    assert restored == report
```

### Unit Testing Approach

- **Artifact Classifier**: 14 artifact types × multiple detection signals = ~50+ test cases
- **ValidatorConfig**: Valid/invalid configuration parsing, precedence testing
- **Report Serializer/Parser**: Round-trip, malformed input, edge cases
- **Risk Registry**: All 190 risks present, queryable, consistent metadata
- **Scanner Registry**: Registration, discovery, lazy loading, availability
- **Gate Decision**: All severity/confidence combinations

### Integration Testing

- End-to-end `verify(path)` with fixture directories
- CLI command invocation with various flags
- Plugin loading via entry points
- Configuration file loading and merging

### Fixture Design

Each of the 14 artifact types has at minimum 2 fixture files:
- One clean file (no risks) — verifies no false positives
- One file with intentional risks — verifies scanner detection

Additional fixtures for:
- Mixed-type directories
- Large files (performance testing)
- Unreadable files (error handling)
- Files matching multiple types (confidence scoring)
- Nested directory structures
