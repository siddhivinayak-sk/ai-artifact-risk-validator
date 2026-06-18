"""Enums for the AI Artifact Risk Validator.

Defines all enumeration types used throughout the validator: artifact types,
risk categories, severity labels, gate actions, priorities, and scanner modules.
"""

from enum import Enum


class ArtifactType(str, Enum):
    """Types of AI artifacts that can be validated."""

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
    """Categories of risks detected by the validator."""

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
    """Human-readable severity labels mapped to severity score ranges."""

    CRITICAL = "Critical"  # S9-S10
    HIGH = "High"  # S7-S8
    MEDIUM = "Medium"  # S5-S6
    LOW = "Low"  # S3-S4
    INFORMATIONAL = "Informational"  # S1-S2


class GateAction(str, Enum):
    """Gate actions representing the validation decision for a finding."""

    BLOCK = "BLOCK"
    WARN = "WARN"
    INFO = "INFO"


class Priority(str, Enum):
    """Implementation urgency labels from P0 (immediate) to P5 (backlog)."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class ScannerModule(str, Enum):
    """Scanner module identifiers for all 13 built-in scanners."""

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
    DYNAMIC_SCAN = "DynamicScan"
    YARA_SCAN = "YaraScan"
    TAINT_TRACK = "TaintTrack"
