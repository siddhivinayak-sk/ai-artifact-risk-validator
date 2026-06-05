"""Risk definitions for Evaluation Harness artifacts (EV-S1 through EV-Q2).

Contains 4 risks covering security and quality categories
for evaluation harness, benchmark configurations, and test suites.
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

RISKS: list[RiskDefinition] = [
    # ===== Security Risks (EV-S1 to EV-S2) =====
    RiskDefinition(
        id="EV-S1",
        title="Eval Harness Data Leakage Risk",
        artifact_types=[ArtifactType.EVAL_HARNESS],
        category=RiskCategory.SECURITY,
        severity_score=6,
        severity_label=SeverityLabel.MEDIUM,
        priority=Priority.P2,
        gate_action=GateAction.WARN,
        description="Evaluation harness may leak training data or sensitive test fixtures through benchmark outputs.",
        examples=["Benchmark using production data as test input", "Eval results exposing internal system details"],
        mitigation=["Use synthetic test data", "Sanitize eval outputs", "Restrict eval result access"],
        detection_mechanisms=["Data leakage pattern detection", "Sensitive data in fixtures check"],
        scanner_modules=[ScannerModule.QUALITY_LINT],
        owasp_refs=["LLM06:2025 Excessive Agency"],
        cwe_refs=["CWE-200"],
    ),
    RiskDefinition(
        id="EV-S2",
        title="Credentials in Eval Configuration",
        artifact_types=[ArtifactType.EVAL_HARNESS],
        category=RiskCategory.SECURITY,
        severity_score=8,
        severity_label=SeverityLabel.HIGH,
        priority=Priority.P0,
        gate_action=GateAction.BLOCK,
        description="Evaluation harness configuration contains embedded API keys or credentials for model endpoints.",
        examples=["OpenAI API key in eval config", "Model endpoint credentials in benchmark YAML"],
        mitigation=["Use environment variables for credentials", "Reference secrets by name", "Remove hardcoded keys"],
        detection_mechanisms=["Secret pattern detection in eval configs", "API key format matching"],
        scanner_modules=[ScannerModule.SECRET_SCAN],
        owasp_refs=["LLM06:2025 Excessive Agency"],
        cwe_refs=["CWE-798"],
    ),
    # ===== Quality Risks (EV-Q1 to EV-Q2) =====
    RiskDefinition(
        id="EV-Q1",
        title="Insufficient Eval Coverage",
        artifact_types=[ArtifactType.EVAL_HARNESS],
        category=RiskCategory.QUALITY,
        severity_score=4,
        severity_label=SeverityLabel.LOW,
        priority=Priority.P3,
        gate_action=GateAction.INFO,
        description="Evaluation harness does not cover critical capability dimensions, risking blind spots.",
        examples=["Only testing accuracy, not safety", "Missing adversarial test cases"],
        mitigation=["Add coverage for all capability dimensions", "Include safety and robustness tests", "Implement adversarial benchmarks"],
        detection_mechanisms=["Eval dimension coverage analysis", "Test case category check"],
        scanner_modules=[ScannerModule.QUALITY_LINT],
        owasp_refs=[],
        cwe_refs=[],
    ),
    RiskDefinition(
        id="EV-Q2",
        title="Non-Reproducible Eval Configuration",
        artifact_types=[ArtifactType.EVAL_HARNESS],
        category=RiskCategory.QUALITY,
        severity_score=3,
        severity_label=SeverityLabel.LOW,
        priority=Priority.P3,
        gate_action=GateAction.INFO,
        description="Evaluation configuration lacks parameters needed for reproducibility (random seeds, model versions).",
        examples=["Missing random seed specification", "No model version pinning"],
        mitigation=["Specify random seeds", "Pin model versions", "Document all evaluation parameters"],
        detection_mechanisms=["Reproducibility parameter check", "Configuration completeness analysis"],
        scanner_modules=[ScannerModule.QUALITY_LINT],
        owasp_refs=[],
        cwe_refs=[],
    ),
]
