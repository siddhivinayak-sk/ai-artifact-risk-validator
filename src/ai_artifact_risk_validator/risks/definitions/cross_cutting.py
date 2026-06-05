"""Cross-cutting risk definitions for the AI Artifact Risk Validator.

Defines 27 cross-cutting risks across 6 dimensions:
- Governance (GOV-1 to GOV-5)
- Ethics (ETH-1 to ETH-4)
- Composability (CMP-1 to CMP-5)
- Regulatory (REG-1 to REG-5)
- Model Portability (MOD-1 to MOD-4)
- Observability (OBS-1 to OBS-4)

These risks apply broadly across multiple artifact types rather than being
specific to a single artifact type.
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

# All 14 artifact types for broadly applicable risks
_ALL_ARTIFACT_TYPES: list[ArtifactType] = list(ArtifactType)

# Artifact types relevant for composability concerns (artifacts that can reference each other)
_COMPOSABLE_TYPES: list[ArtifactType] = [
    ArtifactType.PROMPT,
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.STEERING,
    ArtifactType.MCP,
    ArtifactType.HOOK,
    ArtifactType.INSTRUCTION,
    ArtifactType.PLUGIN,
    ArtifactType.ORCHESTRATION,
]

# Artifact types relevant for model portability (artifacts that interact with LLMs)
_MODEL_FACING_TYPES: list[ArtifactType] = [
    ArtifactType.PROMPT,
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.STEERING,
    ArtifactType.INSTRUCTION,
    ArtifactType.EVAL_HARNESS,
]

# Artifact types relevant for bias detection
_BIAS_RELEVANT_TYPES: list[ArtifactType] = [
    ArtifactType.PROMPT,
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.STEERING,
    ArtifactType.INSTRUCTION,
    ArtifactType.RAG,
    ArtifactType.EVAL_HARNESS,
    ArtifactType.ORCHESTRATION,
]

# Artifact types relevant for compliance/regulatory concerns
_COMPLIANCE_TYPES: list[ArtifactType] = [
    ArtifactType.AGENT,
    ArtifactType.SOP,
    ArtifactType.STEERING,
    ArtifactType.MCP,
    ArtifactType.PLUGIN,
    ArtifactType.MEMORY,
    ArtifactType.RAG,
]

# Artifact types with provenance concerns (shared/distributable artifacts)
_PROVENANCE_TYPES: list[ArtifactType] = [
    ArtifactType.SKILL,
    ArtifactType.AGENT,
    ArtifactType.MCP,
    ArtifactType.PLUGIN,
    ArtifactType.RAG,
]

# ---------------------------------------------------------------------------
# Governance risks (GOV-1 to GOV-5)
# ---------------------------------------------------------------------------

_GOV_1 = RiskDefinition(
    id="GOV-1",
    title="Missing artifact provenance/authorship metadata",
    artifact_types=_PROVENANCE_TYPES,
    category=RiskCategory.GOVERNANCE,
    severity_score=5,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact lacks provenance metadata such as author identity, "
        "creation date, or origin repository. Without provenance, consumers "
        "cannot assess trust or trace the artifact's lineage."
    ),
    examples=[
        "A shared skill file with no author field, creation timestamp, or source repository URL.",
    ],
    mitigation=[
        "Add a metadata header or frontmatter block declaring author, creation date, and source URL.",
        "Use a provenance manifest file (e.g., SLSA provenance) alongside the artifact.",
    ],
    detection_mechanisms=[
        "Check for absence of author/provenance metadata fields in frontmatter or headers.",
        "Verify presence of git history attribution for the artifact file.",
    ],
    scanner_modules=[ScannerModule.PROVENANCE_CHK],
)

_GOV_2 = RiskDefinition(
    id="GOV-2",
    title="Unsigned or unverified artifact integrity",
    artifact_types=_PROVENANCE_TYPES,
    category=RiskCategory.GOVERNANCE,
    severity_score=6,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact does not have a cryptographic signature or integrity hash "
        "that can be verified. This makes it susceptible to tampering or "
        "unauthorized modification without detection."
    ),
    examples=[
        "A plugin package distributed without a signature file or checksum manifest.",
    ],
    mitigation=[
        "Sign artifacts with GPG or sigstore and distribute the signature alongside the artifact.",
        "Publish content hashes (SHA-256) in a verifiable manifest.",
    ],
    detection_mechanisms=[
        "Check for presence of .sig, .asc, or checksum files alongside the artifact.",
        "Verify artifact hash against a known-good manifest.",
    ],
    scanner_modules=[ScannerModule.PROVENANCE_CHK],
)

_GOV_3 = RiskDefinition(
    id="GOV-3",
    title="Missing version control metadata",
    artifact_types=_ALL_ARTIFACT_TYPES,
    category=RiskCategory.GOVERNANCE,
    severity_score=3,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P3,
    gate_action=GateAction.INFO,
    description=(
        "The artifact does not include version information (semantic version, "
        "revision number, or changelog reference). This makes it difficult "
        "to track changes, manage upgrades, or identify breaking modifications."
    ),
    examples=[
        "A steering file with no version field, making it impossible to tell which revision is deployed.",
    ],
    mitigation=[
        "Add a version field to the artifact metadata following semantic versioning.",
        "Maintain a changelog or revision history alongside the artifact.",
    ],
    detection_mechanisms=[
        "Check for version field in metadata/frontmatter.",
        "Inspect git tags or commit history for versioning signals.",
    ],
    scanner_modules=[ScannerModule.QUALITY_LINT],
)

_GOV_4 = RiskDefinition(
    id="GOV-4",
    title="No review/approval trail",
    artifact_types=_ALL_ARTIFACT_TYPES,
    category=RiskCategory.GOVERNANCE,
    severity_score=4,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P3,
    gate_action=GateAction.INFO,
    description=(
        "The artifact has no evidence of peer review or approval process. "
        "Without review trails, there is no assurance that changes were "
        "vetted for correctness, safety, or compliance."
    ),
    examples=[
        "An agent configuration committed directly to main without pull request or approval metadata.",
    ],
    mitigation=[
        "Require pull request approvals before merging artifact changes.",
        "Add an 'approved_by' field or reference to the approval record in metadata.",
    ],
    detection_mechanisms=[
        "Check git history for merge commit patterns indicating PR-based workflow.",
        "Look for approval metadata fields in the artifact.",
    ],
    scanner_modules=[ScannerModule.QUALITY_LINT],
)

_GOV_5 = RiskDefinition(
    id="GOV-5",
    title="Missing deprecation notice",
    artifact_types=_ALL_ARTIFACT_TYPES,
    category=RiskCategory.GOVERNANCE,
    severity_score=3,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P4,
    gate_action=GateAction.INFO,
    description=(
        "The artifact appears outdated or superseded but lacks a deprecation "
        "notice or migration path. Consumers may unknowingly rely on artifacts "
        "that will no longer receive updates."
    ),
    examples=[
        "A prompt template marked as 'legacy' in its filename but lacking a deprecation header or pointer to its replacement.",
    ],
    mitigation=[
        "Add a deprecation notice with effective date and link to the replacement artifact.",
        "Use a 'deprecated: true' field in metadata with a migration guide.",
    ],
    detection_mechanisms=[
        "Detect staleness signals (old dates, 'legacy'/'deprecated' in name/path without formal notice).",
        "Check for deprecation metadata fields.",
    ],
    scanner_modules=[ScannerModule.QUALITY_LINT],
)

# ---------------------------------------------------------------------------
# Ethics risks (ETH-1 to ETH-4)
# ---------------------------------------------------------------------------

_ETH_1 = RiskDefinition(
    id="ETH-1",
    title="Gendered language bias in prompts/instructions",
    artifact_types=_BIAS_RELEVANT_TYPES,
    category=RiskCategory.ETHICS,
    severity_score=6,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact contains gendered language (e.g., he/him as default pronouns, "
        "gendered job titles) that may produce biased or exclusionary outputs from "
        "the AI system."
    ),
    examples=[
        "A prompt using 'he' as the default pronoun: 'When the user asks, he should receive...'",
        "Instructions referencing 'businessman' instead of 'business professional'.",
    ],
    mitigation=[
        "Use gender-neutral language (they/them, 'the user', role-based titles).",
        "Review all persona definitions for gendered assumptions.",
    ],
    detection_mechanisms=[
        "Scan for gendered pronouns used as defaults (he/him/his in generic contexts).",
        "Detect gendered job titles and role descriptions.",
    ],
    scanner_modules=[ScannerModule.BIAS_DETECTOR],
)

_ETH_2 = RiskDefinition(
    id="ETH-2",
    title="Cultural/racial bias in examples",
    artifact_types=_BIAS_RELEVANT_TYPES,
    category=RiskCategory.ETHICS,
    severity_score=7,
    severity_label=SeverityLabel.HIGH,
    priority=Priority.P1,
    gate_action=GateAction.WARN,
    description=(
        "The artifact contains examples, test cases, or sample data that "
        "reflect cultural or racial bias, potentially causing the AI to "
        "perpetuate stereotypes or discriminate."
    ),
    examples=[
        "Few-shot examples that exclusively feature Western names and cultural contexts.",
        "Sample data that associates certain ethnicities with negative outcomes.",
    ],
    mitigation=[
        "Ensure diverse representation in all examples and sample data.",
        "Conduct bias audits on few-shot examples across multiple demographic dimensions.",
    ],
    detection_mechanisms=[
        "Analyze name diversity in examples using NER and demographic databases.",
        "Detect culturally loaded terminology or stereotypical associations.",
    ],
    scanner_modules=[ScannerModule.BIAS_DETECTOR],
)

_ETH_3 = RiskDefinition(
    id="ETH-3",
    title="Stereotyped persona definitions",
    artifact_types=_BIAS_RELEVANT_TYPES,
    category=RiskCategory.ETHICS,
    severity_score=6,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact defines AI personas or roles using stereotypical attributes "
        "that reinforce harmful social biases (e.g., associating certain personality "
        "traits with gender or ethnicity)."
    ),
    examples=[
        "An agent persona described as 'a nurturing female assistant' reinforcing gender stereotypes.",
    ],
    mitigation=[
        "Define personas based on functional capabilities rather than demographic attributes.",
        "Audit persona descriptions for stereotype reinforcement.",
    ],
    detection_mechanisms=[
        "Detect persona definitions with demographic-attribute associations.",
        "Flag role descriptions that correlate traits with protected characteristics.",
    ],
    scanner_modules=[ScannerModule.BIAS_DETECTOR],
)

_ETH_4 = RiskDefinition(
    id="ETH-4",
    title="Missing inclusivity considerations",
    artifact_types=_BIAS_RELEVANT_TYPES,
    category=RiskCategory.ETHICS,
    severity_score=5,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P3,
    gate_action=GateAction.WARN,
    description=(
        "The artifact lacks explicit inclusivity guidance or accessibility "
        "considerations. Without these, the AI system may inadvertently "
        "exclude users with disabilities or from underrepresented groups."
    ),
    examples=[
        "A prompt template with no mention of accessibility, diverse user needs, or inclusive language guidelines.",
    ],
    mitigation=[
        "Add explicit inclusivity guidelines to artifact metadata or instructions.",
        "Include accessibility considerations for output formatting.",
    ],
    detection_mechanisms=[
        "Check for absence of inclusivity/accessibility guidance in artifacts targeting end-users.",
        "Detect lack of diverse example coverage.",
    ],
    scanner_modules=[ScannerModule.BIAS_DETECTOR],
)

# ---------------------------------------------------------------------------
# Composability risks (CMP-1 to CMP-5)
# ---------------------------------------------------------------------------

_CMP_1 = RiskDefinition(
    id="CMP-1",
    title="Cross-artifact contradictions",
    artifact_types=_COMPOSABLE_TYPES,
    category=RiskCategory.COMPOSABILITY,
    severity_score=7,
    severity_label=SeverityLabel.HIGH,
    priority=Priority.P1,
    gate_action=GateAction.WARN,
    description=(
        "Two or more artifacts in the composition provide contradictory "
        "instructions or constraints. When composed, these contradictions "
        "may cause unpredictable AI behavior or silent instruction dropping."
    ),
    examples=[
        "A steering file says 'always respond in formal English' while a prompt says 'use casual slang'.",
    ],
    mitigation=[
        "Establish a priority resolution scheme (e.g., steering > prompt > skill).",
        "Use cross-reference validation to detect contradictions before deployment.",
    ],
    detection_mechanisms=[
        "Apply NLI (natural language inference) across composed artifact pairs to detect contradictions.",
        "Compare constraint declarations for logical conflicts.",
    ],
    scanner_modules=[ScannerModule.COMPOSE_ANALYZE],
)

_CMP_2 = RiskDefinition(
    id="CMP-2",
    title="Priority resolution conflicts",
    artifact_types=_COMPOSABLE_TYPES,
    category=RiskCategory.COMPOSABILITY,
    severity_score=6,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "Multiple artifacts declare the same priority level or overlapping scopes "
        "without a clear resolution order. This ambiguity can cause non-deterministic "
        "behavior when the AI must resolve conflicting instructions."
    ),
    examples=[
        "Two steering files both declare 'priority: high' for the same file glob pattern.",
    ],
    mitigation=[
        "Assign unique priority values within each scope.",
        "Define explicit conflict resolution rules in the orchestration layer.",
    ],
    detection_mechanisms=[
        "Detect duplicate priority declarations within overlapping scopes.",
        "Analyze artifact dependency graph for ambiguous ordering.",
    ],
    scanner_modules=[ScannerModule.COMPOSE_ANALYZE],
)

_CMP_3 = RiskDefinition(
    id="CMP-3",
    title="Context budget overflow from composition",
    artifact_types=_COMPOSABLE_TYPES,
    category=RiskCategory.COMPOSABILITY,
    severity_score=6,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The combined token count of all composed artifacts exceeds the model's "
        "context window or a configured token budget. This may cause silent "
        "truncation of instructions, leading to degraded behavior."
    ),
    examples=[
        "Five steering files totaling 45K tokens composed into a 32K context window model.",
    ],
    mitigation=[
        "Set explicit token budgets per artifact type and validate total composition size.",
        "Implement priority-based truncation with warnings when budgets are exceeded.",
    ],
    detection_mechanisms=[
        "Sum token counts across all composed artifacts and compare against budget limits.",
        "Detect individual artifacts that consume disproportionate context budget.",
    ],
    scanner_modules=[ScannerModule.COMPOSE_ANALYZE, ScannerModule.TOKEN_ANALYZER],
)

_CMP_4 = RiskDefinition(
    id="CMP-4",
    title="Dependency cycle in artifact graph",
    artifact_types=_COMPOSABLE_TYPES,
    category=RiskCategory.COMPOSABILITY,
    severity_score=7,
    severity_label=SeverityLabel.HIGH,
    priority=Priority.P1,
    gate_action=GateAction.WARN,
    description=(
        "The artifact dependency graph contains a cycle (A references B, "
        "B references C, C references A). Circular dependencies can cause "
        "infinite resolution loops or stack overflows during composition."
    ),
    examples=[
        "Skill A invokes Skill B which delegates back to Skill A, creating an infinite loop.",
    ],
    mitigation=[
        "Enforce a directed acyclic graph (DAG) structure for artifact references.",
        "Use cycle detection during artifact registration and reject circular dependencies.",
    ],
    detection_mechanisms=[
        "Build a dependency graph from cross-references and run cycle detection (DFS/Tarjan's).",
    ],
    scanner_modules=[ScannerModule.COMPOSE_ANALYZE],
)

_CMP_5 = RiskDefinition(
    id="CMP-5",
    title="Stale cross-references",
    artifact_types=_COMPOSABLE_TYPES,
    category=RiskCategory.COMPOSABILITY,
    severity_score=4,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P3,
    gate_action=GateAction.INFO,
    description=(
        "The artifact references other artifacts (by name, path, or ID) that "
        "no longer exist or have been renamed. Stale references cause "
        "resolution failures at runtime."
    ),
    examples=[
        "A prompt referencing 'skills/data-lookup' which was renamed to 'skills/database-query'.",
    ],
    mitigation=[
        "Implement reference integrity checks as part of CI/CD pipeline.",
        "Use stable identifiers (UUIDs) rather than path-based references.",
    ],
    detection_mechanisms=[
        "Resolve all cross-artifact references and flag those pointing to non-existent targets.",
    ],
    scanner_modules=[ScannerModule.COMPOSE_ANALYZE],
)

# ---------------------------------------------------------------------------
# Regulatory risks (REG-1 to REG-5)
# ---------------------------------------------------------------------------

_REG_1 = RiskDefinition(
    id="REG-1",
    title="Missing data residency declaration",
    artifact_types=_COMPLIANCE_TYPES,
    category=RiskCategory.COMPLIANCE,
    severity_score=7,
    severity_label=SeverityLabel.HIGH,
    priority=Priority.P1,
    gate_action=GateAction.WARN,
    description=(
        "The artifact processes or stores data without declaring where that "
        "data resides geographically. Missing data residency declarations "
        "can violate data sovereignty laws (GDPR, data localization requirements)."
    ),
    examples=[
        "An agent configuration that sends user queries to an external API without specifying the data processing region.",
    ],
    mitigation=[
        "Add a data_residency metadata field declaring processing and storage regions.",
        "Document data flow paths including all external service regions.",
    ],
    detection_mechanisms=[
        "Check for data residency/region declarations in artifact metadata.",
        "Detect external API calls or data transfers without region specification.",
    ],
    scanner_modules=[ScannerModule.COMPLIANCE_AUDIT],
)

_REG_2 = RiskDefinition(
    id="REG-2",
    title="License compliance violation",
    artifact_types=_PROVENANCE_TYPES,
    category=RiskCategory.COMPLIANCE,
    severity_score=7,
    severity_label=SeverityLabel.HIGH,
    priority=Priority.P1,
    gate_action=GateAction.WARN,
    description=(
        "The artifact includes or references content, code, or models under "
        "licenses that are incompatible with the project's license or usage terms. "
        "This can expose the organization to legal risk."
    ),
    examples=[
        "A RAG knowledge base incorporating GPL-licensed documentation in a proprietary product.",
    ],
    mitigation=[
        "Audit all referenced content for license compatibility.",
        "Maintain a license inventory for all third-party components used in artifacts.",
    ],
    detection_mechanisms=[
        "Scan for license declarations in referenced content and check compatibility.",
        "Detect known copyleft license markers in artifact content.",
    ],
    scanner_modules=[ScannerModule.COMPLIANCE_AUDIT, ScannerModule.PROVENANCE_CHK],
)

_REG_3 = RiskDefinition(
    id="REG-3",
    title="Missing data retention policy",
    artifact_types=_COMPLIANCE_TYPES,
    category=RiskCategory.COMPLIANCE,
    severity_score=6,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact handles user data (memory, context, logs) without "
        "specifying a data retention policy. This violates data minimization "
        "principles and may breach privacy regulations."
    ),
    examples=[
        "A memory artifact that stores conversation history indefinitely without specifying retention limits.",
    ],
    mitigation=[
        "Define explicit retention periods for all stored data.",
        "Implement automated data expiry and deletion mechanisms.",
    ],
    detection_mechanisms=[
        "Check for retention_policy or ttl fields in data-storing artifacts.",
        "Flag memory/context artifacts without explicit lifecycle declarations.",
    ],
    scanner_modules=[ScannerModule.COMPLIANCE_AUDIT],
)

_REG_4 = RiskDefinition(
    id="REG-4",
    title="PII exposure without consent framework",
    artifact_types=_COMPLIANCE_TYPES,
    category=RiskCategory.COMPLIANCE,
    severity_score=8,
    severity_label=SeverityLabel.HIGH,
    priority=Priority.P1,
    gate_action=GateAction.WARN,
    description=(
        "The artifact processes personally identifiable information (PII) "
        "without referencing a consent framework or privacy policy. Processing "
        "PII without documented consent violates GDPR and similar regulations."
    ),
    examples=[
        "A RAG source containing customer email addresses with no consent or privacy declaration.",
    ],
    mitigation=[
        "Reference the applicable privacy policy and consent mechanism in artifact metadata.",
        "Implement PII detection and redaction before storing data in artifacts.",
    ],
    detection_mechanisms=[
        "Detect PII patterns (emails, phone numbers, names) in artifact content.",
        "Check for consent_framework or privacy_policy metadata references.",
    ],
    scanner_modules=[ScannerModule.COMPLIANCE_AUDIT],
    cwe_refs=["CWE-359"],
)

_REG_5 = RiskDefinition(
    id="REG-5",
    title="Missing AI regulation alignment (EU AI Act)",
    artifact_types=_COMPLIANCE_TYPES,
    category=RiskCategory.COMPLIANCE,
    severity_score=6,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact is part of an AI system that may fall under regulatory "
        "frameworks (EU AI Act, NIST AI RMF) but lacks the required transparency, "
        "risk classification, or documentation mandated by those regulations."
    ),
    examples=[
        "An agent deployed in a high-risk domain (HR, finance) without a risk classification declaration or human oversight mechanism.",
    ],
    mitigation=[
        "Classify the AI system's risk tier per applicable regulation.",
        "Document human oversight mechanisms and transparency requirements.",
    ],
    detection_mechanisms=[
        "Check for ai_risk_classification or regulatory_alignment metadata.",
        "Detect high-risk domain keywords without accompanying compliance documentation.",
    ],
    scanner_modules=[ScannerModule.COMPLIANCE_AUDIT],
)

# ---------------------------------------------------------------------------
# Model Portability risks (MOD-1 to MOD-4)
# ---------------------------------------------------------------------------

_MOD_1 = RiskDefinition(
    id="MOD-1",
    title="Model-specific token formats",
    artifact_types=_MODEL_FACING_TYPES,
    category=RiskCategory.MODEL_PORTABILITY,
    severity_score=5,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact uses token formats or special tokens specific to a "
        "particular model (e.g., <|im_start|>, [INST], <s>). This makes "
        "the artifact non-portable across different LLM providers."
    ),
    examples=[
        "A prompt using ChatML tokens (<|im_start|>system) that only work with OpenAI-compatible models.",
        "Instructions containing Llama-specific [INST] markers.",
    ],
    mitigation=[
        "Use model-agnostic prompt structures (role-based sections without model-specific tokens).",
        "Abstract model-specific formatting into a template layer that adapts per provider.",
    ],
    detection_mechanisms=[
        "Regex detection of known model-specific token patterns (<|im_start|>, [INST], <s>, etc.).",
    ],
    scanner_modules=[ScannerModule.PORTABILITY_CHK],
)

_MOD_2 = RiskDefinition(
    id="MOD-2",
    title="Model-specific token limit assumptions",
    artifact_types=_MODEL_FACING_TYPES,
    category=RiskCategory.MODEL_PORTABILITY,
    severity_score=5,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact is designed around a specific model's context window size "
        "(e.g., hardcoded 128K assumption) without fallback for models with "
        "smaller context windows. This breaks portability across model tiers."
    ),
    examples=[
        "A steering file assuming 128K context that fails silently when used with an 8K model.",
    ],
    mitigation=[
        "Parameterize token budgets rather than hardcoding model-specific limits.",
        "Implement graceful degradation for smaller context windows.",
    ],
    detection_mechanisms=[
        "Detect hardcoded token limit values in artifact configuration.",
        "Flag artifacts whose token count exceeds common model minimums without fallback.",
    ],
    scanner_modules=[ScannerModule.PORTABILITY_CHK, ScannerModule.TOKEN_ANALYZER],
)

_MOD_3 = RiskDefinition(
    id="MOD-3",
    title="Vendor-locked capability requirements",
    artifact_types=_MODEL_FACING_TYPES,
    category=RiskCategory.MODEL_PORTABILITY,
    severity_score=5,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P2,
    gate_action=GateAction.WARN,
    description=(
        "The artifact requires capabilities specific to a single vendor's model "
        "(e.g., function calling format, vision input, specific API parameters) "
        "without declaring these requirements or providing alternatives."
    ),
    examples=[
        "A skill relying on OpenAI function calling JSON schema format without declaring the requirement.",
    ],
    mitigation=[
        "Declare required model capabilities in artifact metadata.",
        "Provide capability-check logic and fallback behavior for unsupported models.",
    ],
    detection_mechanisms=[
        "Detect vendor-specific API patterns (function_call, tool_use, vision tags).",
        "Check for capability requirement declarations in metadata.",
    ],
    scanner_modules=[ScannerModule.PORTABILITY_CHK],
)

_MOD_4 = RiskDefinition(
    id="MOD-4",
    title="Missing model fallback strategy",
    artifact_types=_MODEL_FACING_TYPES,
    category=RiskCategory.MODEL_PORTABILITY,
    severity_score=4,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P3,
    gate_action=GateAction.INFO,
    description=(
        "The artifact does not define a fallback strategy for when the primary "
        "model is unavailable or when a capability is not supported. This can "
        "cause hard failures instead of graceful degradation."
    ),
    examples=[
        "An agent configuration targeting GPT-4 with no fallback model defined for outages.",
    ],
    mitigation=[
        "Define a model fallback chain in the artifact configuration.",
        "Implement capability negotiation to adapt behavior per available model.",
    ],
    detection_mechanisms=[
        "Check for fallback_model or model_chain configuration in artifact metadata.",
        "Detect single-model dependencies without resilience declarations.",
    ],
    scanner_modules=[ScannerModule.PORTABILITY_CHK],
)

# ---------------------------------------------------------------------------
# Observability risks (OBS-1 to OBS-4)
# ---------------------------------------------------------------------------

_OBS_1 = RiskDefinition(
    id="OBS-1",
    title="Missing logging instrumentation",
    artifact_types=_ALL_ARTIFACT_TYPES,
    category=RiskCategory.OBSERVABILITY,
    severity_score=4,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P3,
    gate_action=GateAction.INFO,
    description=(
        "The artifact does not include or reference logging instrumentation. "
        "Without logging, it is impossible to debug issues, trace execution "
        "paths, or audit AI system behavior in production."
    ),
    examples=[
        "A complex orchestration workflow with no log_level or logging configuration declared.",
    ],
    mitigation=[
        "Add logging configuration or instrumentation hooks to the artifact.",
        "Reference a centralized logging framework in artifact metadata.",
    ],
    detection_mechanisms=[
        "Check for logging/observability configuration fields in artifact metadata.",
        "Detect absence of log-related declarations in executable artifacts.",
    ],
    scanner_modules=[ScannerModule.QUALITY_LINT],
)

_OBS_2 = RiskDefinition(
    id="OBS-2",
    title="Missing error tracking integration",
    artifact_types=_ALL_ARTIFACT_TYPES,
    category=RiskCategory.OBSERVABILITY,
    severity_score=4,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P3,
    gate_action=GateAction.INFO,
    description=(
        "The artifact does not integrate with an error tracking system. "
        "Without error tracking, failures may go unnoticed and unresolved, "
        "degrading system reliability over time."
    ),
    examples=[
        "An MCP server configuration with no error reporting endpoint or error handling strategy.",
    ],
    mitigation=[
        "Configure error tracking integration (e.g., Sentry, CloudWatch) for the artifact.",
        "Define error escalation policies in artifact metadata.",
    ],
    detection_mechanisms=[
        "Check for error_tracking or error_reporting configuration in metadata.",
        "Detect absence of error handling strategy declarations.",
    ],
    scanner_modules=[ScannerModule.QUALITY_LINT],
)

_OBS_3 = RiskDefinition(
    id="OBS-3",
    title="Missing performance monitoring hooks",
    artifact_types=_ALL_ARTIFACT_TYPES,
    category=RiskCategory.OBSERVABILITY,
    severity_score=3,
    severity_label=SeverityLabel.LOW,
    priority=Priority.P4,
    gate_action=GateAction.INFO,
    description=(
        "The artifact does not define performance monitoring hooks or metrics "
        "collection points. Without these, performance degradation cannot be "
        "detected or measured in production."
    ),
    examples=[
        "A skill that processes large inputs with no latency or throughput metrics configured.",
    ],
    mitigation=[
        "Add performance metric collection points (latency, throughput, token usage).",
        "Define performance baselines and alerting thresholds.",
    ],
    detection_mechanisms=[
        "Check for metrics/monitoring configuration in artifact metadata.",
        "Detect computation-heavy artifacts without performance declarations.",
    ],
    scanner_modules=[ScannerModule.QUALITY_LINT],
)

_OBS_4 = RiskDefinition(
    id="OBS-4",
    title="Missing audit trail configuration",
    artifact_types=_ALL_ARTIFACT_TYPES,
    category=RiskCategory.OBSERVABILITY,
    severity_score=5,
    severity_label=SeverityLabel.MEDIUM,
    priority=Priority.P3,
    gate_action=GateAction.WARN,
    description=(
        "The artifact does not configure audit trail capabilities for tracking "
        "who accessed, modified, or invoked it. Audit trails are essential for "
        "compliance, incident response, and accountability."
    ),
    examples=[
        "An agent with privileged tool access but no audit logging for tool invocations.",
    ],
    mitigation=[
        "Configure audit trail logging for all significant operations.",
        "Ensure audit logs capture actor identity, timestamp, action, and outcome.",
    ],
    detection_mechanisms=[
        "Check for audit_trail or audit_log configuration in metadata.",
        "Detect privileged artifacts without audit instrumentation.",
    ],
    scanner_modules=[ScannerModule.QUALITY_LINT],
)

# ---------------------------------------------------------------------------
# Exported RISKS list (27 total cross-cutting risks)
# ---------------------------------------------------------------------------

RISKS: list[RiskDefinition] = [
    # Governance (5)
    _GOV_1,
    _GOV_2,
    _GOV_3,
    _GOV_4,
    _GOV_5,
    # Ethics (4)
    _ETH_1,
    _ETH_2,
    _ETH_3,
    _ETH_4,
    # Composability (5)
    _CMP_1,
    _CMP_2,
    _CMP_3,
    _CMP_4,
    _CMP_5,
    # Regulatory/Compliance (5)
    _REG_1,
    _REG_2,
    _REG_3,
    _REG_4,
    _REG_5,
    # Model Portability (4)
    _MOD_1,
    _MOD_2,
    _MOD_3,
    _MOD_4,
    # Observability (4)
    _OBS_1,
    _OBS_2,
    _OBS_3,
    _OBS_4,
]
