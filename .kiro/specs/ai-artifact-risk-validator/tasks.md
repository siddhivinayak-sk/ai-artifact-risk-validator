# Implementation Plan: AI Artifact Risk Validator

## Overview

This plan implements the AI Artifact Risk Validator as a Python package with src layout, covering project foundation, core engine architecture, data models, artifact classification, scanner plugin system, risk registry, report generation, gate decision logic, configuration management, CLI, and testing infrastructure. Tasks are ordered so each builds on the previous, ending with full integration wiring.

## Tasks

- [x] 1. Set up project structure, build configuration, and core dependencies
  - [x] 1.1 Create project directory structure with src layout and pyproject.toml
    - Create `src/ai_artifact_risk_validator/` with all sub-packages: `models/`, `scanners/`, `classifiers/`, `risks/`, `reporting/`, `config/`, `cli/`, `pipeline/`, `_internal/`
    - Create `pyproject.toml` with PEP 621 metadata, dependency groups (`[project.dependencies]`, `[project.optional-dependencies.dev]`, `[project.optional-dependencies.test]`, `[project.optional-dependencies.ml]`, `[project.optional-dependencies.secrets]`, `[project.optional-dependencies.security]`, `[project.optional-dependencies.provenance]`, `[project.optional-dependencies.quality]`, `[project.optional-dependencies.all]`)
    - Declare core dependencies: pydantic (>=2.0,<3.0), pyyaml (>=6.0), jsonschema (>=4.17), tiktoken (>=0.5), click (>=8.0), rich (>=13.0), structlog (>=23.0)
    - Register `ai-artifact-validator` console script entry point
    - Add `py.typed` marker file for PEP 561
    - Create `src/ai_artifact_risk_validator/__init__.py` with `__version__` and `Validator` export
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 2.1, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3_

  - [x] 1.2 Create Makefile and development tooling configuration
    - Create `Makefile` with targets: `install`, `test`, `lint`, `format`, `type-check`, `build`, `publish`
    - Configure `ruff` settings in `pyproject.toml` for linting and formatting
    - Configure `mypy` with strict mode in `pyproject.toml`
    - Create `.pre-commit-config.yaml` with ruff and mypy hooks
    - Create `requirements-lock.txt` for reproducible CI installs
    - _Requirements: 1.6, 3.4, 3.5, 23.1, 23.2, 23.5_

- [x] 2. Implement Pydantic data models and enums
  - [x] 2.1 Create enums module
    - Implement `ArtifactType` (14 values), `RiskCategory` (10 values), `SeverityLabel` (5 values), `GateAction` (3 values), `Priority` (6 values), `ScannerModule` (13 values) as `str, Enum` classes in `src/ai_artifact_risk_validator/models/enums.py`
    - _Requirements: 10.1_

  - [x] 2.2 Create finding and report models
    - Implement `FindingLocation` Pydantic model with optional `line`, `end_line`, `section`, `offset` fields
    - Implement `ScanFinding` Pydantic model with all fields: `id` (regex-validated), `severity_score` (1-10), `confidence` (0.0-1.0), `gate_action`, `category`, `title`, `description`, `location`, `evidence`, `scanner_module`, `remediation`, `references`, `false_positive`, `timestamp`
    - Implement `ScanSummary` and `ScanReport` Pydantic models
    - Create `models/__init__.py` re-exporting all models
    - _Requirements: 10.2, 10.3, 10.4, 10.5, 10.6_

  - [x] 2.3 Create configuration models
    - Implement `SuppressionRule` Pydantic model
    - Implement `ValidatorConfig` Pydantic model with all fields: `log_level`, `enabled_scanners`, `disabled_scanners`, `severity_threshold`, `file_include_patterns`, `file_exclude_patterns`, `max_file_size_bytes`, `parallel_files`, `parallel_scanners`, `cache_dir`, `config_path`, `custom_plugin_dirs`, `suppression_rules`, `token_budget_limit`, `gate_overrides`, `custom_artifact_patterns`
    - _Requirements: 5.1, 5.3, 5.4, 5.5, 5.6_

  - [x] 2.4 Write property test for model validation consistency
    - **Property 2: Model Validation Consistency**
    - Test that ScanFinding construction succeeds with valid data and raises ValidationError with invalid data (severity out of range, confidence out of range, id pattern mismatch)
    - **Validates: Requirements 10.2, 10.6**

  - [x] 2.5 Create risk definition model
    - Implement `RiskDefinition` Pydantic model with `id`, `title`, `artifact_types`, `category`, `severity_score`, `severity_label`, `priority`, `gate_action`, `description`, `examples`, `mitigation`, `detection_mechanisms`, `scanner_modules`, `owasp_refs`, `cwe_refs`
    - _Requirements: 11.1, 11.2_

- [~] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement Risk Registry with all 190 risk definitions
  - [x] 4.1 Create Risk Registry class and loading infrastructure
    - Implement `RiskRegistry` class in `src/ai_artifact_risk_validator/risks/registry.py` with `get()`, `query()`, `add_custom()`, `total_count` methods
    - Implement risk loading utilities in `risks/definitions/__init__.py`
    - _Requirements: 11.3, 11.4, 11.5_

  - [x] 4.2 Create risk definitions for all 14 artifact types (163 artifact-specific risks)
    - Implement risk definitions in: `prompts.py` (23 risks), `skills.py` (15), `agents.py` (17), `sops.py` (10), `steering.py` (10), `mcp.py` (20), `hooks.py` (12), `instructions.py` (13), `plugins.py` (17), `memory.py` (7), `rag.py` (7), `eval_harness.py` (4), `orchestration.py` (5), `api_schema.py` (3)
    - Each risk includes correct severity scores, priorities, gate actions, category assignments, scanner module mappings, OWASP/CWE references
    - _Requirements: 11.1, 11.3, 11.6_

  - [x] 4.3 Create cross-cutting risk definitions (27 risks)
    - Implement `cross_cutting.py` with: Governance (GOV-1 to GOV-5), Ethics (ETH-1 to ETH-4), Composability (CMP-1 to CMP-5), Regulatory (REG-1 to REG-5), Model Portability (MOD-1 to MOD-4), Observability (OBS-1 to OBS-4)
    - _Requirements: 11.2_

  - [x] 4.4 Write property test for risk registry completeness and consistency
    - **Property 7: Risk Registry Completeness and Consistency**
    - Test that all 190 risk IDs exist, each has valid severity_score (1-10), severity_label consistent with score, at least one scanner_module, and at least one artifact_type
    - **Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5**

- [ ] 5. Implement Artifact Classifier
  - [x] 5.1 Create classification patterns and detection logic
    - Implement `EXTENSION_PATTERNS`, `PATH_PATTERNS`, `CONTENT_MARKERS`, `DIR_CONTEXT_PATTERNS` dictionaries in `src/ai_artifact_risk_validator/classifiers/patterns.py`
    - Cover all 14 artifact types with detection signals from design (extension weight 0.3, path weight 0.35, content weight 0.25, directory context weight 0.10)
    - _Requirements: 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 9.10, 9.11, 9.12, 9.13, 9.14, 9.15, 9.16_

  - [x] 5.2 Implement ArtifactClassifier class
    - Implement `ClassificationResult` model and `ArtifactClassifier` class in `src/ai_artifact_risk_validator/classifiers/classifier.py`
    - Implement weighted scoring algorithm with threshold (0.3 minimum)
    - Support custom classification patterns via `custom_patterns` parameter
    - Handle confidence scoring and highest-confidence selection when multiple types match
    - Return `None` for unclassifiable files
    - _Requirements: 9.1, 9.2, 9.17, 9.18, 9.19_

  - [x] 5.3 Write unit tests for Artifact Classifier
    - Test all 14 artifact types with representative file paths, extensions, and content markers
    - Test confidence scoring when multiple types match
    - Test None return for unclassifiable files
    - Test custom classification patterns
    - _Requirements: 9.1, 9.2, 9.17, 9.18, 9.19_

- [x] 6. Implement Scanner Plugin Architecture
  - [x] 6.1 Create BaseScanner abstract class
    - Implement `BaseScanner` ABC in `src/ai_artifact_risk_validator/scanners/base.py` with abstract properties: `name`, `applicable_artifact_types`, `detected_risk_ids`, and abstract method `scan()`
    - Implement default `is_available()` method returning True
    - _Requirements: 8.1_

  - [x] 6.2 Implement ScannerRegistry
    - Implement `ScannerRegistry` in `src/ai_artifact_risk_validator/scanners/registry.py`
    - Support direct registration, entry point discovery (`ai_artifact_validator.scanners` group), plugin directory loading
    - Implement `get_scanners_for_artifact()` respecting enabled/disabled config and `is_available()` checks
    - Implement lazy scanner instantiation
    - _Requirements: 8.2, 8.3, 8.4, 8.7, 20.1, 20.2, 20.3_

  - [x] 6.3 Write unit tests for Scanner Registry
    - Test scanner registration, discovery, lazy loading, and availability filtering
    - Test entry point discovery mechanism
    - Test plugin directory loading
    - _Requirements: 8.2, 8.3, 8.4, 8.7_

- [x] 7. Implement Pipeline Engine
  - [x] 7.1 Implement file discovery and filtering
    - Create `FileDiscovery` class in `src/ai_artifact_risk_validator/pipeline/discovery.py`
    - Implement recursive file discovery with include/exclude pattern matching
    - Implement max file size filtering
    - Handle permission errors and encoding issues gracefully
    - _Requirements: 4.1, 4.3, 7.2, 19.1_

  - [x] 7.2 Implement parallel scanner execution engine
    - Create `PipelineExecutor` in `src/ai_artifact_risk_validator/pipeline/executor.py`
    - Implement file-level parallelism using `ThreadPoolExecutor(max_workers=parallel_files)`
    - Implement scanner-level parallelism per file using `ThreadPoolExecutor(max_workers=parallel_scanners)`
    - Implement 30-second timeout per scanner with graceful failure handling
    - _Requirements: 8.5, 8.6, 19.2, 19.3_

  - [x] 7.3 Implement finding aggregation and deduplication
    - Create `Aggregator` in `src/ai_artifact_risk_validator/pipeline/aggregator.py`
    - Deduplicate findings with same risk ID + same location
    - Apply suppression rules (inline and config-based)
    - Mark suppressed findings as `false_positive = True`
    - _Requirements: 18.1, 18.2, 18.3_

- [x] 8. Implement Gate Decision Engine
  - [x] 8.1 Create gate decision logic
    - Implement `assign_gate_action()` function for per-finding gate assignment
    - Implement severity-to-gate mapping: S9-S10→BLOCK, S7-S8→BLOCK, S5-S6→WARN, S3-S4→INFO, S1-S2→INFO
    - Implement low-confidence downgrade (confidence < 0.60 → INFO)
    - Implement gate overrides from config
    - Implement `compute_overall_gate()` for overall gate decision (BLOCK > WARN > INFO)
    - Implement confidence-based suppression (confidence < 0.40 suppressed unless DEBUG)
    - _Requirements: 12.4, 14.1, 14.2, 14.3, 14.4, 15.1, 15.2_

  - [x] 8.2 Write property test for severity-to-gate mapping consistency
    - **Property 4: Severity-to-Gate Mapping Consistency**
    - Test that severity scores consistently map to correct gate actions, and overall gate decision equals the most severe individual gate action
    - **Validates: Requirements 12.4, 14.1, 14.2, 14.3**

  - [x] 8.3 Write property test for low confidence downgrade
    - **Property 5: Low Confidence Downgrade**
    - Test that any finding with confidence < 0.60 has effective gate_action of INFO regardless of severity_score
    - **Validates: Requirements 14.4**

  - [x] 8.4 Write property test for false positive exclusion from counts
    - **Property 6: False Positive Exclusion from Counts**
    - Test that blocking/warning/info counts exclude false_positive findings while total_findings includes all
    - **Validates: Requirements 14.5**

- [~] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Implement Report Generation and Serialization
  - [x] 10.1 Implement report generator
    - Create `ReportGenerator` in `src/ai_artifact_risk_validator/reporting/generator.py`
    - Implement `generate()` to assemble ScanReport from findings and context
    - Compute `ScanSummary` with correct counts (excluding false positives from gate counts)
    - _Requirements: 12.1, 12.2, 12.3, 14.5_

  - [x] 10.2 Implement JSON serializer and parser
    - Create `ReportSerializer` in `src/ai_artifact_risk_validator/reporting/serializer.py` with datetime→ISO 8601 handling
    - Create `ReportParser` in `src/ai_artifact_risk_validator/reporting/parser.py` with validation error reporting for malformed JSON
    - _Requirements: 13.1, 13.2, 13.4_

  - [x] 10.3 Implement output formatters (JSON, text, HTML)
    - Create `json_formatter.py`, `text_formatter.py`, `html_formatter.py` in `reporting/formatters/`
    - Text formatter uses `rich` for terminal output
    - _Requirements: 12.5_

  - [x] 10.4 Write property test for report serialization round-trip
    - **Property 1: Report Serialization Round-Trip**
    - Test that for any valid ScanReport, serializing to JSON then parsing back produces an equivalent object
    - Use Hypothesis strategies to generate valid ScanReport objects
    - **Validates: Requirements 13.1, 13.2, 13.3**

- [x] 11. Implement Configuration Management
  - [x] 11.1 Create configuration manager
    - Implement `ConfigManager` in `src/ai_artifact_risk_validator/config/manager.py`
    - Implement YAML file loading (`.aav.yaml` / `.aav.yml`) with JSON Schema validation
    - Implement environment variable parsing with `AAV_` prefix
    - Implement configuration precedence: CLI args > env vars > config file > defaults
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [x] 11.2 Create config schema and defaults
    - Implement JSON Schema for `.aav.yaml` validation in `src/ai_artifact_risk_validator/config/schema.py`
    - Implement built-in default values in `src/ai_artifact_risk_validator/config/defaults.py`
    - _Requirements: 6.5, 6.6_

- [x] 12. Implement False Positive Management
  - [x] 12.1 Create suppression logic
    - Implement inline suppression comment parsing (`# aav-ignore: RISK-ID`) in `src/ai_artifact_risk_validator/_internal/suppression.py`
    - Support comment styles: `#`, `//`, `<!-- -->`, `/* */`
    - Implement config-based suppression matching (risk_id + file_pattern)
    - Support `--no-ignore` flag override
    - _Requirements: 18.1, 18.2, 18.3, 18.4_

  - [x] 12.2 Write property test for suppression rule application
    - **Property 8: Suppression Rule Application**
    - Test that any finding matching a suppression rule (risk_id + file_pattern) has false_positive set to True
    - **Validates: Requirements 18.1, 18.2, 18.3**

- [x] 13. Implement Caching System
  - [x] 13.1 Create content hashing and scan result caching
    - Implement `ScanCache` in `src/ai_artifact_risk_validator/_internal/cache.py`
    - Implement content-hash based cache key computation (SHA-256 of file content + scanner names + version)
    - Implement cache read/write with JSON storage
    - Implement cache invalidation on content change
    - Create `_internal/hashing.py` for content hash utilities
    - _Requirements: 19.5_

- [ ] 14. Implement Core Validator Engine
  - [x] 14.1 Implement Validator class (main entry point)
    - Create `Validator` class in `src/ai_artifact_risk_validator/validator.py`
    - Wire together: ConfigManager, FileDiscovery, ArtifactClassifier, ScannerRegistry, PipelineExecutor, Aggregator, GateDecisionEngine, ReportGenerator
    - Implement `verify(path)` orchestrating the full pipeline: discovery → classification → scanning → aggregation → gate decision → reporting
    - Implement graceful degradation: catch all exceptions, return ScanReport with error status
    - Handle non-existent paths, file paths, and directory paths
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 7.1, 7.3, 7.4, 7.5_

  - [-] 14.2 Write property test for verify never raises
    - **Property 3: Verify Never Raises**
    - Test that for any input path (valid directory, valid file, non-existent path, empty string), verify() returns a ScanReport and never propagates exceptions
    - **Validates: Requirements 4.2, 4.4, 7.1, 7.4**

- [~] 15. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 16. Implement Scanner Modules (13 scanners)
  - [~] 16.1 Implement SecretScan scanner
    - Create `SecretScanScanner` in `src/ai_artifact_risk_validator/scanners/secret_scan.py`
    - Implement regex patterns for API key formats, entropy analysis (Shannon entropy > 4.5)
    - Implement lazy loading for optional `detect-secrets` and `presidio-analyzer` dependencies
    - Apply to all 14 artifact types
    - Detect risk IDs: P-S3, P-S4, P-S8, SK-S5, SOP-S1, I-S3, M-S2, M-S3, M-S4, EV-S2, and secondary risks
    - _Requirements: 8.1, 8.4, 2.7, 15.1_

  - [~] 16.2 Implement InjectionDet scanner
    - Create `InjectionDetScanner` in `src/ai_artifact_risk_validator/scanners/injection_det.py`
    - Implement regex for known injection phrases, unicode anomaly detection
    - Implement fallback regex-only mode when ML deps unavailable
    - Detect risk IDs: P-S1, P-S2, P-S6, P-S7, P-S9, P-S10, I-S1, I-S2, ST-S1, ST-S2, ST-S5, MCP-S3, MCP-S6, API-S1, M-S1, RAG-S1, OW-S1, A-S4, A-S5
    - _Requirements: 8.1, 8.4, 2.7, 15.1_

  - [~] 16.3 Implement PermAudit scanner
    - Create `PermAuditScanner` in `src/ai_artifact_risk_validator/scanners/perm_audit.py`
    - Implement policy engine checking tool permissions against allowlists, file path pattern analysis, network access audit, destructive action detection
    - Detect risk IDs: SK-S1, SK-S3, SK-S6, A-S1, A-S2, A-S6, ST-S3, ST-S4, MCP-S7, MCP-S10, H-S3, H-S6, I-S4, I-S5, API-S2, OW-S2, M-S5, PL-S2, PL-S6
    - _Requirements: 8.1, 8.4, 15.1_

  - [~] 16.4 Implement TokenAnalyzer scanner
    - Create `TokenAnalyzerScanner` in `src/ai_artifact_risk_validator/scanners/token_analyzer.py`
    - Implement token counting per section via tiktoken, compression ratio analysis, redundancy detection
    - Detect risk IDs: P-P1 through P-P6, SK-P1, A-P2, A-P3, A-P4, I-P1, I-P3, I-P4, M-P1, CMP-3, MCP-P3, MOD-2
    - _Requirements: 8.1, 8.4, 15.1_

  - [~] 16.5 Implement SchemaValid scanner
    - Create `SchemaValidScanner` in `src/ai_artifact_risk_validator/scanners/schema_valid.py`
    - Implement YAML/JSON schema validation, OpenAPI spec validation, frontmatter structure checking
    - Detect risk IDs: I-Q1, ST-Q1, MCP-Q1, API-Q1, PL-Q1
    - _Requirements: 8.1, 8.4, 15.1_

  - [~] 16.6 Implement DepScan scanner
    - Create `DepScanScanner` in `src/ai_artifact_risk_validator/scanners/dep_scan.py`
    - Implement lockfile/manifest parsing, version comparison
    - Implement lazy loading for optional `pip-audit`, `safety`, `packaging` dependencies
    - Detect risk IDs: MCP-S4, MCP-S11, MCP-S12, PL-S3, PL-S8, SK-S7
    - _Requirements: 8.1, 8.4, 2.7, 15.1, 21.1_

  - [~] 16.7 Implement QualityLint scanner
    - Create `QualityLintScanner` in `src/ai_artifact_risk_validator/scanners/quality_lint.py`
    - Implement ambiguity detection, conflict detection, staleness heuristics, metadata presence checks
    - Detect risk IDs: P-Q1 through P-Q7, SK-Q1 through SK-Q3, SOP-Q1 through SOP-Q5, I-Q2, I-Q3, ST-Q2, MCP-Q2, MCP-Q3, H-Q1 through H-Q3, EV-Q1, EV-Q2, M-Q1, RAG-Q1, PL-Q2, PL-Q3, GOV-3 through GOV-5, A-R1 through A-R3, MCP-P1, MCP-P2, MCP-P4
    - _Requirements: 8.1, 8.4, 15.1_

  - [~] 16.8 Implement ProvenanceChk scanner
    - Create `ProvenanceChkScanner` in `src/ai_artifact_risk_validator/scanners/provenance_chk.py`
    - Implement metadata extraction, integrity hash validation
    - Implement lazy loading for optional `gitpython`, `cryptography` dependencies
    - Detect risk IDs: SK-S7, SK-S8, MCP-S4, MCP-S5, PL-S6, PL-S7, A-S8, A-S9, GOV-1, GOV-2, REG-2, RAG-S2
    - _Requirements: 8.1, 8.4, 2.7, 15.1_

  - [~] 16.9 Implement BiasDetector scanner
    - Create `BiasDetectorScanner` in `src/ai_artifact_risk_validator/scanners/bias_detector.py`
    - Implement gendered language detection, name diversity analysis, inclusive language linting
    - Implement lazy loading for optional `transformers` dependency
    - Detect risk IDs: ETH-1, ETH-2, ETH-3, ETH-4
    - _Requirements: 8.1, 8.4, 2.7, 15.1_

  - [~] 16.10 Implement ComposeAnalyze scanner
    - Create `ComposeAnalyzeScanner` in `src/ai_artifact_risk_validator/scanners/compose_analyze.py`
    - Implement cross-artifact contradiction detection, priority resolution simulation, dependency graph analysis
    - Implement lazy loading for optional `networkx`, `sentence-transformers` dependencies
    - Detect risk IDs: CMP-1 through CMP-5, I-P2, ST-P2, A-P5, OW-P1, OW-P2, ST-P3, SK-P2 through SK-P4
    - _Requirements: 8.1, 8.4, 2.7, 15.1_

  - [~] 16.11 Implement PortabilityChk scanner
    - Create `PortabilityChkScanner` in `src/ai_artifact_risk_validator/scanners/portability_chk.py`
    - Implement model-specific token/tag detection via regex, token limit analysis, capability requirement extraction
    - Detect risk IDs: MOD-1, MOD-2, MOD-3, MOD-4
    - _Requirements: 8.1, 8.4, 15.1_

  - [~] 16.12 Implement ComplianceAudit scanner
    - Create `ComplianceAuditScanner` in `src/ai_artifact_risk_validator/scanners/compliance_audit.py`
    - Implement license scanning, data residency flow mapping, retention policy checking
    - Implement lazy loading for optional `presidio-analyzer` dependency
    - Detect risk IDs: REG-1, REG-2, REG-3, REG-4, REG-5, RAG-S3
    - _Requirements: 8.1, 8.4, 2.7, 15.1_

  - [~] 16.13 Implement CodeAudit scanner
    - Create `CodeAuditScanner` in `src/ai_artifact_risk_validator/scanners/code_audit.py`
    - Implement Python AST analysis, pattern matching for dangerous functions (eval, exec, subprocess), SSRF detection
    - Implement lazy loading for optional `bandit` dependency
    - Detect risk IDs: SK-S2, MCP-S1, MCP-S2, MCP-S8, H-S1, H-S4, PL-S1, PL-S5, PL-S9, A-S3, A-S7, H-S5, MCP-S9, PL-S4
    - _Requirements: 8.1, 8.4, 2.7, 15.1, 21.3_

- [~] 17. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 18. Implement CLI
  - [~] 18.1 Create CLI application entry point and verify command
    - Implement Click CLI application in `src/ai_artifact_risk_validator/cli/main.py`
    - Implement `verify` command with options: `--output`, `--format` (json/text), `--config`, `--scanners`, `--severity-threshold`, `--log-level`, `--no-ignore`, `--no-cache`, `--parallel`
    - Implement exit codes: 0 (PASS/INFO), 1 (BLOCK), 2 (WARN)
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8, 16.9, 16.10_

  - [~] 18.2 Implement list-risks and init commands
    - Implement `list-risks` command with filtering options: `--category`, `--artifact-type`, `--severity`, `--scanner`, `--format`
    - Implement `init` command to generate default `.aav.yaml` config file with `--path` and `--force` options
    - Use `rich` library for formatted terminal output
    - _Requirements: 16.1, 16.10_

- [ ] 19. Implement Logging and Observability
  - [-] 19.1 Configure structured logging with structlog
    - Set up `structlog` with JSON-formatted output throughout the package
    - Implement configurable log levels with appropriate message classification (DEBUG/INFO/WARNING/ERROR/CRITICAL)
    - Include contextual fields in log entries: `scanner_module`, `artifact_path`, `artifact_type`, `scan_id`
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 5.2_

- [ ] 20. Create test fixtures and integration tests
  - [~] 20.1 Create sample artifacts corpus (28+ fixture files)
    - Create at least 2 representative fixture files per artifact type (14 types × 2 = 28 minimum)
    - Include clean files (no risks) and files with intentional risks
    - Create additional fixtures: mixed-type directories, unreadable files, nested structures
    - _Requirements: 22.6, 22.7_

  - [~] 20.2 Write integration tests for end-to-end verify pipeline
    - Test `verify(path)` with fixture directories producing complete ScanReports
    - Test CLI command invocation with various flags and exit codes
    - Test plugin loading via entry points
    - Test configuration file loading and merging
    - _Requirements: 22.4_

- [ ] 21. Implement CI/CD pipeline configuration
  - [~] 21.1 Create CI pipeline configuration
    - Create CI configuration (GitHub Actions or equivalent) running: lint, type-check, unit tests, integration tests
    - Configure multi-Python version matrix (3.10, 3.11, 3.12)
    - Enforce 90% coverage threshold
    - Configure tagged release publishing to Nexus
    - Run pip-audit on project dependencies as security gate
    - _Requirements: 25.1, 25.2, 25.3, 25.4, 25.5_

- [ ] 22. Create documentation
  - [~] 22.1 Create README.md and CHANGELOG.md
    - Write README with sections: Overview, Installation, Quick Start, Configuration, API Reference, Scanner Modules, Risk Framework Reference, Contributing
    - Include working code examples demonstrating Validator usage
    - Include JSON report output examples (clean scan and scan with findings)
    - Create CHANGELOG.md following Keep a Changelog format
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5_

- [~] 23. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The implementation language is Python as specified in the design document
- All 13 scanner modules implement the same BaseScanner interface for consistency
- Scanners with optional dependencies use lazy loading and `is_available()` to gracefully degrade

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.5"] },
    { "id": 3, "tasks": ["2.4", "4.1", "5.1", "6.1"] },
    { "id": 4, "tasks": ["4.2", "4.3", "5.2", "6.2"] },
    { "id": 5, "tasks": ["4.4", "5.3", "6.3", "7.1"] },
    { "id": 6, "tasks": ["7.2", "7.3", "8.1"] },
    { "id": 7, "tasks": ["8.2", "8.3", "8.4", "10.1", "11.1", "11.2"] },
    { "id": 8, "tasks": ["10.2", "10.3", "12.1", "13.1"] },
    { "id": 9, "tasks": ["10.4", "12.2", "14.1"] },
    { "id": 10, "tasks": ["14.2", "19.1"] },
    { "id": 11, "tasks": ["16.1", "16.2", "16.3", "16.4", "16.5"] },
    { "id": 12, "tasks": ["16.6", "16.7", "16.8", "16.9", "16.10"] },
    { "id": 13, "tasks": ["16.11", "16.12", "16.13"] },
    { "id": 14, "tasks": ["18.1", "18.2", "20.1"] },
    { "id": 15, "tasks": ["20.2", "21.1", "22.1"] }
  ]
}
```
