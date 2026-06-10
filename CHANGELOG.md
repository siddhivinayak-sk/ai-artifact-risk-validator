# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Semantic analysis engine** — Optional embedding-based detection using sentence-transformers (`semantic/` package) for paraphrased attack detection, semantic compliance gap analysis, and false positive reduction
- `SemanticConfig` model with `enabled`, `model_name`, and `threshold` fields on `ValidatorConfig`
- CLI flags: `--semantic/--no-semantic`, `--semantic-model`, `--semantic-threshold`
- Environment variables: `AAV_SEMANTIC_ENABLED`, `AAV_SEMANTIC_MODEL`, `AAV_SEMANTIC_THRESHOLD`, `AI_VALIDATOR_SEMANTIC_ENABLED`
- `EmbeddingEngine`, `SimilarityScorer`, `EmbeddingCache`, `CorpusManager`, `IntentClassifier` in `semantic/` package
- Smart text chunker (`semantic/chunker.py`) and batch processor (`semantic/batch_processor.py`)
- Cross-file composition analysis (`pipeline/cross_file_analyzer.py`) detecting contradictions and redundancies across artifacts
- `RegulatoryFramework` and `RegulatoryRegistry` classes for EU AI Act, NIST AI RMF, ISO/IEC 42001, US State AI Laws
- `semantic_score` field on `ScanFinding` for embedding-based confidence signals
- Semantic-aware confidence calibration in `Aggregator` (70/30 blend of original confidence and semantic score)
- Semantic corroboration in gate decision engine (high semantic score prevents low-confidence downgrade)
- Context-aware entropy false-positive filtering in SecretScan (UUID, data-URI, integrity hash, placeholder patterns)
- Hybrid detection in InjectionDet, QualityLint, BiasDetector, ComplianceAudit, and Dynamic MCP scanners
- Risk definitions: P-Q8, P-Q9 (semantic quality), CMP-1, CMP-5 (cross-file composition)
- Reference corpora: injection, jailbreak, bias, guardrail-weakening (JSON files in `semantic/corpora/`)
- Semantic config section in `init` command template
- 80+ new tests covering all semantic features

### Changed

- `ScanFinding` model now includes optional `semantic_score` field (defaults to `None`)
- `Aggregator.aggregate()` applies confidence calibration before deduplication
- Gate decision engine considers `semantic_score` in confidence downgrade logic
- Config manager merges nested `semantic` dict from YAML, env vars, and CLI overrides

## [1.0.0] - 2025-06-10

### Added

- Core `Validator` class with `verify(path)` method for programmatic artifact scanning
- CLI entry point `ai-artifact-validator` with three commands: `verify`, `list-risks`, `init`
- 13 scanner modules: SecretScan, InjectionDet, PermAudit, TokenAnalyzer, SchemaValid, DepScan, QualityLint, ProvenanceChk, BiasDetector, ComposeAnalyze, PortabilityChk, ComplianceAudit, CodeAudit
- Complete risk registry with 190 risk definitions (163 artifact-specific + 27 cross-cutting)
- Artifact classifier supporting 14 artifact types with weighted signal scoring
- Scanner plugin architecture with entry point and plugin directory discovery
- Configuration management via `.aav.yaml` files, environment variables (`AAV_` prefix), and CLI args with proper precedence
- Report generation in JSON, rich text, and standalone HTML formats
- Gate decision engine with severity-to-action mapping and confidence-based downgrade
- Parallel file and scanner execution via `concurrent.futures`
- False positive management with inline suppression comments (`# aav-ignore: RISK-ID`) and config-based rules
- Content-hash scan result caching for repeat scans
- Structured logging via structlog with configurable levels
- CI/CD integration with exit codes (0=PASS, 1=BLOCK, 2=WARN)
- `list-risks` command with filters for category, artifact-type, severity, and scanner
- `init` command to generate default `.aav.yaml` configuration
- `AAV_HTML_REPORT_PATH` environment variable for side-effect HTML report generation
- Property-based tests using Hypothesis for model validation, report round-trip serialization, gate decision consistency
- Comprehensive documentation: README.md with Quick Start, API Reference, and CLI usage guide

## [0.2.0] - 2025-06-08

### Added

- Standalone HTML report output format (`--format html`)
- `AAV_HTML_REPORT_PATH` environment variable for side-effect HTML report generation
- `html_report_path` configuration field in `.aav.yaml`
- `format_html()` Python API function for programmatic HTML report generation
- Property-based tests for HTML formatter correctness properties
- Non-regression test suite for JSON and text format stability

## [0.1.0] - 2025-06-05

### Added

- Initial release of the AI Artifact Risk Validator
- Project structure with `src/` layout and PEP 621 `pyproject.toml`
- Pydantic data models: `ScanReport`, `ScanFinding`, `ScanSummary`, `FindingLocation`, `ValidatorConfig`, `RiskDefinition`
- Enums: `ArtifactType` (14 types), `RiskCategory` (10 categories), `SeverityLabel`, `GateAction`, `Priority`, `ScannerModule`
- Optional dependency groups: `[dev]`, `[test]`, `[ml]`, `[secrets]`, `[security]`, `[provenance]`, `[quality]`, `[all]`
- Python 3.11, 3.12 support
- Core dependencies: pydantic, pyyaml, jsonschema, tiktoken, click, rich, structlog
- `py.typed` marker for PEP 561 compliance
- Makefile with standard development targets
- Property-based tests using Hypothesis for model validation, report round-trip serialization, gate decision consistency

[Unreleased]: https://github.com/ai-artifact-validator/ai-artifact-risk-validator/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ai-artifact-validator/ai-artifact-risk-validator/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/ai-artifact-validator/ai-artifact-risk-validator/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ai-artifact-validator/ai-artifact-risk-validator/releases/tag/v0.1.0
