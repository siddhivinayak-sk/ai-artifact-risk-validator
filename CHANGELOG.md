# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Core `Validator` class with `verify(path)` method for programmatic scanning
- CLI entry point `ai-artifact-validator` with `verify` command
- 13 scanner modules: SecretScan, InjectionDet, PermAudit, TokenAnalyzer, SchemaValid, DepScan, QualityLint, ProvenanceChk, BiasDetector, ComposeAnalyze, PortabilityChk, ComplianceAudit, CodeAudit
- Complete risk registry with 190 risk definitions (163 artifact-specific + 27 cross-cutting)
- Artifact classifier supporting 14 artifact types with weighted signal scoring
- Scanner plugin architecture with entry point and plugin directory discovery
- Configuration management via `.aav.yaml` files, environment variables, and CLI args
- Report generation in JSON, text, and HTML formats
- Gate decision engine with severity-to-action mapping and confidence-based downgrade
- Parallel file and scanner execution via `concurrent.futures`
- False positive management with inline suppression comments and config-based rules
- Content-hash scan result caching for repeat scans
- Structured logging via structlog with configurable levels
- CI/CD integration with exit codes (0=PASS, 1=BLOCK, 2=WARN)

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

[Unreleased]: https://github.com/ai-artifact-validator/ai-artifact-risk-validator/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ai-artifact-validator/ai-artifact-risk-validator/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ai-artifact-validator/ai-artifact-risk-validator/releases/tag/v0.1.0
