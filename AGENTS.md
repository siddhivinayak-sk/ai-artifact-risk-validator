# AI Artifact Risk Validator — Agent Instructions

## Build & Test Commands

```bash
make dev-install          # Install core + dev + test deps
make test                 # pytest with coverage (≥90% required)
make lint                 # ruff check src/ tests/
make format               # ruff format + --fix src/ tests/
make type-check           # mypy src/
make install-ml           # Add ML/semantic deps (CPU torch, ~200 MB)
make install-all          # All optional deps (CPU torch)
```

Direct pytest:
```bash
pytest tests/test_validator.py -v                  # single file
pytest -m "not slow and not integration"           # skip slow/integration
pytest --cov --cov-report=term-missing             # with coverage
```

CLI entry point after install:
```bash
ai-artifact-validator verify <path> [options]
# Exit codes: 0=PASS, 1=BLOCK, 2=WARN
```

## Architecture

```
validator.py              # Orchestration: discovery → classify → scan → aggregate → gate → report
classifiers/              # Artifact type detection (PROMPT, SKILL, AGENT, MCP, HOOK, etc.)
pipeline/
  executor.py             # Parallel scanner execution (30s timeout per scanner)
  gate.py                 # BLOCK/WARN/INFO gate decisions + suppression
  aggregator.py           # Deduplication of findings
  discovery.py            # File discovery with include/exclude glob patterns
scanners/
  base.py                 # BaseScanner abstract class — implement to add a scanner
  registry.py             # Entry-point + plugin-dir discovery
  <scanner>.py            # 14 built-in scanners
risks/
  registry.py             # RiskRegistry — query by artifact_type, category, severity, scanner
  definitions/            # 190+ RiskDefinition objects, one file per artifact type
models/                   # Pydantic models: ScanFinding, ScanReport, ValidatorConfig, enums
config/manager.py         # 3-tier config: CLI args > env vars (AAV_*) > .aav.yaml > defaults
reporting/                # ReportGenerator, HTML/JSON/SARIF output
semantic/                 # Optional sentence-transformers embedding analysis
_internal/
  logging.py              # structlog JSON logging
  suppression.py          # Inline & config-based suppression parsing
```

See [docs/AI-Artifact-Risk-Validation-Framework.md](docs/AI-Artifact-Risk-Validation-Framework.md) for the full risk framework reference.

## Adding a Scanner

1. Subclass `BaseScanner` from `src/ai_artifact_risk_validator/scanners/base.py`
2. Implement abstract properties: `name` (ScannerModule), `applicable_artifact_types`, `detected_risk_ids`
3. Implement `scan(artifact_content, artifact_type, artifact_path) -> List[ScanFinding]`
4. Optionally override `is_available()` for graceful degradation when optional deps are missing
5. Register via entry point in `pyproject.toml` under `[project.entry-points."ai_artifact_validator.scanners"]`, or add the class path to `custom_plugin_dirs` in config

## Risk ID Format

`<PREFIX>-<LETTER><NUMBER>` — e.g., `P-S1`, `MCP-S3`, `SK-S5`

- Prefix = artifact type (P=Prompt, SK=Skill, A=Agent, MCP=MCP, I=Instruction, H=Hook, SOP=SOP, etc.)
- Letter = subcategory (S=Security, Q=Quality, C=Compliance, etc.)
- Number = sequence within category
- New cross-scanner prefixes: OH=Orchestration Hijack, SPL=System Prompt Leak, RA=Rogue Agent, TR=Trust & Reliability, TT=Taint Tracking, Y=YARA, AST=AST code analysis, DEP=Dependency

Risk definitions live in `src/ai_artifact_risk_validator/risks/definitions/` (one file per artifact type).

## Gate Actions

| Action | Severity | Exit Code |
|--------|----------|-----------|
| BLOCK  | ≥ 7      | 1         |
| WARN   | 5–6      | 2         |
| INFO   | ≤ 4      | 0         |

Confidence < 0.40 → hidden (debug only). Confidence < 0.60 → gate downgraded to INFO (unless semantic_score ≥ 0.70).

## Configuration (.aav.yaml)

```yaml
log_level: INFO
severity_threshold: 5
enabled_scanners: [secret_scan, injection_det, perm_audit]
suppression_rules:
  - risk_id: P-S1
    file_pattern: "tests/*.py"
    reason: "False positive in test files"
gate_overrides:
  P-S1: WARN
allow_dynamic_scan: false
```

Env vars use `AAV_` prefix (e.g., `AAV_LOG_LEVEL=DEBUG`).

## Suppression Comments

```python
# aav-ignore: P-S1               # Python / YAML
// aav-ignore: MCP-S3             # TypeScript / JavaScript / Java
<!-- aav-ignore: P-S1 -->         # HTML / Markdown
/* aav-ignore: SK-S5 */           # C-style
# aav-ignore: P-S1, P-S3, SK-S5  # Multiple risk IDs (comma-separated)
```

Comment on line N suppresses findings on line N+1.

## Testing Conventions

- **Unit tests**: `tests/test_<module>.py`
- **Property-based tests**: `tests/test_*_property.py` — use `@hypothesis.given` with custom `@st.composite` strategies
- **Integration tests**: `tests/integration/` — require `@pytest.mark.integration`
- Slow tests: mark with `@pytest.mark.slow`
- Per-file ignores in ruff: `tests/**` gets `S101` (assert), `ANN` (annotations), `T20` (print)
- Coverage requirement: ≥ 90% (`fail_under = 90` in pyproject.toml)

## Code Style

- **Formatter**: ruff (line length 100, double quotes)
- **Type checking**: mypy with `disallow_untyped_defs = true`; all public functions must have type annotations
- **Logging**: Use `structlog` with context binding — never use `print()` or stdlib `logging` directly
- **Error handling**: Catch and log exceptions; return error reports rather than raising (graceful degradation pattern)
- **Imports**: First-party package is `ai_artifact_risk_validator` (configured in ruff isort)

## Key Files

| File | Role |
|------|------|
| [src/ai_artifact_risk_validator/validator.py](src/ai_artifact_risk_validator/validator.py) | Main orchestration entry point |
| [src/ai_artifact_risk_validator/scanners/base.py](src/ai_artifact_risk_validator/scanners/base.py) | BaseScanner interface |
| [src/ai_artifact_risk_validator/scanners/registry.py](src/ai_artifact_risk_validator/scanners/registry.py) | Scanner discovery & registration |
| [src/ai_artifact_risk_validator/models/enums.py](src/ai_artifact_risk_validator/models/enums.py) | ArtifactType, RiskCategory, SeverityLabel, GateAction, ScannerModule |
| [src/ai_artifact_risk_validator/models/findings.py](src/ai_artifact_risk_validator/models/findings.py) | ScanFinding data model |
| [src/ai_artifact_risk_validator/pipeline/gate.py](src/ai_artifact_risk_validator/pipeline/gate.py) | Gate decision + suppression logic |
| [src/ai_artifact_risk_validator/risks/definitions/](src/ai_artifact_risk_validator/risks/definitions) | 190+ risk definitions by artifact type |
| [src/ai_artifact_risk_validator/config/manager.py](src/ai_artifact_risk_validator/config/manager.py) | Config loading (3-tier precedence) |
| [pyproject.toml](pyproject.toml) | Entry points, deps, ruff/mypy/pytest config |
