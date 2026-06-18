# Contributing to AI Artifact Risk Validator

Thank you for your interest in contributing to the AI Artifact Risk Validator! This document provides guidelines and instructions to help you get started.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Type Annotations](#type-annotations)
- [Testing](#testing)
- [Adding a New Scanner](#adding-a-new-scanner)
- [Adding Risk Definitions](#adding-risk-definitions)
- [CI/CD Pipeline](#cicd-pipeline)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [License](#license)

---

## Code of Conduct

This project follows a respectful and inclusive community standard. Be kind, constructive, and professional in all interactions. Harassment, discrimination, and disrespectful behavior will not be tolerated.

---

## Getting Started

### Prerequisites

- **Python 3.11 or 3.12** (required)
- **pip** (latest version recommended)
- **Git** for version control
- **make** (optional, for convenience targets — Unix/macOS/WSL)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:

```bash
git clone https://github.com/<your-username>/ai-artifact-risk-validator.git
cd ai-artifact-risk-validator
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/ai-artifact-validator/ai-artifact-risk-validator.git
```

---

## Development Setup

### Install dependencies

```bash
# Install package in editable mode with dev + test dependencies
pip install -e ".[dev,test]"
```

Or using the Makefile (Unix/macOS/WSL):

```bash
make dev-install
```

### Optional: Install ML/semantic dependencies

```bash
# CPU-only torch (~200 MB, recommended for development)
make install-ml

# Or manually:
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[ml]"
```

### Set up pre-commit hooks

```bash
pre-commit install
```

This installs hooks that automatically run **ruff** (lint + format) and **mypy** on every commit.

### Verify your setup

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/ --strict
pytest tests/ --ignore=tests/integration --cov --cov-fail-under=90
```

All four commands must pass before submitting changes.

---

## Project Structure

```
src/ai_artifact_risk_validator/
├── __init__.py              # Package entry with lazy Validator import
├── validator.py             # Core orchestrator (discovery → classify → scan → gate → report)
├── py.typed                 # PEP 561 typed marker
├── _internal/               # Internal utilities (cache, hashing, logging, suppression)
├── classifiers/             # Artifact type classification (pattern-based)
├── cli/                     # Click CLI entry point + commands (verify, list-risks, init)
├── config/                  # Config management (defaults, manager, schema)
├── models/                  # Pydantic v2 models (config, enums, findings, report, risk)
├── pipeline/                # Execution pipeline (aggregator, discovery, executor, gate)
├── reporting/               # Report generation (generator, parser, serializer, formatters/)
├── risks/                   # Risk registry + 190+ risk definitions (one file per artifact type)
├── scanners/                # All 16 scanner implementations + base + registry

tests/
├── fixtures/                # Test artifacts (agents, hooks, mcp, prompts, skills, sops, steering)
├── test_*.py                # Unit tests
├── test_*_property.py       # Property-based tests (Hypothesis)
├── integration/             # Integration tests (optional)
```

---

## Development Workflow

### Branch naming

Create a feature branch from `main`:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### Making changes

1. Write your code following the [Code Style](#code-style) guidelines
2. Add or update tests for your changes
3. Run the full validation suite locally (see [CI/CD Pipeline](#cicd-pipeline))
4. Commit with clear, descriptive messages

### Commit messages

Use clear, concise commit messages:

```
Add BiasDetector scanner for prompt artifacts

- Implement bias detection using keyword + semantic analysis
- Add 15 risk definitions for bias-related risks
- Register scanner in pyproject.toml entry points
- Add unit tests with 95% coverage
```

---

## Code Style

This project uses **ruff** for linting and formatting. Configuration is in `pyproject.toml`.

### Key rules

| Rule | Value |
|------|-------|
| Line length | 100 characters |
| Quote style | Double quotes (`"`) |
| Indent | 4 spaces |
| Import sorting | isort-compatible (ruff `I` rule) |

### Required in every source file

```python
from __future__ import annotations
```

This must be the first import in every module (enables modern type annotation syntax).

### Module docstrings

Every module must have a module-level docstring:

```python
"""Brief description of what this module does."""

from __future__ import annotations
```

### Logging

- Use `structlog` for all logging — never use `print()` or stdlib `logging` in `src/`
- Bind context to loggers for structured output

### Formatting and linting commands

```bash
# Auto-format
ruff format src/ tests/

# Lint with auto-fix
ruff check --fix src/ tests/

# Check only (no changes)
ruff check src/ tests/
ruff format --check src/ tests/
```

---

## Type Annotations

CI runs `mypy src/ --strict`. All code in `src/` must be fully typed.

### Rules

1. **All functions** (public and private) must have complete type annotations (parameters + return type)
2. Use modern syntax: `list[X]`, `dict[K, V]`, `X | None` (not `List`, `Dict`, `Optional`)
3. Use `from __future__ import annotations` for forward references
4. Avoid bare `# type: ignore` — always specify the error code: `# type: ignore[assignment]`
5. Use `Any` sparingly — it triggers `ANN401` warnings

### Running mypy

```bash
# Strict mode (matches CI)
mypy src/ --strict

# Quick check during development
mypy src/
```

### Third-party libraries without stubs

Add overrides to `pyproject.toml` under `[[tool.mypy.overrides]]`:

```toml
[[tool.mypy.overrides]]
module = ["your_library.*"]
ignore_missing_imports = true
```

---

## Testing

### Framework and tools

- **pytest** — test runner
- **pytest-cov** — coverage reporting
- **Hypothesis** — property-based testing

### Running tests

```bash
# Full test suite with coverage
pytest tests/ --ignore=tests/integration --cov --cov-report=term-missing --cov-fail-under=90

# Single test file
pytest tests/test_validator.py -v

# Skip slow and integration tests
pytest -m "not slow and not integration"

# Run only property-based tests
pytest tests/ -k "property"
```

Or using the Makefile:

```bash
make test
```

### Test conventions

| Convention | Rule |
|------------|------|
| File naming | `test_<module>.py` |
| Function naming | `test_<description>` |
| Property tests | `test_*_property.py` files, use `@hypothesis.given` |
| Fixtures | Place in `tests/fixtures/` |
| Slow tests | Mark with `@pytest.mark.slow` |
| Integration tests | Place in `tests/integration/`, mark with `@pytest.mark.integration` |

### Coverage requirements

- **Minimum 90% line coverage** is enforced in CI
- Branch coverage is enabled
- Check coverage before committing:

```bash
pytest --cov --cov-fail-under=90
```

### Writing property-based tests

```python
from hypothesis import given, settings
import hypothesis.strategies as st

@settings(max_examples=100)
@given(text=st.text(min_size=1, max_size=1000))
def test_scanner_never_raises(text: str) -> None:
    """Scanner returns a list (possibly empty) for any input."""
    scanner = MyScanner()
    result = scanner.scan(text, ArtifactType.PROMPT, Path("test.md"))
    assert isinstance(result, list)
```

### Test markers

```python
import pytest

@pytest.mark.slow
def test_large_file_scan() -> None:
    ...

@pytest.mark.integration
def test_end_to_end_pipeline() -> None:
    ...
```

---

## Adding a New Scanner

### Step 1: Create the scanner module

Create `src/ai_artifact_risk_validator/scanners/your_scanner.py`:

```python
"""Your scanner description."""

from __future__ import annotations

from pathlib import Path

from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule
from ai_artifact_risk_validator.models.findings import ScanFinding
from ai_artifact_risk_validator.scanners.base import BaseScanner


class YourScanner(BaseScanner):
    """Brief description of what this scanner detects."""

    @property
    def name(self) -> ScannerModule:
        return ScannerModule.YOUR_SCANNER

    @property
    def applicable_artifact_types(self) -> list[ArtifactType]:
        return [ArtifactType.PROMPT, ArtifactType.AGENT]

    @property
    def detected_risk_ids(self) -> list[str]:
        return ["P-X1", "A-X1"]

    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: Path,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        # Your detection logic here
        # IMPORTANT: Never raise exceptions — return empty list on failure
        return findings
```

### Step 2: Add the ScannerModule enum value

Add your scanner to `src/ai_artifact_risk_validator/models/enums.py`.

### Step 3: Register via entry point

Add to `pyproject.toml`:

```toml
[project.entry-points."ai_artifact_validator.scanners"]
your_scanner = "ai_artifact_risk_validator.scanners.your_scanner:YourScanner"
```

### Step 4: Add risk definitions

Create risk definitions in `src/ai_artifact_risk_validator/risks/definitions/`.

### Step 5: Write tests

- Unit tests in `tests/test_your_scanner.py`
- Property-based tests in `tests/test_your_scanner_property.py`
- Add test fixtures in `tests/fixtures/` if needed

### Scanner contract

- `scan()` must **never raise exceptions** — catch errors and return an empty list
- `is_available()` should return `False` if optional dependencies are missing
- Scanners execute with a 30-second timeout — keep processing efficient

---

## Adding Risk Definitions

Risk IDs follow the format: `<PREFIX>-<LETTER><NUMBER>`

| Prefix | Artifact Type |
|--------|---------------|
| P | Prompt |
| SK | Skill |
| A | Agent |
| MCP | MCP config |
| I | Instruction |
| H | Hook |
| SOP | SOP |
| ST | Steering |
| PL | Plugin |
| MEM | Memory |
| RAG | RAG config |
| EH | Eval harness |
| OR | Orchestration |
| API | API schema |

Subcategory letters: S=Security, P=Performance, Q=Quality, R=Reliability, C=Compliance, E=Ethics

**Important:** Never remove or change existing risk IDs — they may be referenced externally.

---

## CI/CD Pipeline

The CI pipeline has 5 jobs that **all must pass** before merging to `main`:

### 1. Lint

```bash
ruff check src/ tests/
ruff format --check src/ tests/
```

### 2. Type Check

```bash
mypy src/ --strict
```

### 3. Tests (Python 3.11 + 3.12 matrix)

```bash
pytest tests/ --ignore=tests/integration --cov --cov-report=term-missing --cov-fail-under=90
```

### 4. Security Audit

```bash
pip-audit --requirement _audit_requirements.txt --strict --desc
```

### 5. Publish (tagged releases only)

Triggered on `v*` tags after all jobs pass.

### Run everything locally before pushing

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/ --strict
pytest tests/ --ignore=tests/integration --cov --cov-fail-under=90
```

---

## Submitting Changes

### Pull Request process

1. Ensure all CI checks pass locally
2. Push your branch and open a Pull Request against `main`
3. Fill in the PR template:
   - Summary of changes
   - How it was tested
   - Breaking changes (if any)
4. Request review from a maintainer
5. Address review feedback with additional commits (don't force-push during review)

### PR checklist

- [ ] Code follows project style guidelines (ruff passes)
- [ ] Type annotations are complete (mypy --strict passes)
- [ ] Tests added/updated with ≥90% coverage maintained
- [ ] No `print()` statements in `src/`
- [ ] No hardcoded secrets (except in scanner detection patterns)
- [ ] All lines ≤ 100 characters
- [ ] `from __future__ import annotations` in new files
- [ ] Module docstring in new files
- [ ] New scanners registered in `pyproject.toml` entry points
- [ ] Risk definitions not removed or renamed

### What to avoid

- Breaking the `BaseScanner` interface contract
- Changing enum values (they are serialized in reports)
- Removing existing risk IDs
- Breaking backward compatibility of `ValidatorConfig` fields
- Adding unused dependencies to core `dependencies`

---

## Reporting Issues

### Bug reports

Include:

1. Python version and OS
2. Package version (`pip show ai-artifact-risk-validator`)
3. Minimal reproduction steps
4. Expected vs. actual behavior
5. Full error traceback (if applicable)

### Feature requests

Include:

1. Problem description (what are you trying to accomplish?)
2. Proposed solution
3. Alternatives considered
4. Any relevant context (artifact types, risk categories, etc.)

### Security vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. Instead, report it privately via GitHub's security advisory feature or email the maintainers directly.

---

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).
