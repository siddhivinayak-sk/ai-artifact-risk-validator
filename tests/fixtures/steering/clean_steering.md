---
inclusion: auto
priority: 2
scope: workspace
---

# Code Style Steering

## Overview

This steering file enforces consistent code style across the workspace.

## Rules

- Use 4-space indentation for Python files
- Prefer type hints on all public function signatures
- Use descriptive variable names (no single-letter variables except loop counters)
- Maximum line length: 100 characters
- Functions should have docstrings following Google style

## Scope

This applies to all Python source files in the `src/` directory.

## Priority

Priority 2 - applies after security-related steering but before formatting preferences.
