.PHONY: install test lint format type-check build publish clean dev-install help

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with core dependencies
	pip install -e .

install-ml: ## Install with ML/semantic features (CPU-only torch, ~200 MB)
	pip install torch --index-url https://download.pytorch.org/whl/cpu
	pip install -e ".[ml]"

install-ml-gpu: ## Install with ML/semantic features (GPU torch, ~2.5 GB)
	pip install -e ".[ml]"

install-all: ## Install all optional dependencies (CPU-only torch)
	pip install torch --index-url https://download.pytorch.org/whl/cpu
	pip install -e ".[all]"

install-all-gpu: ## Install all optional dependencies (GPU torch)
	pip install -e ".[all]"

dev-install: ## Install the package with all development dependencies
	pip install -e ".[dev,test]"

dev-install-ml: ## Install dev + test + ML dependencies (CPU-only torch)
	pip install torch --index-url https://download.pytorch.org/whl/cpu
	pip install -e ".[dev,test,ml]"

test: ## Run the test suite with coverage
	pytest --cov --cov-report=term-missing --cov-report=html

lint: ## Run ruff linter on source and test files
	ruff check src/ tests/

format: ## Format code with ruff
	ruff format src/ tests/
	ruff check --fix src/ tests/

type-check: ## Run mypy static type checking
	mypy src/

build: ## Build wheel and source distribution
	python -m build

publish: ## Publish package to configured repository (Nexus)
	python -m twine upload dist/*

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	rm -rf .mypy_cache .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
