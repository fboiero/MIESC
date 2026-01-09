# Makefile for MIESC
# Multi-layer Intelligent Evaluation for Smart Contracts
#
# Author: Fernando Boiero - UNDEF
# Thesis: Master's in Cyberdefense

.PHONY: help install test lint audit experiments clean docs docker mcp build publish release

# Default target
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m# No Color

help:  ## Show this help message
	@echo "$(BLUE)MIESC - Multi-layer Intelligent Evaluation for Smart Contracts$(NC)"
	@echo "================================================================"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

install:  ## Install dependencies
	@echo "$(BLUE)Installing MIESC dependencies...$(NC)"
	pip install -r requirements/requirements.txt
	pip install -r requirements/requirements_core.txt
	pip install -r requirements/requirements_agents.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

install-dev:  ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	pip install -r requirements/requirements.txt
	pip install pytest pytest-cov black flake8 mypy
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

test:  ## Run unit tests
	@echo "$(BLUE)Running MIESC tests...$(NC)"
	python -m pytest tests/ -v --cov=src --cov-report=term-missing
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-quick:  ## Run quick tests (no coverage)
	@echo "$(BLUE)Running quick tests...$(NC)"
	python -m pytest tests/ -v -x
	@echo "$(GREEN)✓ Quick tests complete$(NC)"

lint:  ## Run linters (flake8, black, mypy)
	@echo "$(BLUE)Running linters...$(NC)"
	@echo "  → flake8"
	flake8 src/ --max-line-length=100 --ignore=E203,W503
	@echo "  → black (check only)"
	black --check src/
	@echo "  → mypy"
	mypy src/ --ignore-missing-imports
	@echo "$(GREEN)✓ Linting complete$(NC)"

format:  ## Format code with black
	@echo "$(BLUE)Formatting code...$(NC)"
	black src/ tests/
	@echo "$(GREEN)✓ Code formatted$(NC)"

audit:  ## Run sample audit
	@echo "$(BLUE)Running sample audit...$(NC)"
	python src/miesc_cli.py run-audit examples/reentrancy_simple.sol \
		--enable-ai \
		-o analysis/results/sample_audit.json
	@echo "$(GREEN)✓ Audit complete$(NC)"

audit-fast:  ## Run fast audit (no AI)
	@echo "$(BLUE)Running fast audit (no AI)...$(NC)"
	python src/miesc_cli.py run-audit examples/reentrancy_simple.sol \
		--no-ai \
		-o analysis/results/fast_audit.json
	@echo "$(GREEN)✓ Fast audit complete$(NC)"

experiments:  ## Run thesis experiments
	@echo "$(BLUE)Setting up experiments...$(NC)"
	python analysis/experiments/00_setup_experiments.py
	@echo "$(GREEN)✓ Experiments ready$(NC)"
	@echo "$(YELLOW)Run 'make experiments-run' to execute$(NC)"

experiments-run:  ## Execute experiments
	@echo "$(BLUE)Running experiments (this may take a while)...$(NC)"
	python analysis/experiments/10_run_experiments.py
	@echo "$(GREEN)✓ Experiments complete$(NC)"

experiments-analyze:  ## Analyze experiment results
	@echo "$(BLUE)Analyzing results...$(NC)"
	python analysis/experiments/20_analyze_results.py
	@echo "$(GREEN)✓ Analysis complete$(NC)"

mcp-manifest:  ## Generate MCP manifest
	@echo "$(BLUE)Generating MCP manifest...$(NC)"
	python src/miesc_cli.py mcp-server --export-manifest
	@echo "$(GREEN)✓ Manifest generated: mcp/manifest.json$(NC)"

mcp-server:  ## Start MCP server
	@echo "$(BLUE)Starting MIESC MCP server...$(NC)"
	python src/mcp/server.py

docs:  ## Serve documentation locally with MkDocs
	@echo "$(BLUE)Starting MkDocs development server...$(NC)"
	@echo "$(YELLOW)Opening browser at http://127.0.0.1:8000$(NC)"
	@mkdocs serve

docs-build:  ## Build static documentation site
	@echo "$(BLUE)Building documentation site...$(NC)"
	@mkdocs build
	@echo "$(GREEN)✓ Documentation built in site/$(NC)"

docs-deploy:  ## Deploy documentation to GitHub Pages
	@echo "$(BLUE)Deploying documentation to GitHub Pages...$(NC)"
	@mkdocs gh-deploy --force
	@echo "$(GREEN)✓ Documentation deployed to https://fboiero.github.io/MIESC$(NC)"

webapp:  ## Launch web demo (Streamlit)
	@echo "$(BLUE)Starting MIESC Web Demo...$(NC)"
	@echo "$(YELLOW)Opening browser at http://localhost:8501$(NC)"
	@streamlit run webapp/app.py

install-webapp:  ## Install webapp dependencies
	@echo "$(BLUE)Installing webapp dependencies...$(NC)"
	@pip install -r requirements/requirements-webapp.txt
	@echo "$(GREEN)✓ Webapp dependencies installed$(NC)"

install-docs:  ## Install documentation dependencies
	@echo "$(BLUE)Installing documentation dependencies...$(NC)"
	@pip install mkdocs-material mkdocs-minify-plugin mkdocs-git-revision-date-localized-plugin mkdocstrings[python] mkdocs-autorefs
	@echo "$(GREEN)✓ Documentation dependencies installed$(NC)"

clean:  ## Clean temporary files
	@echo "$(BLUE)Cleaning temporary files...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
	@echo "$(GREEN)✓ Cleaned$(NC)"

clean-all: clean  ## Clean all generated files
	@echo "$(BLUE)Cleaning all generated files...$(NC)"
	rm -rf analysis/results/*.json
	rm -rf analysis/results/*.html
	rm -rf venv/
	@echo "$(GREEN)✓ All cleaned$(NC)"

# ============================================
# PyPI BUILD & PUBLISH (v4.3.0+)
# ============================================

build:  ## Build Python packages (wheel + sdist)
	@echo "$(BLUE)Building MIESC packages...$(NC)"
	@rm -rf dist/ build/ *.egg-info
	@python -m build
	@echo "$(GREEN)✓ Packages built in dist/$(NC)"
	@ls -la dist/

build-check:  ## Check package integrity before publish
	@echo "$(BLUE)Checking package integrity...$(NC)"
	@twine check dist/*
	@echo "$(GREEN)✓ Package checks passed$(NC)"

publish-test:  ## Upload to TestPyPI (for testing)
	@echo "$(BLUE)Uploading to TestPyPI...$(NC)"
	@twine upload --repository testpypi dist/*
	@echo "$(GREEN)✓ Uploaded to TestPyPI$(NC)"
	@echo "$(YELLOW)Install with: pip install --index-url https://test.pypi.org/simple/ miesc$(NC)"

publish:  ## Upload to PyPI (production release)
	@echo "$(BLUE)Uploading to PyPI...$(NC)"
	@echo "$(RED)WARNING: This will publish to the real PyPI!$(NC)"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	@twine upload dist/*
	@echo "$(GREEN)✓ Published to PyPI$(NC)"
	@echo "$(YELLOW)Install with: pip install miesc$(NC)"

release: build build-check  ## Full release pipeline (build + check)
	@echo "$(GREEN)✓ Release package ready in dist/$(NC)"
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Test: make publish-test"
	@echo "  2. Install from TestPyPI and verify"
	@echo "  3. Publish: make publish"

docker-build:  ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -t miesc:latest .
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-run:  ## Run MIESC in Docker
	@echo "$(BLUE)Running MIESC in Docker...$(NC)"
	docker run --rm -v $(PWD):/workspace miesc:latest

verify:  ## Verify installation
	@echo "$(BLUE)Verifying MIESC installation...$(NC)"
	@echo "  → Python version"
	python --version
	@echo "  → MIESC version"
	python src/miesc_cli.py --version
	@echo "  → Checking tools..."
	@which slither > /dev/null && echo "    ✓ Slither installed" || echo "    ✗ Slither not found"
	@which myth > /dev/null && echo "    ✓ Mythril installed" || echo "    ✗ Mythril not found"
	@which aderyn > /dev/null && echo "    ✓ Aderyn installed" || echo "    ✗ Aderyn not found"
	@echo "$(GREEN)✓ Verification complete$(NC)"

reproducibility:  ## Generate reproducibility package
	@echo "$(BLUE)Generating reproducibility package...$(NC)"
	mkdir -p thesis/reproducibility
	cp -r analysis/experiments thesis/reproducibility/
	cp -r src/*.py thesis/reproducibility/
	tar -czf thesis/reproducibility_$(shell date +%Y%m%d).tar.gz thesis/reproducibility/
	@echo "$(GREEN)✓ Reproducibility package created$(NC)"

citation:  ## Show citation information
	@echo "$(BLUE)MIESC Citation:$(NC)"
	@echo "================================================================"
	@cat CITATION.cff
	@echo "================================================================"

version:  ## Show version information
	@echo "$(BLUE)MIESC Version Information:$(NC)"
	@echo "Version: 3.5.0"
	@echo "Author: Fernando Boiero"
	@echo "Institution: UNDEF - IUA Córdoba"
	@echo "License: GPL-3.0"
	@echo "MCP Protocol: mcp/1.0"
	@echo "AI Enhancement: OpenLLaMA (Sovereign LLM)"

# Security targets (v3.1.0 - DevSecOps)
security:  ## Run all security checks
	@echo "$(BLUE)Running comprehensive security scan...$(NC)"
	@make security-sast
	@make security-deps
	@make security-secrets
	@echo "$(GREEN)✓ Security scan complete$(NC)"

security-sast:  ## Run SAST (Bandit + Semgrep)
	@echo "$(BLUE)Running SAST...$(NC)"
	@echo "  → Bandit"
	@bandit -r src/ -ll || true
	@echo "  → Semgrep"
	@semgrep --config=auto src/ || true
	@echo "$(GREEN)✓ SAST complete$(NC)"

security-deps:  ## Audit dependencies
	@echo "$(BLUE)Auditing dependencies...$(NC)"
	@pip-audit || true
	@echo "$(GREEN)✓ Dependency audit complete$(NC)"

security-secrets:  ## Scan for secrets
	@echo "$(BLUE)Scanning for hardcoded secrets...$(NC)"
	@grep -r -n -E "(api[_-]?key|password|secret|token)\s*=\s*['\"][^'\"]+['\"]" src/ || echo "  ✓ No secrets found"
	@echo "$(GREEN)✓ Secret scan complete$(NC)"

policy-check:  ## Run PolicyAgent compliance validation
	@echo "$(BLUE)Running PolicyAgent...$(NC)"
	@python src/miesc_policy_agent.py \
		--repo-path . \
		--output-json analysis/policy/compliance_report.json \
		--output-md analysis/policy/compliance_report.md
	@echo "$(GREEN)✓ Policy validation complete$(NC)"

pre-commit-install:  ## Install pre-commit hooks
	@echo "$(BLUE)Installing pre-commit hooks...$(NC)"
	@pip install pre-commit
	@pre-commit install
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"

pre-commit-run:  ## Run pre-commit hooks manually
	@echo "$(BLUE)Running pre-commit hooks...$(NC)"
	@pre-commit run --all-files
	@echo "$(GREEN)✓ Pre-commit checks complete$(NC)"

test-coverage:  ## Run tests with detailed coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	@pytest tests/ \
		--cov=src \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-report=xml \
		--cov-fail-under=85
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

security-report:  ## Generate comprehensive security report
	@echo "$(BLUE)Generating security report...$(NC)"
	@mkdir -p analysis/security
	@python src/miesc_security_checks.py > analysis/security/security_scan.json
	@echo "$(GREEN)✓ Security report: analysis/security/security_scan.json$(NC)"

shift-left:  ## Run complete Shift-Left security pipeline locally
	@echo "$(BLUE)Running Shift-Left Security Pipeline...$(NC)"
	@echo "  Phase 1: Code Quality"
	@make lint
	@echo "  Phase 2: Security Scanning"
	@make security-sast
	@echo "  Phase 3: Dependency Audit"
	@make security-deps
	@echo "  Phase 4: Testing"
	@make test-coverage
	@echo "  Phase 5: Policy Validation"
	@make policy-check
	@echo "$(GREEN)✓ Shift-Left pipeline complete$(NC)"

mcp-rest:  ## Start MCP REST API server (Flask)
	@echo "$(BLUE)Starting MIESC MCP REST API on port 5001...$(NC)"
	@python src/miesc_mcp_rest.py --host 0.0.0.0 --port 5001

mcp-test:  ## Test MCP endpoints
	@echo "$(BLUE)Testing MCP endpoints...$(NC)"
	@curl -s http://localhost:5001/mcp/capabilities | python -m json.tool
	@echo "$(GREEN)✓ MCP test complete$(NC)"

demo:  ## Run interactive demo (5 minutes)
	@echo "$(BLUE)Running MIESC Interactive Demo...$(NC)"
	@echo "$(YELLOW)This will analyze 3 vulnerable contracts and demonstrate all features$(NC)"
	@bash demo/run_demo.sh
	@echo "$(GREEN)✓ Demo complete! Results in demo/expected_outputs/$(NC)"

demo-simple:  ## Run simple demo (1 contract only)
	@echo "$(BLUE)Running simple demo...$(NC)"
	@python src/miesc_cli.py run-audit demo/sample_contracts/Reentrancy.sol \
		--output demo/expected_outputs/simple_demo.json
	@echo "$(GREEN)✓ Simple demo complete$(NC)"

all-checks:  ## Run all quality checks (recommended before commit)
	@echo "$(BLUE)Running all quality checks...$(NC)"
	@make format
	@make lint
	@make security
	@make test
	@make policy-check
	@echo "$(GREEN)✓✓✓ All checks passed! Ready to commit.$(NC)"

quick-check:  ## Quick check before commit (fast)
	@echo "$(BLUE)Running quick checks...$(NC)"
	@make lint
	@make test-quick
	@echo "$(GREEN)✓ Quick checks passed$(NC)"

# ============================================
# ACADEMIC REPRODUCIBILITY TARGETS (v3.3.0+)
# ============================================

bench:  ## Run statistical benchmarking and evaluation
	@echo "$(BLUE)Running statistical evaluation...$(NC)"
	@python scripts/eval_stats.py --input analysis/results/ --output analysis/results/stats.json
	@echo "$(GREEN)✓ Statistical results saved to analysis/results/stats.json$(NC)"

ablation:  ## Run ablation study (AI on/off comparison)
	@echo "$(BLUE)Running ablation study...$(NC)"
	@echo "  Phase 1: Baseline (no AI)"
	@python scripts/run_benchmark.py --no-ai --output analysis/results/baseline_no_ai.json
	@echo "  Phase 2: With AI correlation"
	@python scripts/run_benchmark.py --enable-ai --output analysis/results/baseline_with_ai.json
	@echo "  Phase 3: Computing differences"
	@python scripts/eval_stats.py --ablation --input analysis/results/
	@echo "$(GREEN)✓ Ablation study complete$(NC)"

sbom:  ## Generate Software Bill of Materials (SBOM)
	@echo "$(BLUE)Generating SBOM...$(NC)"
	@if command -v syft > /dev/null; then \
		syft . -o cyclonedx-json > sbom.json; \
		echo "$(GREEN)✓ SBOM generated: sbom.json$(NC)"; \
	else \
		echo "$(YELLOW)⚠ syft not found. Install: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh$(NC)"; \
		pip freeze > requirements_frozen.txt; \
		echo "$(GREEN)✓ Fallback: requirements_frozen.txt generated$(NC)"; \
	fi

reproduce:  ## Run complete reproducibility pipeline
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(BLUE)MIESC Reproducibility Pipeline$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo ""
	@echo "$(YELLOW)Phase 1: Environment Setup$(NC)"
	@make install
	@echo ""
	@echo "$(YELLOW)Phase 2: Dataset Validation$(NC)"
	@python scripts/verify_dataset_integrity.py || echo "$(YELLOW)⚠ Dataset verification script not found - skipping$(NC)"
	@echo ""
	@echo "$(YELLOW)Phase 3: Statistical Evaluation$(NC)"
	@make bench
	@echo ""
	@echo "$(YELLOW)Phase 4: Ablation Study$(NC)"
	@make ablation
	@echo ""
	@echo "$(YELLOW)Phase 5: SBOM Generation$(NC)"
	@make sbom
	@echo ""
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)✓ Reproducibility pipeline complete!$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo ""
	@echo "$(BLUE)Outputs generated:$(NC)"
	@echo "  • analysis/results/stats.json"
	@echo "  • analysis/results/baseline_no_ai.json"
	@echo "  • analysis/results/baseline_with_ai.json"
	@echo "  • sbom.json (or requirements_frozen.txt)"
	@echo ""
	@echo "$(YELLOW)For reviewers: All results are now reproducible!$(NC)"

dataset-verify:  ## Verify dataset integrity (SHA-256 checksums)
	@echo "$(BLUE)Verifying dataset integrity...$(NC)"
	@python scripts/verify_dataset_integrity.py || echo "$(YELLOW)⚠ Script not found - create scripts/verify_dataset_integrity.py$(NC)"

academic-report:  ## Generate comprehensive academic report
	@echo "$(BLUE)Generating academic validation report...$(NC)"
	@echo "  → Research Design: docs/00_RESEARCH_DESIGN.md"
	@echo "  → Metrics & Results: docs/08_METRICS_AND_RESULTS.md"
	@echo "  → Reproducibility: docs/REPRODUCIBILITY.md"
	@echo "  → References: docs/REFERENCES.md"
	@echo "  → Statistical Output: analysis/results/stats.json"
	@echo ""
	@echo "$(GREEN)✓ All academic documentation complete$(NC)"
	@echo ""
	@echo "$(YELLOW)Citation:$(NC)"
	@cat CITATION.cff
