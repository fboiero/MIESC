# Makefile for MIESC
# Multi-layer Intelligent Evaluation for Smart Contracts
#
# Author: Fernando Boiero - UNDEF
# Thesis: Master's in Cyberdefense

.PHONY: help install install-dev test test-quick lint typecheck format audit audit-fast experiments experiments-run experiments-analyze mcp-manifest mcp-server docs docs-build docs-deploy install-docs sphinx-build sphinx-serve sphinx-clean sphinx-api clean clean-build clean-all clean-local-artifacts local-artifacts build build-check publish-test publish release docker-build docker-run researcher-bootstrap researcher-smoke verify reproducibility citation version security security-sast security-deps security-secrets policy-check pre-commit-install pre-commit-run test-coverage security-report shift-left rest-api rest-test mcp-rest mcp-test demo demo-simple all-checks quick-check bench ablation sbom reproduce dataset-verify academic-report mutate mutate-run mutate-quick mutate-results mutate-html mutate-show mutate-check mutate-clean

# Default target
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m# No Color

PYTHON ?= python3

help:  ## Show this help message
	@echo "$(BLUE)MIESC - Multi-layer Intelligent Evaluation for Smart Contracts$(NC)"
	@echo "================================================================"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

install:  ## Install dependencies
	@echo "$(BLUE)Installing MIESC dependencies...$(NC)"
	$(PYTHON) -m pip install -r requirements/requirements.txt
	$(PYTHON) -m pip install -r requirements/requirements_core.txt
	$(PYTHON) -m pip install -r requirements/requirements_agents.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

install-dev:  ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PYTHON) -m pip install -r requirements/requirements.txt
	$(PYTHON) -m pip install pytest pytest-cov ruff black mypy
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

test:  ## Run unit tests
	@echo "$(BLUE)Running MIESC tests...$(NC)"
	$(PYTHON) -m pytest tests/ -v --cov=src --cov-report=term-missing
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-quick:  ## Run quick tests (no coverage)
	@echo "$(BLUE)Running quick tests...$(NC)"
	$(PYTHON) -m pytest tests/ -v -x
	@echo "$(GREEN)✓ Quick tests complete$(NC)"

lint:  ## Run blocking linters (ruff)
	@echo "$(BLUE)Running linters...$(NC)"
	@echo "  → ruff"
	$(PYTHON) -m ruff check miesc/ src/ tests/
	@echo "  → ruff import sorting"
	$(PYTHON) -m ruff check miesc/ src/ tests/ --select I001
	@echo "$(GREEN)✓ Linting complete$(NC)"

typecheck:  ## Run public package type checks
	@echo "$(BLUE)Running public package type checks...$(NC)"
	$(PYTHON) -m mypy miesc/ --ignore-missing-imports --follow-imports=skip --disable-error-code=import-untyped

format:  ## Format code with black
	@echo "$(BLUE)Formatting code...$(NC)"
	black miesc/ src/ tests/
	@echo "$(GREEN)✓ Code formatted$(NC)"

audit:  ## Run sample audit
	@echo "$(BLUE)Running sample audit...$(NC)"
	miesc audit quick examples/reentrancy_simple.sol \
		-o analysis/results/sample_audit.json
	@echo "$(GREEN)✓ Audit complete$(NC)"

audit-fast:  ## Run fast audit (no AI)
	@echo "$(BLUE)Running fast audit (no AI)...$(NC)"
	miesc scan examples/reentrancy_simple.sol \
		-o analysis/results/fast_audit.json
	@echo "$(GREEN)✓ Fast audit complete$(NC)"

experiments:  ## Run thesis experiments
	@echo "$(BLUE)Setting up experiments...$(NC)"
	$(PYTHON) analysis/experiments/00_setup_experiments.py
	@echo "$(GREEN)✓ Experiments ready$(NC)"
	@echo "$(YELLOW)Run 'make experiments-run' to execute$(NC)"

experiments-run:  ## Execute experiments
	@echo "$(BLUE)Running experiments (this may take a while)...$(NC)"
	$(PYTHON) analysis/experiments/10_run_experiments.py
	@echo "$(GREEN)✓ Experiments complete$(NC)"

experiments-analyze:  ## Analyze experiment results
	@echo "$(BLUE)Analyzing results...$(NC)"
	$(PYTHON) analysis/experiments/20_analyze_results.py
	@echo "$(GREEN)✓ Analysis complete$(NC)"

mcp-manifest:  ## Generate local tool inventory for MCP integration
	@echo "$(BLUE)Generating MCP tool inventory...$(NC)"
	@mkdir -p mcp
	@$(PYTHON) -m miesc tools list > mcp/tools.txt
	@echo "$(GREEN)✓ Tool inventory generated: mcp/tools.txt$(NC)"

mcp-server:  ## Start MCP server
	@echo "$(BLUE)Starting MIESC MCP server...$(NC)"
	@$(PYTHON) -m miesc server mcp

docs:  ## Serve documentation locally with MkDocs
	@echo "$(BLUE)Starting MkDocs development server...$(NC)"
	@echo "$(YELLOW)Opening browser at http://127.0.0.1:8000$(NC)"
	@mkdocs serve -f docs/mkdocs.yml

docs-build:  ## Build static documentation site
	@echo "$(BLUE)Building documentation site...$(NC)"
	@mkdocs build -f docs/mkdocs.yml
	@echo "$(GREEN)✓ Documentation built in site/$(NC)"

docs-deploy:  ## Deploy documentation to GitHub Pages
	@echo "$(BLUE)Deploying documentation to GitHub Pages...$(NC)"
	@mkdocs gh-deploy -f docs/mkdocs.yml --force
	@echo "$(GREEN)✓ Documentation deployed to https://fboiero.github.io/MIESC$(NC)"

install-docs:  ## Install documentation dependencies
	@echo "$(BLUE)Installing documentation dependencies...$(NC)"
	@pip install mkdocs-material mkdocs-minify-plugin mkdocs-git-revision-date-localized-plugin mkdocstrings[python] mkdocs-autorefs
	@pip install sphinx sphinx-rtd-theme sphinx-autodoc-typehints sphinx-autobuild
	@echo "$(GREEN)✓ Documentation dependencies installed (MkDocs + Sphinx)$(NC)"

# ============================================
# SPHINX API DOCUMENTATION (v5.1.1+)
# ============================================

sphinx-build:  ## Build Sphinx API documentation
	@echo "$(BLUE)Building Sphinx API documentation...$(NC)"
	@cd docs && sphinx-build -b html . _build/html
	@echo "$(GREEN)✓ Sphinx documentation built in docs/_build/html/$(NC)"

sphinx-serve:  ## Start Sphinx development server with auto-reload
	@echo "$(BLUE)Starting Sphinx development server...$(NC)"
	@echo "$(YELLOW)Opening browser at http://127.0.0.1:8001$(NC)"
	@cd docs && sphinx-autobuild . _build/html --port 8001

sphinx-clean:  ## Clean Sphinx build artifacts
	@echo "$(BLUE)Cleaning Sphinx build...$(NC)"
	@rm -rf docs/_build
	@echo "$(GREEN)✓ Sphinx build cleaned$(NC)"

sphinx-api:  ## Generate API documentation from docstrings
	@echo "$(BLUE)Generating API documentation from docstrings...$(NC)"
	@sphinx-apidoc -o docs/api src/ -f -e -M
	@sphinx-apidoc -o docs/api miesc/ -f -e -M
	@echo "$(GREEN)✓ API documentation generated in docs/api/$(NC)"

clean:  ## Clean temporary files
	@echo "$(BLUE)Cleaning temporary files...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
	@echo "$(GREEN)✓ Cleaned$(NC)"

clean-build:  ## Clean Python packaging artifacts
	@echo "$(BLUE)Cleaning Python build artifacts...$(NC)"
	rm -rf dist/ build/ *.egg-info
	@echo "$(GREEN)✓ Build artifacts cleaned$(NC)"

clean-all: clean clean-build  ## Clean all generated files
	@echo "$(BLUE)Cleaning all generated files...$(NC)"
	rm -rf analysis/results/*.json
	rm -rf analysis/results/*.html
	rm -rf venv/
	@echo "$(GREEN)✓ All cleaned$(NC)"

local-artifacts:  ## Summarize ignored local artifacts without deleting them
	@echo "$(BLUE)Ignored local artifacts currently present:$(NC)"
	@if [ "$(DETAIL)" = "1" ]; then \
		git status --ignored --short | awk '/^!! / {print substr($$0, 4)}' | sort; \
	else \
		git status --ignored --short | awk '/^!! / {print substr($$0, 4)}' | \
			awk -F/ '{print $$1}' | sed 's/^"//' | sed 's/"$$//' | sort | uniq -c | sort -nr; \
		echo ""; \
		echo "$(YELLOW)Use DETAIL=1 make local-artifacts to list every ignored path.$(NC)"; \
	fi

clean-local-artifacts: clean clean-build sphinx-clean  ## Clean local caches/build outputs, preserving paper evidence
	@echo "$(BLUE)Cleaning local generated artifacts...$(NC)"
	rm -rf .ruff_cache .pytest_cache .mypy_cache htmlcov coverage .coverage .coverage.* .coverage\ *
	rm -rf reports evaluation_results docs/reports site
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find paper -maxdepth 1 -type f \( -name "*.aux" -o -name "*.bbl" -o -name "*.blg" -o -name "*.log" -o -name "*.out" -o -name "*.synctex.gz" -o -name "*.fls" -o -name "*.fdb_latexmk" \) -delete
	@echo "$(GREEN)✓ Local generated artifacts cleaned; canonical paper PDFs, sources, and benchmark evidence were preserved$(NC)"

# ============================================
# PyPI BUILD & PUBLISH (v4.3.0+)
# ============================================

build: clean-build  ## Build Python packages (wheel + sdist)
	@echo "$(BLUE)Building MIESC packages...$(NC)"
	@$(PYTHON) -m build
	@echo "$(GREEN)✓ Packages built in dist/$(NC)"
	@ls -la dist/

build-check:  ## Check package integrity before publish
	@echo "$(BLUE)Checking package integrity...$(NC)"
	@$(PYTHON) -m twine check dist/*
	@$(PYTHON) scripts/check_distribution_contents.py dist
	@echo "$(GREEN)✓ Package checks passed$(NC)"

publish-test:  ## Upload to TestPyPI (for testing)
	@echo "$(BLUE)Uploading to TestPyPI...$(NC)"
	@$(PYTHON) -m twine upload --repository testpypi dist/*
	@echo "$(GREEN)✓ Uploaded to TestPyPI$(NC)"
	@echo "$(YELLOW)Install with: pip install --index-url https://test.pypi.org/simple/ miesc$(NC)"

publish:  ## Upload to PyPI (production release)
	@echo "$(BLUE)Uploading to PyPI...$(NC)"
	@echo "$(RED)WARNING: This will publish to the real PyPI!$(NC)"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	@$(PYTHON) -m twine upload dist/*
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
	docker build -f docker/Dockerfile -t miesc:5.4.3 -t miesc:latest .
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-run:  ## Run MIESC in Docker
	@echo "$(BLUE)Running MIESC in Docker...$(NC)"
	docker run --rm -v $(PWD):/workspace miesc:5.4.3 --help

researcher-bootstrap:  ## Install isolated full-tool researcher dependencies
	@echo "$(BLUE)Bootstrapping researcher toolchain...$(NC)"
	./scripts/bootstrap_researcher_tools.sh

researcher-smoke:  ## Run full 9-layer researcher smoke test
	@echo "$(BLUE)Running full researcher smoke test...$(NC)"
	.venv/bin/python -m miesc.cli.main doctor
	.venv/bin/python -m miesc.cli.main audit full tests/fixtures/reentrancy.sol \
		-o /tmp/miesc-full-smoke.json \
		-f json \
		-t 5 \
		--skip-unavailable \
		--no-ml \
		--no-correlate

verify:  ## Verify installation
	@echo "$(BLUE)Verifying MIESC installation...$(NC)"
	@echo "  → Python version"
	$(PYTHON) --version
	@echo "  → MIESC version"
	$(PYTHON) -m miesc.cli.main --version
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
	@echo "Version: 5.4.3"
	@echo "Author: Fernando Boiero"
	@echo "Institution: UNDEF - IUA Córdoba"
	@echo "License: AGPL-3.0-only"
	@echo "MCP Protocol: mcp/1.0"
	@echo "AI Enhancement: Ollama (Local LLM)"

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

policy-check:  ## Run compliance mapping validation
	@echo "$(BLUE)Running compliance mapping check...$(NC)"
	@mkdir -p analysis/policy
	@$(PYTHON) -m miesc compliance examples/contracts/results.json \
		--output analysis/policy/compliance_report.md \
		--format markdown
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
	@$(PYTHON) -m miesc doctor --verbose > analysis/security/security_scan.txt
	@echo "$(GREEN)✓ Security report: analysis/security/security_scan.txt$(NC)"

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

rest-api:  ## Start local REST API server
	@echo "$(BLUE)Starting MIESC REST API on port 8000...$(NC)"
	@$(PYTHON) -m miesc.api.rest --host 0.0.0.0 --port 8000

rest-test:  ## Test local REST API endpoint
	@echo "$(BLUE)Testing local REST API endpoint...$(NC)"
	@curl -s http://localhost:8000/api/v1/health/ | $(PYTHON) -m json.tool
	@echo "$(GREEN)✓ REST API test complete$(NC)"

mcp-rest: rest-api  ## Compatibility alias for rest-api

mcp-test: rest-test  ## Compatibility alias for rest-test

demo:  ## Run interactive demo (5 minutes)
	@echo "$(BLUE)Running MIESC Interactive Demo...$(NC)"
	@echo "$(YELLOW)This will analyze 3 vulnerable contracts and demonstrate all features$(NC)"
	@bash examples/run_demo.sh
	@echo "$(GREEN)✓ Demo complete!$(NC)"

demo-simple:  ## Run simple demo (1 contract only)
	@echo "$(BLUE)Running simple demo...$(NC)"
	@mkdir -p demo/expected_outputs
	@$(PYTHON) -m miesc audit quick examples/contracts/VulnerableBank.sol \
		--output demo/expected_outputs/simple_demo.json
	@echo "$(GREEN)✓ Simple demo complete$(NC)"

all-checks:  ## Run all quality checks (recommended before commit)
	@echo "$(BLUE)Running all quality checks...$(NC)"
	@make format
	@make lint
	@make typecheck
	@make security
	@make test
	@make policy-check
	@echo "$(GREEN)✓✓✓ All checks passed! Ready to commit.$(NC)"

quick-check:  ## Quick check before commit (fast)
	@echo "$(BLUE)Running quick checks...$(NC)"
	@make lint
	@make typecheck
	@make test-quick
	@echo "$(GREEN)✓ Quick checks passed$(NC)"

# ============================================
# ACADEMIC REPRODUCIBILITY TARGETS (v3.3.0+)
# ============================================

bench:  ## Run statistical benchmarking and evaluation
	@echo "$(BLUE)Running statistical evaluation...$(NC)"
	@$(PYTHON) scripts/eval_stats.py --input analysis/results/ --output analysis/results/stats.json
	@echo "$(GREEN)✓ Statistical results saved to analysis/results/stats.json$(NC)"

ablation:  ## Run ablation study (AI on/off comparison)
	@echo "$(BLUE)Running ablation study...$(NC)"
	@echo "  Phase 1: Baseline (no AI)"
	@$(PYTHON) scripts/run_benchmark.py --no-ai --output analysis/results/baseline_no_ai.json
	@echo "  Phase 2: With AI correlation"
	@$(PYTHON) scripts/run_benchmark.py --enable-ai --output analysis/results/baseline_with_ai.json
	@echo "  Phase 3: Computing differences"
	@$(PYTHON) scripts/eval_stats.py --ablation --input analysis/results/
	@echo "$(GREEN)✓ Ablation study complete$(NC)"

sbom:  ## Generate Software Bill of Materials (SBOM)
	@echo "$(BLUE)Generating SBOM...$(NC)"
	@if command -v syft > /dev/null; then \
		syft . -o cyclonedx-json > sbom.json; \
		echo "$(GREEN)✓ SBOM generated: sbom.json$(NC)"; \
	else \
		echo "$(YELLOW)⚠ syft not found. Install: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh$(NC)"; \
		$(PYTHON) -m pip freeze > requirements_frozen.txt; \
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
	@$(PYTHON) scripts/verify_dataset_integrity.py || echo "$(YELLOW)⚠ Dataset verification script not found - skipping$(NC)"
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
	@$(PYTHON) scripts/verify_dataset_integrity.py || echo "$(YELLOW)⚠ Script not found - create scripts/verify_dataset_integrity.py$(NC)"

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

# ============================================
# MUTATION TESTING (v5.1.1+)
# ============================================
# Mutation testing verifies test quality by introducing
# small code changes (mutants) and checking if tests catch them.
# A high mutation score indicates effective tests.
# ============================================

mutate:  ## Run mutation testing (full analysis)
	@echo "$(BLUE)Running mutation testing...$(NC)"
	@echo "$(YELLOW)This may take 30-60 minutes for full analysis$(NC)"
	@mutmut run
	@echo "$(GREEN)✓ Mutation testing complete$(NC)"
	@mutmut results

mutate-run:  ## Run mutation testing with progress output
	@echo "$(BLUE)Running mutation testing with verbose output...$(NC)"
	@mutmut run --paths-to-mutate src/core/ --CI
	@echo "$(GREEN)✓ Mutation run complete$(NC)"

mutate-quick:  ## Quick mutation test (core modules only)
	@echo "$(BLUE)Running quick mutation testing (core only)...$(NC)"
	@mutmut run --paths-to-mutate src/core/
	@echo "$(GREEN)✓ Quick mutation testing complete$(NC)"
	@mutmut results

mutate-results:  ## Show mutation testing results summary
	@echo "$(BLUE)Mutation Testing Results:$(NC)"
	@mutmut results

mutate-html:  ## Generate HTML mutation testing report
	@echo "$(BLUE)Generating mutation testing HTML report...$(NC)"
	@mutmut html
	@echo "$(GREEN)✓ HTML report generated: html/index.html$(NC)"
	@echo "$(YELLOW)Open in browser: open html/index.html$(NC)"

mutate-show:  ## Show details of surviving mutants
	@echo "$(BLUE)Surviving mutants (tests failed to catch):$(NC)"
	@mutmut show all

mutate-check:  ## Check mutation score meets threshold (CI)
	@echo "$(BLUE)Checking mutation score against threshold...$(NC)"
	@$(PYTHON) -c "import subprocess; import re; \
		result = subprocess.run(['mutmut', 'results'], capture_output=True, text=True); \
		match = re.search(r'(\d+)/(\d+)', result.stdout); \
		if match: \
			killed, total = int(match.group(1)), int(match.group(2)); \
			score = (killed/total)*100 if total > 0 else 0; \
			print(f'Mutation score: {score:.1f}% ({killed}/{total} mutants killed)'); \
			exit(0 if score >= 60 else 1); \
		else: \
			print('No mutation results found'); \
			exit(1)"
	@echo "$(GREEN)✓ Mutation score check passed$(NC)"

mutate-clean:  ## Clean mutation testing cache
	@echo "$(BLUE)Cleaning mutation testing cache...$(NC)"
	@rm -rf .mutmut-cache html/
	@echo "$(GREEN)✓ Mutation cache cleaned$(NC)"
