.DEFAULT_GOAL := help
UV ?= uv

.PHONY: help sync fmt lint type test check audit smoke

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

sync: ## Install locked dependencies (all groups)
	$(UV) sync --locked --all-groups

fmt: ## Format code and apply safe lint fixes
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

lint: ## Lint and check formatting (no changes)
	$(UV) run ruff check .
	$(UV) run ruff format --check .

type: ## Strict type checking
	$(UV) run mypy

test: ## Offline test suite with coverage gate
	$(UV) run pytest --cov --cov-report=term-missing

check: lint type test ## Full quality gate (what CI runs)

audit: ## Audit vexproof's own locked dependencies for known vulnerabilities
	$(UV) export --locked --no-hashes --no-emit-project --all-groups -o .audit-requirements.txt
	$(UV) run pip-audit --strict -r .audit-requirements.txt; status=$$?; rm -f .audit-requirements.txt; exit $$status

smoke: ## Live smoke tests against real OSV/KEV/EPSS (needs network)
	$(UV) run pytest -m network --no-cov
