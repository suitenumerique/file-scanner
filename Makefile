# Note to developers:
#
# While editing this file, please respect the following statements:
#
# 1. Every variable should be defined in the ad hoc VARIABLES section with a
#    relevant subsection
# 2. Every new rule should be defined in the ad hoc RULES section with a
#    relevant subsection depending on the targeted service
# 3. Rules should be sorted alphabetically within their section
# 4. .PHONY rule statement should be written after the corresponding rule
# ==============================================================================
# VARIABLES

BOLD  := \033[1m
RESET := \033[0m
GREEN := \033[1;32m

# -- Docker
COMPOSE          = docker compose
COMPOSE_RUN      = $(COMPOSE) run --rm
COMPOSE_RUN_APP  = $(COMPOSE_RUN) app

# ==============================================================================
# RULES

default: help
.PHONY: default

# -- Project

bootstrap: ## Prepare the project for local development (build + start)
bootstrap: \
	build \
	run
.PHONY: bootstrap

# -- Docker/compose

build: ## build the docker images
	@$(COMPOSE) build
.PHONY: build

logs: ## follow the app & worker logs
	@$(COMPOSE) logs -f app worker
.PHONY: logs

run: ## start the full stack (app + worker + clamav + redis) in the background
	@$(COMPOSE) up -d --wait app worker
	@echo "$(GREEN)Service up on http://localhost:8090$(RESET) — waiting on clamav's DB can take a minute (make logs)."
.PHONY: run

stop: ## stop the stack
	@$(COMPOSE) down
.PHONY: stop

# -- Quality

lock: ## rebuild uv.lock from pyproject.toml (run after changing dependencies)
	@uv lock
.PHONY: lock

audit: ## scan dependencies for known vulnerabilities
	@uv run pip-audit
.PHONY: audit

lint: ## run the linters (ruff check + format check)
	@ruff check .
	@ruff format --check .
.PHONY: lint

lint-fix: ## auto-fix lint + format issues
	@ruff check --fix .
	@ruff format .
.PHONY: lint-fix

test: ## run the test suite (in the app container, against clamav)
	@$(COMPOSE_RUN) -e APP_CONFIG=config.TestConfig app python -m pytest
.PHONY: test

# -- Help

help:
	@echo "$(BOLD)File Scanner — available targets$(RESET)"
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-12s$(RESET) %s\n", $$1, $$2}'
.PHONY: help
