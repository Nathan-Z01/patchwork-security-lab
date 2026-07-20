PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
VENV_BIN := $(PROJECT_ROOT)/.venv/bin
DASHBOARD_DIR := $(PROJECT_ROOT)/apps/dashboard
UV_CACHE_DIR ?= $(PROJECT_ROOT)/.cache/uv
PATCHWORK_PORT ?= 8765
SIGNALLAB_DEMO_DIR := $(PROJECT_ROOT)/reports/local/signallab
export UV_CACHE_DIR
export PATCHWORK_PORT

.DEFAULT_GOAL := help

.PHONY: help doctor check-prereqs check-web-prereqs check-dev setup test lint \
	typecheck web-install web-build release-build dev scan-self stock-demo clean

help:
	@echo "Patchwork Security Lab"
	@echo ""
	@echo "  make setup       Install locked Python and dashboard dependencies"
	@echo "  make dev         Run the dashboard and API on http://127.0.0.1:$(PATCHWORK_PORT)"
	@echo "  make test        Run Python and dashboard tests"
	@echo "  make lint        Run Python and dashboard linters"
	@echo "  make typecheck   Run Python and TypeScript type checks"
	@echo "  make web-build   Rebuild and package the dashboard"
	@echo "  make release-build  Build clean source and wheel distributions"
	@echo "  make scan-self   Write a local HTML security report"
	@echo "  make stock-demo  Train and inspect the offline synthetic stock model"
	@echo "  make doctor      Show environment and repository diagnostics"

doctor:
	@echo "Repository: $(PROJECT_ROOT)"
	@echo "Makefile:   $(PROJECT_ROOT)/Makefile"
	@if command -v uv >/dev/null 2>&1; then printf "uv:         "; uv --version; else echo "uv:         missing"; fi
	@if command -v python3 >/dev/null 2>&1; then printf "python3:    "; python3 --version; else echo "python3:    missing"; fi
	@if command -v node >/dev/null 2>&1; then printf "node:       "; node --version; else echo "node:       missing"; fi
	@if command -v npm >/dev/null 2>&1; then printf "npm:        "; npm --version; else echo "npm:        missing"; fi
	@if command -v docker >/dev/null 2>&1; then printf "docker:     "; docker --version; else echo "docker:     missing (optional for Sentinel; recommended for FreshPatch)"; fi
	@test -x "$(VENV_BIN)/patchwork-api" && echo "setup:      ready" || echo "setup:      not installed; run 'make setup'"

check-web-prereqs:
	@command -v node >/dev/null 2>&1 || { echo "Error: Node.js is required. Install Node 20.19+ or 22.12+, then retry."; exit 1; }
	@command -v npm >/dev/null 2>&1 || { echo "Error: npm is required. Install it with Node.js, then retry."; exit 1; }
	@node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (!((major === 20 && minor >= 19) || (major === 22 && minor >= 12) || major > 22)) { console.error("Error: Node 20.19+ or 22.12+ is required; found " + process.versions.node + "."); process.exit(1); }'

check-prereqs: check-web-prereqs
	@command -v uv >/dev/null 2>&1 || { echo "Error: uv is required. Install it from https://docs.astral.sh/uv/ and retry."; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "Error: Python 3 is required. Install Python 3.9+ and retry."; exit 1; }
	@python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else "Error: Python 3.9+ is required.")'

check-dev:
	@test -x "$(VENV_BIN)/patchwork-api" || { echo "Error: the development environment is missing. Run 'make setup' from $(PROJECT_ROOT) first."; exit 1; }

setup: check-prereqs
	uv sync --extra dev --frozen
	npm --prefix "$(DASHBOARD_DIR)" ci

test:
	"$(VENV_BIN)/pytest"
	npm --prefix "$(DASHBOARD_DIR)" test -- --run

lint:
	"$(VENV_BIN)/ruff" check "$(PROJECT_ROOT)/src" "$(PROJECT_ROOT)/tests" "$(PROJECT_ROOT)/scripts"
	npm --prefix "$(DASHBOARD_DIR)" run lint

typecheck:
	"$(VENV_BIN)/mypy" "$(PROJECT_ROOT)/src"
	npm --prefix "$(DASHBOARD_DIR)" run typecheck

web-install: check-web-prereqs
	npm --prefix "$(DASHBOARD_DIR)" ci

web-build: web-install
	python3 "$(PROJECT_ROOT)/scripts/build_dashboard.py" --skip-install

release-build: check-prereqs check-dev
	"$(VENV_BIN)/python" "$(PROJECT_ROOT)/scripts/clean.py"
	npm --prefix "$(DASHBOARD_DIR)" ci
	"$(VENV_BIN)/python" "$(PROJECT_ROOT)/scripts/build_dashboard.py" --skip-install
	uv build --clear

dev: check-dev
	"$(VENV_BIN)/patchwork-api"

scan-self:
	"$(VENV_BIN)/aisec" source "$(PROJECT_ROOT)" --format html --output "$(PROJECT_ROOT)/reports/local/self-scan.html"

stock-demo: check-dev
	@test -x "$(VENV_BIN)/signallab" || { echo "Error: SignalLab is not installed. Run 'make setup' first."; exit 1; }
	mkdir -p "$(SIGNALLAB_DEMO_DIR)"
	"$(VENV_BIN)/signallab" demo-data "$(SIGNALLAB_DEMO_DIR)/market.csv" --rows 700 --force
	"$(VENV_BIN)/signallab" train "$(SIGNALLAB_DEMO_DIR)/market.csv" --output "$(SIGNALLAB_DEMO_DIR)/model.json" --benchmark SYNTH_MKT --horizon-days 20
	"$(VENV_BIN)/signallab" analyze "$(SIGNALLAB_DEMO_DIR)/market.csv" SYNTH_A --artifact "$(SIGNALLAB_DEMO_DIR)/model.json" --benchmark SYNTH_MKT --sample-data

clean:
	python3 "$(PROJECT_ROOT)/scripts/clean.py"
