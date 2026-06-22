# Red Eye -- developer / operator shortcuts.
#
# Usage:
#   make install   # one-line venv + editable install
#   make test      # run the test suite
#   make lint      # ruff
#   make demo      # 60-second mock-backend scan in ./out (zero LLM cost)
#   make init      # run the interactive wizard
#   make scan-pr   # diff-only PR scan against ./
#   make scan-ci   # bounded CI scan against ./
#   make scan-deep # full research scan (slow, no DoS limits)
#   make clean     # remove venv, caches, scan artefacts

PYTHON ?= python3
VENV   ?= .venv
PIP    := $(VENV)/bin/pip
REDEYE := $(VENV)/bin/redeye

.PHONY: install test lint demo init scan-pr scan-ci scan-deep clean help

help:
	@grep -E '^[a-zA-Z_-]+:.*?#' Makefile | sed 's/:.*#/  --/'

install: ## one-line venv + editable install
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip --quiet
	$(PIP) install -e ".[dev]" --quiet
	@echo
	@echo "Installed. Next: source $(VENV)/bin/activate && redeye init"

test: ## run the test suite
	$(VENV)/bin/pytest -q

lint: ## ruff
	$(VENV)/bin/ruff check redeye/ tests/

demo: ## 60-second mock-backend scan in ./out (zero LLM cost)
	@mkdir -p out
	REDEYE_DB_PATH=./out/scans.db $(REDEYE) scan --repo . --preset quick --output-dir ./out
	@echo
	@echo "Report: ./out/redeye_*_report.md"

init: ## run the interactive wizard
	$(REDEYE) init

scan-pr: ## diff-only PR scan against ./
	@mkdir -p out
	$(REDEYE) scan --repo . --preset pr --output-dir ./out \
	    --pr-comment ./out/pr-comment.md

scan-ci: ## bounded CI scan against ./
	@mkdir -p out
	$(REDEYE) scan --repo . --preset ci --output-dir ./out

scan-deep: ## full research scan (slow, no DoS limits)
	@mkdir -p out
	$(REDEYE) scan --repo . --preset deep --output-dir ./out

clean: ## remove venv, caches, scan artefacts
	rm -rf $(VENV) .pytest_cache .ruff_cache out redeye.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
