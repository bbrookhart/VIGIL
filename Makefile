# VIGIL developer commands.
#
# Targets that make a security claim run the tests that back it. `make verify` is what CI
# runs and what a contributor should run before opening a pull request.

SHELL := /bin/bash
.DEFAULT_GOAL := help

PY := sdk/python/.venv/bin/python
PIP := sdk/python/.venv/bin/pip

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- build & test

.PHONY: build
build: ## Build the workspace
	cargo build --workspace

.PHONY: test
test: test-rust test-python ## Run every test

.PHONY: test-rust
test-rust: ## Run the Rust test suite
	cargo test --workspace

.PHONY: test-python
test-python: $(PY) ## Run the Python SDK tests
	$(PY) -m pytest sdk/python/tests -q

.PHONY: test-e2e
test-e2e: ## Run only the end-to-end gate tests (Gate 1/2, Demos 1-3)
	cargo test -p vigil-core --test end_to_end -- --nocapture

.PHONY: test-contract
test-contract: $(PY) ## Run the cross-language contract tests
	cargo test -p vigil-common --test canonical_contract
	cargo test -p vigil-protocol --test sdk_wire_contract
	$(PY) -m pytest sdk/python/tests/test_canonical_contract.py -q

# ---------------------------------------------------------------- quality gates

.PHONY: verify
verify: fmt-check lint test ## Everything CI runs
	@echo "✓ all gates passed"

.PHONY: fmt
fmt: ## Format Rust sources
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without modifying
	cargo fmt --all -- --check

.PHONY: lint
lint: ## Clippy, denying warnings
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: audit-deps
audit-deps: ## Check dependencies for known advisories (requires cargo-audit)
	@command -v cargo-audit >/dev/null 2>&1 \
		|| { echo "cargo-audit not installed: cargo install cargo-audit"; exit 1; }
	cargo audit

# ---------------------------------------------------------------- demos

.PHONY: demo
demo: ## Run the blocked-injection and safe-action demonstrations
	cargo run -q -p vigil-core --example demo

.PHONY: policy-check
policy-check: ## Validate every shipped policy bundle and remit
	cargo test -p vigil-policy --test policy_behaviour

# ---------------------------------------------------------------- fixtures

.PHONY: contract-fixtures
contract-fixtures: $(PY) ## Regenerate the SDK wire fixture consumed by the Rust tests
	cd $(CURDIR) && $(PY) scripts/generate_wire_fixture.py
	@echo "regenerated; run 'make test-contract' to confirm both sides still agree"

# ---------------------------------------------------------------- environment

$(PY): ## Create the Python virtualenv for the SDK
	python3 -m venv sdk/python/.venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -e "sdk/python[dev]"

.PHONY: dev-setup
dev-setup: $(PY) ## Set up local development dependencies
	@echo "✓ Python SDK environment ready at sdk/python/.venv"
	@echo "  Rust toolchain: $$(rustc --version)"

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
	rm -rf sdk/python/.venv sdk/python/**/__pycache__ sdk/python/.pytest_cache
