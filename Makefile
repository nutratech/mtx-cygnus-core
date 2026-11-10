SHELL=/bin/bash
.DEFAULT_GOAL := _help
CARGO ?= cargo

.PHONY: _help
_help:
	@grep -E '^[a-zA-Z_/%-]+:.*?##H' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?##H "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: format lint doc test

.PHONY: format
format: ##H Format code
	$(CARGO) fmt
	-prettier -w $$(git ls-files '*.md' '*.y*ml' '*.json')
	-pre-commit run --all-files

.PHONY: fix
fix: ##H Apply auto-fixes with clippy
	$(CARGO) clippy --fix --allow-dirty --allow-staged --allow-no-vcs --all-targets

.PHONY: lint
lint: ##H Clippy, warnings are errors
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: test
test: ##H Run tests
	$(CARGO) test --workspace --all-features

.PHONY: build
build: ##H Build the workspace and the browser wasm package
	$(CARGO) build --release --workspace --all-targets --all-features
	$(MAKE) wasm

.PHONY: check
check: ##H Cargo check and code dupe
	$(CARGO) check --workspace --all-targets --all-features
	-jscpd $$(git ls-files '*.rs')

.PHONY: doc
doc: ##H Build docs, warnings are errors
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --all-features

.PHONY: typos
typos: ##H Spell-check
	typos

.PHONY: clean
clean: ##H Remove build artifacts
	$(CARGO) clean
	rm -rf cygnus-wasm/pkg

.PHONY: extras/cloc
extras/cloc: ##H Count lines of code (excludes vendored vectors and reference models)
	cloc --vcs=git . --fmt=2 --exclude-dir=vectors,reference_models

.PHONY: wasm
wasm: ##H Build the browser verifier (needs wasm-pack)
	wasm-pack build cygnus-wasm --release --target web --out-dir pkg

# DIHYDROGEN_PATH is the Hydrogen checkout, set in .env (gitignored) or the
# environment; WASM_DEST can still be overridden on the command line.
-include .env
DIHYDROGEN_PATH ?= ../hydrogen
WASM_DEST ?= $(DIHYDROGEN_PATH)/src/matrix/cygnus/wasm
WASM_FILES := cygnus_wasm.js cygnus_wasm.d.ts cygnus_wasm_bg.wasm

.PHONY: install
install: wasm ##H Build the wasm package and copy it into $DIHYDROGEN_PATH (from .env)
	@test -d "$(WASM_DEST)" || { echo "WASM_DEST=$(WASM_DEST) does not exist; set DIHYDROGEN_PATH in .env"; exit 1; }
	cp $(addprefix cygnus-wasm/pkg/,$(WASM_FILES)) "$(WASM_DEST)/"
	@echo "Installed cygnus-wasm $$(git rev-parse --short HEAD)$$(git diff --quiet HEAD || echo -dirty) into $(WASM_DEST)"
