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

.PHONY: lint
lint: ##H Clippy, warnings are errors
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: test
test: ##H Run tests
	$(CARGO) test --workspace --all-features

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
