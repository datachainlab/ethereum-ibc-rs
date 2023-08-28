######## Lint ########

.PHONY: lint-tools
lint-tools:
	rustup component add rustfmt clippy
	cargo install cargo-machete

.PHONY: fmt
fmt:
	@cargo fmt --all $(CARGO_FMT_OPT)

.PHONY: lint
lint:
	@$(MAKE) CARGO_FMT_OPT=--check fmt
	@cargo clippy --locked --tests $(CARGO_TARGET) -- -D warnings
	@cargo machete
