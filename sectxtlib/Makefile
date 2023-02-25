.PHONY: build
build:
	cargo build --all

.PHONY: test
test:
	cargo fmt -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --verbose
