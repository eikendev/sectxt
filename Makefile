.PHONY: test
test:
	cargo fmt -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --verbose

.PHONY: rustup
rustup:
	rustup component add clippy
	rustup component add rustfmt
