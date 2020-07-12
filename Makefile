.PHONY: test
test:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --verbose
