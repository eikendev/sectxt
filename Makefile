.PHONY: build
build:
	cargo build --all

.PHONY: test
test:
	cargo fmt -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --verbose

.PHONY: setup
setup:
	rustup update
	rustup component add clippy
	rustup component add rustfmt
	rustup show

.PHONY: publish
publish:
	cargo publish -p sectxtlib
	cargo publish -p sectxt
