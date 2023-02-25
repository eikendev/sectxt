.PHONY: build
build:
	cargo build --all

.PHONY: test
test:
	cd sectxtbin; cargo fmt -- --check
	cd sectxtlib; cargo fmt -- --check
	cd sectxtbin; cargo clippy --all-targets --all-features -- -D warnings
	cd sectxtlib; cargo clippy --all-targets --all-features -- -D warnings
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
