TARGET_DIR := ./target
FUZZ_DIR := ./fuzz

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

.PHONY: fuzz
fuzz:
	cargo afl build -p sectxtfuzz
	AFL_SKIP_CPUFREQ=1 cargo afl fuzz -i $(FUZZ_DIR)/_examples -o $(FUZZ_DIR)/afl $(TARGET_DIR)/debug/sectxtfuzz
